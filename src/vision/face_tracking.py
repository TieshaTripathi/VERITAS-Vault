"""
VERITAS-Vault Face Tracking & Temporal Consensus Engine
========================================================
Maintains persistent track IDs (TRACK-01, TRACK-02) across video frames.
Buffers observations to enforce multi-frame temporal consensus:
  - 3 out of 5 consistent matches required for VERIFIED
  - 3 consecutive high-quality unknown observations for UNKNOWN_CONFIRMED (ZT-001)
  - 3 consecutive failed PAD observations for LIVENESS_FAILED (ZT-002)
  - Single frame anomalies/blur remain in VERIFYING state (zero false breaches)
  - Caches identity on track to pace heavy embedding operations (~1200ms)
"""
from collections import deque
from dataclasses import dataclass, field
import math
import time
from typing import Any, Deque, Dict, List, Optional, Tuple

from src.vision.config import BiometricConfig, default_biometric_config
from src.vision.face_detection import DetectedFace
from src.vision.face_matcher import BiometricMatchResult, RecognitionState


@dataclass
class ObservationRecord:
    timestamp: float
    state: RecognitionState
    candidate_id: Optional[str]
    candidate_name: Optional[str]
    candidate_role: Optional[str]
    similarity: float
    is_live: bool


class FaceTrack:
    """Represents a continuous facial trajectory with temporal consensus state."""

    def __init__(self, track_id: str, initial_bbox: Tuple[int, int, int, int], now: float):
        self.track_id = track_id
        self.current_bbox = initial_bbox
        self.first_seen_time = now
        self.last_seen_time = now
        self.last_embedding_time = 0.0

        # Temporal observation ring buffer (size 5)
        self.history: Deque[ObservationRecord] = deque(maxlen=5)

        # Consensus consensus state
        self.consensus_verdict: str = "VERIFYING"   # "VERIFYING" | "VERIFIED" | "POSSIBLE_MATCH" | "UNKNOWN_CONFIRMED"
        self.confirmed_identity: Optional[Dict[str, Any]] = None
        self.consecutive_unknown: int = 0
        self.consecutive_pad_fails: int = 0
        self.pad_status: str = "LIVENESS CHECKING"  # "LIVENESS CHECKING" | "LIVENESS PASS" | "LIVENESS FAILED"
        self.best_similarity: float = 0.0

    def should_run_embedding(self, now: float, interval_ms: float = 1200.0) -> bool:
        """Determines if heavy embedding inference should run on this frame."""
        # Always run if track has no observation history yet
        if not self.history:
            return True
        return (now - self.last_embedding_time) * 1000.0 >= interval_ms

    def record_observation(
        self,
        match: BiometricMatchResult,
        is_live: bool,
        now: float,
        config: BiometricConfig
    ) -> None:
        """Appends an observation and re-evaluates temporal consensus."""
        self.last_embedding_time = now
        self.best_similarity = max(self.best_similarity, match.similarity)
        
        record = ObservationRecord(
            timestamp=now,
            state=match.state,
            candidate_id=match.candidate_id,
            candidate_name=match.candidate_name,
            candidate_role=match.candidate_role,
            similarity=match.similarity,
            is_live=is_live
        )
        self.history.append(record)

        # 1. Temporal PAD evaluation (Liveness consensus)
        if is_live:
            self.consecutive_pad_fails = 0
            self.pad_status = "LIVENESS PASS"
        else:
            self.consecutive_pad_fails += 1
            if self.consecutive_pad_fails >= config.pad_confirmation_frames:
                self.pad_status = "LIVENESS FAILED"
            else:
                self.pad_status = "LIVENESS CHECKING"

        # 2. Identity Consensus evaluation
        if match.state == RecognitionState.VERIFIED and match.candidate_id:
            self.consecutive_unknown = 0
            
            # Count matches for this candidate in the last window
            cand_id = match.candidate_id
            match_count = sum(1 for obs in self.history if obs.state == RecognitionState.VERIFIED and obs.candidate_id == cand_id)

            if match_count >= config.match_consensus_frames:
                self.consensus_verdict = "VERIFIED"
                self.confirmed_identity = {
                    "id": cand_id,
                    "name": match.candidate_name,
                    "role": match.candidate_role,
                    "similarity": match.similarity
                }
            else:
                self.consensus_verdict = "VERIFYING"

        elif match.state == RecognitionState.POSSIBLE_MATCH:
            self.consecutive_unknown = 0
            # If already verified, retain verified identity unless new candidate dominates
            if self.consensus_verdict != "VERIFIED":
                self.consensus_verdict = "POSSIBLE_MATCH"
                self.confirmed_identity = {
                    "id": match.candidate_id,
                    "name": match.candidate_name,
                    "role": match.candidate_role,
                    "similarity": match.similarity
                }

        elif match.state == RecognitionState.UNKNOWN:
            # If already established as verified, a single bad frame won't flip it to breach
            if self.consensus_verdict == "VERIFIED":
                return

            self.consecutive_unknown += 1
            if self.consecutive_unknown >= config.unknown_confirmation_frames:
                self.consensus_verdict = "UNKNOWN_CONFIRMED"
                self.confirmed_identity = None
            else:
                self.consensus_verdict = "VERIFYING"


class FaceTracker:
    """Manages active face tracks using spatial IoU / centroid proximity."""

    def __init__(self, config: Optional[BiometricConfig] = None, max_idle_seconds: float = 2.5):
        self.config = config or default_biometric_config
        self.max_idle_seconds = max_idle_seconds
        self._active_tracks: Dict[str, FaceTrack] = {}
        self._next_track_num: int = 1

    def _generate_track_id(self) -> str:
        tid = f"TRACK-{self._next_track_num:02d}"
        self._next_track_num += 1
        return tid

    @staticmethod
    def _compute_iou(box_a: Tuple[int, int, int, int], box_b: Tuple[int, int, int, int]) -> float:
        xa1, ya1, wa, ha = box_a
        xa2, ya2 = xa1 + wa, ya1 + ha
        xb1, yb1, wb, hb = box_b
        xb2, yb2 = xb1 + wb, yb1 + hb

        inter_x1 = max(xa1, xb1)
        inter_y1 = max(ya1, yb1)
        inter_x2 = min(xa2, xb2)
        inter_y2 = min(ya2, yb2)

        if inter_x2 <= inter_x1 or inter_y2 <= inter_y1:
            return 0.0

        inter_area = (inter_x2 - inter_x1) * (inter_y2 - inter_y1)
        area_a = wa * ha
        area_b = wb * hb
        union_area = float(area_a + area_b - inter_area)

        return float(inter_area / max(union_area, 1e-5))

    @staticmethod
    def _centroid_dist(box_a: Tuple[int, int, int, int], box_b: Tuple[int, int, int, int]) -> float:
        cx1 = box_a[0] + box_a[2] / 2.0
        cy1 = box_a[1] + box_a[3] / 2.0
        cx2 = box_b[0] + box_b[2] / 2.0
        cy2 = box_b[1] + box_b[3] / 2.0
        return math.hypot(cx1 - cx2, cy1 - cy2)

    def update_tracks(
        self,
        detected_faces: List[DetectedFace],
        now: Optional[float] = None
    ) -> List[Tuple[DetectedFace, FaceTrack]]:
        """
        Associates detected bounding boxes with existing tracks.
        Creates new tracks for newly entering individuals.
        Prunes inactive tracks.
        """
        curr_time = now if now is not None else time.time()

        # 1. Prune expired tracks
        expired = [tid for tid, trk in self._active_tracks.items() if (curr_time - trk.last_seen_time) > self.max_idle_seconds]
        for tid in expired:
            del self._active_tracks[tid]

        assignments: List[Tuple[DetectedFace, FaceTrack]] = []
        unassigned_faces = list(detected_faces)
        unassigned_track_ids = set(self._active_tracks.keys())

        # 2. Greedily match via IoU and centroid distance
        for face in list(unassigned_faces):
            best_track_id: Optional[str] = None
            best_score = -1.0

            for tid in unassigned_track_ids:
                trk = self._active_tracks[tid]
                iou = self._compute_iou(face.bbox, trk.current_bbox)
                c_dist = self._centroid_dist(face.bbox, trk.current_bbox)

                # Match if IoU >= 0.25 or centroid shifted less than 85 pixels
                if iou >= 0.25 or c_dist < 85.0:
                    score = iou + max(0.0, 1.0 - (c_dist / 120.0))
                    if score > best_score:
                        best_score = score
                        best_track_id = tid

            if best_track_id is not None:
                track = self._active_tracks[best_track_id]
                track.current_bbox = face.bbox
                track.last_seen_time = curr_time
                assignments.append((face, track))
                unassigned_faces.remove(face)
                unassigned_track_ids.remove(best_track_id)

        # 3. Create new tracks for unassigned faces
        for face in unassigned_faces:
            new_tid = self._generate_track_id()
            new_track = FaceTrack(new_tid, face.bbox, curr_time)
            self._active_tracks[new_tid] = new_track
            assignments.append((face, new_track))

        return assignments

    def clear(self) -> None:
        """Resets all active tracking states."""
        self._active_tracks.clear()
        self._next_track_num = 1
