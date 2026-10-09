"""
VERITAS-Vault Unified Biometric Service
=======================================
High-level orchestrator for face detection, canonical alignment,
multisignal presentation attack detection (PAD), 512-D deep embeddings,
in-memory template caching, persistent tracking, and multi-frame temporal consensus.
"""
import base64
import io
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
import cv2
import numpy as np

from src.pwa.security import seal, unseal
from src.vision.config import BiometricConfig, default_biometric_config
from src.vision.face_detection import BaseFaceDetector, DetectedFace, get_default_detector
from src.vision.face_embedding import (
    BaseEmbeddingExtractor,
    aggregate_embeddings,
    get_default_embedding_extractor,
)
from src.vision.face_matcher import (
    BiometricMatchResult,
    EnrolledIdentity,
    RecognitionState,
    match_embedding,
)
from src.vision.face_quality import ENROLLMENT_STEPS, FaceQualityAssessment, evaluate_quality
from src.vision.face_tracking import FaceTrack, FaceTracker
from src.vision.liveness import evaluate_multisignal_pad


class BiometricService:
    """
    Central production biometric engine for VERITAS-Vault.
    Enforces in-memory template caching and thread-safe execution locks.
    """

    def __init__(self, config: Optional[BiometricConfig] = None):
        self.config = config or default_biometric_config
        self.detector: BaseFaceDetector = get_default_detector()
        self.embedding_extractor: BaseEmbeddingExtractor = get_default_embedding_extractor()
        self.tracker: FaceTracker = FaceTracker(config=self.config)

        # In-memory template cache (person_id -> EnrolledIdentity)
        self._cache: Dict[str, EnrolledIdentity] = {}
        self._cache_lock = threading.Lock()
        self._cache_loaded: bool = False

        # Single recognition request lock to prevent queued frame lag
        self._processing_lock = threading.Lock()

    def invalidate_cache(self) -> None:
        """Flushes the in-memory enrolled identity cache."""
        with self._cache_lock:
            self._cache.clear()
            self._cache_loaded = False
        self.tracker.clear()

    def load_cache_if_needed(self, store_personnel: List[Dict[str, Any]]) -> None:
        """Loads and decrypts enrolled templates into RAM once."""
        if self._cache_loaded:
            return

        with self._cache_lock:
            if self._cache_loaded:
                return

            self._cache.clear()
            for person in store_personnel:
                person_id = person.get("id")
                raw_template = person.get("template")
                if not person_id or not raw_template:
                    continue

                try:
                    # Unseal template envelope
                    raw_bytes = unseal(base64.b64decode(raw_template), "person:" + person_id)
                    with np.load(io.BytesIO(raw_bytes), allow_pickle=False) as data:
                        # Standard 512-D embedding payload
                        if "identity_embedding" in data:
                            id_emb = data["identity_embedding"].astype(np.float32)
                            reps: List[np.ndarray] = []
                            if "rep_embeddings" in data and data["rep_embeddings"].size > 0:
                                reps = [r.astype(np.float32) for r in data["rep_embeddings"]]
                            
                            self._cache[person_id] = EnrolledIdentity(
                                id=person_id,
                                name=person.get("name", "Unknown"),
                                role=person.get("role", "Employee"),
                                identity_embedding=id_emb,
                                representative_embeddings=reps,
                                model_version=str(data.get("model_version", self.config.model_version)),
                                quality_score=float(data.get("quality_score", 0.95)),
                                enrolled_at=str(person.get("created_at", ""))
                            )
                        # Backwards compatibility: extract feature vector from legacy template
                        elif "embedding" in data and data["embedding"].size == 512:
                            id_emb = data["embedding"].astype(np.float32)
                            self._cache[person_id] = EnrolledIdentity(
                                id=person_id,
                                name=person.get("name", "Unknown"),
                                role=person.get("role", "Employee"),
                                identity_embedding=id_emb,
                                representative_embeddings=[],
                                model_version="legacy-512d",
                                quality_score=0.90,
                                enrolled_at=str(person.get("created_at", ""))
                            )
                        elif "norm" in data:
                            # Re-extract standard 512-D embedding from stored norm crop
                            norm_crop = data["norm"]
                            id_emb = self.embedding_extractor.extract_embedding(norm_crop)
                            self._cache[person_id] = EnrolledIdentity(
                                id=person_id,
                                name=person.get("name", "Unknown"),
                                role=person.get("role", "Employee"),
                                identity_embedding=id_emb,
                                representative_embeddings=[],
                                model_version="migrated-512d",
                                quality_score=0.85,
                                enrolled_at=str(person.get("created_at", ""))
                            )
                except Exception:
                    # Corrupt or incompatible template is safely bypassed
                    continue

            self._cache_loaded = True

    def process_frame(
        self,
        frame: np.ndarray,
        store_personnel: List[Dict[str, Any]],
        now: Optional[float] = None
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Processes a live camera frame:
          1. Face detection
          2. Tracking association & track continuity
          3. Multi-signal presentation attack detection (PAD)
          4. Cadenced embedding extraction (~1200ms or new tracks)
          5. Cosine similarity matching against in-memory cache
          6. Multi-frame temporal consensus arbitration
        """
        t_start = time.perf_counter()
        curr_time = now if now is not None else time.time()

        # Ensure in-memory template cache is warm
        self.load_cache_if_needed(store_personnel)

        # 1. Face detection
        t_det0 = time.perf_counter()
        detected_faces = self.detector.detect_faces(frame)
        face_detection_ms = round((time.perf_counter() - t_det0) * 1000.0, 2)

        # 2. Tracking association
        tracked_pairs = self.tracker.update_tracks(detected_faces, curr_time)

        faces_output: List[Dict[str, Any]] = []
        embedding_total_ms = 0.0
        matching_total_ms = 0.0

        for face, track in tracked_pairs:
            # 3. Liveness (PAD)
            pad_res = evaluate_multisignal_pad(face.crop, threshold=self.config.pad_threshold)
            face.is_live = (pad_res["status"] == "PASS")
            face.pad_status = pad_res["status"]
            face.pad_score = pad_res["pad_score"]
            face.pad_confidence = pad_res["pad_confidence"]
            face.pad_signals = pad_res["signals"]
            face.pad_reason_codes = pad_res["reason_codes"]

            # 4. Check if heavy embedding inference should run on this track
            if track.should_run_embedding(curr_time, interval_ms=self.config.embedding_interval_ms):
                t_emb0 = time.perf_counter()
                probe_embedding = self.embedding_extractor.extract_embedding(face.crop, face.landmarks)
                embedding_total_ms += (time.perf_counter() - t_emb0) * 1000.0

                # 5. Matching against in-memory cache
                t_mat0 = time.perf_counter()
                with self._cache_lock:
                    match_result = match_embedding(probe_embedding, self._cache, self.config)
                matching_total_ms += (time.perf_counter() - t_mat0) * 1000.0

                # 6. Record observation and update consensus
                track.record_observation(match_result, face.is_live, curr_time, self.config)

            # Determine user-facing verdict from consensus state
            verdict = track.consensus_verdict  # "VERIFIED" | "POSSIBLE_MATCH" | "UNKNOWN_CONFIRMED" | "VERIFYING"
            is_recognized = (verdict == "VERIFIED")
            
            # Identity details
            identity = track.confirmed_identity
            cand_id = identity["id"] if identity else "unknown"
            cand_name = identity["name"] if identity else ("Unknown Person" if verdict == "UNKNOWN_CONFIRMED" else "Verifying Identity...")
            cand_role = identity["role"] if identity else ("Unauthorized" if verdict == "UNKNOWN_CONFIRMED" else "Evaluating Clearance")
            similarity = identity.get("similarity", track.best_similarity) if identity else track.best_similarity

            # Liveness consensus state
            liveness_label = (
                "PASS" if track.pad_status == "LIVENESS PASS"
                else "FAIL" if track.pad_status == "LIVENESS FAILED"
                else "CHECKING"
            )

            faces_output.append({
                "id": cand_id,
                "name": cand_name,
                "role": cand_role,
                "similarity": round(float(similarity), 3),
                "is_recognized": is_recognized,
                "is_live": (track.pad_status != "LIVENESS FAILED"),
                "confidence": round(float(similarity), 3),
                "recognition_state": verdict,
                "candidate_name": cand_name,
                "candidate_similarity": round(float(similarity), 3),
                "liveness": liveness_label,
                "pad_status": "PASS" if face.is_live else "FAIL",
                "pad_score": float(face.pad_score),
                "pad_confidence": float(face.pad_confidence),
                "pad_signals": face.pad_signals,
                "pad_reason_codes": face.pad_reason_codes,
                "consensus": "3/3 CONFIRMED" if verdict == "VERIFIED" else (f"{track.consecutive_unknown}/3 UNKNOWN" if verdict == "UNKNOWN_CONFIRMED" else f"{len(track.history)}/3 EVAL"),
                "track_id": track.track_id,
                "bbox": [int(b) for b in face.bbox],
                "variance": round(float(face.variance), 1)
            })

        total_biometric_ms = round((time.perf_counter() - t_start) * 1000.0, 2)

        # Quality overview report
        brightness = float(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).mean()) if frame.size > 0 else 0.0
        primary_face = detected_faces[0] if detected_faces else None
        quality_eval = evaluate_quality(primary_face, frame.shape[:2])

        quality_report = {
            "face_count": len(detected_faces),
            "brightness": round(brightness, 1),
            "lighting_ok": quality_eval.lighting_ok,
            "aligned": quality_eval.aligned_ok,
            "sharpness": quality_eval.sharpness,
            "texture_ok": bool(detected_faces) and all(f["is_live"] for f in faces_output),
            "guidance": quality_eval.guidance,
            "telemetry": {
                "detector": "OpenCV Haar (Cascade)",
                "embedding_model": getattr(self.embedding_extractor, "version", "Standard-Gradient-512D-v2.0"),
                "face_detection_ms": face_detection_ms,
                "embedding_ms": round(embedding_total_ms, 2),
                "matching_ms": round(matching_total_ms, 2),
                "total_biometric_ms": total_biometric_ms
            }
        }

        return faces_output, quality_report

    def create_multisample_template(
        self,
        person_id: str,
        sample_crops: List[np.ndarray],
        landmarks_list: Optional[List[Optional[Dict]]] = None
    ) -> str:
        """
        Extracts 512-D embeddings from multiple sample crops,
        removes outliers, computes mean identity embedding,
        and serializes into an AES-GCM sealed template string.
        """
        if not sample_crops or len(sample_crops) < self.config.min_enrollment_samples:
            raise ValueError(f"At least {self.config.min_enrollment_samples} samples required for enrollment")

        raw_embeddings: List[np.ndarray] = []
        for i, crop in enumerate(sample_crops):
            lm = landmarks_list[i] if (landmarks_list and i < len(landmarks_list)) else None
            emb = self.embedding_extractor.extract_embedding(crop, lm)
            if emb is not None and emb.size == 512:
                raw_embeddings.append(emb)

        if len(raw_embeddings) < self.config.min_enrollment_samples:
            raise ValueError("Insufficient valid embeddings extracted from enrollment samples")

        # Outlier filtering and aggregation
        identity_embedding, representative_embeddings = aggregate_embeddings(raw_embeddings)

        # Package template data
        buf = io.BytesIO()
        norm_face = cv2.resize(cv2.equalizeHist(cv2.cvtColor(sample_crops[0], cv2.COLOR_BGR2GRAY)), (128, 128))
        np.savez(
            buf,
            identity_embedding=identity_embedding,
            rep_embeddings=np.array(representative_embeddings, dtype=np.float32),
            model_version=self.config.model_version,
            quality_score=0.96,
            norm=norm_face,
            embedding=identity_embedding
        )

        sealed_payload = seal(buf.getvalue(), "person:" + person_id)
        return base64.b64encode(sealed_payload).decode("ascii")


# Global singleton service
default_biometric_service = BiometricService()
