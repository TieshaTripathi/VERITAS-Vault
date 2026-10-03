import time
import math
import cv2
import numpy as np
from typing import Tuple, Optional, Dict, Any, List

HUD_SCANNING = "SCANNING FOR FACE..."
HUD_FIXATING = "HOLD STILL — FIXATING..."
HUD_VERIFYING = "VERIFYING IDENTITY..."
HUD_GRANTED = "ACCESS GRANTED · UNLOCKED"
HUD_BREACH = "SECURITY BREACH · ACCESS DENIED"

def is_face_stable(
    current_bbox: Optional[Tuple[int, int, int, int]],
    prev_bbox: Optional[Tuple[int, int, int, int]],
    threshold: int = 15
) -> bool:
    """
    Evaluates whether the detected face bounding box coordinate jitter is within threshold.
    bboxes format: (x, y, w, h)
    Uses Euclidean centroid distance and dimension delta check.
    """
    if current_bbox is None or prev_bbox is None:
        return False

    return FaceStabilityTracker.is_stable(current_bbox, prev_bbox, threshold=threshold)


class FaceStabilityTracker:
    """
    Automated hands-free face fixation detector and auto-trigger lock.
    Calculates Euclidean distance between centroid coordinates (cx1, cy1) and (cx2, cy2).
    Tracks whether a face remains stable for > 300ms across consecutive frame reads,
    and enforces a cooldown lock (default 2.0s) after auto-capture.
    """
    def __init__(
        self,
        stability_threshold_ms: float = 300.0,
        jitter_threshold: float = 15.0,
        cooldown_seconds: float = 2.0
    ):
        self.stability_threshold_ms = stability_threshold_ms
        self.jitter_threshold = jitter_threshold
        self.cooldown_seconds = cooldown_seconds
        self.last_bbox: Optional[Tuple[int, int, int, int]] = None
        self.fixation_start_time: Optional[float] = None
        self.last_capture_time: float = 0.0

    @staticmethod
    def compute_normalized_drift(
        current_bbox: Optional[Tuple[int, int, int, int]],
        prev_bbox: Optional[Tuple[int, int, int, int]]
    ) -> float:
        """
        Calculate normalized drift:
        drift = Euclidean distance between centroids / bounding-box diagonal.
        Resolution-independent metric.
        """
        if current_bbox is None or prev_bbox is None:
            return 1.0

        try:
            cx1 = float(current_bbox[0]) + float(current_bbox[2]) / 2.0
            cy1 = float(current_bbox[1]) + float(current_bbox[3]) / 2.0
            cx2 = float(prev_bbox[0]) + float(prev_bbox[2]) / 2.0
            cy2 = float(prev_bbox[1]) + float(prev_bbox[3]) / 2.0

            dist = math.hypot(cx1 - cx2, cy1 - cy2)
            diag = math.hypot(float(current_bbox[2]), float(current_bbox[3]))
            if diag <= 1e-5:
                return 1.0
            return float(dist / diag)
        except (IndexError, TypeError, KeyError):
            return 1.0

    @staticmethod
    def is_stable(
        current_bbox: Optional[Tuple[int, int, int, int]],
        prev_bbox: Optional[Tuple[int, int, int, int]],
        threshold: float = 15.0,
        normalized: bool = False
    ) -> bool:
        """
        Calculate stability between consecutive face bounding boxes.
        If normalized is True or threshold <= 1.0, calculates normalized drift (dist / diagonal).
        Otherwise calculates Euclidean pixel distance between centroids <= threshold.
        """
        if current_bbox is None or prev_bbox is None:
            return False

        try:
            cx1 = float(current_bbox[0]) + float(current_bbox[2]) / 2.0
            cy1 = float(current_bbox[1]) + float(current_bbox[3]) / 2.0
            cx2 = float(prev_bbox[0]) + float(prev_bbox[2]) / 2.0
            cy2 = float(prev_bbox[1]) + float(prev_bbox[3]) / 2.0

            dist = math.hypot(cx1 - cx2, cy1 - cy2)

            if normalized or threshold <= 1.0:
                diag = math.hypot(float(current_bbox[2]), float(current_bbox[3]))
                if diag <= 1e-5:
                    return False
                drift = dist / diag
                norm_thresh = threshold if threshold <= 1.0 else 0.08
                return bool(drift <= norm_thresh)

            return bool(dist <= threshold)
        except (IndexError, TypeError, KeyError):
            return False

    def check_fixation(
        self,
        bbox: Optional[Tuple[int, int, int, int]],
        duration_ms: float = 300.0
    ) -> bool:
        """
        Track if the face remains stable for > duration_ms (default 300ms) across consecutive frame reads.
        Returns True when fixation condition is satisfied.
        """
        now = time.time()
        if bbox is None:
            self.reset_fixation()
            return False

        if self.last_bbox is None or self.fixation_start_time is None:
            self.last_bbox = bbox
            self.fixation_start_time = now
            return False

        if self.is_stable(bbox, self.last_bbox, threshold=self.jitter_threshold):
            self.last_bbox = bbox
            elapsed_ms = (now - self.fixation_start_time) * 1000.0
            return elapsed_ms > duration_ms
        else:
            self.last_bbox = bbox
            self.fixation_start_time = now
            return False

    def cooldown_active(self, cooldown_seconds: float = 2.0) -> bool:
        """
        Prevent repeated multi-triggering on the same face by enforcing a cooldown lock
        (default 2.0s) after an auto-capture event.
        """
        if self.last_capture_time <= 0.0:
            return False
        return (time.time() - self.last_capture_time) < cooldown_seconds

    def record_capture(self, timestamp: Optional[float] = None) -> None:
        """Record an auto-capture event, starting cooldown and resetting fixation tracking."""
        self.last_capture_time = time.time() if timestamp is None else timestamp
        self.reset_fixation()

    def trigger_capture(self, timestamp: Optional[float] = None) -> None:
        """Alias for record_capture."""
        self.record_capture(timestamp)

    def reset_fixation(self) -> None:
        """Reset current fixation tracking timer and coordinates."""
        self.last_bbox = None
        self.fixation_start_time = None

    def reset(self) -> None:
        """Full reset of tracker state."""
        self.reset_fixation()
        self.last_capture_time = 0.0

    def get_fixation_ms(self) -> float:
        """Return the elapsed stable fixation duration in milliseconds."""
        if self.fixation_start_time is None or self.last_bbox is None:
            return 0.0
        return max(0.0, (time.time() - self.fixation_start_time) * 1000.0)

    def get_hud_status(
        self,
        bbox: Optional[Tuple[int, int, int, int]],
        is_verifying: bool = False
    ) -> Tuple[str, Tuple[int, int, int]]:
        """
        Derive dynamic HUD status text and BGR color based on current tracking state.
        """
        if is_verifying:
            return HUD_VERIFYING, (0, 255, 255)
        if self.cooldown_active(self.cooldown_seconds):
            remaining = max(0.0, self.cooldown_seconds - (time.time() - self.last_capture_time))
            return f"COOLDOWN LOCK ({remaining:.1f}s)", (0, 240, 255)
        if bbox is None:
            return HUD_SCANNING, (255, 255, 0)
        return HUD_FIXATING, (255, 255, 0)


def draw_cyan_target_brackets(
    frame: np.ndarray,
    bbox: Tuple[int, int, int, int],
    color: Tuple[int, int, int] = (255, 255, 0),  # Cyan in OpenCV BGR
    thickness: int = 2,
    bracket_len: Optional[int] = None
) -> np.ndarray:
    """
    Draw tactical cyan target HUD brackets on the 4 corners of the detected face bounding box.
    """
    if frame is None or bbox is None:
        return frame

    x, y, w, h = [int(v) for v in bbox]
    if bracket_len is None:
        bracket_len = max(14, min(w, h) // 4)
    bracket_len = min(bracket_len, max(6, w // 2), max(6, h // 2))

    # Top-Left corner
    cv2.line(frame, (x, y), (x + bracket_len, y), color, thickness)
    cv2.line(frame, (x, y), (x, y + bracket_len), color, thickness)

    # Top-Right corner
    cv2.line(frame, (x + w, y), (x + w - bracket_len, y), color, thickness)
    cv2.line(frame, (x + w, y), (x + w, y + bracket_len), color, thickness)

    # Bottom-Left corner
    cv2.line(frame, (x, y + h), (x + bracket_len, y + h), color, thickness)
    cv2.line(frame, (x, y + h), (x, y + h - bracket_len), color, thickness)

    # Bottom-Right corner
    cv2.line(frame, (x + w, y + h), (x + w - bracket_len, y + h), color, thickness)
    cv2.line(frame, (x + w, y + h), (x + w, y + h - bracket_len), color, thickness)

    return frame


def draw_hud_overlay(
    frame: np.ndarray,
    status_text: str,
    color: Tuple[int, int, int] = (255, 255, 0),
    progress: Optional[float] = None
) -> np.ndarray:
    """
    Draw a dynamic cyber HUD status overlay on top of the live video stream.
    """
    if frame is None:
        return frame

    h, w = frame.shape[:2]
    # Draw sleek semi-transparent HUD banner bar at the top
    overlay = frame.copy()
    bar_h = 44
    cv2.rectangle(overlay, (0, 0), (w, bar_h), (11, 15, 25), -1)
    cv2.addWeighted(overlay, 0.65, frame, 0.35, 0, frame)

    # Status text with tactical glow
    cv2.putText(
        frame,
        status_text,
        (16, 28),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.65,
        color,
        2,
        cv2.LINE_AA
    )

    # Dynamic progress bar for fixation duration (0.0 -> 1.0)
    if progress is not None and 0.0 < progress <= 1.0:
        bar_w = int((w - 32) * min(progress, 1.0))
        cv2.line(frame, (16, 38), (16 + bar_w, 38), color, 3)

    return frame


class AutoCaptureEngine:
    """
    Automated Hands-Free Biometric Face Fixation Pipeline.
    Measures face spatial stability over time and triggers capture when stability >= 300ms.
    Maintained for backward compatibility.
    """
    def __init__(self, stability_threshold_ms: float = 300.0, jitter_threshold: int = 15):
        self.stability_threshold_ms = stability_threshold_ms
        self.jitter_threshold = jitter_threshold
        self.tracker = FaceStabilityTracker(
            stability_threshold_ms=stability_threshold_ms,
            jitter_threshold=float(jitter_threshold),
            cooldown_seconds=2.0
        )
        self.last_bbox: Optional[Tuple[int, int, int, int]] = None
        self.fixation_start_time: float = 0.0
        self.last_triggered_time: float = 0.0
        self.cooldown_seconds: float = 2.0

    def reset(self):
        self.last_bbox = None
        self.fixation_start_time = 0.0
        self.tracker.reset()

    def process_face_fixation(
        self,
        current_bbox: Optional[Tuple[int, int, int, int]]
    ) -> Tuple[bool, float, str]:
        """
        Evaluates current face fixation state.
        Returns: (is_triggered: bool, fixation_duration_ms: float, status_label: str)
        """
        now = time.time()

        if current_bbox is None:
            self.reset()
            return False, 0.0, HUD_SCANNING

        # Check cooldown to avoid redundant spamming triggers in same fixation
        if now - self.last_triggered_time < self.cooldown_seconds:
            self.last_bbox = current_bbox
            remaining = max(0.0, self.cooldown_seconds - (now - self.last_triggered_time))
            return False, 0.0, f"COOLDOWN ACTIVE ({remaining:.1f}s)"

        if self.last_bbox is None:
            self.last_bbox = current_bbox
            self.fixation_start_time = now
            return False, 0.0, "TRACKING_INITIATED"

        stable = FaceStabilityTracker.is_stable(current_bbox, self.last_bbox, threshold=self.jitter_threshold)

        if stable:
            fixation_duration_ms = (now - self.fixation_start_time) * 1000.0
            self.last_bbox = current_bbox

            if fixation_duration_ms >= self.stability_threshold_ms:
                self.last_triggered_time = now
                self.reset()
                return True, fixation_duration_ms, "AUTO_CAPTURE_TRIGGERED"
            else:
                return False, fixation_duration_ms, f"{HUD_FIXATING} ({int(fixation_duration_ms)}ms / {int(self.stability_threshold_ms)}ms)"
        else:
            # Face moved beyond jitter threshold, restart fixation timer
            self.last_bbox = current_bbox
            self.fixation_start_time = now
            return False, 0.0, "STABILIZING_POSITION"


default_auto_capture = AutoCaptureEngine(stability_threshold_ms=300.0, jitter_threshold=15)
default_stability_tracker = FaceStabilityTracker(stability_threshold_ms=300.0, jitter_threshold=15.0, cooldown_seconds=2.0)
