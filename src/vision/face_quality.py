"""
VERITAS-Vault Face Quality Assessment & Guidance Gate
=====================================================
Validates facial capture conditions prior to biometric processing:
- Illumination / brightness
- Sharpness / focus
- Bounding-box coverage (face scale)
- Alignment & pose estimation
- Actionable user guidance feedback
"""
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
import cv2
import numpy as np

from src.vision.config import default_biometric_config
from src.vision.face_detection import DetectedFace

ENROLLMENT_STEPS = [
    "LOOK STRAIGHT",
    "TURN SLIGHTLY LEFT",
    "TURN SLIGHTLY RIGHT",
    "MOVE SLIGHTLY CLOSER",
    "NEUTRAL POSITION"
]


@dataclass
class FaceQualityAssessment:
    is_valid: bool
    status: str                         # "PASS" | "RETRY" | "FAIL"
    brightness: float
    sharpness: float
    face_size_ratio: float
    lighting_ok: bool
    aligned_ok: bool
    sharpness_ok: bool
    guidance: str                       # User-facing prompt (e.g., "HOLD STILL", "IMPROVE LIGHTING")
    reason_codes: List[str] = field(default_factory=list)


def evaluate_quality(
    detected_face: Optional[DetectedFace],
    frame_shape: Tuple[int, int],
    expected_step: Optional[str] = None
) -> FaceQualityAssessment:
    """
    Evaluates quality of a detected face against biometric admission standards.
    Provides targeted user instruction.
    """
    cfg = default_biometric_config
    if detected_face is None or detected_face.crop is None or detected_face.crop.size == 0:
        return FaceQualityAssessment(
            is_valid=False,
            status="RETRY",
            brightness=0.0,
            sharpness=0.0,
            face_size_ratio=0.0,
            lighting_ok=False,
            aligned_ok=False,
            sharpness_ok=False,
            guidance="ADJUST POSITION — NO FACE DETECTED",
            reason_codes=["NO_FACE"]
        )

    h_frame, w_frame = frame_shape[:2]
    x, y, w, h = detected_face.bbox
    crop = detected_face.crop

    gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY) if len(crop.shape) == 3 else crop
    brightness = float(gray.mean())
    sharpness = detected_face.variance if detected_face.variance > 0 else float(cv2.Laplacian(gray, cv2.CV_64F).var())
    face_ratio = float(w) / max(1.0, float(w_frame))

    reasons: List[str] = []
    lighting_ok = cfg.min_brightness <= brightness <= cfg.max_brightness
    sharpness_ok = sharpness >= cfg.min_sharpness_var
    size_ok = (w >= cfg.min_face_size_pixels and face_ratio >= cfg.min_face_size_ratio)
    
    # Check if face is clipped at borders
    not_clipped = (x > 2 and y > 2 and (x + w) < (w_frame - 2) and (y + h) < (h_frame - 2))

    if not size_ok:
        reasons.append("FACE_TOO_SMALL")
    if not lighting_ok:
        reasons.append("POOR_LIGHTING" if brightness < cfg.min_brightness else "OVEREXPOSED")
    if not sharpness_ok:
        reasons.append("BLURRY_OR_LOW_CONTRAST")
    if not not_clipped:
        reasons.append("FACE_CLIPPED")

    # Determine user-friendly guidance message
    if not size_ok:
        guidance = "MOVE SLIGHTLY CLOSER"
    elif brightness < cfg.min_brightness:
        guidance = "IMPROVE LIGHTING — TOO DARK"
    elif brightness > cfg.max_brightness:
        guidance = "ADJUST LIGHTING — OVEREXPOSED"
    elif not sharpness_ok:
        guidance = "HOLD STILL — BLUR DETECTED"
    elif not not_clipped:
        guidance = "CENTER FACE IN FRAME"
    else:
        # Quality meets baseline requirements
        if expected_step:
            guidance = f"{expected_step} — READY"
        else:
            guidance = "HOLD STILL — VERIFYING"

    is_valid = len(reasons) == 0
    return FaceQualityAssessment(
        is_valid=is_valid,
        status="PASS" if is_valid else "RETRY",
        brightness=round(brightness, 1),
        sharpness=round(sharpness, 1),
        face_size_ratio=round(face_ratio, 3),
        lighting_ok=lighting_ok,
        aligned_ok=size_ok and not_clipped,
        sharpness_ok=sharpness_ok,
        guidance=guidance,
        reason_codes=reasons
    )
