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
import math
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
    pose_ok: bool = True
    yaw: float = 0.0
    pitch: float = 0.0
    roll: float = 0.0


def evaluate_quality(
    detected_face: Optional[DetectedFace],
    frame_shape: Tuple[int, int],
    expected_step: Optional[str] = None
) -> FaceQualityAssessment:
    """
    Evaluates quality of a detected face against biometric admission standards.
    Rejects poor-quality face crops before embedding extraction.
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

    h_frame, w_frame = getattr(detected_face, "source_frame_shape", None) or frame_shape[:2]
    x, y, w, h = detected_face.bbox
    crop = detected_face.crop

    gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY) if len(crop.shape) == 3 else crop
    brightness = float(gray.mean())

    # Normalize face crop dimensions before measuring sharpness for scale-invariant sharpness
    norm_gray = cv2.resize(gray, (112, 112), interpolation=cv2.INTER_LINEAR)
    sharpness = float(cv2.Laplacian(norm_gray, cv2.CV_64F).var())
    face_ratio = float(w) / max(1.0, float(w_frame))

    reasons: List[str] = []
    lighting_ok = cfg.min_brightness <= brightness <= cfg.max_brightness
    sharpness_ok = sharpness >= cfg.min_sharpness_var
    size_ok = (w >= cfg.min_face_size_pixels and face_ratio >= cfg.min_face_size_ratio and face_ratio <= cfg.max_face_size_ratio)
    
    # Check if face is clipped at borders
    if detected_face.landmarks and len(detected_face.landmarks) >= 5:
        lm_pts = list(detected_face.landmarks.values())
        not_clipped = all(
            2 <= pt[0] < (w_frame - 2) and 2 <= pt[1] < (h_frame - 2)
            for pt in lm_pts
        )
    else:
        not_clipped = (x > 2 and y > 2 and (x + w) < (w_frame - 2) and (y + h) < (h_frame - 2))

    # Pose estimation: yaw, pitch, roll
    pose_ok = True
    yaw, pitch, roll = 0.0, 0.0, 0.0
    if not expected_step or expected_step in ("LOOK STRAIGHT", "NEUTRAL POSITION"):
        if detected_face.landmarks and "left_eye" in detected_face.landmarks and "right_eye" in detected_face.landmarks:
            le = detected_face.landmarks["left_eye"]
            re = detected_face.landmarks["right_eye"]
            # In image space, right eye is to the left (smaller x), left eye is to the right (larger x)
            dx = float(le[0] - re[0])
            dy = float(le[1] - re[1])
            roll = math.degrees(math.atan2(dy, dx if abs(dx) > 1e-5 else 1e-5))
            if "nose" in detected_face.landmarks:
                nose = detected_face.landmarks["nose"]
                d_left = abs(nose[0] - le[0])
                d_right = abs(re[0] - nose[0])
                yaw = abs(d_left - d_right) / max(d_left + d_right, 1e-5) * 45.0
        else:
            # Fallback luminance / quadrant asymmetry for pose estimation
            half_w = gray.shape[1] // 2
            half_h = gray.shape[0] // 2
            if half_w > 5 and half_h > 5:
                l_mean = float(gray[:, :half_w].mean())
                r_mean = float(gray[:, half_w:].mean())
                t_mean = float(gray[:half_h, :].mean())
                b_mean = float(gray[half_h:, :].mean())
                yaw = (abs(l_mean - r_mean) / max(l_mean + r_mean, 1e-5)) * 45.0
                pitch = (abs(t_mean - b_mean) / max(t_mean + b_mean, 1e-5)) * 30.0

        has_5pt = getattr(detected_face, "raw_landmarks_5", None) is not None
        roll_exceeded = (abs(roll) > cfg.max_pose_angle_deg) if not has_5pt else False
        if yaw > cfg.max_pose_angle_deg or pitch > cfg.max_pose_angle_deg or roll_exceeded:
            pose_ok = False
            reasons.append("EXCESSIVE_POSE")

    if not size_ok:
        reasons.append("FACE_TOO_SMALL" if face_ratio < cfg.min_face_size_ratio else "FACE_TOO_LARGE")
    if not lighting_ok:
        reasons.append("POOR_LIGHTING" if brightness < cfg.min_brightness else "OVEREXPOSED")
    if not sharpness_ok:
        reasons.append("BLURRY_OR_LOW_CONTRAST")
    if not not_clipped:
        reasons.append("FACE_CLIPPED")

    # Determine user-friendly guidance message
    if not size_ok:
        guidance = "MOVE SLIGHTLY CLOSER" if face_ratio < cfg.min_face_size_ratio else "MOVE SLIGHTLY BACK"
    elif brightness < cfg.min_brightness:
        guidance = "IMPROVE LIGHTING — TOO DARK"
    elif brightness > cfg.max_brightness:
        guidance = "ADJUST LIGHTING — OVEREXPOSED"
    elif not sharpness_ok:
        guidance = "HOLD STILL — BLUR DETECTED"
    elif not not_clipped:
        guidance = "CENTER FACE IN FRAME"
    elif not pose_ok:
        guidance = "LOOK DIRECTLY AT CAMERA"
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
        reason_codes=reasons,
        pose_ok=pose_ok,
        yaw=round(yaw, 1),
        pitch=round(pitch, 1),
        roll=round(roll, 1)
    )

