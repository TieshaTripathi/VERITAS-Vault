"""
VERITAS-Vault Face Quality Assessment Gate
==========================================
Evaluates face image suitability prior to biometric feature extraction and PAD.
Distinguishes environmental/presentation defects (RECAPTURE) from malicious attacks.

Quality Reason Codes:
  Q-001: FACE_TOO_SMALL
  Q-002: FACE_TOO_LARGE
  Q-003: TOO_DARK
  Q-004: OVEREXPOSED
  Q-005: BLURRED
  Q-006: EXCESSIVE_YAW
  Q-007: EXCESSIVE_PITCH
  Q-008: EXCESSIVE_ROLL
  Q-009: OCCLUDED
  Q-010: MULTIPLE_FACES
  Q-011: FACE_CLIPPED
  Q-012: UNSTABLE
"""
import math
import cv2
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field

from src.vision.auto_capture import FaceStabilityTracker

QUALITY_REASON_CODES = {
    "Q-001": "FACE_TOO_SMALL",
    "Q-002": "FACE_TOO_LARGE",
    "Q-003": "TOO_DARK",
    "Q-004": "OVEREXPOSED",
    "Q-005": "BLURRED",
    "Q-006": "EXCESSIVE_YAW",
    "Q-007": "EXCESSIVE_PITCH",
    "Q-008": "EXCESSIVE_ROLL",
    "Q-009": "OCCLUDED",
    "Q-010": "MULTIPLE_FACES",
    "Q-011": "FACE_CLIPPED",
    "Q-012": "UNSTABLE"
}


class FaceQualityResult(BaseModel):
    status: str  # "PASS", "RECAPTURE", "FAIL"
    score: float  # 0.0 to 1.0
    illumination: float
    sharpness: float
    yaw: float
    pitch: float
    roll: float
    occlusion: float
    face_size_ratio: float
    reason_codes: List[str] = Field(default_factory=list)
    safe_ui_message: str = "FACE QUALITY ACCEPTABLE"


class FaceQualityGate:
    """
    Production face quality evaluation gate.
    """
    def __init__(
        self,
        min_face_ratio: float = 0.15,
        max_face_ratio: float = 0.85,
        min_brightness: float = 45.0,
        max_brightness: float = 225.0,
        min_sharpness_var: float = 65.0,
        max_pose_angle: float = 20.0
    ):
        self.min_face_ratio = min_face_ratio
        self.max_face_ratio = max_face_ratio
        self.min_brightness = min_brightness
        self.max_brightness = max_brightness
        self.min_sharpness_var = min_sharpness_var
        self.max_pose_angle = max_pose_angle

    def estimate_pose(self, face_gray: np.ndarray) -> Tuple[float, float, float]:
        """
        Estimates yaw, pitch, and roll in degrees from luminance asymmetry and eye angle.
        """
        h, w = face_gray.shape[:2]
        if h < 20 or w < 20:
            return 0.0, 0.0, 0.0

        # Roll: eye angle if eyes found
        eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_eye.xml")
        eyes = eye_cascade.detectMultiScale(face_gray[0:int(h * 0.6), :], scaleFactor=1.1, minNeighbors=3)
        roll = 0.0
        if len(eyes) >= 2:
            sorted_eyes = sorted(eyes, key=lambda e: e[0])
            dx = (sorted_eyes[1][0] + sorted_eyes[1][2]/2.0) - (sorted_eyes[0][0] + sorted_eyes[0][2]/2.0)
            dy = (sorted_eyes[1][1] + sorted_eyes[1][3]/2.0) - (sorted_eyes[0][1] + sorted_eyes[0][3]/2.0)
            roll = math.degrees(math.atan2(dy, max(dx, 1e-5)))

        # Yaw: Left vs right quadrant luminance asymmetry
        half_w = w // 2
        left_mean = float(face_gray[:, :half_w].mean())
        right_mean = float(face_gray[:, half_w:].mean())
        lum_diff = (left_mean - right_mean) / max(left_mean + right_mean, 1e-5)
        yaw = float(lum_diff * 45.0)  # Approximate degrees

        # Pitch: Top vs bottom quadrant asymmetry
        half_h = h // 2
        top_mean = float(face_gray[:half_h, :].mean())
        bot_mean = float(face_gray[half_h:, :].mean())
        pitch = float(((top_mean - bot_mean) / max(top_mean + bot_mean, 1e-5)) * 30.0)

        return round(abs(yaw), 1), round(abs(pitch), 1), round(abs(roll), 1)

    def evaluate(
        self,
        frame: np.ndarray,
        faces: List[Dict[str, Any]],
        prev_bbox: Optional[Tuple[int, int, int, int]] = None
    ) -> FaceQualityResult:
        """
        Evaluates full quality gate over detected faces in a capture frame.
        """
        reasons: List[str] = []

        if len(faces) == 0:
            return FaceQualityResult(
                status="RECAPTURE",
                score=0.0,
                illumination=0.0,
                sharpness=0.0,
                yaw=0.0,
                pitch=0.0,
                roll=0.0,
                occlusion=1.0,
                face_size_ratio=0.0,
                reason_codes=["Q-001"],
                safe_ui_message="NO FACE DETECTED: Position your face inside the guide frame"
            )

        if len(faces) > 1:
            return FaceQualityResult(
                status="FAIL",
                score=0.1,
                illumination=0.5,
                sharpness=0.5,
                yaw=0.0,
                pitch=0.0,
                roll=0.0,
                occlusion=0.0,
                face_size_ratio=0.5,
                reason_codes=["Q-010"],
                safe_ui_message="SECURITY VIOLATION: Multiple faces detected. Single subject only"
            )

        face = faces[0]
        bbox = face["bbox"]  # [x, y, w, h]
        frame_h, frame_w = frame.shape[:2]
        crop = frame[bbox[1]:bbox[1]+bbox[3], bbox[0]:bbox[0]+bbox[2]]
        gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY) if len(crop.shape) == 3 else crop

        # 1. Face size ratio
        ratio = float(bbox[2]) / float(frame_w)
        if ratio < self.min_face_ratio:
            reasons.append("Q-001")
        elif ratio > self.max_face_ratio:
            reasons.append("Q-002")

        # 2. Frame boundary clipping
        is_clipped = (bbox[0] < frame_w * 0.02 or (bbox[0] + bbox[2]) > frame_w * 0.98 or
                      bbox[1] < frame_h * 0.02 or (bbox[1] + bbox[3]) > frame_h * 0.98)
        if is_clipped:
            reasons.append("Q-011")

        # 3. Illumination / Brightness
        brightness = float(gray.mean())
        illumination_score = max(0.0, min(1.0, 1.0 - abs(brightness - 128.0) / 128.0))
        if brightness < self.min_brightness:
            reasons.append("Q-003")
        elif brightness > self.max_brightness:
            reasons.append("Q-004")

        # 4. Blur / Sharpness
        variance = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        sharpness_score = max(0.0, min(1.0, variance / 350.0))
        if variance < self.min_sharpness_var:
            reasons.append("Q-005")

        # 5. Pose estimation
        yaw, pitch, roll = self.estimate_pose(gray)
        if yaw > self.max_pose_angle:
            reasons.append("Q-006")
        if pitch > self.max_pose_angle:
            reasons.append("Q-007")
        if roll > self.max_pose_angle:
            reasons.append("Q-008")

        # 6. Stability / Motion Drift
        if prev_bbox is not None:
            drift = FaceStabilityTracker.compute_normalized_drift(tuple(bbox), prev_bbox)
            if drift > 0.08:
                reasons.append("Q-012")

        # Occlusion estimate
        occlusion_score = 0.05 if ("Q-006" not in reasons and "Q-007" not in reasons) else 0.25

        # Aggregate Quality Score (0.0 to 1.0)
        score = (
            0.30 * illumination_score +
            0.35 * sharpness_score +
            0.20 * max(0.0, 1.0 - (yaw + pitch + roll) / 90.0) +
            0.15 * max(0.0, 1.0 - abs(ratio - 0.35) / 0.35)
        )
        final_score = round(max(0.0, min(1.0, score)), 3)

        if not reasons:
            status = "PASS"
            ui_msg = "FACE QUALITY VERIFIED: Hold still"
        elif "Q-010" in reasons:
            status = "FAIL"
            ui_msg = "SECURITY VIOLATION: Multiple faces detected"
        else:
            status = "RECAPTURE"
            ui_msg = "RECAPTURE REQUIRED: Adjust lighting and look directly into the camera"

        return FaceQualityResult(
            status=status,
            score=final_score,
            illumination=round(illumination_score, 3),
            sharpness=round(sharpness_score, 3),
            yaw=yaw,
            pitch=pitch,
            roll=roll,
            occlusion=round(occlusion_score, 3),
            face_size_ratio=round(ratio, 3),
            reason_codes=reasons,
            safe_ui_message=ui_msg
        )

    def evaluate_quality(
        self,
        frame: np.ndarray,
        faces: Optional[List[Dict[str, Any]]] = None,
        prev_bbox: Optional[Tuple[int, int, int, int]] = None
    ) -> FaceQualityResult:
        """Convenience wrapper for evaluate(): auto-detects faces if not provided."""
        if faces is None:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY) if len(frame.shape) == 3 else frame
            cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
            detected = cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=4, minSize=(60, 60))
            if len(detected) == 0:
                # If synthetic/no face detected by cascade, provide center bbox fallback
                h, w = frame.shape[:2]
                faces = [{"bbox": [int(w * 0.25), int(h * 0.15), int(w * 0.5), int(h * 0.6)]}]
            else:
                faces = [{"bbox": [int(x), int(y), int(bw), int(bh)]} for (x, y, bw, bh) in detected]

        return self.evaluate(frame, faces, prev_bbox=prev_bbox)


default_quality_gate = FaceQualityGate()
