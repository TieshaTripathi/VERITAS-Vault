"""
VERITAS-Vault Face Detection Module
====================================
Modular face detection layer with support for pluggable backends.
Provides standardized face bounding boxes, facial landmarks, crops,
and detection confidence scores.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from functools import lru_cache
import os
from typing import Any, Dict, List, Optional, Tuple
import cv2
import numpy as np


@dataclass
class DetectedFace:
    """Standardized detected face entity."""
    bbox: Tuple[int, int, int, int]  # (x, y, w, h)
    crop: np.ndarray                 # Raw BGR cropped face region
    confidence: float = 1.0          # Detection confidence [0.0, 1.0]
    landmarks: Optional[Dict[str, Tuple[float, float]]] = None  # e.g., 'left_eye', 'right_eye'
    variance: float = 0.0            # Laplacian sharpness variance
    is_live: bool = True             # PAD liveness flag (populated in pipeline)
    pad_status: str = "PASS"
    pad_score: float = 0.85
    pad_confidence: float = 0.90
    pad_signals: Dict[str, Any] = field(default_factory=dict)
    pad_reason_codes: List[str] = field(default_factory=list)
    quality: Any = None
    raw_landmarks_5: Optional[np.ndarray] = None
    raw_yunet_row: Optional[np.ndarray] = None
    source_frame_shape: Optional[Tuple[int, int]] = None


class BaseFaceDetector(ABC):
    """Abstract interface for replaceable face detection models."""

    @abstractmethod
    def detect_faces(self, frame: np.ndarray) -> List[DetectedFace]:
        """Detect faces in a standard BGR image frame.
        
        Args:
            frame: BGR image numpy array.
            
        Returns:
            List of DetectedFace objects.
        """
        pass


class OpenCVFaceDetector(BaseFaceDetector):
    """
    Robust OpenCV-based face detector with secondary eye landmark extraction.
    Serves as an efficient, highly reliable baseline with zero external weight dependencies.
    """

    def __init__(self, min_size: Tuple[int, int] = (60, 60), scale_factor: float = 1.1, min_neighbors: int = 5):
        self.min_size = min_size
        self.scale_factor = scale_factor
        self.min_neighbors = min_neighbors
        self._face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
        self._eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_eye.xml")

    def detect_faces(self, frame: np.ndarray) -> List[DetectedFace]:
        if frame is None or frame.size == 0:
            return []

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY) if len(frame.shape) == 3 else frame
        boxes = self._face_cascade.detectMultiScale(
            gray,
            scaleFactor=self.scale_factor,
            minNeighbors=self.min_neighbors,
            minSize=self.min_size
        )

        detected: List[DetectedFace] = []
        h_frame, w_frame = frame.shape[:2]

        for (x, y, w, h) in boxes:
            # Clamp bounding box inside image boundaries
            x1, y1 = max(0, int(x)), max(0, int(y))
            x2, y2 = min(w_frame, int(x + w)), min(h_frame, int(y + h))
            crop = frame[y1:y2, x1:x2]
            if crop.size == 0:
                continue

            gray_crop = gray[y1:y2, x1:x2]
            var = float(cv2.Laplacian(gray_crop, cv2.CV_64F).var())

            # Detect eye landmarks in upper 60% of face region
            landmarks: Dict[str, Tuple[float, float]] = {}
            upper_crop = gray_crop[0:int(h * 0.60), :]
            eyes = self._eye_cascade.detectMultiScale(upper_crop, scaleFactor=1.1, minNeighbors=3, minSize=(14, 14))

            if len(eyes) >= 2:
                # Sort left to right
                sorted_eyes = sorted(eyes, key=lambda e: e[0])
                e1, e2 = sorted_eyes[0], sorted_eyes[1]
                landmarks["left_eye"] = (float(x1 + e1[0] + e1[2] / 2.0), float(y1 + e1[1] + e1[3] / 2.0))
                landmarks["right_eye"] = (float(x1 + e2[0] + e2[2] / 2.0), float(y1 + e2[1] + e2[3] / 2.0))

            detected.append(DetectedFace(
                bbox=(int(x1), int(y1), int(w), int(h)),
                crop=crop,
                confidence=0.95,
                landmarks=landmarks if landmarks else None,
                variance=var
            ))

        return detected


class YuNetFaceDetector(BaseFaceDetector):
    """
    High-performance YuNet ONNX face detector with 5-point facial landmark extraction.
    Loads models/face_detection_yunet_2023mar.onnx.
    Provides sub-25ms face detection and 5-point landmark localization (eyes, nose, mouth corners).
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        score_threshold: float = 0.6,
        nms_threshold: float = 0.3,
        top_k: int = 5000
    ):
        if model_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            candidate = os.path.join(base_dir, "models", "face_detection_yunet_2023mar.onnx")
            if os.path.isfile(candidate):
                model_path = candidate
            else:
                model_path = os.environ.get("YUNET_MODEL_PATH", "models/face_detection_yunet_2023mar.onnx")

        self.model_path = model_path
        self.score_threshold = score_threshold
        self.nms_threshold = nms_threshold
        self.top_k = top_k
        self._detector = None
        self._current_size: Tuple[int, int] = (300, 300)

        if os.path.isfile(self.model_path):
            self._init_detector()

    def _init_detector(self) -> None:
        if hasattr(cv2, "FaceDetectorYN"):
            try:
                self._detector = cv2.FaceDetectorYN.create(
                    model=self.model_path,
                    config="",
                    input_size=self._current_size,
                    score_threshold=self.score_threshold,
                    nms_threshold=self.nms_threshold,
                    top_k=self.top_k
                )
            except Exception:
                self._detector = None

    def _detect_on_frame(self, frame: np.ndarray) -> List[DetectedFace]:
        if frame is None or frame.size == 0 or self._detector is None:
            return []

        h_frame, w_frame = frame.shape[:2]
        if self._current_size != (w_frame, h_frame):
            self._current_size = (w_frame, h_frame)
            self._detector.setInputSize((w_frame, h_frame))

        ret, faces = self._detector.detect(frame)
        if faces is None or len(faces) == 0:
            return []

        detected: List[DetectedFace] = []
        for face in faces:
            conf = float(face[14])
            if conf < self.score_threshold:
                continue

            x = int(round(face[0]))
            y = int(round(face[1]))
            w = int(round(face[2]))
            h = int(round(face[3]))

            x1 = max(0, x)
            y1 = max(0, y)
            x2 = min(w_frame, x + w)
            y2 = min(h_frame, y + h)

            if x2 <= x1 or y2 <= y1:
                continue

            crop = frame[y1:y2, x1:x2]
            if crop.size == 0:
                continue

            gray_crop = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY) if len(crop.shape) == 3 else crop
            norm_crop = cv2.resize(gray_crop, (112, 112))
            var = float(cv2.Laplacian(norm_crop, cv2.CV_64F).var())

            # 5-point landmarks: right_eye, left_eye, nose, right_mouth, left_mouth
            landmarks: Dict[str, Tuple[float, float]] = {
                "right_eye": (float(face[4]), float(face[5])),
                "left_eye": (float(face[6]), float(face[7])),
                "nose": (float(face[8]), float(face[9])),
                "right_mouth": (float(face[10]), float(face[11])),
                "left_mouth": (float(face[12]), float(face[13])),
            }

            detected.append(DetectedFace(
                bbox=(int(x1), int(y1), int(x2 - x1), int(y2 - y1)),
                crop=crop,
                confidence=conf,
                landmarks=landmarks,
                variance=var,
                raw_landmarks_5=face[4:14].reshape((5, 2)),
                raw_yunet_row=face,
                source_frame_shape=frame.shape[:2]
            ))

        return detected

    def detect_faces(self, frame: np.ndarray) -> List[DetectedFace]:
        if frame is None or frame.size == 0:
            return []

        if self._detector is None:
            if os.path.isfile(self.model_path):
                self._init_detector()
            if self._detector is None:
                return OpenCVFaceDetector().detect_faces(frame)

        # 1. Primary pass on standard upright orientation
        detected = self._detect_on_frame(frame)
        if detected:
            return detected

        # 2. Secondary orientation passes (supports tilted cameras or users reclining)
        for rot_code in (cv2.ROTATE_90_COUNTERCLOCKWISE, cv2.ROTATE_90_CLOCKWISE):
            rot_frame = cv2.rotate(frame, rot_code)
            rot_detected = self._detect_on_frame(rot_frame)
            if rot_detected:
                return rot_detected

        return []


@lru_cache(maxsize=1)
def get_default_detector() -> BaseFaceDetector:
    """Factory to retrieve the active face detector instance."""
    detector_type = os.environ.get("VAULT_FACE_DETECTOR", "").lower()
    if detector_type == "opencv":
        return OpenCVFaceDetector()

    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    yunet_path = os.path.join(base_dir, "models", "face_detection_yunet_2023mar.onnx")
    if os.path.isfile(yunet_path) and hasattr(cv2, "FaceDetectorYN"):
        try:
            return YuNetFaceDetector(model_path=yunet_path)
        except Exception:
            pass
    return OpenCVFaceDetector()

