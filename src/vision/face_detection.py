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


@lru_cache(maxsize=1)
def get_default_detector() -> BaseFaceDetector:
    """Factory to retrieve the active face detector instance."""
    detector_type = os.environ.get("VAULT_FACE_DETECTOR", "opencv").lower()
    return OpenCVFaceDetector()
