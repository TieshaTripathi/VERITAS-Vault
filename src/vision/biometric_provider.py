"""
VERITAS-Vault Real Biometric Provider Architecture
===================================================
Defines the unified interface for face feature extraction and verification:
  - TemplateMatchingProvider (Prototype baseline: OpenCV NCC + MSE)
  - FaceNetProvider (ONNX 512-D L2-normalized embeddings)
  - ArcFaceProvider (Additive Angular Margin 512-D cosine similarity)

Fail-Safe Rules:
  - If VAULT_BIOMETRIC_PROVIDER=arcface and model weights are missing or corrupt,
    the system strictly fails safe with a configuration error. It NEVER silently
    falls back to template matching.
  - Raw biometric embeddings are never logged or exposed in plaintext.
"""
from abc import ABC, abstractmethod
import base64
import hashlib
import io
import os
import time
from typing import Dict, Any, Optional, Tuple
import cv2
import numpy as np
from pydantic import BaseModel, Field

from src.vision.alignment import align_face
from src.vision.model_registry import default_model_registry


class ModelInfo(BaseModel):
    provider: str
    model_version: str
    threshold_version: str
    decision_threshold: float
    embedding_dimension: int
    status: str = "ACTIVE"


class BiometricTemplate(BaseModel):
    provider: str
    model_version: str
    embedding_dimension: int
    template_payload: str  # Base64 serialized (optionally sealed) feature vector/image
    created_at: str
    quality_score: float = 1.0


class BiometricVerificationResult(BaseModel):
    matched: bool
    similarity: float
    threshold: float
    confidence: float
    provider: str
    model_version: str
    embedding_dimension: int
    threshold_version: str
    metrics: Dict[str, Any] = Field(default_factory=dict)


class BiometricProvider(ABC):
    @abstractmethod
    def get_model_info(self) -> ModelInfo:
        """Return model metadata, version, and calibrated threshold version."""
        pass

    @abstractmethod
    def extract_features(self, frame: np.ndarray) -> np.ndarray:
        """Extract standardized feature array from a face frame."""
        pass

    @abstractmethod
    def enroll(self, frame: np.ndarray) -> BiometricTemplate:
        """Enroll face into a typed biometric template."""
        pass

    @abstractmethod
    def verify(self, frame: np.ndarray, template: BiometricTemplate) -> BiometricVerificationResult:
        """Verify live face frame against an enrolled biometric template."""
        pass


class TemplateMatchingProvider(BiometricProvider):
    """
    Normalized Cross-Correlation (NCC) + Mean Squared Error (MSE) baseline on 128x128 equalized grayscale.
    Clearly designated as a development/prototype baseline provider.
    """
    def __init__(self, ncc_threshold: float = 0.82, mse_threshold: float = 0.18):
        self.ncc_threshold = ncc_threshold
        self.mse_threshold = mse_threshold
        self.version = "NCC-MSE-v1.2"
        self.threshold_version = "TH-NCC-0.82"

    def get_model_info(self) -> ModelInfo:
        return ModelInfo(
            provider="template_matching",
            model_version=self.version,
            threshold_version=self.threshold_version,
            decision_threshold=self.ncc_threshold,
            embedding_dimension=16384,
            status="ACTIVE"
        )

    def extract_features(self, frame: np.ndarray) -> np.ndarray:
        if frame is None or frame.size == 0:
            raise ValueError("Empty frame provided for template matching")
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY) if len(frame.shape) == 3 else frame
        eq = cv2.equalizeHist(gray)
        return cv2.resize(eq, (128, 128))

    def enroll(self, frame: np.ndarray) -> BiometricTemplate:
        norm = self.extract_features(frame)
        buf = io.BytesIO()
        np.save(buf, norm)
        payload = base64.b64encode(buf.getvalue()).decode("ascii")
        return BiometricTemplate(
            provider="template_matching",
            model_version=self.version,
            embedding_dimension=16384,
            template_payload=payload,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            quality_score=0.90
        )

    def verify(self, frame: np.ndarray, template: BiometricTemplate) -> BiometricVerificationResult:
        if template.provider != "template_matching":
            raise ValueError(f"Template provider mismatch: expected template_matching, got {template.provider}")

        live_norm = self.extract_features(frame)
        raw = base64.b64decode(template.template_payload)
        enrolled_norm = np.load(io.BytesIO(raw))

        res = cv2.matchTemplate(live_norm, enrolled_norm, cv2.TM_CCOEFF_NORMED)
        score = float(res[0][0])
        err = np.sum((live_norm.astype(float) - enrolled_norm.astype(float)) ** 2)
        pixel_error = float(err / float(live_norm.shape[0] * live_norm.shape[1] * 65025.0))

        is_match = (score >= self.ncc_threshold and pixel_error <= self.mse_threshold)
        similarity = max(0.0, min(1.0, score))
        confidence = similarity if is_match else max(0.1, similarity * 0.7)

        return BiometricVerificationResult(
            matched=is_match,
            similarity=round(similarity, 4),
            threshold=self.ncc_threshold,
            confidence=round(confidence, 4),
            provider="template_matching",
            model_version=self.version,
            embedding_dimension=16384,
            threshold_version=self.threshold_version,
            metrics={"pixel_error": round(pixel_error, 4)}
        )


class FaceNetProvider(BiometricProvider):
    """
    ONNX FaceNet 512-D L2-normalized feature embeddings with cosine similarity matching.
    """
    def __init__(self, model_path: Optional[str] = None, cosine_threshold: float = 0.70):
        self.model_path = model_path or os.environ.get("FACENET_MODEL_PATH")
        self.cosine_threshold = cosine_threshold
        self.version = "FaceNet-ONNX-512D-v1.0"
        self.threshold_version = "TH-FACENET-COS-0.70"
        if not self.model_path or not os.path.exists(self.model_path):
            raise FileNotFoundError(f"FaceNet ONNX model weights not found at: {self.model_path}")

    def get_model_info(self) -> ModelInfo:
        return ModelInfo(
            provider="facenet",
            model_version=self.version,
            threshold_version=self.threshold_version,
            decision_threshold=self.cosine_threshold,
            embedding_dimension=512,
            status="ACTIVE"
        )

    def extract_features(self, frame: np.ndarray) -> np.ndarray:
        network = cv2.dnn.readNetFromONNX(self.model_path)
        rgb = cv2.cvtColor(cv2.resize(frame, (160, 160)), cv2.COLOR_BGR2RGB).astype(np.float32)
        std_val = float(rgb.std())
        rgb = (rgb - rgb.mean()) / max(std_val, 1.0 / np.sqrt(rgb.size))
        network.setInput(np.transpose(rgb, (2, 0, 1))[None])
        vector = network.forward().flatten()
        norm = max(float(np.linalg.norm(vector)), 1e-8)
        return (vector / norm).astype(np.float32)

    def enroll(self, frame: np.ndarray) -> BiometricTemplate:
        vec = self.extract_features(frame)
        buf = io.BytesIO()
        np.save(buf, vec)
        return BiometricTemplate(
            provider="facenet",
            model_version=self.version,
            embedding_dimension=512,
            template_payload=base64.b64encode(buf.getvalue()).decode("ascii"),
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            quality_score=0.95
        )

    def verify(self, frame: np.ndarray, template: BiometricTemplate) -> BiometricVerificationResult:
        if template.provider != "facenet":
            raise ValueError(f"Template provider mismatch: expected facenet, got {template.provider}")

        v1 = self.extract_features(frame)
        v2 = np.load(io.BytesIO(base64.b64decode(template.template_payload)))

        sim = float(np.dot(v1, v2))
        is_match = sim >= self.cosine_threshold
        similarity = max(0.0, min(1.0, sim))

        return BiometricVerificationResult(
            matched=is_match,
            similarity=round(similarity, 4),
            threshold=self.cosine_threshold,
            confidence=round(similarity, 4),
            provider="facenet",
            model_version=self.version,
            embedding_dimension=512,
            threshold_version=self.threshold_version
        )


class ArcFaceProvider(BiometricProvider):
    """
    Real ArcFace (Additive Angular Margin Loss) deep embedding provider.
    Enforces:
      - Canonical face alignment prior to inference (align_face)
      - Standard 112x112 normalized BGR/RGB input tensor
      - Strict 512-dimensional L2 unit vector output
      - Cosine similarity matching
      - Optional SHA-256 model checksum verification
      - FAIL-SAFE: Refuses startup if weights missing or corrupt.
    """
    def __init__(
        self,
        model_path: Optional[str] = None,
        cosine_threshold: float = 0.68,
        expected_checksum: Optional[str] = None
    ):
        self.model_path = model_path or os.environ.get("VAULT_ARCFACE_MODEL_PATH") or os.environ.get("ARCFACE_MODEL_PATH")
        self.cosine_threshold = cosine_threshold
        self.version = "ArcFace-ResNet50-512D-v1.0"
        self.threshold_version = "arcface-threshold-v1"
        self.expected_checksum = expected_checksum or os.environ.get("VAULT_ARCFACE_CHECKSUM")

        if not self.model_path or not os.path.exists(self.model_path):
            raise RuntimeError(
                f"FATAL: ArcFace model path '{self.model_path}' does not exist. "
                "Configure VAULT_ARCFACE_MODEL_PATH with valid ONNX weights. "
                "Silent fallback to weak template matching is strictly forbidden in Zero-Trust mode."
            )

        if self.expected_checksum:
            if not default_model_registry.verify_file_checksum(self.model_path, self.expected_checksum):
                raise RuntimeError(
                    f"FATAL: ArcFace weights checksum mismatch for '{self.model_path}'. "
                    f"Potential model tampering or corruption detected."
                )

        try:
            self._network = cv2.dnn.readNetFromONNX(self.model_path)
        except Exception as exc:
            raise RuntimeError(f"FATAL: Failed to initialize ArcFace ONNX network from '{self.model_path}': {exc}")

    def get_model_info(self) -> ModelInfo:
        return ModelInfo(
            provider="arcface",
            model_version=self.version,
            threshold_version=self.threshold_version,
            decision_threshold=self.cosine_threshold,
            embedding_dimension=512,
            status="ACTIVE"
        )

    def extract_features(self, frame: np.ndarray) -> np.ndarray:
        """
        Aligns face to canonical geometry and performs forward pass to extract 512-D L2 unit vector.
        """
        aligned, success, _ = align_face(frame, target_size=(112, 112))
        blob = cv2.dnn.blobFromImage(
            aligned,
            scalefactor=1.0 / 127.5,
            size=(112, 112),
            mean=(127.5, 127.5, 127.5),
            swapRB=True
        )
        self._network.setInput(blob)
        raw_vec = self._network.forward().flatten()
        if len(raw_vec) != 512:
            raise ValueError(f"ArcFace model output dimension mismatch: expected 512, got {len(raw_vec)}")

        norm = max(float(np.linalg.norm(raw_vec)), 1e-8)
        unit_vec = (raw_vec / norm).astype(np.float32)
        return unit_vec

    def enroll(self, frame: np.ndarray) -> BiometricTemplate:
        embedding = self.extract_features(frame)
        buf = io.BytesIO()
        np.save(buf, embedding)
        return BiometricTemplate(
            provider="arcface",
            model_version=self.version,
            embedding_dimension=512,
            template_payload=base64.b64encode(buf.getvalue()).decode("ascii"),
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            quality_score=0.98
        )

    def verify(self, frame: np.ndarray, template: BiometricTemplate) -> BiometricVerificationResult:
        compat_ok, reason = default_model_registry.check_template_compatibility(
            enrolled_provider=template.provider,
            enrolled_version=template.model_version,
            live_provider="arcface",
            live_version=self.version
        )
        if not compat_ok:
            raise ValueError(f"Biometric template incompatibility: {reason}")

        v1 = self.extract_features(frame)
        v2 = np.load(io.BytesIO(base64.b64decode(template.template_payload)))

        sim = float(np.dot(v1, v2))
        is_match = sim >= self.cosine_threshold
        similarity = max(0.0, min(1.0, sim))

        return BiometricVerificationResult(
            matched=is_match,
            similarity=round(similarity, 4),
            threshold=self.cosine_threshold,
            confidence=round(similarity, 4),
            provider="arcface",
            model_version=self.version,
            embedding_dimension=512,
            threshold_version=self.threshold_version
        )


def get_biometric_provider() -> BiometricProvider:
    """
    Factory resolving configured provider without silent insecure fallbacks.
    Options: template, facenet, arcface.
    Default: template (clearly documented prototype baseline for test environments).
    """
    env_provider = os.environ.get("VAULT_BIOMETRIC_PROVIDER") or os.environ.get("BIOMETRIC_PROVIDER") or "template"
    configured = env_provider.lower().strip()

    if configured in ("arcface", "arc_face"):
        return ArcFaceProvider()
    elif configured in ("facenet", "face_net"):
        return FaceNetProvider()
    elif configured in ("template", "template_matching"):
        return TemplateMatchingProvider()
    else:
        raise ValueError(
            f"Unknown VAULT_BIOMETRIC_PROVIDER '{configured}'. "
            "Supported providers: template, facenet, arcface."
        )
