"""
VERITAS-Vault Biometric Model Registry
======================================
Tracks biometric feature extraction models, versioning, SHA-256 file checksums,
and lifecycle states (ACTIVE, STAGING, RETIRED, ROLLED_BACK).

Enforces strict template compatibility: Prevents comparing embeddings generated
by incompatible models or different vector dimensions without explicit migration.
"""
import hashlib
import os
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field


class ModelLifecycleStatus(str, Enum):
    ACTIVE = "ACTIVE"
    STAGING = "STAGING"
    RETIRED = "RETIRED"
    ROLLED_BACK = "ROLLED_BACK"


class BiometricModelMetadata(BaseModel):
    model_id: str
    provider: str  # "template_matching", "facenet", "arcface"
    model_version: str
    model_path: Optional[str] = None
    expected_checksum: Optional[str] = None
    embedding_dimension: int  # e.g., 512 for ArcFace/FaceNet, 16384 for 128x128 template
    metric: str = "cosine"  # "cosine" or "ncc_mse"
    default_threshold: float
    status: ModelLifecycleStatus = ModelLifecycleStatus.ACTIVE


class ModelRegistry:
    """
    Centralized registry of verified biometric feature extraction models.
    """
    def __init__(self):
        self._models: Dict[str, BiometricModelMetadata] = {
            "template_matching_v1": BiometricModelMetadata(
                model_id="template_matching_v1",
                provider="template_matching",
                model_version="NCC-MSE-v1.2",
                embedding_dimension=16384,
                metric="ncc_mse",
                default_threshold=0.82,
                status=ModelLifecycleStatus.ACTIVE
            ),
            "facenet_v1": BiometricModelMetadata(
                model_id="facenet_v1",
                provider="facenet",
                model_version="FaceNet-ONNX-512D-v1.0",
                embedding_dimension=512,
                metric="cosine",
                default_threshold=0.70,
                status=ModelLifecycleStatus.STAGING
            ),
            "arcface_r50_v1": BiometricModelMetadata(
                model_id="arcface_r50_v1",
                provider="arcface",
                model_version="ArcFace-ResNet50-512D-v1.0",
                embedding_dimension=512,
                metric="cosine",
                default_threshold=0.68,
                status=ModelLifecycleStatus.ACTIVE
            )
        }

    def register_model(self, metadata: BiometricModelMetadata) -> None:
        self._models[metadata.model_id] = metadata

    def get_model(self, model_id: str) -> Optional[BiometricModelMetadata]:
        return self._models.get(model_id)

    def verify_file_checksum(self, file_path: str, expected_sha256: str) -> bool:
        """
        Calculates SHA-256 hash of a weights/ONNX file and checks against expected value.
        """
        p = Path(file_path)
        if not p.is_file():
            return False
        hasher = hashlib.sha256()
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        calculated = hasher.hexdigest().lower()
        return calculated == expected_sha256.lower()

    def check_template_compatibility(
        self,
        enrolled_provider: str,
        enrolled_version: str,
        live_provider: str,
        live_version: str
    ) -> Tuple[bool, str]:
        """
        Ensures biometric templates are only compared against compatible models.
        """
        if enrolled_provider != live_provider:
            return False, f"Incompatible biometric providers: {enrolled_provider} != {live_provider}"
        if enrolled_version != live_version:
            return False, f"Model version mismatch: enrolled with {enrolled_version}, verified with {live_version}"
        return True, "COMPATIBLE"


default_model_registry = ModelRegistry()
