"""
VERITAS-Vault Presentation Attack Detection (PAD) Provider Abstraction
======================================================================
Defines unified interface for presentation attack detection.
Separates:
  - HeuristicPADProvider (Production prototype: 2D FFT Moiré, texture, color, contrast)
  - NeuralPADProvider (Interface for future deep learning anti-spoofing models)

Accurately documented: The current active engine is a multi-signal heuristic prototype,
not a certified neural anti-spoofing model.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import numpy as np
from pydantic import BaseModel, Field

from src.vision.liveness import evaluate_multisignal_pad, PAD_MODEL_VERSION


class PADResult(BaseModel):
    status: str  # "PASS", "FAIL", "INCONCLUSIVE"
    pad_score: float  # 0.0 to 1.0 (higher = more likely bona fide live)
    confidence: float  # 0.0 to 1.0
    reason_codes: List[str] = Field(default_factory=list)
    signals: Dict[str, float] = Field(default_factory=dict)
    engine_name: str
    engine_version: str
    threshold_version: str


class PADProvider(ABC):
    @abstractmethod
    def get_engine_info(self) -> Dict[str, str]:
        pass

    @abstractmethod
    def evaluate(self, face_crop: np.ndarray, threshold: float = 0.80) -> PADResult:
        pass


class HeuristicPADProvider(PADProvider):
    """
    Multi-signal heuristic PAD prototype using 2D FFT Moiré frequency spectrum analysis,
    Laplacian micro-texture variance, and YCrCb chrominance diffusion.
    """
    def __init__(self, threshold_version: str = "pad-threshold-v1.2"):
        self.engine_name = "multisignal-heuristic-pad"
        self.version = PAD_MODEL_VERSION
        self.threshold_version = threshold_version

    def get_engine_info(self) -> Dict[str, str]:
        return {
            "engine": self.engine_name,
            "version": self.version,
            "threshold_version": self.threshold_version,
            "type": "HEURISTIC_FREQUENCY_TEXTURE_COLOR",
            "certified_apcer": "NOT_MEASURED"
        }

    def evaluate(self, face_crop: np.ndarray, threshold: float = 0.80) -> PADResult:
        res = evaluate_multisignal_pad(face_crop, threshold=threshold)
        status = res["status"]

        # Support INCONCLUSIVE state: if contrast is low or border scores without clear spoof
        if status == "FAIL" and res["signals"].get("texture", 0.0) >= 0.15 and res["signals"].get("moire", 0.0) < 0.8:
            status = "INCONCLUSIVE"

        return PADResult(
            status=status,
            pad_score=res["pad_score"],
            confidence=res["pad_confidence"],
            reason_codes=res["reason_codes"],
            signals=res["signals"],
            engine_name=self.engine_name,
            engine_version=self.version,
            threshold_version=self.threshold_version
        )


class NeuralPADProvider(PADProvider):
    """
    Prepared interface for future deep neural network anti-spoofing backends.
    """
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.engine_name = "neural-minifasnet-pad"
        self.version = "MiniFASNet-v1.0"
        self.threshold_version = "neural-threshold-v1"
        if not self.model_path:
            raise FileNotFoundError("Neural PAD model path not configured.")

    def get_engine_info(self) -> Dict[str, str]:
        return {
            "engine": self.engine_name,
            "version": self.version,
            "threshold_version": self.threshold_version,
            "type": "DEEP_CONVOLUTIONAL_NEURAL_NETWORK"
        }

    def evaluate(self, face_crop: np.ndarray, threshold: float = 0.80) -> PADResult:
        raise NotImplementedError("Neural PAD weights must be provided to execute inference.")


# Global default active PAD provider
default_pad_provider = HeuristicPADProvider()
