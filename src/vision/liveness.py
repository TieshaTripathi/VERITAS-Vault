"""
VERITAS-Vault Multi-Signal Presentation Attack Detection (PAD) Engine
=====================================================================
Evaluates biometric presentation attack risk using multi-signal analysis:
  1. High-frequency micro-texture (Laplacian variance)
  2. Color chrominance diffusion (YCrCb subspace dispersion)
  3. Moiré / screen artifact detection (2D FFT frequency spectrum energy)
  4. Global illumination & RMS contrast dynamics

Exposes:
  - pad_score: float (0.0 to 1.0)
  - pad_confidence: float (0.0 to 1.0)
  - pad_status: 'PASS' | 'FAIL'
  - pad_signals: dict of individual signal scores
  - pad_reason_codes: list of machine-readable codes
  - pad_model_version: str
"""
import cv2
import numpy as np
from typing import Tuple, Dict, Any, List

PAD_MODEL_VERSION = "VERITAS-PAD-v2.1-MULTISIGNAL"


def analyze_screen_moire(gray_crop: np.ndarray) -> Tuple[float, bool]:
    """
    Computes 2D Fast Fourier Transform (FFT) magnitude spectrum to detect
    regular dot matrix, OLED refresh, or pixel grid frequency peaks.
    Returns (moire_artifact_score [0.0 to 1.0, lower is better/cleaner], is_artifact_free: bool).
    """
    if gray_crop.shape[0] < 32 or gray_crop.shape[1] < 32:
        return 0.1, True

    # Standardize window size for FFT
    resized = cv2.resize(gray_crop, (64, 64)).astype(np.float32)
    # 2D FFT
    f = np.fft.fft2(resized)
    fshift = np.fft.fftshift(f)
    magnitude_spectrum = 20 * np.log(np.abs(fshift) + 1e-6)

    # Zero out the DC component at center (center 8x8)
    cy, cx = 32, 32
    magnitude_spectrum[cy-4:cy+4, cx-4:cx+4] = 0

    # High frequency outer ring energy vs total energy
    total_energy = np.sum(magnitude_spectrum)
    if total_energy <= 0:
        return 0.1, True

    # Check for concentrated periodic spikes (indicating pixel grids or printed dots)
    max_val = np.max(magnitude_spectrum)
    mean_val = np.mean(magnitude_spectrum)
    peak_to_average = max_val / (mean_val + 1e-5)

    # If peak-to-average is unnaturally high (> 8.5), periodic screen artifact is detected
    has_moire = peak_to_average > 9.0
    moire_score = float(min(1.0, peak_to_average / 10.0))
    return moire_score, not has_moire


def evaluate_multisignal_pad(
    face_crop: np.ndarray,
    threshold: float = 0.80
) -> Dict[str, Any]:
    """
    Modular Multi-Signal Presentation Attack Detection.
    """
    if face_crop is None or not isinstance(face_crop, np.ndarray) or face_crop.size == 0:
        return {
            "pad_score": 0.0,
            "pad_confidence": 0.0,
            "status": "FAIL",
            "signals": {"texture": 0.0, "color": 0.0, "contrast": 0.0, "moire": 1.0},
            "reason_codes": ["PAD-EMPTY-FRAME"],
            "pad_model_version": PAD_MODEL_VERSION
        }

    reasons: List[str] = []

    if len(face_crop.shape) == 3 and face_crop.shape[2] == 3:
        gray = cv2.cvtColor(face_crop, cv2.COLOR_BGR2GRAY)
        ycrcb = cv2.cvtColor(face_crop, cv2.COLOR_BGR2YCrCb)
        cr_channel = ycrcb[:, :, 1]
        cb_channel = ycrcb[:, :, 2]
        color_std = float(np.std(cr_channel) + np.std(cb_channel))
        color_score = float(min(1.0, color_std / 30.0))
    else:
        gray = face_crop
        color_score = 0.85

    # 1. Texture analysis on normalized 112x112 canonical face crop
    norm_gray = cv2.resize(gray, (112, 112), interpolation=cv2.INTER_LINEAR)
    laplacian_var = float(cv2.Laplacian(norm_gray, cv2.CV_64F).var())
    texture_score = float(min(1.0, laplacian_var / 350.0))

    if laplacian_var < 45.0:
        reasons.append("PAD-TEXTURE-BLUR-SPOOF")

    # 2. Contrast analysis
    contrast = float(np.std(norm_gray))
    contrast_score = float(min(1.0, contrast / 45.0))
    if contrast_score < 0.35:
        reasons.append("PAD-LOW-CONTRAST")

    # 3. Screen Moiré analysis
    moire_score, is_clean = analyze_screen_moire(gray)
    if not is_clean:
        reasons.append("PAD-SCREEN-MOIRE-DETECTED")

    # Composite PAD Score (0.0 to 1.0)
    # Weights: 40% Texture, 25% Color, 20% Contrast, 15% Screen Artifact Absence
    screen_clean_score = max(0.0, 1.0 - moire_score)
    raw_pad = (
        0.40 * texture_score +
        0.25 * color_score +
        0.20 * contrast_score +
        0.15 * screen_clean_score
    )

    pad_score = round(float(min(1.0, max(0.0, raw_pad))), 3)
    if laplacian_var < 20.0 or not is_clean:
        pad_confidence = round(float(min(0.45, max(0.05, laplacian_var / 80.0))), 2)
    elif laplacian_var < 45.0:
        pad_confidence = round(float(min(0.65, max(0.30, laplacian_var / 70.0))), 2)
    else:
        pad_confidence = round(float(min(0.99, max(0.70, 0.70 + pad_score * 0.29))), 2)

    is_confirmed_attack = (not is_clean) or (laplacian_var < 20.0 and contrast < 12.0) or (pad_score < 0.25)
    is_confirmed_live = (
        pad_confidence >= threshold and
        laplacian_var >= 45.0 and
        is_clean and
        contrast_score >= 0.35
    )

    if is_confirmed_live:
        status = "PASS"
    elif is_confirmed_attack:
        status = "FAIL"
    else:
        # Uncertain heuristic PAD result: requires additional verification, not an immediate attack
        status = "UNCERTAIN"
        if not reasons:
            reasons.append("PAD-HEURISTIC-UNCERTAIN")

    return {
        "pad_score": pad_score,
        "pad_confidence": pad_confidence,
        "status": status,
        "signals": {
            "texture": round(texture_score, 3),
            "color": round(color_score, 3),
            "contrast": round(contrast_score, 3),
            "moire": round(moire_score, 3)
        },
        "reason_codes": reasons if status != "PASS" else [],
        "pad_model_version": PAD_MODEL_VERSION

    }


def estimate_liveness(face_crop: np.ndarray, threshold: float = 0.80) -> Tuple[bool, float]:
    """
    Backward-compatible liveness function used by existing test suites.
    """
    result = evaluate_multisignal_pad(face_crop, threshold=threshold)
    is_live = (result["status"] == "PASS")
    return is_live, result["pad_confidence"]


class LivenessEstimator:
    """
    Edge-AI Biometric Liveness Estimator class wrapper.
    """
    def __init__(self, threshold: float = 0.80):
        self.threshold = threshold

    def evaluate_face_liveness(self, frame: np.ndarray, bbox: tuple) -> Tuple[float, bool]:
        if frame is None or frame.size == 0:
            return 0.0, False

        x, y, w, h = bbox
        height, width = frame.shape[:2]

        x_min = max(0, x)
        y_min = max(0, y)
        x_max = min(width, x + w)
        y_max = min(height, y + h)

        face_crop = frame[y_min:y_max, x_min:x_max]
        result = evaluate_multisignal_pad(face_crop, threshold=self.threshold)
        return result["pad_confidence"], (result["status"] == "PASS")


default_liveness_estimator = LivenessEstimator(threshold=0.80)
