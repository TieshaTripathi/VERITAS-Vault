"""
VERITAS-Vault Centralized Biometric Configuration
=================================================
Centralizes all biometric thresholds, temporal consensus parameters,
and quality gates to eliminate scattered magic constants.
"""
from dataclasses import dataclass
import os


@dataclass(frozen=True)
class BiometricConfig:
    # Recognition Thresholds
    # Cosine similarity >= recognition_threshold -> VERIFIED
    recognition_threshold: float = float(os.environ.get("VAULT_RECOGNITION_THRESHOLD", "0.70"))
    
    # Cosine similarity in [possible_match_threshold, recognition_threshold) -> POSSIBLE_MATCH
    # POSSIBLE_MATCH never grants authorization; prompts user to hold still / adjust
    possible_match_threshold: float = float(os.environ.get("VAULT_POSSIBLE_MATCH_THRESHOLD", "0.55"))

    # Temporal Consensus Settings
    # Minimum consistent matches out of last consensus_window_size observations to declare VERIFIED
    match_consensus_frames: int = int(os.environ.get("VAULT_MATCH_CONSENSUS_FRAMES", "3"))
    consensus_window_size: int = int(os.environ.get("VAULT_CONSENSUS_WINDOW_SIZE", "5"))

    # Consecutive high-quality unknown observations required before confirming ZT-001 breach
    unknown_confirmation_frames: int = int(os.environ.get("VAULT_UNKNOWN_CONFIRMATION_FRAMES", "3"))

    # Consecutive failed PAD observations required before confirming ZT-002 breach
    pad_confirmation_frames: int = int(os.environ.get("VAULT_PAD_CONFIRMATION_FRAMES", "3"))
    pad_threshold: float = float(os.environ.get("VAULT_PAD_THRESHOLD", "0.80"))

    # Scheduling & Cadence
    # Track recognition embedding cadence (ms) - avoids running heavy embedding on every video frame
    embedding_interval_ms: float = float(os.environ.get("VAULT_EMBEDDING_INTERVAL_MS", "1200.0"))

    # Multi-Sample Enrollment
    min_enrollment_samples: int = int(os.environ.get("VAULT_MIN_ENROLLMENT_SAMPLES", "5"))
    max_enrollment_samples: int = int(os.environ.get("VAULT_MAX_ENROLLMENT_SAMPLES", "8"))

    # Quality Criteria
    min_face_size_pixels: int = 60
    min_face_size_ratio: float = 0.15
    max_face_size_ratio: float = 0.85
    min_sharpness_var: float = 45.0
    min_brightness: float = 40.0
    max_brightness: float = 225.0
    max_pose_angle_deg: float = 25.0

    # Model & Feature Settings
    embedding_dim: int = 512
    model_version: str = "VERITAS-BIOMETRIC-v2.0"


# Global default configuration instance
default_biometric_config = BiometricConfig()
