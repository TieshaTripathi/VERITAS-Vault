"""
VERITAS-Vault Biometric Matching & State Classification Module
==============================================================
Performs 512-D cosine similarity matching against cached enrolled templates.
Classifies live observations into three discrete biometric states:
  - VERIFIED: High confidence match (>= recognition_threshold)
  - POSSIBLE_MATCH: Ambiguous candidate (between possible and verified thresholds)
  - UNKNOWN: No enrolled candidate matches above threshold
"""
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional
import numpy as np

from src.vision.config import BiometricConfig, default_biometric_config


class RecognitionState(str, Enum):
    VERIFIED = "VERIFIED"
    POSSIBLE_MATCH = "POSSIBLE_MATCH"
    UNKNOWN = "UNKNOWN"


@dataclass
class EnrolledIdentity:
    """In-memory representation of an enrolled biometric subject."""
    id: str
    name: str
    role: str
    identity_embedding: np.ndarray             # 512-D unit vector (mean of valid enrollment samples)
    representative_embeddings: List[np.ndarray] # 1 to 3 distinct sample unit vectors
    model_version: str
    embedding_version: str = "v2.0"
    quality_score: float = 0.95
    enrolled_at: str = ""


@dataclass
class BiometricMatchResult:
    """Outcome of a single embedding comparison."""
    state: RecognitionState
    candidate_id: Optional[str]
    candidate_name: Optional[str]
    candidate_role: Optional[str]
    similarity: float
    threshold: float
    is_verified: bool
    second_best_id: Optional[str] = None
    margin: float = 0.0


def compute_cosine_similarity(vec_a: np.ndarray, vec_b: np.ndarray) -> float:
    """Cosine similarity of unit vectors is their dot product."""
    if vec_a is None or vec_b is None or vec_a.size == 0 or vec_b.size == 0:
        return 0.0
    return float(np.dot(vec_a, vec_b))


def match_embedding(
    probe_embedding: np.ndarray,
    enrolled_identities: Dict[str, EnrolledIdentity],
    config: Optional[BiometricConfig] = None
) -> BiometricMatchResult:
    """
    Compares a probe feature vector against all enrolled identities.
    Returns the best matching candidate and the discrete classification state.
    """
    cfg = config or default_biometric_config
    if not enrolled_identities or probe_embedding is None or probe_embedding.size == 0:
        return BiometricMatchResult(
            state=RecognitionState.UNKNOWN,
            candidate_id=None,
            candidate_name="Unknown Person",
            candidate_role="Unauthorized",
            similarity=0.0,
            threshold=cfg.recognition_threshold,
            is_verified=False
        )

    best_id: Optional[str] = None
    best_sim = -1.0
    second_sim = -1.0
    second_id: Optional[str] = None

    for person_id, identity in enrolled_identities.items():
        # Match against mean centroid vector
        sim = compute_cosine_similarity(probe_embedding, identity.identity_embedding)
        
        # Also check against representative sample vectors for pose tolerance
        if identity.representative_embeddings:
            rep_sims = [compute_cosine_similarity(probe_embedding, rep) for rep in identity.representative_embeddings]
            sim = max(sim, max(rep_sims))

        if sim > best_sim:
            second_sim = best_sim
            second_id = best_id
            best_sim = sim
            best_id = person_id
        elif sim > second_sim:
            second_sim = sim
            second_id = person_id

    similarity = round(max(0.0, min(1.0, best_sim)), 4)
    margin = round(best_sim - second_sim, 4) if second_sim >= 0 else similarity

    # Decision logic based on centralized thresholds
    if best_id and similarity >= cfg.recognition_threshold:
        candidate = enrolled_identities[best_id]
        return BiometricMatchResult(
            state=RecognitionState.VERIFIED,
            candidate_id=candidate.id,
            candidate_name=candidate.name,
            candidate_role=candidate.role,
            similarity=similarity,
            threshold=cfg.recognition_threshold,
            is_verified=True,
            second_best_id=second_id,
            margin=margin
        )
    elif best_id and similarity >= cfg.possible_match_threshold:
        candidate = enrolled_identities[best_id]
        return BiometricMatchResult(
            state=RecognitionState.POSSIBLE_MATCH,
            candidate_id=candidate.id,
            candidate_name=candidate.name,
            candidate_role=candidate.role,
            similarity=similarity,
            threshold=cfg.recognition_threshold,
            is_verified=False,
            second_best_id=second_id,
            margin=margin
        )
    else:
        return BiometricMatchResult(
            state=RecognitionState.UNKNOWN,
            candidate_id=None,
            candidate_name="Unknown Person",
            candidate_role="Unauthorized",
            similarity=similarity,
            threshold=cfg.recognition_threshold,
            is_verified=False,
            second_best_id=second_id,
            margin=margin
        )
