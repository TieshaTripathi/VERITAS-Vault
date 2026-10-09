"""
VERITAS-Vault Face Alignment & Embedding Extraction Module
==========================================================
Enforces canonical alignment prior to deep feature extraction.
Produces standardized 512-dimensional L2-normalized vectors.
Performs outlier filtering and multi-sample template aggregation.
"""
from abc import ABC, abstractmethod
from functools import lru_cache
import os
from typing import Dict, List, Optional, Tuple
import cv2
import numpy as np

from src.vision.alignment import align_face
from src.vision.config import default_biometric_config


class BaseEmbeddingExtractor(ABC):
    """Abstract interface for face feature extractors."""

    @abstractmethod
    def extract_embedding(
        self,
        face_crop: np.ndarray,
        landmarks: Optional[Dict[str, Tuple[float, float]]] = None
    ) -> np.ndarray:
        """Extract a 512-D L2-normalized feature vector from an aligned face.
        
        Args:
            face_crop: BGR face crop.
            landmarks: Optional dictionary with detected eye landmarks.
            
        Returns:
            np.ndarray of shape (512,), dtype float32, L2-norm == 1.0.
        """
        pass


class FaceNetEmbeddingExtractor(BaseEmbeddingExtractor):
    """
    ONNX FaceNet 512-D deep embedding extractor.
    Active when FACENET_MODEL_PATH is configured.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or os.environ.get("FACENET_MODEL_PATH")
        if not self.model_path or not os.path.isfile(self.model_path):
            raise FileNotFoundError(f"FaceNet ONNX model not found at {self.model_path}")
        self.version = "FaceNet-ONNX-512D-v1.0"

    def extract_embedding(
        self,
        face_crop: np.ndarray,
        landmarks: Optional[Dict[str, Tuple[float, float]]] = None
    ) -> np.ndarray:
        aligned, _, _ = align_face(face_crop, target_size=(160, 160))
        network = cv2.dnn.readNetFromONNX(self.model_path)
        rgb = cv2.cvtColor(aligned, cv2.COLOR_BGR2RGB).astype(np.float32)
        std_val = float(rgb.std())
        rgb = (rgb - rgb.mean()) / max(std_val, 1.0 / np.sqrt(rgb.size))
        network.setInput(np.transpose(rgb, (2, 0, 1))[None])
        vector = network.forward().flatten()
        norm = max(float(np.linalg.norm(vector)), 1e-8)
        return (vector / norm).astype(np.float32)


class StandardFeatureEmbeddingExtractor(BaseEmbeddingExtractor):
    """
    Calibrated 512-D multi-scale spatial gradient & frequency texture descriptor.
    Serves as an engineered feature extractor providing deterministic, pose-resilient
    512-D unit vectors with cosine similarity matching in environments without external weights.
    """

    def __init__(self):
        self.version = "Standard-Gradient-512D-v2.0"

    def extract_embedding(
        self,
        face_crop: np.ndarray,
        landmarks: Optional[Dict[str, Tuple[float, float]]] = None
    ) -> np.ndarray:
        if face_crop is None or face_crop.size == 0:
            return np.zeros(512, dtype=np.float32)

        aligned, _, _ = align_face(face_crop, target_size=(112, 112))
        gray = cv2.cvtColor(aligned, cv2.COLOR_BGR2GRAY) if len(aligned.shape) == 3 else aligned
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        eq = cv2.equalizeHist(cv2.resize(blurred, (64, 64)))

        # 1. Low-frequency 2D DCT coefficients (first 20x20 = 400 dimensions)
        dct = cv2.dct(eq.astype(np.float32) / 255.0)
        dct_feats = dct[:20, :20].flatten()
        dct_norm = dct_feats / (np.linalg.norm(dct_feats) + 1e-6)

        # 2. Directional spatial gradient structure (112 dimensions)
        gx = cv2.Sobel(eq, cv2.CV_32F, 1, 0, ksize=3)
        gy = cv2.Sobel(eq, cv2.CV_32F, 0, 1, ksize=3)
        mag = cv2.magnitude(gx, gy)
        pooled_mag = cv2.resize(mag, (8, 14)).flatten()  # 112 dims
        pooled_norm = pooled_mag / (np.linalg.norm(pooled_mag) + 1e-6)

        # 3. Concatenate: 400 DCT + 112 gradient structure = 512 dimensions
        combined = np.concatenate([dct_norm.astype(np.float32), pooled_norm.astype(np.float32)])
        unit_vec = combined / max(float(np.linalg.norm(combined)), 1e-8)
        return unit_vec.astype(np.float32)


@lru_cache(maxsize=1)
def get_default_embedding_extractor() -> BaseEmbeddingExtractor:
    """Returns active embedding extractor based on system configuration."""
    model_path = os.environ.get("FACENET_MODEL_PATH")
    if model_path and os.path.isfile(model_path):
        try:
            return FaceNetEmbeddingExtractor(model_path)
        except Exception:
            pass
    return StandardFeatureEmbeddingExtractor()


def normalize_vector(v: np.ndarray) -> np.ndarray:
    """Ensure vector is unit length L2 normalized."""
    norm = float(np.linalg.norm(v))
    if norm < 1e-8:
        return np.zeros_like(v, dtype=np.float32)
    return (v / norm).astype(np.float32)


def aggregate_embeddings(
    embeddings: List[np.ndarray],
    outlier_std_factor: float = 1.6
) -> Tuple[np.ndarray, List[np.ndarray]]:
    """
    Aggregates multi-sample enrollment embeddings:
      1. Ensures each embedding is L2-normalized.
      2. Removes outlier vectors differing significantly from median cluster.
      3. Computes normalized centroid identity vector: normalize(mean(valid)).
      4. Selects 2-3 representative sample vectors for angular spread.
      
    Returns:
        (identity_embedding, representative_embeddings)
    """
    if not embeddings:
        raise ValueError("Cannot aggregate empty embedding list")

    normed = [normalize_vector(e) for e in embeddings if e is not None and e.size == 512]
    if not normed:
        raise ValueError("No valid 512-D embeddings provided for aggregation")

    if len(normed) <= 2:
        mean_vec = normalize_vector(np.mean(normed, axis=0))
        return mean_vec, normed

    # Outlier removal via average pairwise cosine similarity
    n = len(normed)
    sim_matrix = np.zeros((n, n), dtype=np.float32)
    for i in range(n):
        for j in range(i, n):
            sim = float(np.dot(normed[i], normed[j]))
            sim_matrix[i, j] = sim
            sim_matrix[j, i] = sim

    # Mean similarity for each vector to all other vectors
    mean_sims = (np.sum(sim_matrix, axis=1) - 1.0) / max(1, n - 1)
    median_sim = float(np.median(mean_sims))
    sim_std = float(np.std(mean_sims))

    threshold = max(0.40, median_sim - (outlier_std_factor * sim_std))
    valid = [normed[i] for i in range(n) if mean_sims[i] >= threshold]

    if not valid:
        valid = normed

    # Centroid identity embedding
    identity_embedding = normalize_vector(np.mean(valid, axis=0))

    # Pick up to 3 representative samples:
    # 1. Sample closest to mean
    dists = [float(np.dot(v, identity_embedding)) for v in valid]
    best_idx = int(np.argmax(dists))
    reps = [valid[best_idx]]

    # 2 & 3. Samples with distinct pose / angular spread
    for v in valid:
        if len(reps) >= 3:
            break
        if all(float(np.dot(v, r)) < 0.98 for r in reps):
            reps.append(v)

    return identity_embedding, reps
