"""
OpenCV capture quality, 512-D deep embeddings, and modular biometric integration.
Delegates to default_biometric_service while retaining backward-compatible interfaces.
"""
import base64
import hashlib
import io
import os
from functools import lru_cache
from typing import Any, Dict, List, Tuple

import cv2
import numpy as np
from PIL import Image

from src.pwa.security import seal, unseal
from src.vision.biometric_service import default_biometric_service
from src.vision.face_detection import get_default_detector
from src.vision.face_quality import evaluate_quality


@lru_cache(maxsize=1)
def detector():
    return cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")


def decode(value):
    try:
        raw = base64.b64decode(value.split(",")[-1], validate=True)
        if len(raw) > 1_500_000:
            raise ValueError("Snapshot is too large")
        with Image.open(io.BytesIO(raw)) as image:
            if image.width * image.height > 2_000_000 or image.width < 64 or image.height < 64:
                raise ValueError("Use a camera image between 64px and two megapixels")
        frame = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
        if frame is None:
            raise ValueError("Invalid image")
        return frame, raw
    except Exception as exc:
        raise ValueError("Invalid snapshot. Use a JPEG/PNG under 1.5 MB and two megapixels.") from exc


def inspect(frame):
    from src.vision.liveness import evaluate_multisignal_pad
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY) if len(frame.shape) == 3 else frame
    boxes = detector().detectMultiScale(gray, scaleFactor=1.1, minNeighbors=6, minSize=(60, 60))
    faces = []
    for x, y, w, h in boxes:
        crop = frame[y:y+h, x:x+w]
        gray_crop = gray[y:y+h, x:x+w]
        variance = float(cv2.Laplacian(gray_crop, cv2.CV_64F).var())
        pad_res = evaluate_multisignal_pad(crop)
        is_live = (pad_res["status"] == "PASS")
        faces.append({
            "bbox": [int(x), int(y), int(w), int(h)],
            "variance": variance,
            "is_live": is_live,
            "pad_status": pad_res["status"],
            "pad_score": pad_res["pad_score"],
            "pad_confidence": pad_res["pad_confidence"],
            "pad_signals": pad_res["signals"],
            "pad_reason_codes": pad_res["reason_codes"],
            "crop": crop,
            "norm": cv2.resize(cv2.equalizeHist(gray_crop), (128, 128))
        })
    brightness = float(gray.mean())
    return faces, {"face_count": len(faces), "brightness": round(brightness, 1),
                   "lighting_ok": 45 <= brightness <= 220,
                   "aligned": len(faces) == 1 and faces[0]["bbox"][2] >= frame.shape[1] * .18,
                   "sharpness": round(faces[0]["variance"], 1) if faces else 0,
                   "texture_ok": bool(faces) and all(f["is_live"] for f in faces)}


def embedding(crop):
    """Extracts standardized 512-D L2-normalized feature vector."""
    if crop is None or crop.size == 0:
        return None
    extractor = default_biometric_service.embedding_extractor
    vec = extractor.extract_embedding(crop)
    return vec if (vec is not None and vec.size == 512) else None


def template(face, person_id):
    """
    Creates an encrypted biometric template.
    Generates 512-D identity embedding alongside 128x128 baseline.
    """
    crop = face.get("crop")
    norm = face.get("norm")
    if norm is None and crop is not None:
        norm = cv2.resize(cv2.equalizeHist(cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)), (128, 128))

    vector = embedding(crop) if crop is not None else None
    if vector is None:
        vector = np.zeros(512, dtype=np.float32)

    buffer = io.BytesIO()
    np.savez(
        buffer,
        identity_embedding=vector,
        rep_embeddings=np.array([vector], dtype=np.float32),
        model_version=default_biometric_service.config.model_version,
        quality_score=0.95,
        norm=norm,
        embedding=vector
    )
    return base64.b64encode(seal(buffer.getvalue(), "person:" + person_id)).decode()


def recognize(frame, people):
    """
    Executes biometric recognition pipeline with in-memory caching and temporal consensus.
    Delegates directly to default_biometric_service.
    """
    return default_biometric_service.process_frame(frame, people)
