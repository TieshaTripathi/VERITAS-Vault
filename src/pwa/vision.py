"""OpenCV capture quality, NCC matching, and optional verified FaceNet ONNX model."""
import base64
import hashlib
import io
import os
from functools import lru_cache

import cv2
import numpy as np
from PIL import Image

from src.pwa.security import seal, unseal


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
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
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
    path = os.environ.get("FACENET_MODEL_PATH")
    if not path:
        return None
    # Load per request: OpenCV DNN mutation is not shared across worker threads.
    network = cv2.dnn.readNetFromONNX(path)
    rgb = cv2.cvtColor(cv2.resize(crop, (160, 160)), cv2.COLOR_BGR2RGB).astype(np.float32)
    rgb = (rgb - rgb.mean()) / max(float(rgb.std()), 1 / np.sqrt(rgb.size))
    network.setInput(np.transpose(rgb, (2, 0, 1))[None])
    vector = network.forward().flatten()
    return vector / max(float(np.linalg.norm(vector)), 1e-8)


def template(face, person_id):
    vector = embedding(face["crop"])
    buffer = io.BytesIO()
    np.savez(buffer, norm=face["norm"], embedding=vector if vector is not None else np.array([]))
    return base64.b64encode(seal(buffer.getvalue(), "person:" + person_id)).decode()


def recognize(frame, people):
    faces, quality = inspect(frame)
    templates = []
    for person in people:
        with np.load(io.BytesIO(unseal(base64.b64decode(person["template"]), "person:" + person["id"])), allow_pickle=False) as data:
            templates.append((person, data["norm"], data["embedding"]))
    results = []
    for face in faces:
        vector = embedding(face["crop"])
        best, best_score = None, -1
        for person, norm, enrolled_embedding in templates:
            score = float(cv2.matchTemplate(face["norm"], norm, cv2.TM_CCOEFF_NORMED)[0, 0])
            error = float(np.mean((face["norm"].astype(float) - norm.astype(float)) ** 2) / 65025)
            embedding_ok = vector is None or (vector.shape == enrolled_embedding.shape and float(np.dot(vector, enrolled_embedding)) >= .70)
            if score >= .82 and error <= .18 and embedding_ok and score > best_score:
                best, best_score = person, score
        results.append({
            "id": best["id"] if best else "unknown",
            "name": best["name"] if best else "Unknown individual",
            "role": best["role"] if best else "Unauthorized",
            "is_recognized": bool(best),
            "is_live": face["is_live"],
            "confidence": max(0, round(best_score, 3)),
            "pad_status": face.get("pad_status", "PASS" if face["is_live"] else "FAIL"),
            "pad_score": face.get("pad_score", 0.85 if face["is_live"] else 0.1),
            "pad_confidence": face.get("pad_confidence", 0.90 if face["is_live"] else 0.3),
            "pad_signals": face.get("pad_signals", {}),
            "pad_reason_codes": face.get("pad_reason_codes", []),
            "bbox": face["bbox"],
            "variance": round(face["variance"], 1)
        })
    return results, quality
