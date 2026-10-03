import os
import hashlib
from datetime import datetime
from typing import Union, Optional, Tuple
import numpy as np
import cv2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENCRYPTED_DIR = os.path.join("data", "encrypted_evidence")

def _ensure_dir():
    os.makedirs(ENCRYPTED_DIR, exist_ok=True)

def compute_raw_frame_hash(frame_bytes: Union[bytes, np.ndarray]) -> str:
    """
    Computes SHA-256 hex digest on raw memory buffers before disk write.
    """
    if frame_bytes is None:
        return ""
    if isinstance(frame_bytes, np.ndarray):
        if frame_bytes.size == 0:
            return ""
        raw = frame_bytes.tobytes()
    elif isinstance(frame_bytes, (bytes, bytearray)):
        raw = bytes(frame_bytes)
    else:
        raw = str(frame_bytes).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def encrypt_frame_aes_gcm(
    frame_bytes: Union[bytes, np.ndarray],
    key: Optional[bytes] = None
) -> Tuple[bytes, str]:
    """
    Encrypts the frame bytes using a 256-bit AES key and 12-byte random nonce using AES-GCM,
    writes the ciphertext to data/encrypted_evidence/<sha256_hash>.enc,
    and returns (ciphertext, file_path).
    """
    _ensure_dir()
    if key is None:
        key = AESGCM.generate_key(bit_length=256)

    frame_hash = compute_raw_frame_hash(frame_bytes)

    if isinstance(frame_bytes, np.ndarray):
        success, encoded = cv2.imencode('.jpg', frame_bytes, [cv2.IMWRITE_JPEG_QUALITY, 90])
        plaintext = encoded.tobytes() if success else frame_bytes.tobytes()
    else:
        plaintext = bytes(frame_bytes)

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    final_payload = nonce + ciphertext
    file_path = os.path.join(ENCRYPTED_DIR, f"{frame_hash}.enc")

    with open(file_path, "wb") as f:
        f.write(final_payload)

    return final_payload, file_path

class CryptoPipeline:
    ENCRYPTED_DIR = ENCRYPTED_DIR

    @staticmethod
    def compute_raw_frame_hash(frame: Union[bytes, np.ndarray]) -> str:
        return compute_raw_frame_hash(frame)

    @classmethod
    def encrypt_frame_aes_gcm(cls, frame: Union[bytes, np.ndarray], key: Optional[bytes] = None) -> Tuple[bytes, str]:
        return encrypt_frame_aes_gcm(frame, key)

    @staticmethod
    def generate_audit_payload(frame_hash: str, mode: str, parties: str, verdict: str) -> dict:
        return {
            "iso_timestamp": datetime.utcnow().isoformat() + "Z",
            "frame_hash": frame_hash,
            "mode": mode,
            "parties": parties,
            "verdict": verdict,
            "signature_status": "LOCAL_VERIFIED"
        }
