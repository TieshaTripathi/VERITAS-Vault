"""Encryption, local bootstrap authentication, and strict runtime settings."""
import base64
import hashlib
import hmac
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[2]


def data_dir():
    return Path(os.environ.get("VAULT_DATA_DIR", ROOT / "data" / "pwa"))


def encryption_key():
    value = os.environ.get("VAULT_ENCRYPTION_KEY", "")
    if not value:
        raise RuntimeError("VAULT_ENCRYPTION_KEY is required. Run python scripts/setup_local.py.")
    key = base64.b64decode(value, validate=True)
    if len(key) != 32:
        raise RuntimeError("VAULT_ENCRYPTION_KEY must encode 32 bytes.")
    return key


def seal(raw: bytes, context: str) -> bytes:
    nonce = os.urandom(12)
    return b"VV1" + nonce + AESGCM(encryption_key()).encrypt(nonce, raw, context.encode())


def unseal(blob: bytes, context: str) -> bytes:
    if not blob.startswith(b"VV1"):
        raise ValueError("Unsupported evidence envelope")
    return AESGCM(encryption_key()).decrypt(blob[3:15], blob[15:], context.encode())


def password_hash(password: str, salt=None):
    salt = salt or os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000)
    return f"pbkdf2_sha256$600000${salt}${digest.hex()}"


def check_password(password, stored):
    try:
        scheme, rounds, salt, digest = stored.split("$")
        if scheme != "pbkdf2_sha256" or int(rounds) != 600_000:
            return False
        return hmac.compare_digest(password_hash(password, salt).split("$")[-1], digest)
    except (ValueError, AttributeError):
        return False
