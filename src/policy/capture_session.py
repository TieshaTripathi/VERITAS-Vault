"""
VERITAS-Vault Trusted Capture Session Pipeline
===============================================
Enforces anti-replay protection, device identity validation, and frame integrity binding.
Every frame evaluated by the biometric engine must be cryptographically bound
to an active, unexpired, single-use capture session nonce.
"""
import hashlib
import hmac
import os
import secrets
import time
import uuid
from typing import Dict, Any, Optional, Tuple

# Standard session time-to-live: 10 seconds to account for network transmission
SESSION_TTL_SECONDS = float(os.environ.get("VAULT_SESSION_TTL_SECONDS", "10.0"))
MAX_NONCE_HISTORY = 10000


class CaptureSessionManager:
    """
    Manages short-lived capture session challenges and validates anti-replay proofs.
    """
    def __init__(self, ttl_seconds: float = SESSION_TTL_SECONDS):
        self.ttl_seconds = ttl_seconds
        # session_id -> {nonce, device_id, checkpoint_id, created_at, expires_at, used}
        self._active_sessions: Dict[str, Dict[str, Any]] = {}
        # Used nonces cache: nonce -> timestamp (to prevent replay across expired session records)
        self._used_nonces: Dict[str, float] = {}
        # Registered trusted devices: device_id -> {checkpoint_id, status, shared_secret}
        self._trusted_devices: Dict[str, Dict[str, Any]] = {
            "DEV-EDGE-01": {
                "checkpoint_id": "CP-MAIN-01",
                "status": "ACTIVE",
                "secret": os.environ.get("VAULT_DEVICE_SECRET", "default-dev-edge-secret-key-32b!")
            },
            "DEV-PWA-01": {
                "checkpoint_id": "CP-MAIN-01",
                "status": "ACTIVE",
                "secret": os.environ.get("VAULT_DEVICE_SECRET", "default-dev-edge-secret-key-32b!")
            }
        }

    def _cleanup_expired(self, now: float):
        """Purge sessions and nonces older than 2x TTL."""
        expired_sessions = [
            sid for sid, data in self._active_sessions.items()
            if now > data["expires_at"]
        ]
        for sid in expired_sessions:
            del self._active_sessions[sid]

        nonce_cutoff = now - (self.ttl_seconds * 3)
        expired_nonces = [
            nonce for nonce, ts in self._used_nonces.items()
            if ts < nonce_cutoff
        ]
        for nonce in expired_nonces:
            del self._used_nonces[nonce]

    def register_device(self, device_id: str, checkpoint_id: str, secret: str, status: str = "ACTIVE"):
        """Register or update a trusted capture device."""
        self._trusted_devices[device_id] = {
            "checkpoint_id": checkpoint_id,
            "status": status,
            "secret": secret
        }

    def create_session(self, device_id: str, checkpoint_id: str) -> Dict[str, Any]:
        """
        Issue a new cryptographic capture session challenge.
        """
        now = time.time()
        self._cleanup_expired(now)

        device = self._trusted_devices.get(device_id)
        if not device or device["status"] != "ACTIVE":
            raise ValueError(f"Untrusted or revoked capture device: {device_id}")
        if device["checkpoint_id"] != checkpoint_id:
            raise ValueError(f"Device {device_id} is not authorized for checkpoint {checkpoint_id}")

        session_id = str(uuid.uuid4())
        nonce = secrets.token_hex(16)
        expires_at = now + self.ttl_seconds

        session_record = {
            "session_id": session_id,
            "device_id": device_id,
            "checkpoint_id": checkpoint_id,
            "capture_nonce": nonce,
            "created_at": now,
            "expires_at": expires_at,
            "used": False
        }
        self._active_sessions[session_id] = session_record

        return {
            "session_id": session_id,
            "device_id": device_id,
            "checkpoint_id": checkpoint_id,
            "capture_nonce": nonce,
            "expires_at": expires_at,
            "ttl_seconds": self.ttl_seconds
        }

    def compute_frame_hash(self, frame_bytes: bytes) -> str:
        """Compute canonical SHA-256 hash of raw frame bytes."""
        return hashlib.sha256(frame_bytes).hexdigest()

    def generate_device_signature(self, device_id: str, session_id: str, capture_nonce: str, frame_hash: str) -> str:
        """Helper to generate expected HMAC signature for a trusted device."""
        device = self._trusted_devices.get(device_id)
        if not device:
            return ""
        secret = device["secret"].encode()
        payload = f"{session_id}:{capture_nonce}:{frame_hash}".encode()
        return hmac.new(secret, payload, hashlib.sha256).hexdigest()

    def validate_capture(
        self,
        session_id: str,
        capture_nonce: str,
        device_id: str,
        checkpoint_id: str,
        raw_frame_bytes: bytes,
        signature: Optional[str] = None,
        require_signature: bool = False
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Validates the capture session against replay, expiration, and tampering.
        Returns: (is_valid: bool, reason_code: str, frame_hash: Optional[str])
        """
        now = time.time()
        self._cleanup_expired(now)

        # 1. Check if nonce was already spent
        if capture_nonce in self._used_nonces:
            return False, "ZT-009 REPLAY_DETECTED: Capture nonce already consumed", None

        # 2. Check session existence
        session = self._active_sessions.get(session_id)
        if not session:
            return False, "ZT-013 CAPTURE_INTEGRITY_FAILED: Invalid or expired session", None

        # 3. Check if session already used
        if session["used"]:
            self._used_nonces[capture_nonce] = now
            return False, "ZT-009 REPLAY_DETECTED: Session already consumed", None

        # 4. Check expiration
        if now > session["expires_at"]:
            return False, "ZT-013 CAPTURE_INTEGRITY_FAILED: Capture session expired", None

        # 5. Check nonce match
        if not hmac.compare_digest(session["capture_nonce"], capture_nonce):
            return False, "ZT-013 CAPTURE_INTEGRITY_FAILED: Nonce mismatch", None

        # 6. Check device and checkpoint binding
        if session["device_id"] != device_id or session["checkpoint_id"] != checkpoint_id:
            return False, "ZT-003 DEVICE_UNTRUSTED: Device or checkpoint binding mismatch", None

        device = self._trusted_devices.get(device_id)
        if not device or device["status"] != "ACTIVE":
            return False, "ZT-003 DEVICE_UNTRUSTED: Device is not active or recognized", None

        # 7. Compute frame hash
        frame_hash = self.compute_frame_hash(raw_frame_bytes)

        # 8. Check device signature if required or provided
        if require_signature or signature:
            expected_sig = self.generate_device_signature(device_id, session_id, capture_nonce, frame_hash)
            if not signature or not hmac.compare_digest(expected_sig, signature):
                return False, "ZT-003 DEVICE_UNTRUSTED: Invalid device signature on capture payload", None

        # Consume the session and mark nonce as used (atomic single-use)
        session["used"] = True
        self._used_nonces[capture_nonce] = now
        del self._active_sessions[session_id]

        return True, "CAPTURE_VALIDATED", frame_hash


# Singleton instance for server runtime
default_capture_manager = CaptureSessionManager()
