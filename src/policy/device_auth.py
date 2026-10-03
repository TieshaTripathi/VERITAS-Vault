"""
VERITAS-Vault Hardware-Ready Device Authenticator and Key Lifecycle
===================================================================
Defines device authentication and cryptographic key lifecycle management.

CURRENT MATURITY:
- Software HMAC-SHA256 device proof with rotation & grace period support.

FUTURE ARCHITECTURE:
- TPM 2.0 / Secure Element private-key-backed attestation (mTLS / IEEE 802.1AR DevID).
- HardwareAttestedDeviceAuthenticator and CertificateDeviceAuthenticator are reserved
  interfaces for physical HSM/TPM integration.
"""

from abc import ABC, abstractmethod
import time
import hmac
import hashlib
from typing import Dict, Any, Optional, List, Tuple
from pydantic import BaseModel, Field


class DeviceKeyStatus:
    ACTIVE = "ACTIVE"
    ROTATING = "ROTATING"  # Grace period: old key accepted, new key preferred
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class DeviceKeyRecord(BaseModel):
    key_id: str
    secret: str
    active_from: float
    expires_at: float
    revoked_at: Optional[float] = None
    status: str = DeviceKeyStatus.ACTIVE


class DeviceAuthenticator(ABC):
    """Abstract interface for edge device authentication."""

    @abstractmethod
    def verify_device_proof(
        self,
        device_id: str,
        payload: bytes,
        signature: str,
        key_id: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Verify device authenticity."""
        pass

    @abstractmethod
    def rotate_key(self, device_id: str, new_key_id: str, new_secret: str, grace_period_sec: float = 3600.0) -> Dict[str, Any]:
        """Rotate device key with grace period support."""
        pass

    @abstractmethod
    def revoke_key(self, device_id: str, key_id: str, reason: str = "COMPROMISED") -> Dict[str, Any]:
        """Revoke a device key immediately."""
        pass


class HMACDeviceAuthenticator(DeviceAuthenticator):
    """
    Production-prototype software HMAC-SHA256 device authenticator.
    Maintains active and rotating grace-period keys.
    """
    def __init__(self):
        # device_id -> List[DeviceKeyRecord]
        self._device_keys: Dict[str, List[DeviceKeyRecord]] = {}
        self._audit_events: List[Dict[str, Any]] = []

    def register_device(self, device_id: str, key_id: str, secret: str, ttl_seconds: float = 86400 * 30):
        now = time.time()
        key_rec = DeviceKeyRecord(
            key_id=key_id,
            secret=secret,
            active_from=now,
            expires_at=now + ttl_seconds,
            status=DeviceKeyStatus.ACTIVE
        )
        self._device_keys[device_id] = [key_rec]

    def verify_device_proof(
        self,
        device_id: str,
        payload: bytes,
        signature: str,
        key_id: Optional[str] = None
    ) -> Tuple[bool, str]:
        keys = self._device_keys.get(device_id, [])
        if not keys:
            return False, f"DEVICE_UNKNOWN: No keys registered for {device_id}"

        now = time.time()

        # Filter candidates
        candidate_keys = []
        for k in keys:
            if k.status == DeviceKeyStatus.REVOKED:
                continue
            if now > k.expires_at:
                k.status = DeviceKeyStatus.EXPIRED
                continue
            if key_id and k.key_id != key_id:
                continue
            if k.status in (DeviceKeyStatus.ACTIVE, DeviceKeyStatus.ROTATING):
                candidate_keys.append(k)

        if not candidate_keys:
            if any(k.status == DeviceKeyStatus.REVOKED for k in keys if not key_id or k.key_id == key_id):
                return False, "DEVICE_KEY_REVOKED: Key has been revoked"
            return False, "DEVICE_KEY_EXPIRED: No valid active keys available"

        # Try verifying signature against candidate keys (supporting rotation grace period)
        for k in candidate_keys:
            expected_sig = hmac.new(k.secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
            if hmac.compare_digest(expected_sig, signature):
                if k.status == DeviceKeyStatus.ROTATING:
                    return True, "DEVICE_VERIFIED_GRACE_PERIOD"
                return True, "DEVICE_VERIFIED_ACTIVE"

        return False, "DEVICE_SIGNATURE_MISMATCH: Invalid HMAC signature"

    def rotate_key(
        self,
        device_id: str,
        new_key_id: str,
        new_secret: str,
        grace_period_sec: float = 3600.0,
        ttl_seconds: float = 86400 * 30
    ) -> Dict[str, Any]:
        now = time.time()
        keys = self._device_keys.setdefault(device_id, [])

        # Mark current active keys as ROTATING with expiration matching grace period
        for k in keys:
            if k.status == DeviceKeyStatus.ACTIVE:
                k.status = DeviceKeyStatus.ROTATING
                k.expires_at = min(k.expires_at, now + grace_period_sec)

        # Add new active key
        new_key = DeviceKeyRecord(
            key_id=new_key_id,
            secret=new_secret,
            active_from=now,
            expires_at=now + ttl_seconds,
            status=DeviceKeyStatus.ACTIVE
        )
        keys.append(new_key)

        event = {
            "type": "DEVICE_KEY_ROTATED",
            "device_id": device_id,
            "new_key_id": new_key_id,
            "timestamp": now,
            "grace_period_sec": grace_period_sec
        }
        self._audit_events.append(event)
        return event

    def revoke_key(self, device_id: str, key_id: str, reason: str = "COMPROMISED") -> Dict[str, Any]:
        now = time.time()
        keys = self._device_keys.get(device_id, [])
        revoked = False
        for k in keys:
            if k.key_id == key_id:
                k.status = DeviceKeyStatus.REVOKED
                k.revoked_at = now
                revoked = True

        event = {
            "type": "DEVICE_KEY_REVOKED",
            "device_id": device_id,
            "key_id": key_id,
            "reason": reason,
            "timestamp": now,
            "revoked": revoked
        }
        self._audit_events.append(event)
        return event

    def get_audit_events(self) -> List[Dict[str, Any]]:
        return list(self._audit_events)


class CertificateDeviceAuthenticator(DeviceAuthenticator):
    """
    Prepared architecture for future X.509 client certificate (mTLS) device identity.
    """
    def __init__(self, ca_cert_path: Optional[str] = None):
        self.ca_cert_path = ca_cert_path

    def verify_device_proof(self, device_id: str, payload: bytes, signature: str, key_id: Optional[str] = None) -> Tuple[bool, str]:
        raise NotImplementedError("Certificate device authentication requires mTLS / PKI infrastructure.")

    def rotate_key(self, device_id: str, new_key_id: str, new_secret: str, grace_period_sec: float = 3600.0) -> Dict[str, Any]:
        raise NotImplementedError("Certificate device authentication requires mTLS / PKI infrastructure.")

    def revoke_key(self, device_id: str, key_id: str, reason: str = "COMPROMISED") -> Dict[str, Any]:
        raise NotImplementedError("Certificate device authentication requires mTLS / PKI infrastructure.")


class HardwareAttestedDeviceAuthenticator(DeviceAuthenticator):
    """
    Prepared architecture for future TPM 2.0 / Secure Element DevID attestation.
    """
    def __init__(self, aik_cert_path: Optional[str] = None):
        self.aik_cert_path = aik_cert_path

    def verify_device_proof(self, device_id: str, payload: bytes, signature: str, key_id: Optional[str] = None) -> Tuple[bool, str]:
        raise NotImplementedError("TPM hardware attestation requires hardware root of trust.")

    def rotate_key(self, device_id: str, new_key_id: str, new_secret: str, grace_period_sec: float = 3600.0) -> Dict[str, Any]:
        raise NotImplementedError("TPM hardware attestation requires hardware root of trust.")

    def revoke_key(self, device_id: str, key_id: str, reason: str = "COMPROMISED") -> Dict[str, Any]:
        raise NotImplementedError("TPM hardware attestation requires hardware root of trust.")
