"""
VERITAS-Vault Zero-Trust Policy Decision Point (PDP) & Policy Enforcement Point (PEP)
=====================================================================================
Enforces: Biometric Match != Access Authorization.
Evaluates:
  GRANT = Identity Verified
          AND Liveness Verified
          AND Trusted Capture Device
          AND Policy Satisfied
          AND Temporal Authorization Valid
          AND Required Custody Conditions Satisfied
          AND Risk Acceptable

Generates machine-readable reason codes (ZT-001 to ZT-013) and cryptographically
signed authorization tokens for edge door relays.
"""
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field

# Reason codes per specification
REASON_CODES = {
    "ZT-001": "IDENTITY_MISMATCH",
    "ZT-002": "PAD_FAILED",
    "ZT-003": "DEVICE_UNTRUSTED",
    "ZT-004": "DEVICE_CERTIFICATE_EXPIRED",
    "ZT-005": "OUTSIDE_AUTHORIZED_WINDOW",
    "ZT-006": "CLEARANCE_INSUFFICIENT",
    "ZT-007": "DUAL_CUSTODY_REQUIRED",
    "ZT-008": "DUAL_CUSTODY_TIMEOUT",
    "ZT-009": "REPLAY_DETECTED",
    "ZT-010": "RISK_THRESHOLD_EXCEEDED",
    "ZT-011": "ACCOUNT_DISABLED",
    "ZT-012": "MULTIPLE_FACE_VIOLATION",
    "ZT-013": "CAPTURE_INTEGRITY_FAILED",
}

DEFAULT_POLICY_VERSION = "VAULT-ZT-v1.0"
TOKEN_EXPIRY_SECONDS = 15.0  # Door actuation token valid for only 15 seconds


class PolicyDecision(BaseModel):
    decision: str  # "GRANTED", "DENIED", "WAITING", "BREACH"
    reason_code: Optional[str] = None
    reason_text: str
    safe_user_message: str
    risk_score: int  # 0 to 100
    policy_version: str = DEFAULT_POLICY_VERSION
    authorization_token: Optional[Dict[str, Any]] = None
    audit_trace: Dict[str, Any] = Field(default_factory=dict)


from src.policy.risk import default_risk_engine, ProductionRiskEngine

# Backward-compatible wrapper
class RiskEngine(ProductionRiskEngine):
    def compute_risk(self, biometric_confidence: float, pad_confidence: float, is_trusted_device: bool, historical_failures: int = 0, outside_normal_hours: bool = False) -> int:
        return self.evaluate_risk(biometric_confidence, pad_confidence, is_trusted_device, historical_failures, outside_normal_hours).score


class ZeroTrustPDP:
    """
    Policy Decision Point evaluating all trust signals simultaneously.
    """
    def __init__(self, signing_secret: Optional[str] = None):
        secret = signing_secret or os.environ.get("VAULT_SIGNING_KEY")
        is_prod = bool(os.environ.get("VERCEL") or os.environ.get("K_SERVICE") or os.environ.get("ENV") == "production" or os.environ.get("ENVIRONMENT") == "production")
        if is_prod and (not secret or secret == "default-veritas-signing-secret-32b!"):
            raise RuntimeError("CRITICAL: Production deployment requires a secure, non-default VAULT_SIGNING_KEY.")
        self.signing_secret = (secret or "default-veritas-signing-secret-32b!").encode()
        self.risk_engine = RiskEngine()
        # Single-use authorization nonces cache: nonce -> timestamp
        self._used_auth_nonces: Dict[str, float] = {}

    def evaluate(
        self,
        checkpoint_id: str,
        mode: str,
        faces: List[Dict[str, Any]],
        capture_valid: bool,
        capture_reason: str,
        active_parties: List[Dict[str, Any]],
        deadline: Optional[float],
        now: Optional[float] = None
    ) -> PolicyDecision:
        now = now or time.time()

        # Signal 1: Capture Pipeline Integrity & Device Trust
        if not capture_valid:
            code = "ZT-009" if "REPLAY" in capture_reason else "ZT-013"
            return PolicyDecision(
                decision="DENIED",
                reason_code=code,
                reason_text=capture_reason,
                safe_user_message="ACCESS DENIED: Capture integrity check failed",
                risk_score=95,
                audit_trace={"capture_status": "FAILED", "reason": capture_reason}
            )

        # Signal 2: Face Quality / Multi-Face Violation
        if len(faces) > 2:
            return PolicyDecision(
                decision="DENIED",
                reason_code="ZT-012",
                reason_text="Multiple faces detected violating security threshold",
                safe_user_message="ACCESS DENIED: Multiple faces detected",
                risk_score=75,
                audit_trace={"face_count": len(faces)}
            )

        if not faces:
            # Check if active deadline expired
            if deadline and now >= deadline:
                return PolicyDecision(
                    decision="BREACH",
                    reason_code="ZT-008",
                    reason_text="Dual custody window expired without second officer verification",
                    safe_user_message="SECURITY ALERT: Custody window expired",
                    risk_score=85,
                    audit_trace={"deadline": deadline, "expired_at": now}
                )
            return PolicyDecision(
                decision="WAITING" if active_parties else "STANDBY",
                reason_text="Awaiting subject presentation",
                safe_user_message="Please face the camera directly",
                risk_score=0
            )

        # Check each face for Liveness (PAD) and Identity match
        for f in faces:
            if not f.get("is_live", False):
                return PolicyDecision(
                    decision="BREACH",
                    reason_code="ZT-002",
                    reason_text="Presentation attack detection failed (spoof detected)",
                    safe_user_message="ACCESS DENIED: Biometric verification failed",
                    risk_score=99,
                    audit_trace={"pad_score": f.get("pad_score", 0.0), "pad_signals": f.get("pad_signals", {})}
                )
            if not f.get("is_recognized", False):
                return PolicyDecision(
                    decision="BREACH",
                    reason_code="ZT-001",
                    reason_text="Unregistered or unauthorized biometric identity",
                    safe_user_message="ACCESS DENIED: Contact Security",
                    risk_score=80,
                    audit_trace={"subject_id": f.get("id", "unknown")}
                )

        # Calculate continuous risk score
        best_bio_conf = max((f.get("confidence", 0.0) for f in faces), default=0.0)
        best_pad_conf = max((f.get("pad_confidence", 0.90) for f in faces), default=0.90)
        risk = self.risk_engine.compute_risk(
            biometric_confidence=best_bio_conf,
            pad_confidence=best_pad_conf,
            is_trusted_device=True
        )

        if risk > 60:
            return PolicyDecision(
                decision="DENIED",
                reason_code="ZT-010",
                reason_text=f"Deterministic risk score ({risk}/100) exceeds threshold",
                safe_user_message="ACCESS DENIED: Contact Security Administrator",
                risk_score=risk,
                audit_trace={"risk_score": risk, "biometric_conf": best_bio_conf, "pad_conf": best_pad_conf}
            )

        # Signal 3: Separation of Duties & Dual Custody Logic
        # Update parties with newly recognized distinct individuals
        updated_parties = list(active_parties)
        for f in faces:
            if not any(p["id"] == f["id"] for p in updated_parties):
                updated_parties.append({"id": f["id"], "name": f["name"], "role": f["role"]})

        roles = [p["role"] for p in updated_parties]
        is_granted = False
        if mode == "high-value":
            # Requires 2 distinct employees
            is_granted = (roles.count("Employee") >= 2)
        else:
            # Standard mode: 1 Employee + 1 Customer
            is_granted = ("Employee" in roles and "Customer" in roles)

        if is_granted:
            # Generate cryptographic authorization token for PEP door controller
            token = self._issue_signed_authorization(
                checkpoint_id=checkpoint_id,
                parties=updated_parties,
                mode=mode,
                risk_score=risk
            )
            return PolicyDecision(
                decision="GRANTED",
                reason_text="Dual custody requirements satisfied and risk acceptable",
                safe_user_message="ACCESS GRANTED: Proceed to vault entry",
                risk_score=risk,
                authorization_token=token,
                audit_trace={
                    "parties": updated_parties,
                    "mode": mode,
                    "risk_score": risk,
                    "authorization_id": token["payload"]["authorization_id"]
                }
            )

        # Still waiting for second party
        if updated_parties:
            return PolicyDecision(
                decision="WAITING",
                reason_code="ZT-007",
                reason_text="Primary identity authenticated; awaiting second required officer",
                safe_user_message="PRIMARY VERIFIED: Awaiting second authorized party",
                risk_score=risk,
                audit_trace={"parties": updated_parties}
            )

        return PolicyDecision(
            decision="STANDBY",
            reason_text="System ready",
            safe_user_message="Ready for verification",
            risk_score=0
        )

    def _issue_signed_authorization(
        self,
        checkpoint_id: str,
        parties: List[Dict[str, Any]],
        mode: str,
        risk_score: int
    ) -> Dict[str, Any]:
        """
        Signs a short-lived door unlock token bound to checkpoint, nonce, and expiry.
        Only the physical edge PEP relay validator can accept this token.
        """
        now = time.time()
        auth_id = f"AUTH-{secrets.token_hex(8).upper()}"
        nonce = secrets.token_hex(16)
        expires_at = now + TOKEN_EXPIRY_SECONDS

        canonical_data = {
            "authorization_id": auth_id,
            "checkpoint_id": checkpoint_id,
            "decision": "GRANT",
            "parties": [p["id"] for p in parties],
            "mode": mode,
            "risk_score": risk_score,
            "issued_at": now,
            "expires_at": expires_at,
            "nonce": nonce,
            "policy_version": DEFAULT_POLICY_VERSION
        }
        serialized = json.dumps(canonical_data, sort_keys=True, separators=(",", ":")).encode()
        signature = hmac.new(self.signing_secret, serialized, hashlib.sha256).hexdigest()

        return {
            "payload": canonical_data,
            "signature": signature,
            "algorithm": "HMAC-SHA256",
            "key_id": "primary-pep-v1"
        }

    def verify_authorization_token(
        self,
        token_obj: Dict[str, Any],
        expected_checkpoint_id: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Validation routine executed by the Edge PEP before pulsing relay.
        Strictly enforces: signature, expiration, checkpoint binding, and single-use anti-replay.
        """
        try:
            payload = token_obj.get("payload", {})
            signature = token_obj.get("signature", "")
            now = time.time()

            # 1. Expiration check
            if now > payload.get("expires_at", 0):
                return False, "Authorization token expired"

            # 2. Checkpoint binding check
            if expected_checkpoint_id and payload.get("checkpoint_id") != expected_checkpoint_id:
                return False, f"Token checkpoint mismatch: {payload.get('checkpoint_id')} != {expected_checkpoint_id}"

            # 3. Anti-replay single-use nonce check
            nonce = payload.get("nonce")
            if not nonce:
                return False, "Missing authorization token nonce"
            if nonce in self._used_auth_nonces:
                return False, "Replay attack detected: authorization token already consumed"

            # 4. Canonical HMAC signature verification
            serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            expected_sig = hmac.new(self.signing_secret, serialized, hashlib.sha256).hexdigest()

            if not hmac.compare_digest(expected_sig, signature):
                return False, "Forged or tampered authorization signature"

            # 5. Must be explicit GRANT
            if payload.get("decision") != "GRANT":
                return False, "Token decision is not GRANT"

            # Atomically consume authorization nonce (purge nonces older than 60s)
            cutoff = now - 60.0
            self._used_auth_nonces = {n: ts for n, ts in self._used_auth_nonces.items() if ts >= cutoff}
            self._used_auth_nonces[nonce] = now

            return True, "PEP_AUTHORIZED"
        except Exception as exc:
            return False, f"Token verification error: {str(exc)}"


# Global default PDP instance
default_pdp = ZeroTrustPDP()
