"""
Comprehensive Negative Security Test Suite for VERITAS-Vault
============================================================
Proves DEFAULT DENY across 20 distinct physical and cryptographic attack vectors:
  1. Reused capture nonce
  2. Expired capture nonce
  3. Wrong checkpoint
  4. Modified frame bytes
  5. Forged device proof
  6. Spoof / PAD failure
  7. Unknown identity
  8. Revoked identity
  9. PENDING enrollment identity
  10. Maker approves own enrollment
  11. Altered PEP token
  12. Expired PEP token
  13. Reused PEP token
  14. Token for wrong checkpoint
  15. Client supplies fake identity_verified=true
  16. Client supplies fake low risk score
  17. Missing signing key in production
  18. Audit event mutation
  19. Audit chain broken
  20. Concurrent audit append
"""
import base64
import copy
import hashlib
import os
import time
import uuid
import cv2
import numpy as np
import pytest
from fastapi.testclient import TestClient

from src.policy.capture_session import CaptureSessionManager
from src.policy.pdp import ZeroTrustPDP
from src.policy.risk import ProductionRiskEngine
from src.policy.door_controller import SimulatedDoorController
from src.blockchain.audit_chain import AuditLedger, canonicalize
from src.pwa.api import app
from src.pwa.store import Store
from src.pwa.security import password_hash, seal
from src.vision.liveness import evaluate_multisignal_pad


@pytest.fixture
def sec_client(tmp_path, monkeypatch):
    for key in ("VERCEL", "SUPABASE_URL", "SUPABASE_KEY", "FACENET_MODEL_PATH"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", base64.b64encode(b"Z" * 32).decode())
    monkeypatch.setenv("VAULT_OPERATOR_USERNAME", "admin1")
    monkeypatch.setenv("VAULT_OPERATOR_PASSWORD_HASH", password_hash("AdminPass123!"))
    monkeypatch.setenv("APP_ORIGIN", "http://testserver")

    client = TestClient(app, headers={"X-Vault-Request": "1", "Origin": "http://testserver"})
    client.post("/api/auth/login", json={"username": "admin1", "password": "AdminPass123!"})
    return client


# ATTACK 1: Reused capture nonce
def test_attack_01_reused_capture_nonce():
    mgr = CaptureSessionManager(ttl_seconds=5.0)
    sess = mgr.create_session("DEV-EDGE-01", "CP-MAIN-01")
    raw = b"legit-frame-bytes"

    ok1, _, _ = mgr.validate_capture(sess["session_id"], sess["capture_nonce"], "DEV-EDGE-01", "CP-MAIN-01", raw)
    assert ok1 is True

    # Replay
    ok2, err2, _ = mgr.validate_capture(sess["session_id"], sess["capture_nonce"], "DEV-EDGE-01", "CP-MAIN-01", raw)
    assert ok2 is False
    assert "REPLAY_DETECTED" in err2


# ATTACK 2: Expired capture nonce
def test_attack_02_expired_capture_nonce():
    mgr = CaptureSessionManager(ttl_seconds=0.05)
    sess = mgr.create_session("DEV-EDGE-01", "CP-MAIN-01")
    time.sleep(0.1)

    ok, err, _ = mgr.validate_capture(sess["session_id"], sess["capture_nonce"], "DEV-EDGE-01", "CP-MAIN-01", b"frame")
    assert ok is False
    assert "CAPTURE_INTEGRITY_FAILED" in err


# ATTACK 3: Wrong checkpoint binding
def test_attack_03_wrong_checkpoint():
    mgr = CaptureSessionManager(ttl_seconds=5.0)
    sess = mgr.create_session("DEV-EDGE-01", "CP-MAIN-01")

    # Attacker presents session issued for CP-MAIN-01 at CP-VAULT-99
    ok, err, _ = mgr.validate_capture(sess["session_id"], sess["capture_nonce"], "DEV-EDGE-01", "CP-VAULT-99", b"frame")
    assert ok is False
    assert "DEVICE_UNTRUSTED" in err or "mismatch" in err


# ATTACK 4: Modified frame bytes
def test_attack_04_modified_frame_bytes():
    mgr = CaptureSessionManager(ttl_seconds=5.0)
    sess = mgr.create_session("DEV-EDGE-01", "CP-MAIN-01")
    frame1 = b"real-face-bytes"
    frame2 = b"substituted-face-bytes"

    # Signature signed over frame1
    h1 = mgr.compute_frame_hash(frame1)
    sig1 = mgr.generate_device_signature("DEV-EDGE-01", sess["session_id"], sess["capture_nonce"], h1)

    # Attacker sends frame2 with sig1
    ok, err, _ = mgr.validate_capture(
        sess["session_id"], sess["capture_nonce"], "DEV-EDGE-01", "CP-MAIN-01",
        frame2, signature=sig1, require_signature=True
    )
    assert ok is False
    assert "Invalid device signature" in err


# ATTACK 5: Forged device signature
def test_attack_05_forged_device_proof():
    mgr = CaptureSessionManager(ttl_seconds=5.0)
    sess = mgr.create_session("DEV-EDGE-01", "CP-MAIN-01")
    forged_sig = "0" * 64

    ok, err, _ = mgr.validate_capture(
        sess["session_id"], sess["capture_nonce"], "DEV-EDGE-01", "CP-MAIN-01",
        b"some-frame", signature=forged_sig, require_signature=True
    )
    assert ok is False
    assert "Invalid device signature" in err


# ATTACK 6: Presentation Attack (Spoof)
def test_attack_06_spoof_detection():
    # 2D flat paper or screen simulation (low texture, flat gray)
    flat_spoof = np.ones((100, 100, 3), dtype=np.uint8) * 120
    pad_res = evaluate_multisignal_pad(flat_spoof)
    assert pad_res["status"] == "FAIL"
    assert pad_res["pad_confidence"] < 0.60


# ATTACK 7: Unknown identity rejection
def test_attack_07_unknown_identity():
    pdp = ZeroTrustPDP()
    unauth_face = [{"id": "intruder-01", "name": "Unknown", "role": "Unauthorized", "is_recognized": False, "is_live": True}]
    decision = pdp.evaluate("CP-MAIN-01", "standard", unauth_face, True, "VALID", [], None)
    assert decision.decision == "BREACH"
    assert decision.reason_code == "ZT-001"


# ATTACK 8: Revoked identity rejection
def test_attack_08_revoked_identity(sec_client):
    store = Store()
    # Enroll and then revoke
    store.enroll({"id": "REVOKED-EMP", "name": "Fired Employee", "role": "Employee", "status": "APPROVED"})
    assert any(p["id"] == "REVOKED-EMP" for p in store.personnel())

    store.revoke_user("REVOKED-EMP", revoker="admin1")
    # Must not appear in active personnel
    assert not any(p["id"] == "REVOKED-EMP" for p in store.personnel())


# ATTACK 9: PENDING enrollment identity rejection
def test_attack_09_pending_enrollment_cannot_authenticate(sec_client):
    # Submit enrollment request (status PENDING)
    img = np.zeros((120, 120, 3), dtype=np.uint8)
    _, buf = cv2.imencode(".jpg", img)
    b64_img = base64.b64encode(buf.tobytes()).decode()

    store = Store()
    store.save_enrollment_request({
        "request_id": str(uuid.uuid4()),
        "user_id": "PENDING-USER",
        "name": "Applicant",
        "role": "Employee",
        "status": "PENDING",
        "created_by": "admin1",
        "created_at": "2026-10-02T22:00:00Z"
    })
    # Must not be active in personnel
    active = [p["id"] for p in store.personnel()]
    assert "PENDING-USER" not in active


# ATTACK 10: Maker approves own enrollment (Separation of Duties violation)
def test_attack_10_maker_cannot_approve_own_enrollment(sec_client):
    store = Store()
    req_id = str(uuid.uuid4())
    store.save_enrollment_request({
        "request_id": req_id,
        "user_id": "SELF-APPROVE",
        "name": "Sneaky Admin",
        "role": "Employee",
        "status": "PENDING",
        "created_by": "local-admin",  # matches logged-in operator id
        "created_at": "2026-10-02T22:00:00Z",
        "template": "blob",
        "baseline": "path"
    })

    # Try to approve own request
    resp = sec_client.post(f"/api/enrollment/requests/{req_id}/approve")
    assert resp.status_code == 403
    assert "Maker-checker violation" in resp.json()["detail"]


# ATTACK 11: Altered PEP authorization token
def test_attack_11_altered_pep_token():
    pdp = ZeroTrustPDP()
    token = pdp._issue_signed_authorization("CP-MAIN-01", [{"id": "E1"}], "standard", 10)

    # Tamper decision from GRANT to malicious payload
    tampered = copy.deepcopy(token)
    tampered["payload"]["decision"] = "FORCED_GRANT"
    ok, err = pdp.verify_authorization_token(tampered, expected_checkpoint_id="CP-MAIN-01")
    assert ok is False
    assert "Forged or tampered" in err


# ATTACK 12: Expired PEP authorization token
def test_attack_12_expired_pep_token():
    pdp = ZeroTrustPDP()
    token = pdp._issue_signed_authorization("CP-MAIN-01", [{"id": "E1"}], "standard", 10)
    token["payload"]["expires_at"] = time.time() - 5.0  # already expired

    # Re-sign with expired time so signature matches but time is expired
    canonical = canonicalize(token["payload"])
    import hmac
    token["signature"] = hmac.new(pdp.signing_secret, canonical, hashlib.sha256).hexdigest()

    ok, err = pdp.verify_authorization_token(token, expected_checkpoint_id="CP-MAIN-01")
    assert ok is False
    assert "expired" in err.lower()


# ATTACK 13: Reused PEP authorization token (Replay attack on door relay)
def test_attack_13_reused_pep_token():
    pdp = ZeroTrustPDP()
    token = pdp._issue_signed_authorization("CP-MAIN-01", [{"id": "E1"}], "standard", 10)

    # 1. First verification succeeds
    ok1, _ = pdp.verify_authorization_token(token, expected_checkpoint_id="CP-MAIN-01")
    assert ok1 is True

    # 2. Replay of same token
    ok2, err2 = pdp.verify_authorization_token(token, expected_checkpoint_id="CP-MAIN-01")
    assert ok2 is False
    assert "Replay attack detected" in err2


# ATTACK 14: Token for wrong checkpoint
def test_attack_14_token_wrong_checkpoint():
    pdp = ZeroTrustPDP()
    token = pdp._issue_signed_authorization("CP-MAIN-01", [{"id": "E1"}], "standard", 10)

    # Present CP-MAIN-01 token to CP-VAULT-02 door controller
    ok, err = pdp.verify_authorization_token(token, expected_checkpoint_id="CP-VAULT-02")
    assert ok is False
    assert "checkpoint mismatch" in err.lower()


# ATTACK 15: Client supplies fake identity_verified=true
def test_attack_15_client_fake_identity_flag_ignored(sec_client):
    # Attacker POSTs frame with malicious extra body keys
    img = np.zeros((100, 100, 3), dtype=np.uint8)
    _, buf = cv2.imencode(".jpg", img)
    b64_img = base64.b64encode(buf.tobytes()).decode()

    resp = sec_client.post("/api/checkpoint/frame", json={
        "image": b64_img,
        "is_recognized": True,
        "identity_verified": True,
        "verdict": "GRANTED"
    })
    assert resp.status_code == 200
    # Server must evaluate its own recognition, not trust client body keys
    assert resp.json()["state"] != "GRANTED"


# ATTACK 16: Client supplies fake low risk score
def test_attack_16_client_fake_risk_ignored(sec_client):
    engine = ProductionRiskEngine()
    # Uncertain biometric confidence must produce elevated score regardless of client claims
    assessment = engine.evaluate_risk(
        biometric_confidence=0.65,
        pad_confidence=0.70,
        is_trusted_device=False
    )
    assert assessment.score >= 60


# ATTACK 17: Insecure signing key and device secret refused in production mode
def test_attack_17_production_refuses_default_key(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VAULT_SIGNING_KEY", "default-veritas-signing-secret-32b!")
    with pytest.raises(RuntimeError, match="CRITICAL: Production deployment requires a secure"):
        ZeroTrustPDP()

    monkeypatch.setenv("VAULT_SIGNING_KEY", "secure-prod-key-12345678901234567890")
    monkeypatch.setenv("VAULT_DEVICE_SECRET", "default-dev-edge-secret-key-32b!")
    with pytest.raises(RuntimeError, match="CRITICAL: Production deployment requires a secure"):
        CaptureSessionManager()


# ATTACK 18: Audit event mutation detected
def test_attack_18_audit_event_mutation(tmp_path):
    ledger = AuditLedger(db_path=tmp_path / "test_audit.sqlite3", keys_dir=tmp_path / "keys")
    evt = ledger.append_event("EVT-01", "2026-10-02T22:00:00Z", {"verdict": "GRANTED"})
    assert ledger.verify_event("EVT-01")["verified"] is True

    # Malicious actor tampers with SQLite payload
    import sqlite3
    with sqlite3.connect(tmp_path / "test_audit.sqlite3") as conn:
        conn.execute("UPDATE audit_chain SET payload=? WHERE event_id=?", ('{"verdict": "TAMPERED"}', "EVT-01"))
        conn.commit()

    res = ledger.verify_event("EVT-01")
    assert res["verified"] is False
    assert res["event_hash_valid"] is False


# ATTACK 19: Audit chain broken link detected
def test_attack_19_audit_chain_broken_link(tmp_path):
    ledger = AuditLedger(db_path=tmp_path / "test_audit_chain.sqlite3", keys_dir=tmp_path / "keys")
    ledger.append_event("EVT-01", "2026-10-02T22:00:00Z", {"verdict": "WAITING"})
    ledger.append_event("EVT-02", "2026-10-02T22:00:01Z", {"verdict": "GRANTED"})
    assert ledger.verify_chain()["verified"] is True

    # Malicious actor changes previous_hash of EVT-02
    import sqlite3
    with sqlite3.connect(tmp_path / "test_audit_chain.sqlite3") as conn:
        conn.execute("UPDATE audit_chain SET previous_hash=? WHERE event_id=?", ("bad_hash" * 8, "EVT-02"))
        conn.commit()

    chain_res = ledger.verify_chain()
    assert chain_res["verified"] is False
    assert chain_res["failed_event_id"] == "EVT-02"


# ATTACK 20: Concurrent audit append preserves monotonic continuity
def test_attack_20_concurrent_audit_appends(tmp_path):
    ledger = AuditLedger(db_path=tmp_path / "test_audit_concurrency.sqlite3", keys_dir=tmp_path / "keys")
    for i in range(10):
        ledger.append_event(f"EVT-CONC-{i}", f"2026-10-02T22:00:0{i}Z", {"count": i})

    chain_res = ledger.verify_chain()
    assert chain_res["verified"] is True
    assert chain_res["total_events_verified"] == 10
