"""
Unit and integration tests for VERITAS-Vault Zero-Trust Architecture:
  - Trusted Capture Pipeline (anti-replay nonces, session TTL, frame hash)
  - Zero-Trust PDP & PEP Signed Authorization Tokens
  - Multi-Signal Presentation Attack Detection (PAD)
  - Machine-readable reason codes (ZT-001 to ZT-013)
  - Deterministic Risk Engine
"""
import base64
import hashlib
import time
import cv2
import numpy as np
import pytest
from fastapi.testclient import TestClient

from src.policy.capture_session import CaptureSessionManager
from src.policy.pdp import ZeroTrustPDP, RiskEngine
from src.vision.liveness import evaluate_multisignal_pad, estimate_liveness
from src.pwa.api import app
from src.pwa.security import seal


def test_capture_session_lifecycle():
    manager = CaptureSessionManager(ttl_seconds=2.0)
    session = manager.create_session("DEV-EDGE-01", "CP-MAIN-01")

    assert "session_id" in session
    assert "capture_nonce" in session
    assert session["ttl_seconds"] == 2.0

    raw_frame = b"fake-camera-frame-bytes-12345"

    # 1. First validation succeeds
    valid, reason, f_hash = manager.validate_capture(
        session_id=session["session_id"],
        capture_nonce=session["capture_nonce"],
        device_id="DEV-EDGE-01",
        checkpoint_id="CP-MAIN-01",
        raw_frame_bytes=raw_frame
    )
    assert valid is True
    assert reason == "CAPTURE_VALIDATED"
    assert f_hash == hashlib.sha256(raw_frame).hexdigest()

    # 2. Replay attack: reusing the same nonce is strictly rejected
    replay_valid, replay_reason, _ = manager.validate_capture(
        session_id=session["session_id"],
        capture_nonce=session["capture_nonce"],
        device_id="DEV-EDGE-01",
        checkpoint_id="CP-MAIN-01",
        raw_frame_bytes=raw_frame
    )
    assert replay_valid is False
    assert "REPLAY_DETECTED" in replay_reason


def test_capture_session_expired():
    manager = CaptureSessionManager(ttl_seconds=0.1)
    session = manager.create_session("DEV-EDGE-01", "CP-MAIN-01")
    time.sleep(0.2)

    valid, reason, _ = manager.validate_capture(
        session_id=session["session_id"],
        capture_nonce=session["capture_nonce"],
        device_id="DEV-EDGE-01",
        checkpoint_id="CP-MAIN-01",
        raw_frame_bytes=b"sample-frame"
    )
    assert valid is False
    assert "CAPTURE_INTEGRITY_FAILED" in reason


def test_capture_session_untrusted_device():
    manager = CaptureSessionManager(ttl_seconds=5.0)
    with pytest.raises(ValueError, match="Untrusted or revoked"):
        manager.create_session("ROGUE-CAMERA-99", "CP-MAIN-01")


def test_deterministic_risk_engine():
    engine = RiskEngine()
    # High confidence, trusted device -> low risk
    low_risk = engine.compute_risk(
        biometric_confidence=0.95,
        pad_confidence=0.95,
        is_trusted_device=True,
        historical_failures=0
    )
    assert 0 <= low_risk <= 20

    # Low liveness and biometric uncertainty -> elevated risk
    high_risk = engine.compute_risk(
        biometric_confidence=0.65,
        pad_confidence=0.60,
        is_trusted_device=False,
        historical_failures=3
    )
    assert high_risk >= 70


def test_zero_trust_pdp_evaluation_and_pep_token():
    pdp = ZeroTrustPDP(signing_secret="test-secret-key-32b-length-padded!")

    # 1. Capture integrity failure produces DENIED with ZT-013 or ZT-009
    decision_fail = pdp.evaluate(
        checkpoint_id="CP-MAIN-01",
        mode="standard",
        faces=[],
        capture_valid=False,
        capture_reason="ZT-009 REPLAY_DETECTED: Nonce reused",
        active_parties=[],
        deadline=None
    )
    assert decision_fail.decision == "DENIED"
    assert decision_fail.reason_code == "ZT-009"
    assert decision_fail.authorization_token is None

    # 2. Spoof detected produces BREACH with ZT-002
    spoof_face = [{"id": "E1", "name": "Alice", "role": "Employee", "is_recognized": True, "is_live": False}]
    decision_spoof = pdp.evaluate(
        checkpoint_id="CP-MAIN-01",
        mode="standard",
        faces=spoof_face,
        capture_valid=True,
        capture_reason="CAPTURE_VALIDATED",
        active_parties=[],
        deadline=None
    )
    assert decision_spoof.decision == "BREACH"
    assert decision_spoof.reason_code == "ZT-002"

    # 3. Dual custody satisfied produces GRANTED with signed PEP authorization token
    auth_faces = [
        {"id": "E1", "name": "Alice", "role": "Employee", "is_recognized": True, "is_live": True, "confidence": 0.92, "pad_confidence": 0.95},
        {"id": "C1", "name": "Bob", "role": "Customer", "is_recognized": True, "is_live": True, "confidence": 0.88, "pad_confidence": 0.92}
    ]
    decision_grant = pdp.evaluate(
        checkpoint_id="CP-MAIN-01",
        mode="standard",
        faces=auth_faces,
        capture_valid=True,
        capture_reason="CAPTURE_VALIDATED",
        active_parties=[],
        deadline=None
    )
    assert decision_grant.decision == "GRANTED"
    assert decision_grant.authorization_token is not None

    token = decision_grant.authorization_token
    assert "signature" in token
    assert token["payload"]["checkpoint_id"] == "CP-MAIN-01"

    # 4. Verify the PEP token
    pep_ok, pep_msg = pdp.verify_authorization_token(token)
    assert pep_ok is True
    assert pep_msg == "PEP_AUTHORIZED"

    # 5. Tampered token rejected by PEP
    tampered = dict(token)
    tampered["signature"] = "bad" + token["signature"][3:]
    pep_tampered, _ = pdp.verify_authorization_token(tampered)
    assert pep_tampered is False


def test_multisignal_pad_evaluation():
    # Synthetic face crop (random sharp image)
    sharp_face = np.random.randint(60, 200, (120, 120, 3), dtype=np.uint8)
    res = evaluate_multisignal_pad(sharp_face, threshold=0.75)

    assert "pad_score" in res
    assert "pad_confidence" in res
    assert "signals" in res
    assert "texture" in res["signals"]
    assert "color" in res["signals"]
    assert "moire" in res["signals"]
    assert res["pad_model_version"].startswith("VERITAS-PAD")

    # Degraded blurred image (simulate print attack blur)
    blurred_face = cv2.GaussianBlur(sharp_face, (25, 25), 0)
    is_live, conf = estimate_liveness(blurred_face, threshold=0.80)
    assert is_live is False


def test_api_session_and_pep_verification(tmp_path, monkeypatch):
    for key in ("VERCEL", "SUPABASE_URL", "SUPABASE_KEY", "FACENET_MODEL_PATH"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", base64.b64encode(b"A" * 32).decode())
    monkeypatch.setenv("VAULT_OPERATOR_USERNAME", "admin")
    from src.pwa.security import password_hash
    monkeypatch.setenv("VAULT_OPERATOR_PASSWORD_HASH", password_hash("secret123"))
    monkeypatch.setenv("APP_ORIGIN", "http://testserver")

    client = TestClient(app, headers={"X-Vault-Request": "1", "Origin": "http://testserver"})
    # Login
    auth_resp = client.post("/api/auth/login", json={"username": "admin", "password": "secret123"})
    assert auth_resp.status_code == 200

    # 1. Issue capture session
    sess_resp = client.post("/api/checkpoint/session",
                            json={"device_id": "DEV-EDGE-01", "checkpoint_id": "CP-MAIN-01"},
                            headers={"x-vault-request": "1"})
    assert sess_resp.status_code == 200
    sess_data = sess_resp.json()
    assert "session_id" in sess_data
    assert "capture_nonce" in sess_data

    # 2. PEP verification endpoint with valid signed token
    pdp = ZeroTrustPDP()
    valid_token = pdp._issue_signed_authorization(
        checkpoint_id="CP-MAIN-01",
        parties=[{"id": "EMP1"}],
        mode="standard",
        risk_score=10
    )
    pep_resp = client.post("/api/pep/verify", json={"token": valid_token},
                           headers={"x-vault-request": "1"})
    assert pep_resp.status_code == 200
    assert pep_resp.json()["status"] == "RELAY_ACTUATED"

    # 3. PEP verification with forged token fails with 403
    forged_token = dict(valid_token)
    forged_token["signature"] = "deadbeef" * 8
    pep_bad = client.post("/api/pep/verify", json={"token": forged_token},
                          headers={"x-vault-request": "1"})
    assert pep_bad.status_code == 403


def test_checkpoint_frame_anti_replay(tmp_path, monkeypatch):
    for key in ("VERCEL", "SUPABASE_URL", "SUPABASE_KEY", "FACENET_MODEL_PATH"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", base64.b64encode(b"A" * 32).decode())
    monkeypatch.setenv("VAULT_OPERATOR_USERNAME", "admin")
    from src.pwa.security import password_hash
    monkeypatch.setenv("VAULT_OPERATOR_PASSWORD_HASH", password_hash("secret123"))
    monkeypatch.setenv("APP_ORIGIN", "http://testserver")

    client = TestClient(app, headers={"X-Vault-Request": "1", "Origin": "http://testserver"})
    client.post("/api/auth/login", json={"username": "admin", "password": "secret123"})

    # Issue capture session challenge
    sess_resp = client.post("/api/checkpoint/session",
                            json={"device_id": "DEV-EDGE-01", "checkpoint_id": "CP-MAIN-01"})
    session = sess_resp.json()

    # Generate synthetic image
    img = np.zeros((100, 100, 3), dtype=np.uint8)
    _, buf = cv2.imencode(".jpg", img)
    b64_img = base64.b64encode(buf.tobytes()).decode()

    # First frame submission with session challenge
    frame_resp = client.post("/api/checkpoint/frame", json={
        "image": b64_img,
        "session_id": session["session_id"],
        "capture_nonce": session["capture_nonce"],
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    })
    assert frame_resp.status_code == 200

    # Second submission with the exact same nonce (Replay Attack)
    replay_resp = client.post("/api/checkpoint/frame", json={
        "image": b64_img,
        "session_id": session["session_id"],
        "capture_nonce": session["capture_nonce"],
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    })
    assert replay_resp.status_code == 200
    replay_data = replay_resp.json()
    assert replay_data["state"] == "BREACH"
    assert replay_data["reason_code"] == "ZT-009"
    assert "REPLAY_DETECTED" in replay_data["reason"]

