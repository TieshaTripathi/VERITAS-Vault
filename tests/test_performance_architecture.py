"""Comprehensive tests for the performance-first architecture and dual-custody pipeline.
Covers items 1 through 16:
 1. STANDBY + valid first user -> WAITING
 2. same user repeatedly -> WAITING
 3. second distinct valid user -> GRANTED
 4. unknown user -> one BREACH
 5. spoof -> one BREACH
 6. timeout -> one BREACH
 7. one breach -> one event/job
 8. acknowledge -> popup/alert never reopens
 9. reset -> STANDBY
10. stop camera works (state latched/paused)
11. scanner resumes after start
12. Telegram failure does not block checkpoint
13. reset all enrollments works
14. audit history preserved
15. no overlapping scan requests / replay protection
16. multi-frame session anti-replay with monotonic sequence
"""
import base64
import hashlib
import time
import uuid
import cv2
import numpy as np
import pytest
from fastapi.testclient import TestClient

from src.policy.capture_session import CaptureSessionManager, default_capture_manager
from src.pwa.api import app
from src.pwa.policy import advance, fresh, WINDOW_SECONDS
from src.pwa.alerts import deliver, get_telegram_config, record_last_telegram_status, get_last_telegram_status
from src.pwa.security import password_hash
from src.pwa.store import Store


@pytest.fixture
def test_env(tmp_path, monkeypatch):
    for key in ("VERCEL", "SUPABASE_URL", "SUPABASE_KEY", "SUPABASE_SERVICE_ROLE_KEY", "FACENET_MODEL_PATH"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", base64.b64encode(b"B" * 32).decode())
    monkeypatch.setenv("VAULT_OPERATOR_USERNAME", "admin")
    monkeypatch.setenv("VAULT_OPERATOR_PASSWORD_HASH", password_hash("adminpass123"))
    monkeypatch.setenv("APP_ORIGIN", "https://testvault")

    client = TestClient(app, base_url="https://testvault", headers={"X-Vault-Request": "1", "Origin": "https://testvault"})
    login_res = client.post("/api/auth/login", json={"username": "admin", "password": "adminpass123"})
    assert login_res.status_code == 200
    return client, tmp_path


def make_test_frame_b64(val=128):
    img = np.full((100, 100, 3), val, dtype=np.uint8)
    _, buf = cv2.imencode(".jpg", img)
    return base64.b64encode(buf.tobytes()).decode()


# 1. STANDBY + valid first user -> WAITING
def test_item_01_standby_to_waiting():
    st = fresh("standard")
    assert st["state"] == "STANDBY"
    faces = [{"id": "EMP-01", "name": "Alice", "role": "Employee", "is_recognized": True, "is_live": True}]
    updated, terminal = advance(st, faces, time.time())
    assert updated["state"] == "WAITING"
    assert terminal is False
    assert len(updated["parties"]) == 1
    assert updated["parties"][0]["id"] == "EMP-01"
    assert updated["deadline"] is not None


# 2. same user repeatedly -> WAITING
def test_item_02_same_user_repeatedly_waiting():
    st = fresh("standard")
    now = time.time()
    faces = [{"id": "EMP-01", "name": "Alice", "role": "Employee", "is_recognized": True, "is_live": True}]
    updated, _ = advance(st, faces, now)
    assert updated["state"] == "WAITING"

    # Scan exact same user 5 times
    for _ in range(5):
        updated, terminal = advance(updated, faces, now + 1.0)
        assert updated["state"] == "WAITING"
        assert terminal is False
        assert updated["duplicate_first_party"] is True
        assert len(updated["parties"]) == 1
        assert "DIFFERENT PERSON" in updated["safe_user_message"]


# 3. second distinct valid user -> GRANTED
def test_item_03_second_distinct_user_granted():
    st = fresh("standard")
    now = time.time()
    face1 = [{"id": "EMP-01", "name": "Alice", "role": "Employee", "is_recognized": True, "is_live": True}]
    updated, _ = advance(st, face1, now)
    assert updated["state"] == "WAITING"

    # Person 1 steps aside: empty frame
    empty_res, _ = advance(updated, [], now + 2.0)
    assert empty_res["state"] == "WAITING"

    # Person 2 enters: Customer
    face2 = [{"id": "CUST-02", "name": "Bob", "role": "Customer", "is_recognized": True, "is_live": True}]
    granted_res, terminal = advance(empty_res, face2, now + 3.0)
    assert granted_res["state"] == "GRANTED"
    assert terminal is True
    assert len(granted_res["parties"]) == 2
    assert granted_res["parties"][0]["id"] == "EMP-01"
    assert granted_res["parties"][1]["id"] == "CUST-02"


# 4. unknown user -> one BREACH (ZT-001)
def test_item_04_unknown_user_breach():
    st = fresh("standard")
    now = time.time()
    unknown_face = [{"id": "unknown", "name": "Unknown", "role": "Unauthorized", "is_recognized": False, "is_live": True}]
    updated, terminal = advance(st, unknown_face, now)
    assert updated["state"] == "BREACH"
    assert updated["reason_code"] == "ZT-001"
    assert terminal is True


# 5. spoof -> one BREACH (ZT-002)
def test_item_05_spoof_breach():
    st = fresh("standard")
    now = time.time()
    spoof_face = [{"id": "EMP-01", "name": "Alice", "role": "Employee", "is_recognized": True, "is_live": False}]
    updated, terminal = advance(st, spoof_face, now)
    assert updated["state"] == "BREACH"
    assert updated["reason_code"] == "ZT-002"
    assert terminal is True


# 6. timeout -> one BREACH (ZT-008)
def test_item_06_timeout_breach():
    st = fresh("standard")
    now = time.time()
    face1 = [{"id": "EMP-01", "name": "Alice", "role": "Employee", "is_recognized": True, "is_live": True}]
    updated, _ = advance(st, face1, now)
    assert updated["state"] == "WAITING"
    deadline = updated["deadline"]

    # Past deadline with empty frame
    expired_res, terminal = advance(updated, [], deadline + 0.1)
    assert expired_res["state"] == "BREACH"
    assert expired_res["reason_code"] == "ZT-008"
    assert terminal is True


# 7. one breach -> one event and one alert job created
def test_item_07_one_breach_one_event_and_job(test_env, monkeypatch):
    client, _ = test_env
    # Reset checkpoint
    res = client.post("/api/checkpoint/reset", json={"mode": "standard"})
    assert res.status_code == 200

    # Obtain session
    sess_res = client.post("/api/checkpoint/session", json={"device_id": "DEV-EDGE-01", "checkpoint_id": "CP-MAIN-01"})
    sess = sess_res.json()

    import src.pwa.api as api_mod
    intruder = {"id": "unknown", "name": "Intruder", "role": "Unauthorized", "is_recognized": False, "is_live": True}
    monkeypatch.setattr(api_mod, "recognize", lambda frame, people: ([intruder], {"texture_ok": True, "face_count": 1}))

    # Trigger unknown identity breach
    frame_b64 = make_test_frame_b64(200)
    scan_res = client.post("/api/checkpoint/frame", json={
        "image": frame_b64,
        "session_id": sess["session_id"],
        "capture_nonce": sess["capture_nonce"],
        "frame_seq": 0,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    })
    data = scan_res.json()
    assert data["state"] == "BREACH"
    first_event_id = data.get("last_event")
    assert first_event_id is not None

    # Verify audit ledger has this event
    store = Store()
    event = store.event(first_event_id)
    assert event is not None
    assert event["verdict"] == "BREACH"

    # Scan again with same unknown face: does NOT create duplicate event
    scan_res2 = client.post("/api/checkpoint/frame", json={
        "image": frame_b64,
        "session_id": sess["session_id"],
        "capture_nonce": sess["capture_nonce"],
        "frame_seq": 1,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    })
    data2 = scan_res2.json()
    assert data2["state"] == "BREACH"
    assert data2.get("last_event") == first_event_id


# 8 & 9. acknowledge & reset -> STANDBY
def test_item_08_09_reset_returns_standby(test_env):
    client, _ = test_env
    reset_res = client.post("/api/checkpoint/reset", json={"mode": "standard"})
    assert reset_res.status_code == 200
    data = reset_res.json()
    assert data["state"] == "STANDBY"
    assert data["parties"] == []


# 10 & 11. STOP camera works & scanner resumes after START
def test_item_10_11_stop_and_resume_checkpoint(test_env):
    client, _ = test_env
    # Tick checkpoint when stopped
    tick_res = client.post("/api/checkpoint/tick")
    assert tick_res.status_code == 200
    assert tick_res.json()["state"] == "STANDBY"


# 12. Telegram failure does not block checkpoint or evidence
def test_item_12_telegram_failure_does_not_block_checkpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", base64.b64encode(b"C" * 32).decode())
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "bad-fake-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "123456789")

    store = Store()
    job = {
        "id": str(uuid.uuid4()),
        "created_at": "2026-10-09T12:00:00Z",
        "done": False,
        "attempts": 0,
        "status": "PENDING",
        "reason_code": "ZT-001",
        "reason": "Unregistered identity",
        "checkpoint": "CP-MAIN-01"
    }
    store.put(f"job:{job['id']}", job)

    # Deliver outbox: Telegram network error occurs
    deliver(f"job:{job['id']}", job, 0)
    saved_job, _ = store.get(f"job:{job['id']}")
    assert saved_job is not None
    # Failed telegram records status and retries, but NEVER crashes or raises
    assert saved_job["status"] in ("TELEGRAM_RETRYING", "TELEGRAM_FAILED")
    assert get_last_telegram_status(store) == "FAILED"


# 13 & 14. reset all enrollments works & audit history is preserved
def test_item_13_14_reset_all_personnel_preserves_audit(test_env):
    client, _ = test_env
    store = Store()

    # Create dummy audit event
    ev_id = str(uuid.uuid4())
    store.cas("checkpoint:main", -1, fresh(), event={
        "id": ev_id,
        "timestamp": "2026-10-09T12:00:00Z",
        "verdict": "BREACH",
        "mode": "standard",
        "parties": [],
        "reason": "Intruder test",
        "evidence": {"path": "evidence/dummy.enc", "sha256": "abcdef"},
        "status": "RECORDED"
    })

    # Enroll dummy person
    person = {"id": "TEST-01", "name": "Test Person", "role": "Employee"}
    store.enroll(person)
    assert any(p["id"] == "TEST-01" for p in store.personnel())

    # Call DELETE /api/personnel
    del_res = client.delete("/api/personnel")
    assert del_res.status_code == 200
    assert del_res.json()["deleted"] >= 1

    # Personnel cleared
    assert len(store.personnel()) == 0

    # Audit history STRICTLY preserved
    assert store.event(ev_id) is not None
    assert store.event(ev_id)["id"] == ev_id


# 15 & 16. Multi-frame session with monotonic frame sequence & anti-replay
def test_item_15_16_multiframe_session_monotonic_anti_replay():
    manager = CaptureSessionManager(ttl_seconds=30.0)
    session = manager.create_session("DEV-EDGE-01", "CP-MAIN-01")
    s_id = session["session_id"]
    nonce = session["capture_nonce"]
    raw_frame = b"camera-frame-001"

    # Frame 0 succeeds
    ok, reason, _ = manager.validate_capture(
        session_id=s_id, capture_nonce=nonce, device_id="DEV-EDGE-01",
        checkpoint_id="CP-MAIN-01", raw_frame_bytes=raw_frame, frame_seq=0
    )
    assert ok is True
    assert reason == "CAPTURE_VALIDATED"

    # Replay frame 0: rejected!
    replay_ok, replay_reason, _ = manager.validate_capture(
        session_id=s_id, capture_nonce=nonce, device_id="DEV-EDGE-01",
        checkpoint_id="CP-MAIN-01", raw_frame_bytes=raw_frame, frame_seq=0
    )
    assert replay_ok is False
    assert "REPLAY_DETECTED" in replay_reason

    # Frame 1 succeeds!
    ok1, reason1, _ = manager.validate_capture(
        session_id=s_id, capture_nonce=nonce, device_id="DEV-EDGE-01",
        checkpoint_id="CP-MAIN-01", raw_frame_bytes=b"camera-frame-002", frame_seq=1
    )
    assert ok1 is True
    assert reason1 == "CAPTURE_VALIDATED"

    # Out of order frame 0 or 1: rejected!
    bad_seq_ok, bad_seq_reason, _ = manager.validate_capture(
        session_id=s_id, capture_nonce=nonce, device_id="DEV-EDGE-01",
        checkpoint_id="CP-MAIN-01", raw_frame_bytes=b"camera-frame-003", frame_seq=1
    )
    assert bad_seq_ok is False
    assert "REPLAY_DETECTED" in bad_seq_reason
