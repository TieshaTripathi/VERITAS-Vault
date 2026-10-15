"""Automated regression suite for Pushover breach notification service.
Verifies:
1. Reading credentials from PUSHOVER_APP_TOKEN and PUSHOVER_USER_KEY
2. Delivery of confirmed critical breaches (ZT-001, ZT-002, ZT-008, ZT-009, ZT-013)
3. Breach code, checkpoint, timestamp, and audit event link payload verification
4. Deduplication: one breach = one logical alert (event ID tracking)
5. Outbox lifecycle integration: retries, bounded backoff, and status progression
6. Payload safety: zero transmission of raw biometric data, keys, or unsealed frames
7. Duplicate prevention across Telegram, FCM, and legacy Web Push channels
8. Admin-only test and diagnostic endpoints with role enforcement
"""
import base64
import time
import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

from src.pwa import api as backend
from src.pwa.security import password_hash
from src.pwa.alerts import (
    CRITICAL_BREACH_CODES,
    deliver,
    get_last_pushover_status,
    get_outbox_summary,
    get_pushover_config,
    get_pushover_diagnostic_status,
    send_pushover_alert,
    send_test_pushover,
)
from src.pwa.store import Store


@pytest.fixture
def client(tmp_path, monkeypatch):
    for key in ("VERCEL", "SUPABASE_URL", "SUPABASE_KEY", "SUPABASE_SERVICE_ROLE_KEY", "FACENET_MODEL_PATH", "CALLMEBOT_API_KEY", "CALLMEBOT_PHONE", "VAPID_PRIVATE_KEY"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", base64.b64encode(b"T" * 32).decode())
    monkeypatch.setenv("VAULT_OPERATOR_USERNAME", "test-operator")
    monkeypatch.setenv("VAULT_OPERATOR_PASSWORD_HASH", password_hash("test-only-password-strong"))
    monkeypatch.setenv("APP_ORIGIN", "https://testserver")
    monkeypatch.setattr(backend, "ROOT", tmp_path)
    return TestClient(backend.app, base_url="https://testserver", headers={"X-Vault-Request": "1", "Origin": "https://testserver"})


def signin(client):
    response = client.post("/api/auth/login", json={"username": "test-operator", "password": "test-only-password-strong"})
    assert response.status_code == 200, response.text
    return response


def test_pushover_config_reading_from_environment(monkeypatch):
    """Verifies credentials read exclusively from environment variables."""
    monkeypatch.delenv("PUSHOVER_APP_TOKEN", raising=False)
    monkeypatch.delenv("PUSHOVER_USER_KEY", raising=False)

    cfg = get_pushover_config()
    assert cfg["configured"] is False
    assert cfg["token"] == ""
    assert cfg["user"] == ""

    monkeypatch.setenv("PUSHOVER_APP_TOKEN", "a" * 30)
    monkeypatch.setenv("PUSHOVER_USER_KEY", "u" * 30)

    cfg_active = get_pushover_config()
    assert cfg_active["configured"] is True
    assert cfg_active["token"] == "a" * 30
    assert cfg_active["user"] == "u" * 30


@pytest.mark.parametrize("breach_code", ["ZT-001", "ZT-002", "ZT-008", "ZT-009", "ZT-013"])
def test_pushover_successful_critical_breach_dispatch(breach_code, tmp_path, monkeypatch):
    """Verifies that all 5 critical breach codes dispatch to Pushover with full metadata."""
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path / "data"))
    store = Store()
    monkeypatch.setenv("PUSHOVER_APP_TOKEN", "test_app_token_12345")
    monkeypatch.setenv("PUSHOVER_USER_KEY", "test_user_key_67890")
    monkeypatch.setenv("APP_ORIGIN", "https://vault.example.com")

    event_id = f"evt-breach-{breach_code.lower()}"
    job_key = f"job:{event_id}"
    job_data = {
        "id": event_id,
        "status": "QUEUED",
        "done": False,
        "attempts": 0,
        "reason_code": breach_code,
        "reason": f"Critical security breach: {breach_code}",
        "checkpoint": "CP-MAIN-01",
        "created_at": "2026-10-15T11:00:00Z",
    }
    store.put(job_key, job_data)

    captured_requests = []

    class MockPushoverResponse:
        status_code = 200
        content = b'{"status": 1, "request": "req-12345"}'

        def json(self):
            return {"status": 1, "request": "req-12345"}

    def mock_post(url, *args, **kwargs):
        captured_requests.append((url, kwargs))
        return MockPushoverResponse()

    monkeypatch.setattr("httpx.post", mock_post)

    deliver(job_key, job_data, 0)

    updated_job, _ = store.get(job_key)
    assert updated_job["done"] is True
    assert updated_job["status"] == "PUSHOVER_SENT"
    assert "pushover" in updated_job["delivered"]
    assert get_last_pushover_status(store) == "SENT"

    assert len(captured_requests) == 1
    url, kwargs = captured_requests[0]
    assert url == "https://api.pushover.net/1/messages.json"
    data = kwargs.get("data", {})
    assert data["token"] == "test_app_token_12345"
    assert data["user"] == "test_user_key_67890"
    assert breach_code in data["title"]
    assert breach_code in data["message"]
    assert "CP-MAIN-01" in data["message"]
    assert "2026-10-15T11:00:00Z" in data["message"]
    assert f"https://vault.example.com/audit?event={event_id}" in data["message"]
    assert data["url"] == f"https://vault.example.com/audit?event={event_id}"
    assert data["priority"] == 1
    assert data["sound"] == "siren"


@pytest.mark.parametrize("non_breach_code", ["STANDBY", "ZT-007", "GRANTED", "RESET"])
def test_pushover_non_breach_events_never_dispatch(non_breach_code, tmp_path, monkeypatch):
    """Verifies that non-breach codes (STANDBY, GRANTED, etc.) never send Pushover alerts."""
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path / "data"))
    store = Store()
    monkeypatch.setenv("PUSHOVER_APP_TOKEN", "test_app_token")
    monkeypatch.setenv("PUSHOVER_USER_KEY", "test_user_key")

    job_id = f"job-non-breach-{non_breach_code.lower()}"
    job_key = f"job:{job_id}"
    job_data = {
        "id": job_id,
        "status": "QUEUED",
        "done": False,
        "attempts": 0,
        "reason_code": non_breach_code,
        "reason": f"System state: {non_breach_code}",
        "checkpoint": "CP-MAIN-01",
    }
    store.put(job_key, job_data)

    mock_post = MagicMock()
    monkeypatch.setattr("httpx.post", mock_post)

    deliver(job_key, job_data, 0)

    updated_job, _ = store.get(job_key)
    assert updated_job["done"] is True
    assert updated_job["status"] == "SKIPPED_NOT_BREACH"
    assert not mock_post.called


def test_pushover_never_transmits_biometrics_or_keys(tmp_path, monkeypatch):
    """Verifies that Pushover payload never contains raw image bytes, embeddings, or keys."""
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path / "data"))
    store = Store()
    monkeypatch.setenv("PUSHOVER_APP_TOKEN", "test_app_token")
    monkeypatch.setenv("PUSHOVER_USER_KEY", "test_user_key")

    raw_frame_bytes = b"\xff\xd8\xff\xe0" + b"sensitive_unsealed_frame_pixels" * 10
    ev_path = "evidence/sensitive_frame.enc"
    store.save_blob(ev_path, raw_frame_bytes)

    job_key = "job:evt-payload-safety"
    job_data = {
        "id": "evt-payload-safety",
        "status": "QUEUED",
        "done": False,
        "attempts": 0,
        "reason_code": "ZT-001",
        "reason": "Unregistered identity detected",
        "checkpoint": "CP-MAIN-01",
        "evidence_path": ev_path,
        "evidence_hash": "a1b2c3d4e5f67890",
    }
    store.put(job_key, job_data)

    captured_requests = []

    def mock_post(url, *args, **kwargs):
        captured_requests.append(kwargs)
        res = MagicMock()
        res.status_code = 200
        res.content = b'{"status": 1}'
        res.json.return_value = {"status": 1}
        return res

    monkeypatch.setattr("httpx.post", mock_post)

    deliver(job_key, job_data, 0)

    assert len(captured_requests) == 1
    sent_data = captured_requests[0].get("data", {})

    for k, v in sent_data.items():
        assert raw_frame_bytes not in str(v).encode()
        assert "sensitive_unsealed_frame_pixels" not in str(v)
        assert "private_key" not in str(v).lower()


def test_pushover_duplicate_prevention_across_channels(tmp_path, monkeypatch):
    """Verifies that when Pushover is configured as primary, Telegram and Web Push do NOT fire,
    and multiple passes do not produce duplicate alerts.
    """
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path / "data"))
    store = Store()
    monkeypatch.setenv("PUSHOVER_APP_TOKEN", "test_po_token")
    monkeypatch.setenv("PUSHOVER_USER_KEY", "test_po_user")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "12345:telegram_token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    # Add active Web Push subscription
    sub_key = "push:test-sub"
    store.put(sub_key, {
        "subscription": {
            "endpoint": "https://fcm.googleapis.com/fcm/send/test-token",
            "keys": {"p256dh": "key1", "auth": "auth1"}
        },
        "active": True
    })

    job_id = "evt-dedup-check-001"
    job_key = f"job:{job_id}"
    job_data = {
        "id": job_id,
        "status": "QUEUED",
        "done": False,
        "attempts": 0,
        "reason_code": "ZT-001",
        "reason": "Intruder detected",
        "checkpoint": "CP-MAIN-01",
    }
    store.put(job_key, job_data)

    pushover_calls = []
    telegram_calls = []

    def mock_post(url, *args, **kwargs):
        if "pushover.net" in url:
            pushover_calls.append(kwargs)
            res = MagicMock()
            res.status_code = 200
            res.content = b'{"status": 1}'
            res.json.return_value = {"status": 1}
            return res
        elif "telegram.org" in url:
            telegram_calls.append(kwargs)
            res = MagicMock()
            res.status_code = 200
            res.content = b'{"ok": true}'
            res.json.return_value = {"ok": True}
            return res
        return MagicMock(status_code=404)

    webpush_mock = MagicMock()
    monkeypatch.setattr("httpx.post", mock_post)
    monkeypatch.setattr("pywebpush.webpush", webpush_mock)

    # First delivery pass
    deliver(job_key, job_data, 0)

    # Pushover must have executed exactly once
    assert len(pushover_calls) == 1
    # Telegram and Web Push must NOT have been called (no duplicate notifications)
    assert len(telegram_calls) == 0
    assert not webpush_mock.called

    # Second delivery pass with updated state
    updated_job, ver = store.get(job_key)
    assert updated_job["done"] is True
    assert "pushover" in updated_job["delivered"]

    deliver(job_key, updated_job, ver)

    # Ensure no second call was made to Pushover or other channels
    assert len(pushover_calls) == 1
    assert len(telegram_calls) == 0
    assert not webpush_mock.called


def test_pushover_failure_retry_progression_and_backoff(tmp_path, monkeypatch):
    """Verifies that Pushover errors increment attempts, set PUSHOVER_RETRYING, and calculate backoff."""
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path / "data"))
    store = Store()
    monkeypatch.setenv("PUSHOVER_APP_TOKEN", "test_po_token")
    monkeypatch.setenv("PUSHOVER_USER_KEY", "test_po_user")

    job_id = "evt-retry-001"
    job_key = f"job:{job_id}"
    job_data = {
        "id": job_id,
        "status": "QUEUED",
        "done": False,
        "attempts": 0,
        "reason_code": "ZT-002",
        "reason": "Biometric spoof detected",
        "checkpoint": "CP-MAIN-01",
    }
    store.put(job_key, job_data)

    def mock_post_fail(url, *args, **kwargs):
        res = MagicMock()
        res.status_code = 500
        res.content = b'{"status": 0, "errors": ["Internal Pushover Error"]}'
        res.json.return_value = {"status": 0, "errors": ["Internal Pushover Error"]}
        return res

    monkeypatch.setattr("httpx.post", mock_post_fail)

    t_before = time.time()
    deliver(job_key, job_data, 0)

    retry_job, _ = store.get(job_key)
    assert retry_job["done"] is False
    assert retry_job["status"] == "PUSHOVER_RETRYING"
    assert retry_job["attempts"] == 1
    assert retry_job["next_at"] >= t_before + 9  # 2^1 * 5 = 10s backoff
    assert get_last_pushover_status(store) == "FAILED"


def test_pushover_max_retries_exhaustion(tmp_path, monkeypatch):
    """Verifies that exceeding max retries transitions job to PUSHOVER_FAILED with done=True."""
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path / "data"))
    store = Store()
    monkeypatch.setenv("PUSHOVER_APP_TOKEN", "test_po_token")
    monkeypatch.setenv("PUSHOVER_USER_KEY", "test_po_user")

    job_id = "evt-fail-max"
    job_key = f"job:{job_id}"
    job_data = {
        "id": job_id,
        "status": "PUSHOVER_RETRYING",
        "done": False,
        "attempts": 2,  # Next attempt is 3 (max_retries = 3)
        "reason_code": "ZT-008",
        "reason": "Custody timeout expired",
        "checkpoint": "CP-MAIN-01",
    }
    store.put(job_key, job_data)

    def mock_post_fail(url, *args, **kwargs):
        res = MagicMock()
        res.status_code = 400
        res.content = b'{"status": 0, "errors": ["Invalid application token"]}'
        res.json.return_value = {"status": 0, "errors": ["Invalid application token"]}
        return res

    monkeypatch.setattr("httpx.post", mock_post_fail)

    deliver(job_key, job_data, 0)

    failed_job, _ = store.get(job_key)
    assert failed_job["done"] is True
    assert failed_job["status"] == "PUSHOVER_FAILED"
    assert failed_job["attempts"] == 3


def test_pushover_unconfigured_falls_back_to_legacy_channels(tmp_path, monkeypatch):
    """Verifies backward compatibility: if Pushover is unconfigured, Telegram delivers normally."""
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path / "data"))
    store = Store()
    monkeypatch.delenv("PUSHOVER_APP_TOKEN", raising=False)
    monkeypatch.delenv("PUSHOVER_USER_KEY", raising=False)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "12345:tg_token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    job_id = "evt-fallback-tg"
    job_key = f"job:{job_id}"
    job_data = {
        "id": job_id,
        "status": "QUEUED",
        "done": False,
        "attempts": 0,
        "reason_code": "ZT-001",
        "reason": "Intruder detected",
        "checkpoint": "CP-MAIN-01",
    }
    store.put(job_key, job_data)

    tg_calls = []

    def mock_post(url, *args, **kwargs):
        if "telegram.org" in url:
            tg_calls.append(kwargs)
            res = MagicMock()
            res.status_code = 200
            res.content = b'{"ok": true}'
            res.json.return_value = {"ok": True}
            return res
        return MagicMock(status_code=404)

    monkeypatch.setattr("httpx.post", mock_post)

    deliver(job_key, job_data, 0)

    updated_job, _ = store.get(job_key)
    assert updated_job["done"] is True
    assert updated_job["status"] == "TELEGRAM_SENT"
    assert "telegram" in updated_job["delivered"]
    assert len(tg_calls) == 1


def test_pushover_admin_endpoints(client, monkeypatch):
    """Verifies that /api/alerts/pushover/test and /api/alerts/pushover/status enforce admin auth and handle sends."""
    # 1. Unauthenticated requests are rejected
    res_no_auth = client.post("/api/alerts/pushover/test")
    assert res_no_auth.status_code in (401, 403)

    res_status_no_auth = client.get("/api/alerts/pushover/status")
    assert res_status_no_auth.status_code in (401, 403)

    # 2. Authenticate as admin
    signin(client)

    # 3. Test endpoint when unconfigured
    monkeypatch.delenv("PUSHOVER_APP_TOKEN", raising=False)
    monkeypatch.delenv("PUSHOVER_USER_KEY", raising=False)

    res_unconf = client.post("/api/alerts/pushover/test").json()
    assert res_unconf["ok"] is False
    assert res_unconf["sent"] is False
    assert "Set PUSHOVER_APP_TOKEN" in res_unconf["error"]

    status_unconf = client.get("/api/alerts/pushover/status").json()
    assert status_unconf["configured"] is False

    # 4. Test endpoint when configured and send succeeds
    monkeypatch.setenv("PUSHOVER_APP_TOKEN", "app_tok_1234567890abcdef")
    monkeypatch.setenv("PUSHOVER_USER_KEY", "usr_key_1234567890abcdef")

    def mock_httpx_post(url, *args, **kwargs):
        res = MagicMock()
        res.status_code = 200
        if "messages.json" in url:
            res.content = b'{"status": 1, "request": "req-test-99"}'
            res.json.return_value = {"status": 1, "request": "req-test-99"}
        elif "validate.json" in url:
            res.content = b'{"status": 1, "group": 0}'
            res.json.return_value = {"status": 1, "group": 0}
        return res

    monkeypatch.setattr("httpx.post", mock_httpx_post)

    res_conf = client.post("/api/alerts/pushover/test").json()
    assert res_conf["ok"] is True
    assert res_conf["sent"] is True
    assert "recipient" in res_conf

    status_conf = client.get("/api/alerts/pushover/status").json()
    assert status_conf["configured"] is True
    assert status_conf["token_valid"] is True
    assert status_conf["description"] == "CONNECTED"


def test_outbox_summary_aggregates_pushover_statuses(tmp_path, monkeypatch):
    """Verifies that get_outbox_summary counts PUSHOVER_SENT, PUSHOVER_RETRYING, and PUSHOVER_FAILED properly."""
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path / "data"))
    store = Store()
    store.put("job:test-summary-1", {"status": "PUSHOVER_SENT", "done": True})
    store.put("job:test-summary-2", {"status": "PUSHOVER_RETRYING", "done": False})
    store.put("job:test-summary-3", {"status": "PUSHOVER_FAILED", "done": True})

    summary = get_outbox_summary(store)
    assert summary["SENT"] >= 1
    assert summary["RETRYING"] >= 1
    assert summary["FAILED"] >= 1
