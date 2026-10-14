import base64
import hashlib
import json
import os
import time
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from app import app
from src.pwa.alerts import (
    deliver,
    ensure_vapid_keys,
    get_active_subscriptions,
    get_outbox_summary,
    valid_push_endpoint,
)
from src.pwa.policy import fresh
from src.pwa.security import password_hash
from src.pwa.store import Store
from src.pwa import api as backend


@pytest.fixture
def p3_env(tmp_path, monkeypatch):
    for key in (
        "VERCEL", "SUPABASE_URL", "SUPABASE_KEY", "SUPABASE_SERVICE_ROLE_KEY",
        "FACENET_MODEL_PATH", "CALLMEBOT_API_KEY", "CALLMEBOT_PHONE",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", base64.b64encode(b"P" * 32).decode())
    monkeypatch.setenv("VAULT_OPERATOR_USERNAME", "admin_lead")
    monkeypatch.setenv("VAULT_OPERATOR_PASSWORD_HASH", password_hash("AdminPass123!"))
    monkeypatch.setenv("APP_ORIGIN", "https://vault.local")
    monkeypatch.setattr(backend, "ROOT", tmp_path)

    client = TestClient(app, base_url="https://vault.local", headers={"X-Vault-Request": "1", "Origin": "https://vault.local"})
    auth_resp = client.post("/api/auth/login", json={"username": "admin_lead", "password": "AdminPass123!"})
    assert auth_resp.status_code == 200
    token = auth_resp.json().get("token")
    return client, tmp_path, token


def test_standardized_push_subscription_lifecycle(p3_env):
    """Verifies VAPID public key, genuine Web Push subscription storage, deduplication, and deactivation."""
    client, _, _ = p3_env

    # 1. Fetch VAPID public key
    key_res = client.get("/api/push/public-key")
    assert key_res.status_code == 200
    pub_key = key_res.json().get("public_key")
    assert pub_key and len(pub_key) > 20

    # 2. Genuine Web Push subscription payload
    sub_payload = {
        "endpoint": "https://fcm.googleapis.com/fcm/send/device-unique-token-xyz-987",
        "keys": {
            "p256dh": "BEl2RmluZGluZy1hdXRoZW50aWNhdGVkLXB1c2gta2V5LXRlc3QtZXhhbXBsZQ",
            "auth": "YXV0aC1zZWNyZXQta2V5LTE2Yg",
        },
        "device_label": "Pixel 8 Pro Mobile PWA",
    }
    sub_res = client.post("/api/push/subscribe", json=sub_payload)
    assert sub_res.status_code == 200
    assert sub_res.json()["subscribed"] is True

    # Check that active subscriptions returns exactly 1 genuine subscription
    store = Store()
    active_subs = get_active_subscriptions(store)
    assert len(active_subs) == 1
    sub_key, sub_val = active_subs[0]
    assert sub_val["device_label"] == "Pixel 8 Pro Mobile PWA"
    assert sub_val["subscription"]["endpoint"] == sub_payload["endpoint"]

    # 3. Deduplication: Registering same endpoint with updated device_label updates in-place
    sub_payload["device_label"] = "Pixel 8 Pro (Re-enrolled)"
    client.post("/api/push/subscribe", json=sub_payload)
    active_subs2 = get_active_subscriptions(store)
    assert len(active_subs2) == 1
    assert active_subs2[0][1]["device_label"] == "Pixel 8 Pro (Re-enrolled)"

    # 4. Unsubscribe marks inactive
    unsub_res = client.post("/api/push/unsubscribe", json={"endpoint": sub_payload["endpoint"], "keys": sub_payload["keys"]})
    assert unsub_res.status_code == 200
    assert unsub_res.json()["subscribed"] is False
    assert len(get_active_subscriptions(store)) == 0


def test_fcm_registration_does_not_pollute_push_subscriptions(p3_env):
    """Verifies FCM token registration does NOT inject corrupted entries into push_subscriptions."""
    client, _, _ = p3_env
    store = Store()

    # Register raw FCM token
    fcm_payload = {
        "fcm_token": "fcm_raw_device_registration_token_abc_123_456_789",
        "device_label": "Samsung Galaxy S24 Ultra",
    }
    fcm_res = client.post("/api/fcm/register", json=fcm_payload)
    assert fcm_res.status_code == 200
    assert fcm_res.json()["registered"] is True
    assert fcm_res.json()["provider"] == "FCM"

    # Confirms FCM token is saved under fcm:
    fcm_records = list(store.records("fcm:"))
    assert len(fcm_records) == 1
    assert fcm_records[0][1]["fcm_token"] == fcm_payload["fcm_token"]

    # CRITICAL: Confirms get_active_subscriptions() contains NO dummy fcm_token subscriptions!
    active_subs = get_active_subscriptions(store)
    for _, sub_data in active_subs:
        keys = sub_data.get("subscription", {}).get("keys", {})
        assert keys.get("p256dh") != "fcm_token", "Push subscriptions must never contain raw FCM tokens"
        assert keys.get("auth") != "fcm_token"


def test_breach_creates_single_logical_notification_job(p3_env, monkeypatch):
    """Verifies that a confirmed breach generates exactly one outbox job with QUEUED status."""
    client, _, _ = p3_env
    store = Store()

    # Clear existing jobs
    for k, _, _ in store.records("job:"):
        store.put(k, {"done": True, "status": "CLEARED"})

    # Trigger terminal breach via transition()
    unknown_face = {
        "id": "unknown-intruder",
        "name": "Unknown Person",
        "role": "Unauthorized",
        "is_recognized": False,
        "is_live": True,
        "confidence": 0.1,
        "recognition_state": "UNKNOWN",
        "liveness": "PASS",
        "bbox": [20, 20, 100, 100],
    }
    res, terminal = backend.transition([unknown_face])
    assert res["state"] == "BREACH"
    assert terminal is True
    event_id = res.get("last_event")
    assert event_id is not None

    # Verify exactly one active alert job was committed
    active_jobs = [v for k, v, _ in store.records("job:") if not v.get("done") and v.get("status") in ("QUEUED", "PENDING")]
    assert len(active_jobs) == 1
    job = active_jobs[0]
    assert job["id"] == event_id
    assert job["reason_code"] == "ZT-001"
    assert job["status"] in ("QUEUED", "PENDING")


def test_notification_delivery_tracking_and_status_progression(p3_env, monkeypatch):
    """Verifies delivery status tracking progression: QUEUED -> SENT / RETRYING -> FAILED."""
    client, _, _ = p3_env
    store = Store()

    # Set up genuine push subscription
    sub_payload = {
        "endpoint": "https://fcm.googleapis.com/fcm/send/tracking-device-token",
        "keys": {
            "p256dh": "BEl2RmluZGluZy1hdXRoZW50aWNhdGVkLXB1c2gta2V5LXRlc3QtZXhhbXBsZQ",
            "auth": "YXV0aC1zZWNyZXQta2V5LTE2Yg",
        },
        "device_label": "Security Dispatch Tablet",
    }
    client.post("/api/push/subscribe", json=sub_payload)

    # 1. Create a test job in QUEUED status
    job_id = "job-track-001"
    job_key = f"job:{job_id}"
    job_data = {
        "id": job_id,
        "status": "QUEUED",
        "done": False,
        "attempts": 0,
        "reason_code": "ZT-001",
        "reason": "Unauthorized access attempt",
        "checkpoint": "CP-MAIN-01",
    }
    store.put(job_key, job_data)

    # Mock webpush to simulate successful provider acceptance (201 Created)
    webpush_mock = MagicMock()
    monkeypatch.setattr("pywebpush.webpush", webpush_mock)

    deliver(job_key, job_data, 0)

    updated_job, _ = store.get(job_key)
    assert updated_job["done"] is True
    assert updated_job["status"] == "SENT"
    assert webpush_mock.called

    # 2. Test retry progression on transient failure
    job_fail_id = "job-track-002"
    job_fail_key = f"job:{job_fail_id}"
    job_fail_data = {
        "id": job_fail_id,
        "status": "QUEUED",
        "done": False,
        "attempts": 0,
        "reason_code": "ZT-002",
        "reason": "Biometric spoof detected",
        "checkpoint": "CP-MAIN-01",
    }
    store.put(job_fail_key, job_fail_data)

    from pywebpush import WebPushException
    mock_err_resp = MagicMock()
    mock_err_resp.status_code = 503
    webpush_fail = MagicMock(side_effect=WebPushException("503 Gateway Timeout", response=mock_err_resp))
    monkeypatch.setattr("pywebpush.webpush", webpush_fail)

    deliver(job_fail_key, job_fail_data, 0)
    retry_job, _ = store.get(job_fail_key)
    assert retry_job["done"] is False
    assert retry_job["status"] in ("RETRY", "RETRYING")
    assert retry_job["attempts"] == 1

    # Simulate 3rd failure (max retries reached)
    retry_job, cur_ver = store.get(job_fail_key)
    retry_job["attempts"] = 2
    retry_job["lease_until"] = 0
    retry_job["next_at"] = 0
    deliver(job_fail_key, retry_job, cur_ver)
    failed_job, _ = store.get(job_fail_key)
    assert failed_job["done"] is True
    assert failed_job["status"] == "FAILED"

    # 3. Check outbox summary aggregation
    summary = get_outbox_summary(store)
    assert summary["SENT"] >= 1
    assert summary["FAILED"] >= 1


def test_device_push_receipt_confirmation(p3_env):
    """Verifies that the device receipt endpoint distinguishes push-service acceptance from actual receipt on phone."""
    client, _, _ = p3_env
    store = Store()

    event_id = "evt-receipt-test-123"
    job_key = f"job:{event_id}"
    job_data = {
        "id": event_id,
        "status": "SENT",
        "done": True,
        "device_received": False,
    }
    store.put(job_key, job_data)

    # Phone receives push and acknowledges receipt
    receipt_res = client.post("/api/push/receipt", json={
        "event_id": event_id,
        "device_label": "Officer Alice Phone",
    })
    assert receipt_res.status_code == 200
    assert receipt_res.json()["status"] == "CONFIRMED"

    saved_job, _ = store.get(job_key)
    assert saved_job["device_received"] is True
    assert "device_received_at" in saved_job
    assert saved_job["device_label"] == "Officer Alice Phone"


def test_lightweight_liveness_and_readiness_checks(p3_env):
    """Verifies separated liveness (/api/health) and readiness (/api/health/ready) checks."""
    client, _, _ = p3_env

    # 1. Liveness check: instant, lightweight
    health_res = client.get("/api/health")
    assert health_res.status_code == 200
    health_data = health_res.json()
    assert health_data["status"] == "healthy"
    assert health_data["service"] == "VERITAS"
    assert "commit" in health_data
    assert "timestamp" in health_data

    # 2. Readiness check: verifies database, biometrics, notifications
    ready_res = client.get("/api/health/ready")
    assert ready_res.status_code == 200
    ready_data = ready_res.json()
    assert ready_data["status"] == "ready"
    assert ready_data["database"]["connected"] is True
    assert ready_data["database"]["status"] == "HEALTHY"
    assert ready_data["biometrics"]["ready"] is True
    assert "notifications" in ready_data

    # Readiness alias check
    alias_res = client.get("/api/ready")
    assert alias_res.status_code == 200
    assert alias_res.json()["status"] == "ready"


def test_service_worker_headers_and_handlers(p3_env):
    """Verifies that sw.js is served with proper headers, scope, and notificationclick handling."""
    client, _, _ = p3_env

    sw_res = client.get("/sw.js")
    assert sw_res.status_code == 200
    assert sw_res.headers.get("Service-Worker-Allowed") == "/"
    assert "no-cache" in sw_res.headers.get("Cache-Control", "")

    sw_content = sw_res.text
    # Verifies cache version
    assert "veritas-shell-v4.2.0" in sw_content
    # Verifies push event handles event_id and posts receipt
    assert "self.addEventListener(\"push\"" in sw_content
    assert "/api/push/receipt" in sw_content
    # Verifies notificationclick focuses and opens exact audit event
    assert "self.addEventListener(\"notificationclick\"" in sw_content
    assert "/audit?event=" in sw_content


def test_monitor_session_persistence_via_bearer_token(p3_env, monkeypatch):
    """Verifies monitor session persistence via Authorization: Bearer token without cookies."""
    client, _, _ = p3_env
    store = Store()

    # Create monitor user
    monitor_user = {
        "id": "mon-001",
        "username": "patrol_monitor",
        "role": "monitor",
        "password_hash": password_hash("MonitorPass999!"),
        "status": "APPROVED",
    }
    store.put("user:patrol_monitor", monitor_user)

    # Monitor signs in
    login_res = client.post("/api/auth/login", json={"username": "patrol_monitor", "password": "MonitorPass999!"})
    assert login_res.status_code == 200
    session_token = login_res.json().get("token")
    assert session_token is not None

    # Create a fresh client simulating standalone PWA reopening without cookies
    no_cookie_client = TestClient(
        app,
        base_url="https://vault.local",
        headers={
            "X-Vault-Request": "1",
            "Origin": "https://vault.local",
            "Authorization": f"Bearer {session_token}",
        },
    )

    me_res = no_cookie_client.get("/api/auth/me")
    assert me_res.status_code == 200
    assert me_res.json()["role"] == "monitor"

    logs_res = no_cookie_client.get("/api/logs")
    assert logs_res.status_code == 200


def test_control_room_delivery_summary_endpoint(p3_env):
    """Verifies that Control Room endpoints expose outbox delivery pipeline metrics."""
    client, _, _ = p3_env

    # Admin requests control status
    ctrl_res = client.get("/api/control")
    assert ctrl_res.status_code == 200
    ctrl_data = ctrl_res.json()
    assert "delivery_summary" in ctrl_data
    summary = ctrl_data["delivery_summary"]
    for key in ("QUEUED", "SENT", "RETRYING", "FAILED", "DEVICE_CONFIRMED", "total"):
        assert key in summary

    # Monitor requests alerts status
    alerts_res = client.get("/api/alerts/status")
    assert alerts_res.status_code == 200
    alerts_data = alerts_res.json()
    assert "delivery_summary" in alerts_data
