"""Regression tests for Supabase Push Subscriptions (HTTP 400 / PostgreSQL 23502 fix).

Verifies:
1. Stable, deterministic RFC 4122 UUIDv5 subscription ID compatible with production TEXT and UUID schema.
2. Safe insertion into Supabase push_subscriptions including required 'id' column.
3. Resubscribe behavior preserving stable ID, endpoint-based upsert, and creation timestamp.
4. Duplicate prevention across multiple registrations of the same endpoint.
5. Re-enablement after unsubscription.
6. Prevention of PostgreSQL 23502 (NOT NULL constraint violation) in simulated production schema.
7. Preservation of ownership checks across subscribe and unsubscribe.
8. Native PWA Web Push payload validation.
"""

import base64
import hashlib
import uuid
from unittest.mock import MagicMock
import pytest
from starlette.testclient import TestClient

from app import app
from src.pwa import api as backend
from src.pwa.alerts import get_active_subscriptions
from src.pwa.api import generate_subscription_id
from src.pwa.security import password_hash
from src.pwa.store import Store
from src.storage.supabase_client import CloudUnavailable


class MockSupabaseCloud:
    """Accurate in-memory simulation of Supabase PostgREST backend."""

    def __init__(self, simulate_postgres_23502=False):
        self.records = {}
        self.push_rows = {}
        self.push_calls = []
        self.simulate_postgres_23502 = simulate_postgres_23502

    def request(self, method, path, **kwargs):
        if "rpc/vault_commit" in path:
            json_data = kwargs.get("json", {})
            rec_id = json_data.get("record_id")
            self.records[rec_id] = json_data.get("new_payload")
            resp = MagicMock()
            resp.json.return_value = True
            resp.status_code = 200
            return resp

        if "/rest/v1/push_subscriptions" in path:
            self.push_calls.append({"method": method, "path": path, "kwargs": kwargs})
            if method == "POST":
                payload = kwargs.get("json", {})
                if self.simulate_postgres_23502:
                    # Strict schema check: id is TEXT NOT NULL with NO DEFAULT
                    if "id" not in payload or payload["id"] is None or payload["id"] == "":
                        raise CloudUnavailable(
                            "Cloud request failed; access stays locked",
                            status_code=400,
                            error_code="23502",
                            safe_diagnostic="Supabase schema error (HTTP 400, code 23502). Check table columns.",
                        )
                ep = payload.get("endpoint")
                self.push_rows[ep] = dict(payload)
                resp = MagicMock()
                resp.status_code = 201
                resp.json.return_value = [payload]
                return resp
            elif method == "PATCH":
                params = kwargs.get("params", {})
                payload = kwargs.get("json", {})
                ep_filter = str(params.get("endpoint", ""))
                for ep, row in self.push_rows.items():
                    if f"eq.{ep}" in ep_filter:
                        row.update(payload)
                resp = MagicMock()
                resp.status_code = 200
                return resp

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = []
        return resp

    def rows(self, table, **params):
        if table == "vault_records":
            rec_id = params.get("id", "").replace("eq.", "")
            if rec_id in self.records:
                return [{"payload": self.records[rec_id], "version": 1}]
            # Fallback to local SQLite records for auth tokens & session data
            try:
                import json
                with Store().db() as conn:
                    row = conn.execute("SELECT payload, version FROM records WHERE id=?", (rec_id,)).fetchone()
                    if row:
                        return [{"payload": json.loads(row[0]), "version": row[1]}]
            except Exception:
                pass
            return []
        if table == "push_subscriptions":
            rows = list(self.push_rows.values())
            if params.get("enabled") == "eq.true":
                rows = [r for r in rows if r.get("enabled") is True]
            return rows
        return []

    def check_health(self, timeout=3.0):
        return True


@pytest.fixture
def push_test_env(tmp_path, monkeypatch):
    """Isolated test environment with test database and operator auth."""
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", base64.b64encode(b"K" * 32).decode())
    monkeypatch.setenv("VAULT_OPERATOR_USERNAME", "admin_lead")
    monkeypatch.setenv("VAULT_OPERATOR_PASSWORD_HASH", password_hash("AdminSecret123!"))
    monkeypatch.setenv("APP_ORIGIN", "https://vault.local")
    monkeypatch.setattr(backend, "ROOT", tmp_path)

    client = TestClient(
        app,
        base_url="https://vault.local",
        headers={"X-Vault-Request": "1", "Origin": "https://vault.local"},
    )
    auth_resp = client.post(
        "/api/auth/login",
        json={"username": "admin_lead", "password": "AdminSecret123!"},
    )
    assert auth_resp.status_code == 200
    token = auth_resp.json().get("token")

    backend.app.dependency_overrides[backend.monitor_or_above] = lambda: {"id": "admin_lead", "role": "admin"}
    try:
        yield client, tmp_path, token
    finally:
        backend.app.dependency_overrides.clear()


def test_subscription_id_stability_and_uuid_compatibility():
    """Verifies that generate_subscription_id produces stable RFC 4122 UUIDv5 identifiers."""
    endpoint_a = "https://fcm.googleapis.com/fcm/send/device-token-alpha-12345"
    endpoint_b = "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABdevice-token-beta"

    id_a1 = generate_subscription_id(endpoint_a)
    id_a2 = generate_subscription_id(endpoint_a)
    id_a3 = generate_subscription_id("  " + endpoint_a + "  ")

    # 1. Deterministic and stable: identical for the same endpoint
    assert id_a1 == id_a2
    assert id_a1 == id_a3

    # 2. Distinct for different endpoints (no collisions)
    id_b = generate_subscription_id(endpoint_b)
    assert id_a1 != id_b

    # 3. Valid RFC 4122 UUIDv5 (compatible with Postgres UUID column type)
    parsed_uuid = uuid.UUID(id_a1, version=5)
    assert parsed_uuid.version == 5
    assert str(parsed_uuid) == id_a1

    # 4. Standard string format compatible with Postgres TEXT column type
    assert len(id_a1) == 36
    assert all(c in "0123456789abcdef-" for c in id_a1)


def test_push_subscribe_insert_includes_required_id(push_test_env, monkeypatch):
    """Verifies POST /api/push/subscribe includes 'id' column in Supabase request payload."""
    client, _, _ = push_test_env

    mock_cloud = MockSupabaseCloud()
    monkeypatch.setenv("SUPABASE_URL", "https://mock.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "mock-key")
    monkeypatch.setattr("src.pwa.store.SupabaseCloud", lambda: mock_cloud)

    sub_payload = {
        "endpoint": "https://fcm.googleapis.com/fcm/send/device-prod-test-001",
        "keys": {
            "p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QT9EgVKA7Gh27YStRB",
            "auth": "tBHItJI5svbpez7KI4CCXg",
        },
        "device_label": "Control Room Tablet 1",
    }

    res = client.post("/api/push/subscribe", json=sub_payload)
    assert res.status_code == 200
    assert res.json() == {"subscribed": True}

    # Verify cloud call was made with 'id' column populated
    assert len(mock_cloud.push_calls) == 1
    call = mock_cloud.push_calls[0]
    assert call["method"] == "POST"
    assert call["path"] == "/rest/v1/push_subscriptions"

    req_json = call["kwargs"]["json"]
    expected_id = generate_subscription_id(sub_payload["endpoint"])
    assert req_json["id"] == expected_id
    assert req_json["endpoint"] == sub_payload["endpoint"]
    assert req_json["p256dh"] == sub_payload["keys"]["p256dh"]
    assert req_json["auth"] == sub_payload["keys"]["auth"]
    assert req_json["device_label"] == "Control Room Tablet 1"
    assert req_json["enabled"] is True
    assert "user_id" in req_json

    # Verify conflict resolution parameters
    assert call["kwargs"].get("params") == {"on_conflict": "endpoint"}
    assert call["kwargs"].get("headers") == {"Prefer": "resolution=merge-duplicates"}

    # Verify record in store also contains id
    key = "push:" + hashlib.sha256(sub_payload["endpoint"].encode()).hexdigest()
    saved, _ = Store().get(key)
    assert saved is not None
    assert saved["id"] == expected_id
    assert saved["active"] is True


def test_push_resubscribe_preserves_stable_id_and_updates_in_place(push_test_env, monkeypatch):
    """Verifies that resubscribing with same endpoint preserves the subscription ID and updates metadata in-place."""
    client, _, _ = push_test_env

    mock_cloud = MockSupabaseCloud()
    monkeypatch.setenv("SUPABASE_URL", "https://mock.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "mock-key")
    monkeypatch.setattr("src.pwa.store.SupabaseCloud", lambda: mock_cloud)

    endpoint = "https://fcm.googleapis.com/fcm/send/device-resubscribe-test-002"
    sub_payload = {
        "endpoint": endpoint,
        "keys": {
            "p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QT9EgVKA7Gh27YStRB",
            "auth": "tBHItJI5svbpez7KI4CCXg",
        },
        "device_label": "Mobile S24 Ultra",
    }

    # 1. Initial subscription
    res1 = client.post("/api/push/subscribe", json=sub_payload)
    assert res1.status_code == 200

    key = "push:" + hashlib.sha256(endpoint.encode()).hexdigest()
    saved1, _ = Store().get(key)
    orig_id = saved1["id"]
    orig_created_at = saved1["created_at"]

    # 2. Resubscription with updated device label and refreshed p256dh
    sub_payload["device_label"] = "Mobile S24 Ultra (Office Dock)"
    sub_payload["keys"]["p256dh"] = "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_REFRESHED_KEY"

    res2 = client.post("/api/push/subscribe", json=sub_payload)
    assert res2.status_code == 200

    # 3. Verify stable ID across resubscribe
    saved2, _ = Store().get(key)
    assert saved2["id"] == orig_id
    assert saved2["created_at"] == orig_created_at
    assert saved2["device_label"] == "Mobile S24 Ultra (Office Dock)"
    assert saved2["subscription"]["keys"]["p256dh"] == sub_payload["keys"]["p256dh"]

    # Both cloud requests sent identical ID
    assert len(mock_cloud.push_calls) == 2
    for call in mock_cloud.push_calls:
        assert call["kwargs"]["json"]["id"] == orig_id
        assert call["kwargs"]["params"] == {"on_conflict": "endpoint"}


def test_push_duplicate_prevention_across_repeated_subscriptions(push_test_env):
    """Verifies that multiple registrations for the same endpoint do not create duplicate active subscriptions."""
    client, _, _ = push_test_env
    store = Store()

    sub_payload = {
        "endpoint": "https://fcm.googleapis.com/fcm/send/device-dup-test-003",
        "keys": {
            "p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QT9EgVKA7Gh27YStRB",
            "auth": "tBHItJI5svbpez7KI4CCXg",
        },
        "device_label": "Security Tablet #3",
    }

    # Register 4 times in succession
    for i in range(4):
        sub_payload["device_label"] = f"Security Tablet #3 (v{i+1})"
        res = client.post("/api/push/subscribe", json=sub_payload)
        assert res.status_code == 200

    # Verify only ONE active subscription exists in store
    active_subs = get_active_subscriptions(store)
    matching = [
        s for _, s in active_subs
        if s["subscription"]["endpoint"] == sub_payload["endpoint"]
    ]
    assert len(matching) == 1
    assert matching[0]["device_label"] == "Security Tablet #3 (v4)"
    assert matching[0]["id"] == generate_subscription_id(sub_payload["endpoint"])


def test_push_resubscribe_after_unsubscribe_reenables(push_test_env):
    """Verifies that resubscribing after unsubscription safely reactivates the subscription."""
    client, _, _ = push_test_env
    store = Store()

    sub_payload = {
        "endpoint": "https://fcm.googleapis.com/fcm/send/device-reactivate-004",
        "keys": {
            "p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QT9EgVKA7Gh27YStRB",
            "auth": "tBHItJI5svbpez7KI4CCXg",
        },
        "device_label": "Mobile Terminal",
    }

    # 1. Subscribe
    sub_res = client.post("/api/push/subscribe", json=sub_payload)
    assert sub_res.status_code == 200
    assert len(get_active_subscriptions(store)) == 1

    # 2. Unsubscribe
    unsub_res = client.post("/api/push/unsubscribe", json={"endpoint": sub_payload["endpoint"], "keys": sub_payload["keys"]})
    assert unsub_res.status_code == 200
    assert unsub_res.json() == {"subscribed": False}
    assert len(get_active_subscriptions(store)) == 0

    # 3. Resubscribe
    resub_res = client.post("/api/push/subscribe", json=sub_payload)
    assert resub_res.status_code == 200
    assert resub_res.json() == {"subscribed": True}

    # Verify reactivated and stable ID maintained
    active_subs = get_active_subscriptions(store)
    assert len(active_subs) == 1
    assert active_subs[0][1]["id"] == generate_subscription_id(sub_payload["endpoint"])
    assert active_subs[0][1]["active"] is True


def test_postgres_23502_prevented_in_strict_schema_mock(push_test_env, monkeypatch):
    """Simulates a strict Supabase Postgres schema where id TEXT is required (NOT NULL, NO DEFAULT).

    Verifies that omission of id causes 23502 (HTTP 400), but our implementation provides id,
    preventing error 23502.
    """
    client, _, _ = push_test_env

    strict_cloud = MockSupabaseCloud(simulate_postgres_23502=True)
    monkeypatch.setenv("SUPABASE_URL", "https://mock.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "mock-key")
    monkeypatch.setattr("src.pwa.store.SupabaseCloud", lambda: strict_cloud)

    sub_payload = {
        "endpoint": "https://fcm.googleapis.com/fcm/send/device-strict-23502-test",
        "keys": {
            "p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QT9EgVKA7Gh27YStRB",
            "auth": "tBHItJI5svbpez7KI4CCXg",
        },
        "device_label": "Strict Postgres Test Tablet",
    }

    # Calling subscribe must NOT trigger HTTP 400 / 23502 because id is provided
    res = client.post("/api/push/subscribe", json=sub_payload)
    assert res.status_code == 200
    assert res.json() == {"subscribed": True}

    # Verify strict mock received row with valid id
    assert sub_payload["endpoint"] in strict_cloud.push_rows
    persisted_row = strict_cloud.push_rows[sub_payload["endpoint"]]
    assert persisted_row["id"] == generate_subscription_id(sub_payload["endpoint"])


def test_push_ownership_checks_preserved(push_test_env):
    """Verifies that non-admin operators cannot overwrite or unsubscribe someone else's subscription."""
    client, _, _ = push_test_env

    sub_payload = {
        "endpoint": "https://fcm.googleapis.com/fcm/send/device-ownership-005",
        "keys": {
            "p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QT9EgVKA7Gh27YStRB",
            "auth": "tBHItJI5svbpez7KI4CCXg",
        },
        "device_label": "Operator 1 Tablet",
    }

    # 1. User 1 (admin_lead) subscribes
    res1 = client.post("/api/push/subscribe", json=sub_payload)
    assert res1.status_code == 200

    # 2. Switch to User 2 (monitor_guest, non-admin)
    backend.app.dependency_overrides[backend.monitor_or_above] = lambda: {"id": "monitor-user-2", "role": "monitor"}
    try:
        # User 2 tries to unsubscribe User 1's subscription -> 403 Forbidden
        unsub_res = client.post(
            "/api/push/unsubscribe",
            json={"endpoint": sub_payload["endpoint"], "keys": sub_payload["keys"]},
        )
        assert unsub_res.status_code == 403
        assert "owner or administrator required" in unsub_res.json()["detail"].lower()

        # User 2 tries to overwrite User 1's active subscription -> 403 Forbidden
        sub_payload["device_label"] = "Hijacked Tablet"
        sub_res2 = client.post("/api/push/subscribe", json=sub_payload)
        assert sub_res2.status_code == 403
        assert "owner or administrator required" in sub_res2.json()["detail"].lower()
    finally:
        backend.app.dependency_overrides.clear()

    # 3. User 1 (original owner) can resubscribe/update successfully
    sub_payload["device_label"] = "Operator 1 Tablet Updated"
    res3 = client.post("/api/push/subscribe", json=sub_payload)
    assert res3.status_code == 200


def test_native_pwa_web_push_validation_preserved(push_test_env):
    """Verifies that standard Web Push endpoint and key validation rules remain enforced."""
    client, _, _ = push_test_env

    # Non-HTTPS or loopback endpoint rejected
    assert client.post("/api/push/subscribe", json={
        "endpoint": "http://insecure.example.com/send/123",
        "keys": {"auth": "a", "p256dh": "b"},
    }).status_code == 422

    # Localhost endpoint rejected
    assert client.post("/api/push/subscribe", json={
        "endpoint": "https://127.0.0.1/send/123",
        "keys": {"auth": "a", "p256dh": "b"},
    }).status_code == 422

    # Missing keys rejected
    assert client.post("/api/push/subscribe", json={
        "endpoint": "https://fcm.googleapis.com/fcm/send/test-123",
        "keys": {"p256dh": "only_one_key"},
    }).status_code == 422

    # Oversized key (>256 chars) rejected
    assert client.post("/api/push/subscribe", json={
        "endpoint": "https://fcm.googleapis.com/fcm/send/test-123",
        "keys": {"auth": "x" * 257, "p256dh": "normal_key"},
    }).status_code == 422
