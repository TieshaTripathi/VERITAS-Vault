import base64
import os
import pytest
from starlette.testclient import TestClient
from src.pwa import api as backend
from src.pwa.store import Store

@pytest.fixture
def monitor_client(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_OPERATOR_USERNAME", "admin")
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", base64.b64encode(b"K" * 32).decode())
    monkeypatch.setenv("APP_ORIGIN", "https://veritas-vault14.web.app")
    monkeypatch.setattr(backend, "ROOT", tmp_path)
    return TestClient(backend.app, base_url="https://veritas-vault14.web.app", headers={"X-Vault-Request": "1", "Origin": "https://veritas-vault14.web.app"})

def test_monitor_role_read_only_and_bearer_auth(monitor_client, monkeypatch):
    # 1. Production fallback monitor account is removed/disabled and rejected
    fallback_res = monitor_client.post("/api/auth/login", json={"username": "monitor", "password": "monitor"})
    assert fallback_res.status_code == 401

    # 2. Authenticate Supabase user with vault_role = "monitor"
    _db = {}
    class MockSupabaseCloud:
        def request(self, method, path, **kwargs):
            if "rpc/vault_commit" in path:
                json_data = kwargs.get("json", {})
                _db[json_data.get("record_id")] = json_data.get("new_payload")
                class RpcResp:
                    def json(self):
                        return True
                return RpcResp()
            class MockResp:
                def json(self):
                    return {
                        "user": {
                            "id": "supabase-monitor-uuid-1234",
                            "app_metadata": {"vault_role": "monitor"},
                        },
                        "access_token": "mock-supabase-jwt-token",
                        "expires_in": 3600,
                    }
            return MockResp()

        def rows(self, table, **params):
            id_val = params.get("id", "").replace("eq.", "")
            if id_val in _db:
                return [{"payload": _db[id_val], "version": 1}]
            return []

        def cas(self, key, ver, payload, *args, **kwargs):
            _db[key] = payload
            return True

        def put(self, key, payload):
            _db[key] = payload

    test_store = Store()
    test_store.cloud = MockSupabaseCloud()
    monkeypatch.setattr(backend, "Store", lambda: test_store)

    login_res = monitor_client.post("/api/auth/login", json={"username": "monitor@example.com", "password": "secure-monitor-pass"})
    assert login_res.status_code == 200, login_res.text
    login_data = login_res.json()
    assert login_data["role"] == "monitor"
    assert "token" in login_data
    token = login_data["token"]

    # 2. Test Bearer token header without relying on cookies
    no_cookie_client = TestClient(
        backend.app,
        base_url="https://veritas-vault14.web.app",
        headers={
            "X-Vault-Request": "1",
            "Origin": "https://veritas-vault14.web.app",
            "Authorization": f"Bearer {token}",
        },
        cookies={},
    )

    # 3. Verify monitor can read status, me, logs
    me_res = no_cookie_client.get("/api/auth/me")
    assert me_res.status_code == 200
    assert me_res.json()["role"] == "monitor"

    status_res = no_cookie_client.get("/api/checkpoint/status")
    assert status_res.status_code == 200
    assert "state" in status_res.json()

    logs_res = no_cookie_client.get("/api/logs")
    assert logs_res.status_code == 200

    # 4. Verify monitor can register for Push and FCM alerts
    push_key_res = no_cookie_client.get("/api/push/public-key")
    assert push_key_res.status_code == 200

    fcm_res = no_cookie_client.post("/api/fcm/register", json={
        "fcm_token": "fcm_test_token_mobile_monitor_device_12345",
        "device_label": "iPhone 15 Mobile PWA"
    })
    assert fcm_res.status_code == 200
    assert fcm_res.json()["registered"] is True
    assert fcm_res.json()["provider"] == "FCM"

    # Repeated registration (simulating PWA restart on same device) is idempotent
    fcm_restart_res = no_cookie_client.post("/api/fcm/register", json={
        "fcm_token": "fcm_test_token_mobile_monitor_device_12345",
        "device_label": "iPhone 15 Mobile PWA"
    })
    assert fcm_restart_res.status_code == 200
    assert fcm_restart_res.json()["registered"] is True

    # 5. Verify monitor CANNOT modify system state (403 Forbidden)
    reset_chk_res = no_cookie_client.post("/api/checkpoint/reset", json={"mode": "standard"})
    assert reset_chk_res.status_code == 403
    assert "Operator or administrator access required" in reset_chk_res.json()["detail"]

    reset_demo_res = no_cookie_client.post("/api/admin/reset-demo")
    assert reset_demo_res.status_code == 403

    scan_res = no_cookie_client.post("/api/checkpoint/frame", json={"image": "dummy"})
    assert scan_res.status_code == 403

    clear_personnel_res = no_cookie_client.delete("/api/personnel")
    assert clear_personnel_res.status_code == 403
