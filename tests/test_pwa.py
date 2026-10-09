import base64
import hashlib
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import cv2
import numpy as np
import pytest
from fastapi.testclient import TestClient

from src.pwa.policy import advance, fresh, WINDOW_SECONDS
from src.pwa.security import password_hash, seal, unseal
from src.pwa.store import Store
from src.storage.supabase_client import CloudUnavailable
from src.pwa.alerts import valid_push_endpoint
from src.pwa import api as backend

ROOT = Path(__file__).resolve().parents[1]


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


def person(id="A", role="Employee", **changes):
    return dict(id=id, name="Test " + id, role=role, is_recognized=True, is_live=True, **changes)


def jpeg():
    _, image = cv2.imencode(".jpg", np.random.default_rng(4).integers(0, 255, (128,128,3), dtype=np.uint8))
    return base64.b64encode(image).decode()


@pytest.mark.parametrize("page", ["checkpoint", "enrollment", "logs", "audit", "control"])
def test_routes_are_real_documents_with_pwa_shell(client, page):
    response = client.get("/" + page)
    assert response.status_code == 200
    script = "logs" if page == "audit" else page
    assert '<nav class="nav"' in response.text and f'/assets/{script}.js' in response.text
    assert 'rel="manifest"' in response.text
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "SUPABASE_KEY" not in response.text


def test_auth_csrf_logout_and_admin_boundary(client):
    assert client.get("/api/logs").status_code == 401
    assert client.post("/api/checkpoint/reset", json={}).status_code == 401
    assert client.post("/api/auth/login", json={"username":"x","password":"x"}, headers={"Origin":"https://attacker.invalid"}).status_code == 403
    response = signin(client)
    assert "HttpOnly" in response.headers["set-cookie"] and "SameSite=none" in response.headers["set-cookie"] and "Secure" in response.headers["set-cookie"]
    assert client.get("/api/control").status_code == 200
    key, record, version = Store().records("auth:")[0]
    record["role"] = "operator"
    Store().cas(key, version, record)
    assert client.get("/api/control").status_code == 403
    assert client.get("/api/logs").status_code == 200
    logout_res = client.post("/api/auth/logout")
    assert logout_res.status_code == 200
    logout_cookie = logout_res.headers.get("set-cookie", "").lower()
    assert "httponly" in logout_cookie and "samesite=none" in logout_cookie and "secure" in logout_cookie
    assert client.get("/api/logs").status_code == 401


def test_fifteen_second_deadline_and_duplicate_person():
    state, terminal = advance(fresh(), [person()], 100, "frame1")
    assert state["state"] == "WAITING" and state["deadline"] == 115 and not terminal
    state, _ = advance(state, [person()], 102, "frame2")
    assert state["deadline"] == 115 and len(state["parties"]) == 1
    state, terminal = advance(state, [person("B", "Customer")], 115, "frame3")
    assert state["state"] == "BREACH" and terminal
    assert state["reason_code"] == "ZT-008"
    assert "15-second custody window expired" in state["reason"]
    assert advance(state, [person("B", "Customer")], 116)[0]["state"] == "BREACH"


def test_roles_liveness_and_frame_replay():
    state, _ = advance(fresh(), [person()], 100, "same")
    state, _ = advance(state, [person("B","Customer")], 101, "same")
    assert state["state"] == "WAITING"
    state, terminal = advance(state, [person("B","Customer")], 110.0, "new")
    assert state["state"] == "GRANTED" and terminal
    assert "Distinct identities verified within 15 seconds" in state["reason"]
    high, _ = advance(fresh("high-value"), [person(), person("B","Customer")], 100)
    assert high["state"] == "WAITING"
    spoof = person("C"); spoof["is_live"] = False
    assert advance(high, [spoof], 101)[0]["state"] == "BREACH"
    high, _ = advance(fresh("high-value"), [person(), person("B")], 100)
    assert high["state"] == "GRANTED"


def test_atomic_cas_has_one_winner(client):
    store = Store()
    def commit(_):
        return store.cas("race", -1, {"ok": True})
    with ThreadPoolExecutor(max_workers=8) as pool:
        winners = list(pool.map(commit, range(8)))
    assert sum(winners) == 1


def test_crypto_authenticated_envelope(client):
    raw=b"private frame"
    one, two = seal(raw,"frame:1"), seal(raw,"frame:1")
    assert one != two and unseal(one,"frame:1") == raw
    with pytest.raises(Exception):
        unseal(one,"frame:2")
    with pytest.raises(Exception):
        unseal(one[:-1]+bytes([one[-1]^1]),"frame:1")


def test_scan_evidence_and_exactly_once_audit(client, monkeypatch):
    signin(client)
    monkeypatch.setattr(backend,"recognize",lambda frame,people:([person(),person("B","Customer")],{"texture_ok":True,"face_count":2}))
    response=client.post('/api/checkpoint/frame',json={"image":jpeg()})
    assert response.status_code==200,response.text
    assert response.json()["state"]=="GRANTED"
    client.post('/api/checkpoint/frame',json={"image":jpeg()})
    client.post('/api/checkpoint/tick')
    events=client.get('/api/logs').json()
    assert len(events)==1 and events[0]["verdict"]=="GRANTED"
    encrypted=client.get(f"/api/logs/{events[0]['id']}/evidence")
    assert encrypted.status_code==200 and encrypted.headers['cache-control']=='no-store, private'
    raw=unseal(encrypted.content,'evidence:'+events[0]['sha256_hash'])
    frame=cv2.imdecode(np.frombuffer(raw,np.uint8),cv2.IMREAD_COLOR)
    assert hashlib.sha256(frame.tobytes()).hexdigest()==events[0]['sha256_hash']


def test_timeout_persists_once_and_queues_alert(client):
    signin(client)
    state, _ = advance(fresh(), [person()], time.time() - (WINDOW_SECONDS + 1))
    Store().put('checkpoint:main', state)
    assert client.post('/api/checkpoint/tick').json()['state'] == 'BREACH'
    assert client.post('/api/checkpoint/tick').json()['state']=='BREACH'
    assert len(Store().logs())==1 and len(Store().records('job:'))==1


def test_quality_invalid_input_and_duplicate_enrollment(client, monkeypatch):
    signin(client)
    assert client.post('/api/enrollment/quality',json={'image':'not-an-image'}).status_code==422
    frame=np.random.default_rng(4).integers(0,255,(128,128,3),dtype=np.uint8)
    face={'norm':cv2.cvtColor(frame,cv2.COLOR_BGR2GRAY),'crop':frame}
    monkeypatch.setattr(backend,'inspect',lambda _:([face],{'lighting_ok':True,'aligned':True,'texture_ok':True,'face_count':1}))
    body={'image':jpeg(),'name':'Test Person','personnel_id':'EMP-1','role':'Employee'}
    assert client.post('/api/enrollment',json=body).status_code==200
    assert client.post('/api/enrollment',json=body).status_code==409
    people=client.get('/api/personnel').json()
    assert 'template' not in people[0]


def test_cloud_missing_or_partial_credentials_never_falls_back(client,monkeypatch):
    monkeypatch.setenv('VERCEL','1')
    with pytest.raises(CloudUnavailable):Store()
    monkeypatch.delenv('VERCEL')
    monkeypatch.setenv('SUPABASE_URL','https://example.supabase.co')
    with pytest.raises(CloudUnavailable):Store()


def test_push_ssrf_and_secret_redaction(client):
    signin(client)
    assert not valid_push_endpoint('http://localhost:8502/api/control')
    assert not valid_push_endpoint('https://fcm.googleapis.com.evil.invalid/push')
    assert valid_push_endpoint('https://fcm.googleapis.com/fcm/send/example')
    assert client.post('/api/push/subscribe',json={'endpoint':'https://127.0.0.1/','keys':{'auth':'a','p256dh':'b'}}).status_code==422
    assert client.post('/api/control/settings',json={'CALLMEBOT_API_KEY':'private-test-key'}).status_code==200
    assert 'private-test-key' not in client.get('/api/control').text
    assert 'private-test-key' not in json.dumps(Store().get('config:alerts'))


def test_partially_configured_alert_remains_pending(client):
    from src.pwa.alerts import deliver
    signin(client)
    client.post('/api/control/settings', json={'CALLMEBOT_API_KEY':'test-key-without-recipient'})
    job={'id':'test-job','done':False,'attempts':0}
    Store().put('job:test-job',job)
    deliver('job:test-job',job,0)
    saved,_=Store().get('job:test-job')
    assert not saved['done'] and saved['status']=='UNCONFIGURED'


def test_provider_failure_is_retained_for_retry(client,monkeypatch):
    from src.pwa import alerts
    signin(client)
    client.post('/api/control/settings',json={'CALLMEBOT_API_KEY':'test-key','CALLMEBOT_PHONE':'+15550000000'})
    def fail(*args,**kwargs):
        raise RuntimeError('Provider unavailable')
    monkeypatch.setattr(alerts.httpx,'get',fail)
    job={'id':'retry-job','done':False,'attempts':0}
    Store().put('job:retry-job',job)
    alerts.deliver('job:retry-job',job,0)
    saved,_=Store().get('job:retry-job')
    assert saved['status']=='RETRY' and saved['attempts']==1 and saved['next_at']>time.time()


def test_telegram_getme_validation(client, monkeypatch):
    from src.pwa import alerts
    signin(client)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:VALID_BOT_TOKEN")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    class MockGetMeResponse:
        status_code = 200
        content = b'{"ok": true}'
        def json(self): return {"ok": True, "result": {"is_bot": True, "username": "veritas_bot"}}

    class MockGetChatResponse:
        status_code = 200
        content = b'{"ok": true}'
        def json(self): return {"ok": True, "result": {"id": 987654321, "type": "private"}}

    def mock_get(url, *args, **kwargs):
        if "getMe" in url:
            return MockGetMeResponse()
        if "getChat" in url:
            return MockGetChatResponse()
        return MockGetMeResponse()

    monkeypatch.setattr(alerts.httpx, "get", mock_get)
    res = client.get("/api/alerts/telegram/status")
    assert res.status_code == 200
    data = res.json()
    assert data["configured"] is True
    assert data["bot_reachable"] is True
    assert data["chat_reachable"] is True
    assert data["description"] == "CONNECTED"


def test_telegram_invalid_token(client, monkeypatch):
    from src.pwa import alerts
    signin(client)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "INVALID_TOKEN")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    class MockUnauthorizedResponse:
        status_code = 401
        content = b'{"ok": false, "description": "Unauthorized"}'
        def json(self): return {"ok": False, "error_code": 401, "description": "Unauthorized"}

    monkeypatch.setattr(alerts.httpx, "get", lambda url, *args, **kwargs: MockUnauthorizedResponse())
    res = client.get("/api/alerts/telegram/status")
    assert res.status_code == 200
    data = res.json()
    assert data["configured"] is True
    assert data["bot_reachable"] is False
    assert data["chat_reachable"] is False
    assert data["description"] == "Unauthorized"


def test_telegram_invalid_chat_id(client, monkeypatch):
    from src.pwa import alerts
    signin(client)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:VALID_TOKEN")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "INVALID_CHAT_ID")

    class MockGetMeResponse:
        status_code = 200
        content = b'{"ok": true}'
        def json(self): return {"ok": True, "result": {"is_bot": True}}

    class MockBadChatResponse:
        status_code = 400
        content = b'{"ok": false, "description": "Bad Request: chat not found"}'
        def json(self): return {"ok": False, "error_code": 400, "description": "Bad Request: chat not found"}

    def mock_get(url, *args, **kwargs):
        if "getMe" in url:
            return MockGetMeResponse()
        if "getChat" in url:
            return MockBadChatResponse()
        return MockGetMeResponse()

    monkeypatch.setattr(alerts.httpx, "get", mock_get)
    res = client.get("/api/alerts/telegram/status")
    assert res.status_code == 200
    data = res.json()
    assert data["configured"] is True
    assert data["bot_reachable"] is True
    assert data["chat_reachable"] is False
    assert data["description"] == "Bad Request: chat not found"


def test_telegram_text_test_succeeds(client, monkeypatch):
    from src.pwa import alerts
    signin(client)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    sent_requests = []
    class MockPostResponse:
        status_code = 200
        content = b'{"ok": true}'
        def json(self): return {"ok": True, "result": {"message_id": 42}}

    def mock_post(url, *args, **kwargs):
        sent_requests.append((url, kwargs))
        return MockPostResponse()

    monkeypatch.setattr(alerts.httpx, "post", mock_post)
    res = client.post("/api/alerts/telegram/test").json()
    assert res["ok"] is True
    assert res["text_sent"] is True
    assert res["photo_sent"] is True
    assert len(sent_requests) == 2

    # Verify plain text sent first
    text_url, text_kwargs = sent_requests[0]
    assert "sendMessage" in text_url
    assert text_kwargs["json"]["chat_id"] == "987654321"
    assert "🚨 VERITAS TEST ALERT" in text_kwargs["json"]["text"]
    assert "Telegram connection successful." in text_kwargs["json"]["text"]
    assert "Checkpoint: CP-MAIN-01" in text_kwargs["json"]["text"]


def test_telegram_photo_test_succeeds(client, monkeypatch):
    from src.pwa import alerts
    signin(client)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    sent_requests = []
    class MockPostResponse:
        status_code = 200
        content = b'{"ok": true}'
        def json(self): return {"ok": True, "result": {"message_id": 43}}

    monkeypatch.setattr(alerts.httpx, "post", lambda url, *a, **k: (sent_requests.append((url, k)), MockPostResponse())[1])
    res = client.post("/api/alerts/telegram/test").json()
    assert res["ok"] is True
    assert res["photo_sent"] is True

    # Verify photo sent second
    photo_url, photo_kwargs = sent_requests[1]
    assert "sendPhoto" in photo_url
    assert photo_kwargs["data"]["chat_id"] == "987654321"
    assert "photo" in photo_kwargs["files"]
    photo_filename, photo_bytes, content_type = photo_kwargs["files"]["photo"]
    assert content_type == "image/jpeg"
    assert len(photo_bytes) > 0


def test_telegram_text_succeeds_but_photo_fails(client, monkeypatch):
    from src.pwa import alerts
    signin(client)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    class MockTextOkResponse:
        status_code = 200
        content = b'{"ok": true}'
        def json(self): return {"ok": True, "result": {"message_id": 44}}

    class MockPhotoFailResponse:
        status_code = 400
        content = b'{"ok": false, "description": "Bad Request: wrong file identifier/HTTP URL specified"}'
        def json(self): return {"ok": False, "description": "Bad Request: wrong file identifier/HTTP URL specified"}

    def mock_post(url, *args, **kwargs):
        if "sendMessage" in url:
            return MockTextOkResponse()
        return MockPhotoFailResponse()

    monkeypatch.setattr(alerts.httpx, "post", mock_post)
    res = client.post("/api/alerts/telegram/test").json()
    assert res["ok"] is False
    assert res["text_sent"] is True
    assert res["photo_sent"] is False
    assert "Telegram API rejected photo" in res["error"]
    assert "wrong file identifier" in res["error"]


def test_telegram_failure_does_not_break_breach(client, monkeypatch):
    from src.pwa import alerts
    from src.pwa.security import seal
    signin(client)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    def mock_post_fail(url, *args, **kwargs):
        raise httpx.ConnectError("Network unreachable")

    monkeypatch.setattr(alerts.httpx, "post", mock_post_fail)

    fake_frame = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' + b'fake_jpeg'
    ev_digest = hashlib.sha256(fake_frame).hexdigest()
    ev_path = "evidence/breach-fail-test.enc"
    Store().save_blob(ev_path, seal(fake_frame, "evidence:" + ev_digest))

    job = {
        "id": "evt-breach-tg-fail",
        "checkpoint": "CP-MAIN-01",
        "reason_code": "ZT-001",
        "reason": "Unregistered identity detected at CP-MAIN-01",
        "evidence_path": ev_path,
        "evidence_hash": ev_digest,
        "created_at": "2026-10-08T12:00:00Z",
        "done": False,
        "attempts": 0,
        "status": "PENDING"
    }
    Store().put("job:evt-breach-tg-fail", job)

    alerts.deliver("job:evt-breach-tg-fail", job, 0)

    saved, _ = Store().get("job:evt-breach-tg-fail")
    assert saved is not None
    assert saved["status"] == "TELEGRAM_RETRYING"
    assert saved["attempts"] == 1
    assert not saved["done"]


def test_unknown_face_creates_telegram_alert_job(client, monkeypatch):
    signin(client)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    from src.pwa import api as pwa_api
    fake_frame = np.full((120, 120, 3), 128, dtype=np.uint8)
    def mock_decode(img_b64):
        return fake_frame, b'fake_raw_bytes'

    def mock_recognize(frame, personnel):
        return [{
            "id": "unknown",
            "name": "Unknown",
            "role": "Unknown",
            "is_recognized": False,
            "is_live": True,
            "bbox": [10, 10, 80, 80]
        }], {"texture_ok": True, "face_count": 1}

    monkeypatch.setattr(pwa_api, "decode", mock_decode)
    monkeypatch.setattr(pwa_api, "recognize", mock_recognize)

    res = client.post("/api/checkpoint/frame", json={"image": "data:image/jpeg;base64,AAAA"})
    assert res.status_code == 200
    data = res.json()
    assert data["state"] == "BREACH"
    assert data["reason_code"] == "ZT-001"

    jobs = [v for _, v, _ in Store().records("job:")]
    assert len(jobs) > 0
    latest_job = jobs[-1]
    assert latest_job["reason_code"] == "ZT-001"
    assert latest_job["evidence_path"] is not None
    assert latest_job["evidence_hash"] is not None


def test_telegram_receives_captured_evidence_bytes(client, monkeypatch):
    from src.pwa import alerts
    from src.pwa.security import seal
    signin(client)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    fake_frame = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' + b'captured_evidence_pixels'
    ev_digest = hashlib.sha256(fake_frame).hexdigest()
    ev_path = "evidence/test-telegram-evidence.enc"
    Store().save_blob(ev_path, seal(fake_frame, "evidence:" + ev_digest))

    job = {
        "id": "evt-tg-evidence-test",
        "checkpoint": "CP-MAIN-01",
        "reason_code": "ZT-001",
        "reason": "Unregistered identity detected at CP-MAIN-01",
        "evidence_path": ev_path,
        "evidence_hash": ev_digest,
        "created_at": "2026-10-08T14:30:00Z",
        "done": False,
        "attempts": 0,
        "status": "PENDING"
    }
    Store().put("job:evt-tg-evidence-test", job)

    sent_requests = []
    class MockPostResponse:
        status_code = 200
        content = b'{"ok": true}'
        def json(self): return {"ok": True, "result": {"message_id": 99}}

    monkeypatch.setattr(alerts.httpx, "post", lambda url, *a, **k: (sent_requests.append((url, k)), MockPostResponse())[1])

    alerts.deliver("job:evt-tg-evidence-test", job, 0)
    saved, _ = Store().get("job:evt-tg-evidence-test")
    assert saved["done"] is True
    assert saved["status"] == "TELEGRAM_SENT"
    assert "telegram" in saved["delivered"]

    assert len(sent_requests) == 1
    url, kwargs = sent_requests[0]
    assert "sendPhoto" in url
    assert kwargs["data"]["chat_id"] == "987654321"

    # Verify exact caption format
    caption = kwargs["data"]["caption"]
    assert "🚨 VERITAS BREACH ALERT" in caption
    assert "Checkpoint: CP-MAIN-01" in caption
    assert "Access: DENIED" in caption
    assert "Reason: Unregistered identity detected at CP-MAIN-01" in caption
    assert "Time: 2026-10-08T14:30:00Z" in caption
    assert "Evidence ID: evt-tg-evidence-test" in caption

    # Verify exact decrypted bytes sent in photo file
    assert kwargs["files"]["photo"][1] == fake_frame


def test_no_telegram_alert_for_granted_waiting_standby(client, monkeypatch):
    from src.pwa import alerts
    signin(client)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:TEST_TOKEN")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    sent_requests = []
    monkeypatch.setattr(alerts.httpx, "post", lambda url, *a, **k: (sent_requests.append(url), None)[1])

    # 1. STANDBY job or event
    job_standby = {"id": "job-standby", "verdict": "STANDBY", "reason_code": "STANDBY", "done": False, "attempts": 0}
    Store().put("job:job-standby", job_standby)
    alerts.deliver("job:job-standby", job_standby, 0)
    assert len(sent_requests) == 0

    # 2. WAITING state
    job_waiting = {"id": "job-waiting", "verdict": "WAITING", "reason_code": "ZT-007", "done": False, "attempts": 0}
    Store().put("job:job-waiting", job_waiting)
    alerts.deliver("job:job-waiting", job_waiting, 0)
    assert len(sent_requests) == 0

    # 3. GRANTED state
    job_granted = {"id": "job-granted", "verdict": "GRANTED", "reason_code": "GRANTED", "done": False, "attempts": 0}
    Store().put("job:job-granted", job_granted)
    alerts.deliver("job:job-granted", job_granted, 0)
    assert len(sent_requests) == 0


def test_manifest_icons_and_cache_privacy(client):
    from PIL import Image
    manifest=client.get('/manifest.json').json()
    assert manifest['name']=='VERITAS-Vault Security' and manifest['display']=='standalone'
    for size in (192,512):
        with Image.open(ROOT/'public'/'icons'/f'icon-{size}.png') as img:
            assert img.size==(size,size)
    sw=client.get('/sw.js')
    assert sw.status_code==200 and sw.headers['service-worker-allowed']=='/'
    allowlist=re.search(r'const SHELL\s*=\s*(\[.*?\]);', sw.text, re.S).group(1)
    assert '/api/' not in allowlist and 'evidence' not in allowlist
    assert re.search(r'addEventListener\([\"\x27]push[\"\x27]',sw.text)
    assert re.search(r'addEventListener\([\"\x27]notificationclick[\"\x27]',sw.text)


def test_firebase_render_cors_and_csp(client):
    prod_origin = "https://veritas-vault14.web.app"
    # Preflight OPTIONS request from Firebase production origin
    res_opt = client.options(
        "/api/auth/login",
        headers={
            "Origin": prod_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type, X-Vault-Request",
        },
    )
    assert res_opt.status_code == 200
    assert res_opt.headers.get("access-control-allow-origin") == prod_origin
    assert res_opt.headers.get("access-control-allow-credentials") == "true"

    # Preflight OPTIONS request from disallowed origin does not allow origin
    res_bad_opt = client.options(
        "/api/auth/login",
        headers={
            "Origin": "https://attacker.invalid",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type, X-Vault-Request",
        },
    )
    assert res_bad_opt.headers.get("access-control-allow-origin") != "https://attacker.invalid"

    # POST from disallowed origin is denied
    res_bad_post = client.post(
        "/api/auth/login",
        json={"username": "test-operator", "password": "wrong"},
        headers={"Origin": "https://attacker.invalid"},
    )
    assert res_bad_post.status_code == 403

    # CSP header on response allows Render backend in connect-src
    health_res = client.get("/api/health")
    assert health_res.status_code == 200
    csp = health_res.headers.get("content-security-policy", "")
    assert "connect-src 'self' https://veritas-vault-backend.onrender.com" in csp


def test_supabase_service_role_key_regression_no_503(monkeypatch):
    """Regression test: SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY without SUPABASE_KEY must initialize Store.cloud without 503/CloudUnavailable."""
    from src.storage.supabase_client import SupabaseCloud
    monkeypatch.setenv("SUPABASE_URL", "https://ppnfoogpapokpgmarttl.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy_key")
    monkeypatch.delenv("SUPABASE_KEY", raising=False)
    monkeypatch.delenv("NEXT_PUBLIC_SUPABASE_ANON_KEY", raising=False)
    monkeypatch.delenv("VERCEL", raising=False)

    store = Store()
    assert store.cloud is not None
    assert isinstance(store.cloud, SupabaseCloud)
    assert store.cloud.url == "https://ppnfoogpapokpgmarttl.supabase.co"
    assert store.cloud.key == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy_key"


def test_login_with_service_role_key_returns_auth_error_not_503(monkeypatch, tmp_path):
    """Proves wrong-password login produces 401 auth error, NOT 503 infrastructure failure when only SUPABASE_SERVICE_ROLE_KEY is set."""
    from src.storage.supabase_client import SupabaseCloud
    monkeypatch.setenv("SUPABASE_URL", "https://ppnfoogpapokpgmarttl.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy_key")
    monkeypatch.delenv("SUPABASE_KEY", raising=False)
    monkeypatch.delenv("NEXT_PUBLIC_SUPABASE_ANON_KEY", raising=False)
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", base64.b64encode(b"T" * 32).decode())
    monkeypatch.setenv("APP_ORIGIN", "https://testserver")

    # Mock cloud requests offline: rate_limit CAS/get and Supabase auth token
    def mock_request(self, method, path, **kwargs):
        if "/auth/v1/token" in path:
            raise CloudUnavailable("Invalid credentials from identity provider")
        if "/rpc/vault_commit" in path:
            mock_resp = type("Response", (), {"json": lambda s: True})()
            return mock_resp
        if "/rest/v1/vault_records" in path:
            mock_resp = type("Response", (), {"json": lambda s: []})()
            return mock_resp
        return type("Response", (), {"json": lambda s: {}})()

    monkeypatch.setattr(SupabaseCloud, "request", mock_request)

    test_client = TestClient(
        backend.app,
        base_url="https://testserver",
        headers={"X-Vault-Request": "1", "Origin": "https://testserver"},
    )
    resp = test_client.post(
        "/api/auth/login",
        json={"username": "operator@example.com", "password": "wrong-password"},
    )
    assert resp.status_code == 401
    assert "Unable to authenticate operator" in resp.json().get("detail", "")


def test_evidence_preview_security_and_authorization(client, monkeypatch):
    """Proves evidence preview endpoint enforces authentication, returns 404 for missing/invalid events, and securely streams in-memory decrypted image."""
    # 1. Unauthenticated request must return 401
    unauth_res = client.get("/api/logs/00000000-0000-0000-0000-000000000000/evidence/preview")
    assert unauth_res.status_code == 401

    signin(client)
    # Ensure checkpoint is in clean STANDBY state
    client.post("/api/checkpoint/reset", json={})

    # 2. Non-existent event with valid UUID pattern returns 404
    assert client.get("/api/logs/00000000-0000-0000-0000-000000000000/evidence/preview").status_code == 404

    # 3. Path traversal / malformed ID returns 422 or 404
    assert client.get("/api/logs/../../etc/passwd/evidence/preview").status_code in (404, 422)
    assert client.get("/api/logs/nonexistent-invalid-chars/evidence/preview").status_code == 422

    # 4. Generate an audit log with encrypted evidence
    monkeypatch.setattr(
        backend,
        "recognize",
        lambda frame, people: ([person(), person("B", "Customer")], {"texture_ok": True, "face_count": 2}),
    )
    scan_res = client.post("/api/checkpoint/frame", json={"image": jpeg()})
    assert scan_res.status_code == 200
    assert scan_res.json()["state"] == "GRANTED"

    events = client.get("/api/logs").json()
    assert len(events) >= 1
    event = events[0]
    assert "evidence" in event
    ev_path = event["evidence"]["path"] if isinstance(event["evidence"], dict) else event["evidence"]
    assert ev_path.endswith(".enc")

    # 5. Authenticated preview retrieves decrypted image
    preview_res = client.get(f"/api/logs/{event['id']}/evidence/preview")
    assert preview_res.status_code == 200
    assert preview_res.headers.get("cache-control") == "no-store, private"
    assert preview_res.headers.get("x-content-type-options") == "nosniff"
    assert preview_res.headers.get("content-type") in ("image/jpeg", "image/png")

    # Verify bytes decode to a valid image
    img = cv2.imdecode(np.frombuffer(preview_res.content, np.uint8), cv2.IMREAD_COLOR)
    assert img is not None
    assert hashlib.sha256(img.tobytes()).hexdigest() == event["sha256_hash"]


def test_unknown_identity_breach_and_encrypted_evidence_metadata(client, monkeypatch):
    """Proves unknown face triggers ZT-001 BREACH, saves encrypted evidence, and never persists raw image in metadata."""
    signin(client)
    # Reset checkpoint to clear previous terminal state
    client.post("/api/checkpoint/reset", json={})

    # Simulate unknown face detection (is_recognized=False)
    unknown_face = dict(
        id="unknown-1",
        name="Unknown",
        role="Unknown",
        is_recognized=False,
        is_live=True,
        confidence=0.12,
        pad_status="PASS",
        bbox=[10, 20, 100, 120],
    )
    monkeypatch.setattr(
        backend,
        "recognize",
        lambda frame, people: ([unknown_face], {"texture_ok": True, "face_count": 1}),
    )

    frame_payload = {"image": jpeg()}
    res = client.post("/api/checkpoint/frame", json=frame_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["state"] == "BREACH"
    assert data.get("reason_code") == "ZT-001"
    assert "Unregistered" in data.get("reason", "")
    assert "frame_size" in data

    # Audit event must be recorded
    logs = client.get("/api/logs").json()
    breach_logs = [l for l in logs if l.get("reason_code") == "ZT-001"]
    assert len(breach_logs) >= 1
    breach_event = breach_logs[0]

    assert breach_event["verdict"] == "BREACH"
    assert breach_event["reason_code"] == "ZT-001"
    assert "evidence" in breach_event
    ev_path = breach_event["evidence"]["path"] if isinstance(breach_event["evidence"], dict) else breach_event["evidence"]
    assert ev_path.endswith(".enc")
    assert "sha256_hash" in breach_event

    # Verify no raw image or base64 plaintext in log record metadata
    serialized_log = json.dumps(breach_event)
    assert frame_payload["image"] not in serialized_log

    # Preview works for breach event
    preview = client.get(f"/api/logs/{breach_event['id']}/evidence/preview")
    assert preview.status_code == 200
    assert preview.headers.get("cache-control") == "no-store, private"
    assert preview.headers.get("x-content-type-options") == "nosniff"


def test_push_endpoints_lifecycle_and_security(client):
    """Verifies public key, subscribe auth check, subscription storage, duplicate update, and unsubscribe."""
    # 1. Public key requires auth
    res = client.get("/api/push/public-key")
    assert res.status_code == 401

    signin(client)
    # 2. Public key returned for authenticated operator
    key_res = client.get("/api/push/public-key")
    assert key_res.status_code == 200
    pub_key = key_res.json()["public_key"]
    assert len(pub_key) > 20

    # Key endpoint backward compatibility
    assert client.get("/api/push/key").json()["public_key"] == pub_key

    # 3. Valid subscription stored
    sub_payload = {
        "endpoint": "https://fcm.googleapis.com/fcm/send/test-device-token-123",
        "keys": {
            "p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QT9EgVKA7Gh27YStRB",
            "auth": "tBHItJI5svbpez7KI4CCXg",
        },
        "device_label": "Test Android Phone",
    }
    sub_res = client.post("/api/push/subscribe", json=sub_payload)
    assert sub_res.status_code == 200
    assert sub_res.json()["subscribed"] is True

    # Check status
    status_res = client.get("/api/push/status")
    assert status_res.status_code == 200
    assert status_res.json()["configured"] is True
    assert status_res.json()["subscriptions"] >= 1

    # 4. Duplicate endpoint updates rather than duplicates
    sub_payload["device_label"] = "Updated Device Label"
    sub_res2 = client.post("/api/push/subscribe", json=sub_payload)
    assert sub_res2.status_code == 200
    store = Store()
    matching = [v for k, v, _ in store.records("push:") if v["subscription"]["endpoint"] == sub_payload["endpoint"] and v.get("active")]
    assert len(matching) == 1
    assert matching[0]["device_label"] == "Updated Device Label"

    # 5. Unsubscribe
    unsub_res = client.post("/api/push/unsubscribe", json={"endpoint": sub_payload["endpoint"], "keys": sub_payload["keys"]})
    assert unsub_res.status_code == 200
    assert unsub_res.json()["subscribed"] is False

    matching_active = [v for k, v, _ in store.records("push:") if v["subscription"]["endpoint"] == sub_payload["endpoint"] and v.get("active")]
    assert len(matching_active) == 0


def test_push_test_admin_only(client):
    """Verifies that POST /api/push/test is admin-only and triggers dispatch without creating a breach."""
    # Unauthenticated rejected
    assert client.post("/api/push/test").status_code == 401

    signin(client)
    res = client.post("/api/push/test")
    assert res.status_code == 200
    data = res.json()
    assert "sent" in data
    # Ensure no breach was created
    cp = client.post("/api/checkpoint/tick").json()
    assert cp["state"] != "BREACH"


def test_breach_triggers_push_dispatch_and_waiting_granted_do_not(client, monkeypatch):
    """Verifies BREACH queues an outbox job with push metadata, while WAITING and GRANTED do not queue jobs."""
    signin(client)
    client.post("/api/checkpoint/reset", json={})
    store = Store()

    # Clear old jobs
    jobs_before = len([k for k, v, _ in store.records("job:") if not v.get("done")])

    # 1. WAITING state (single valid party): policy transition returns terminal=False, no alert job
    store.enroll({"id": "EMP-99", "name": "Alice Guard", "role": "Employee", "created_at": time.time()})
    person = store.personnel()[0]
    face = dict(id=person["id"], name=person["name"], role=person["role"], is_recognized=True, is_live=True, confidence=0.95, pad_status="PASS", bbox=[10, 10, 50, 50])
    st_waiting, term_waiting = advance(fresh(), [face], time.time())
    assert st_waiting["state"] == "WAITING"
    assert term_waiting is False

    # 2. GRANTED state (dual custody satisfied): terminal=True, but state is GRANTED, so no breach alert job
    person2 = dict(id="CUST-01", name="Bob Customer", role="Customer", created_at=time.time())
    store.enroll(person2)
    face2 = dict(id=person2["id"], name=person2["name"], role=person2["role"], is_recognized=True, is_live=True, confidence=0.92, pad_status="PASS", bbox=[60, 10, 100, 50])
    st_granted, term_granted = advance(st_waiting, [face2], time.time() + 1.0)
    assert st_granted["state"] == "GRANTED"
    assert term_granted is True

    # Checkpoint transition directly with GRANTED faces produces no breach alert job
    res_granted, _ = backend.transition([face, face2])
    assert res_granted["state"] == "GRANTED"
    jobs_after_granted = [v for k, v, _ in store.records("job:") if not v.get("done")]
    assert len(jobs_after_granted) == jobs_before

    # Reset
    client.post("/api/checkpoint/reset", json={})

    # 3. Unknown identity triggers terminal BREACH: MUST create alert job with ZT-001
    unknown_face = dict(id="unknown-x", name="Unknown", role="Unknown", is_recognized=False, is_live=True, confidence=0.1, pad_status="PASS", bbox=[10, 10, 50, 50])
    monkeypatch.setattr(backend, "recognize", lambda f, p: ([unknown_face], {"texture_ok": True, "face_count": 1}))
    res_breach = client.post("/api/checkpoint/frame", json={"image": jpeg()})
    assert res_breach.status_code == 200
    assert res_breach.json()["state"] == "BREACH"

    jobs_after_breach = [v for k, v, _ in store.records("job:") if not v.get("done") and v.get("reason_code") == "ZT-001"]
    assert len(jobs_after_breach) >= 1
    latest_job = jobs_after_breach[-1]
    assert latest_job["reason_code"] == "ZT-001"
    assert "Unregistered" in latest_job["reason"]


def test_dead_subscription_disables_it_and_delivery_failure_does_not_block_breach(client, monkeypatch):
    """Verifies that 410 Gone from Web Push marks subscription inactive without breaking access or breach flow."""
    from src.pwa import alerts
    from pywebpush import WebPushException
    signin(client)
    store = Store()

    # Store a dummy active subscription
    sub_key = "push:dead-endpoint-test"
    sub_data = {
        "subscription": {"endpoint": "https://fcm.googleapis.com/fcm/send/dead-device", "keys": {"p256dh": "dummy", "auth": "dummy"}},
        "active": True,
        "owner": "admin",
    }
    store.put(sub_key, sub_data)

    class Mock410Response:
        status_code = 410

    def mock_webpush_fail(*args, **kwargs):
        raise WebPushException("Subscription has expired or is invalid", response=Mock410Response())

    monkeypatch.setattr(alerts, "ensure_vapid_keys", lambda s: {
        "VAPID_PUBLIC_KEY": "pub", "VAPID_PRIVATE_KEY": "priv", "VAPID_SUBJECT": "mailto:sec@example.com",
        "CALLMEBOT_PHONE": "", "CALLMEBOT_API_KEY": ""
    })
    import pywebpush
    monkeypatch.setattr(pywebpush, "webpush", mock_webpush_fail)

    job = {"id": "test-dead-sub-job", "done": False, "attempts": 0, "reason": "Test breach", "reason_code": "ZT-001"}
    store.put("job:test-dead-sub-job", job)

    # Deliver should catch 410 and mark subscription active=False
    alerts.deliver("job:test-dead-sub-job", job, 0)
    saved_sub, _ = store.get(sub_key)
    assert saved_sub["active"] is False


def test_frontend_files_contain_correct_notification_and_camera_handlers():
    """Verifies checkpoint.js, alerts.js, and sw.js contain required UI and camera logic."""
    cp_text = (ROOT / "public" / "assets" / "checkpoint.js").read_text(encoding="utf-8")
    alerts_text = (ROOT / "public" / "assets" / "alerts.js").read_text(encoding="utf-8")
    sw_text = (ROOT / "public" / "sw.js").read_text(encoding="utf-8")

    # Camera state logging
    assert "CAMERA_INIT_START" in cp_text
    assert "CAMERA_PERMISSION_GRANTED" in cp_text
    assert "CAMERA_STREAM_READY" in cp_text
    assert "CAMERA_PLAYING" in cp_text
    assert "CAMERA_INIT_FAILED" in cp_text

    # Liveness NO FACE initial handling
    assert 'NO FACE' in cp_text

    # Web Push exports in alerts.js
    assert "subscribePush" in alerts_text
    assert "getPushSubscription" in alerts_text
    assert "testPush" in alerts_text
    assert "testSiren" in alerts_text

    # Service worker dynamic notification tags
    assert "payload.event_id" in sw_text
    assert "payload.title" in sw_text


def test_continuous_surveillance_deduplicates_intruder_incident(client, monkeypatch):
    """Proves that a continuous intruder standing in front of the camera for repeated scans
    creates only one incident, one audit record, and one alert job during cooldown."""
    signin(client)
    intruder = [{"id": "INTRUDER_99", "name": "Unknown Person", "role": "Unknown", "is_recognized": False, "is_live": True}]
    monkeypatch.setattr(
        backend,
        "recognize",
        lambda frame, people: (intruder, {"texture_ok": True, "face_count": 1}),
    )

    # Frame 1: Initial breach detection
    r1 = client.post("/api/checkpoint/frame", json={"image": jpeg()})
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["state"] == "BREACH"
    assert d1["incident_code"] == "ZT-001"
    first_incident = d1["active_incident"]
    assert first_incident != "NONE"

    # Frame 2: Same intruder visible 500ms later (simulating continuous surveillance loop)
    r2 = client.post("/api/checkpoint/frame", json={"image": jpeg()})
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["state"] == "BREACH"
    assert d2["active_incident"] == first_incident

    # Frame 3: Same intruder visible 1200ms later
    r3 = client.post("/api/checkpoint/frame", json={"image": jpeg()})
    assert r3.status_code == 200
    d3 = r3.json()
    assert d3["state"] == "BREACH"
    assert d3["active_incident"] == first_incident

    # Verify duplicate suppression: Exactly 1 audit log and 1 alert job exist
    store = Store()
    assert len(store.logs()) == 1
    assert len(store.records("job:")) == 1

    # Reset checkpoint: incident is cleared
    reset_res = client.post("/api/checkpoint/reset", json={"mode": "standard"})
    assert reset_res.status_code == 200
    assert reset_res.json()["active_incident"] == "NONE"

    # Frame 4 after reset: new incident is registered
    r4 = client.post("/api/checkpoint/frame", json={"image": jpeg()})
    assert r4.status_code == 200
    d4 = r4.json()
    assert d4["state"] == "BREACH"
    assert d4["active_incident"] != first_incident
    breach_logs = [l for l in store.logs() if l.get("verdict") == "BREACH"]
    assert len(breach_logs) == 2
    assert len(store.records("job:")) == 2


@pytest.mark.anyio
async def test_automatic_alert_worker_loop_drains_jobs(monkeypatch):
    """Proves that alert_worker_loop processes pending alert jobs automatically."""
    import asyncio
    from src.pwa import alerts

    delivered_jobs = []
    def mock_deliver(key, job, attempt):
        delivered_jobs.append(job["id"])
        job["done"] = True
        job["status"] = "SENT"
        Store().put(key, job)

    monkeypatch.setattr(alerts, "deliver", mock_deliver)

    store = Store()
    test_job = {
        "id": "job-auto-drain-001",
        "created_at": "2026-10-09T05:00:00Z",
        "done": False,
        "attempts": 0,
        "status": "PENDING",
        "checkpoint": "CP-MAIN-01",
        "reason_code": "ZT-001",
        "reason": "Test auto drain",
    }
    store.put("job:job-auto-drain-001", test_job)

    # Run alert_worker_loop for 1 iteration
    worker_task = asyncio.create_task(backend.alert_worker_loop())
    await asyncio.sleep(0.1)
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass

    assert "job-auto-drain-001" in delivered_jobs
    saved, _ = store.get("job:job-auto-drain-001")
    assert saved["done"] is True


def test_fifteen_second_dual_custody_full_lifecycle(client):
    """Complete verification of 15s dual-custody timeout behavior:
    1. First identity -> WAITING, countdown starts near 15s
    2. Repeated scanning of SAME identity does not restart or shorten timer
    3. Second distinct identity at ~10s -> GRANTED (both standard & high-value modes)
    4. No second identity -> ZT-008 only after 15.0s
    5. Reset -> STANDBY
    """
    from src.pwa.policy import advance, fresh, WINDOW_SECONDS

    # 0. Initial camera standby with no faces does NOT trigger ZT-008
    s0 = fresh()
    s_idle, term_idle = advance(s0, [], 100)
    assert s_idle["state"] == "STANDBY"
    assert s_idle["deadline"] is None
    assert not term_idle

    # 1. First valid identity scanned at t=100 -> WAITING, countdown starts near 15 sec
    emp1 = person(id="EMP-01", role="Employee")
    s1, term1 = advance(s_idle, [emp1], 100, "f1")
    assert s1["state"] == "WAITING"
    assert s1["deadline"] == 100 + WINDOW_SECONDS  # 115.0
    assert not term1
    assert len(s1["parties"]) == 1

    # 2. Same identity repeatedly scanned at t=102, 105, 108 -> still 1 party, deadline not restarted/shortened
    for scan_t in (102, 105, 108):
        s_repeat, term_repeat = advance(s1, [emp1], scan_t, f"repeat_{scan_t}")
        assert s_repeat["state"] == "WAITING"
        assert s_repeat["deadline"] == 115.0  # unchanged
        assert len(s_repeat["parties"]) == 1
        assert not term_repeat

    # 3. Second distinct valid identity appears at t=110 (~10 sec after first) -> GRANTED
    cust1 = person(id="CUST-01", role="Customer")
    s_granted, term_granted = advance(s1, [cust1], 110, "f_grant")
    assert s_granted["state"] == "GRANTED"
    assert term_granted
    assert "Distinct identities verified within 15 seconds" in s_granted["reason"]
    assert len(s_granted["parties"]) == 2

    # 3b. High-value mode: Employee + Employee -> GRANTED
    emp2 = person(id="EMP-02", role="Employee")
    hv_state = fresh("high-value")
    hv1, _ = advance(hv_state, [emp1], 100, "hv1")
    assert hv1["state"] == "WAITING"
    hv_grant, hv_term = advance(hv1, [emp2], 110, "hv2")
    assert hv_grant["state"] == "GRANTED"
    assert hv_term

    # 4. No second identity appears: stays WAITING until 15s, then triggers ZT-008
    s_timeout_start, _ = advance(fresh(), [emp1], 200, "t_start")
    assert s_timeout_start["state"] == "WAITING"
    assert s_timeout_start["deadline"] == 215.0

    # At t=214.9 (14.9s elapsed): still WAITING
    s_near_timeout, term_near = advance(s_timeout_start, [], 214.9)
    assert s_near_timeout["state"] == "WAITING"
    assert not term_near

    # At t=215.0 (15.0s elapsed): ZT-008 triggers
    s_breached, term_breached = advance(s_timeout_start, [], 215.0)
    assert s_breached["state"] == "BREACH"
    assert term_breached
    assert s_breached["reason_code"] == "ZT-008"
    assert "15-second custody window expired" in s_breached["reason"]

    # 5. Reset via API -> STANDBY
    signin(client)
    res_reset = client.post("/api/checkpoint/reset", json={"mode": "standard"})
    assert res_reset.status_code == 200
    reset_data = res_reset.json()
    assert reset_data["state"] == "STANDBY"
    assert reset_data["deadline"] is None
    assert reset_data["parties"] == []




