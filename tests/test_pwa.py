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

from src.pwa.policy import advance, fresh
from src.pwa.security import password_hash, seal, unseal
from src.pwa.store import Store
from src.storage.supabase_client import CloudUnavailable
from src.pwa.alerts import valid_push_endpoint
from src.pwa import api as backend

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client(tmp_path, monkeypatch):
    for key in ("VERCEL", "SUPABASE_URL", "SUPABASE_KEY", "FACENET_MODEL_PATH", "CALLMEBOT_API_KEY", "CALLMEBOT_PHONE", "VAPID_PRIVATE_KEY"):
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
    client.post("/api/auth/logout")
    assert client.get("/api/logs").status_code == 401


def test_five_second_deadline_and_duplicate_person():
    state, terminal = advance(fresh(), [person()], 100, "frame1")
    assert state["state"] == "WAITING" and state["deadline"] == 105 and not terminal
    state, _ = advance(state, [person()], 102, "frame2")
    assert state["deadline"] == 105 and len(state["parties"]) == 1
    state, terminal = advance(state, [person("B", "Customer")], 105, "frame3")
    assert state["state"] == "BREACH" and terminal
    assert advance(state, [person("B", "Customer")], 106)[0]["state"] == "BREACH"


def test_roles_liveness_and_frame_replay():
    state, _ = advance(fresh(), [person()], 100, "same")
    state, _ = advance(state, [person("B","Customer")], 101, "same")
    assert state["state"] == "WAITING"
    state, terminal = advance(state, [person("B","Customer")], 104.9, "new")
    assert state["state"] == "GRANTED" and terminal
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
    state,_=advance(fresh(),[person()],time.time()-6)
    Store().put('checkpoint:main',state)
    assert client.post('/api/checkpoint/tick').json()['state']=='BREACH'
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

    # CSP header on response allows Render backend in connect-src
    health_res = client.get("/api/health")
    assert health_res.status_code == 200
    csp = health_res.headers.get("content-security-policy", "")
    assert "connect-src 'self' https://veritas-vault-backend.onrender.com" in csp
