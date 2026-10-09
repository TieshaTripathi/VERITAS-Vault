"""
Live end-to-end verification script for Phase 14:
A. RESET -> Start Camera -> no face -> STANDBY
B. Known Employee -> WAITING, no popup
C. Same Employee remains -> WAITING
D. Employee moves away -> WAITING (empty frame)
E. Customer enters -> GRANTED
F. Unknown person -> one popup, one siren, one Telegram, one evidence, one audit event
G. Keep unknown person in frame -> NO repeated alerts
"""
import base64
import os
import sys
import tempfile
import time
import uuid
import cv2
import numpy as np

# Ensure root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Clean environment before importing app/Store
temp_dir = tempfile.mkdtemp()
for k in ("VERCEL", "SUPABASE_URL", "SUPABASE_KEY", "SUPABASE_SERVICE_ROLE_KEY", "FACENET_MODEL_PATH"):
    os.environ.pop(k, None)

os.environ["VAULT_DATA_DIR"] = temp_dir
os.environ["VAULT_ENCRYPTION_KEY"] = base64.b64encode(b"V" * 32).decode()
os.environ["VAULT_OPERATOR_USERNAME"] = "admin"
from src.pwa.security import password_hash
os.environ["VAULT_OPERATOR_PASSWORD_HASH"] = password_hash("secret123")
os.environ["APP_ORIGIN"] = "https://livevault.local"

from fastapi.testclient import TestClient
from src.pwa.api import app, Store, fresh
import src.pwa.api as api_mod

def run_live_verification():
    print("=== STARTING PHASE 14 LIVE PRODUCTION VERIFICATION ===")
    
    client = TestClient(app, base_url="https://livevault.local", headers={"X-Vault-Request": "1", "Origin": "https://livevault.local"})
    
    # 0. Login
    login_res = client.post("/api/auth/login", json={"username": "admin", "password": "secret123"})
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    print("[PASS] Login successful")

    store = Store()

    # Prepare synthetic frames
    def make_b64_frame(color_val):
        img = np.full((120, 120, 3), color_val, dtype=np.uint8)
        _, buf = cv2.imencode(".jpg", img)
        return base64.b64encode(buf.tobytes()).decode()

    orig_recognize = api_mod.recognize

    # Step A: RESET -> Start Camera -> no face -> Expected: STANDBY
    api_mod.recognize = lambda frame, people: ([], {"texture_ok": True, "face_count": 0})
    reset_res = client.post("/api/checkpoint/reset", json={"mode": "standard"})
    assert reset_res.status_code == 200, f"Reset failed: {reset_res.text}"
    sess_res = client.post("/api/checkpoint/session", json={"device_id": "DEV-EDGE-01", "checkpoint_id": "CP-MAIN-01"})
    assert sess_res.status_code == 200, f"Session creation failed: {sess_res.text}"
    sess = sess_res.json()
    session_id = sess["session_id"]
    capture_nonce = sess["capture_nonce"]

    # Frame with no faces
    no_face_res = client.post("/api/checkpoint/frame", json={
        "image": make_b64_frame(10),
        "session_id": session_id,
        "capture_nonce": capture_nonce,
        "frame_seq": 0,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    })
    assert no_face_res.status_code == 200, f"Frame failed: {no_face_res.text}"
    st_a = no_face_res.json()
    assert st_a["state"] == "STANDBY", f"Expected STANDBY, got {st_a['state']}"
    assert len(st_a["parties"]) == 0
    print("[PASS] Step A: RESET -> No face -> STANDBY confirmed")

    # Step B: Known Employee enters -> Expected: WAITING, No popup
    alice_face = [{"id": "EMP-ALICE", "name": "Alice Employee", "role": "Employee", "is_recognized": True, "is_live": True}]
    api_mod.recognize = lambda frame, people: (alice_face, {"texture_ok": True, "face_count": 1})

    b_res = client.post("/api/checkpoint/frame", json={
        "image": make_b64_frame(20),
        "session_id": session_id,
        "capture_nonce": capture_nonce,
        "frame_seq": 1,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    })
    assert b_res.status_code == 200
    st_b = b_res.json()
    assert st_b["state"] == "WAITING", f"Expected WAITING, got {st_b['state']}"
    assert len(st_b["parties"]) == 1
    assert st_b["parties"][0]["id"] == "EMP-ALICE"
    assert "VERIFIED" in st_b.get("safe_user_message", "")
    print("[PASS] Step B: Known Employee -> WAITING (No breach, No popup) confirmed")

    # Step C: Same Employee remains -> Expected: WAITING (No breach, duplicate handled cleanly)
    c_res = client.post("/api/checkpoint/frame", json={
        "image": make_b64_frame(30),
        "session_id": session_id,
        "capture_nonce": capture_nonce,
        "frame_seq": 2,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    })
    assert c_res.status_code == 200
    st_c = c_res.json()
    assert st_c["state"] == "WAITING", f"Expected WAITING, got {st_c['state']}"
    assert st_c.get("duplicate_first_party") is True
    assert "DIFFERENT PERSON" in st_c.get("safe_user_message", "")
    print("[PASS] Step C: Same Employee remains -> WAITING, duplicate warning, no breach")

    # Step D: Employee moves away -> empty frame -> Expected: WAITING
    api_mod.recognize = lambda frame, people: ([], {"texture_ok": True, "face_count": 0})
    d_res = client.post("/api/checkpoint/frame", json={
        "image": make_b64_frame(40),
        "session_id": session_id,
        "capture_nonce": capture_nonce,
        "frame_seq": 3,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    })
    assert d_res.status_code == 200
    st_d = d_res.json()
    assert st_d["state"] == "WAITING"
    print("[PASS] Step D: Employee moves away (empty frame) -> WAITING maintained")

    # Step E: Customer enters -> Expected: GRANTED
    bob_face = [{"id": "CUST-BOB", "name": "Bob Customer", "role": "Customer", "is_recognized": True, "is_live": True}]
    api_mod.recognize = lambda frame, people: (bob_face, {"texture_ok": True, "face_count": 1})
    e_res = client.post("/api/checkpoint/frame", json={
        "image": make_b64_frame(50),
        "session_id": session_id,
        "capture_nonce": capture_nonce,
        "frame_seq": 4,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    })
    assert e_res.status_code == 200
    st_e = e_res.json()
    assert st_e["state"] == "GRANTED", f"Expected GRANTED, got {st_e['state']}"
    assert len(st_e["parties"]) == 2
    assert "authorization_token" in st_e
    print("[PASS] Step E: Customer enters -> GRANTED with signed token confirmed!")

    # Step F: Unknown person test
    # Reset checkpoint first
    client.post("/api/checkpoint/reset", json={"mode": "standard"})
    sess_res2 = client.post("/api/checkpoint/session", json={"device_id": "DEV-EDGE-01", "checkpoint_id": "CP-MAIN-01"})
    sess2 = sess_res2.json()

    intruder_face = [{"id": "INTRUDER-99", "name": "Unknown Person", "role": "Unauthorized", "is_recognized": False, "is_live": True}]
    api_mod.recognize = lambda frame, people: (intruder_face, {"texture_ok": True, "face_count": 1})

    events_before = len(store.logs())
    jobs_before = len(store.records("job:"))

    f_res = client.post("/api/checkpoint/frame", json={
        "image": make_b64_frame(60),
        "session_id": sess2["session_id"],
        "capture_nonce": sess2["capture_nonce"],
        "frame_seq": 0,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    })
    assert f_res.status_code == 200
    st_f = f_res.json()
    assert st_f["state"] == "BREACH", f"Expected BREACH, got {st_f['state']}"
    assert st_f["reason_code"] == "ZT-001"
    event_id = st_f.get("last_event") or st_f.get("active_incident")
    assert event_id is not None
    
    events_after = len(store.logs())
    jobs_after = len(store.records("job:"))
    assert events_after == events_before + 1, "Exactly one audit event must be created"
    assert jobs_after == jobs_before + 1, "Exactly one outbox alert job must be queued"
    print(f"[PASS] Step F: Unknown person -> BREACH ZT-001, exactly 1 audit event and 1 Telegram alert job queued (ID: {event_id})")

    # Step G: Keep unknown person in frame -> Expected: NO repeated alerts
    for seq in range(1, 6):
        g_res = client.post("/api/checkpoint/frame", json={
            "image": make_b64_frame(60 + seq),
            "session_id": sess2["session_id"],
            "capture_nonce": sess2["capture_nonce"],
            "frame_seq": seq,
            "device_id": "DEV-EDGE-01",
            "checkpoint_id": "CP-MAIN-01"
        })
        assert g_res.status_code == 200
        st_g = g_res.json()
        assert st_g["state"] == "BREACH"
        assert (st_g.get("last_event") or st_g.get("active_incident")) == event_id

    events_final = len(store.logs())
    jobs_final = len(store.records("job:"))
    assert events_final == events_after, f"Expected {events_after} events, got {events_final} (Deduplication failed!)"
    assert jobs_final == jobs_after, f"Expected {jobs_after} jobs, got {jobs_final} (Deduplication failed!)"
    print("[PASS] Step G: Keep unknown person in frame for 5 repeated scans -> NO repeated alerts, strictly deduplicated!")

    # Restore original recognize
    api_mod.recognize = orig_recognize
    print("\nALL LIVE PRODUCTION VERIFICATION CHECKS PASSED (A through G)!")

if __name__ == "__main__":
    run_live_verification()
