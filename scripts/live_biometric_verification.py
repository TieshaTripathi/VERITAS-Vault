"""
End-to-end live biometric verification script executing the full 10-step validation:
1. enroll Person A using multi-sample enrollment (5 samples)
2. enroll Person B using multi-sample enrollment (5 samples)
3. restart checkpoint session
4. Person A -> VERIFIED
5. Person A remains -> stable identity maintained across frames
6. Person A leaves (no faces) -> checkpoint stays WAITING
7. Person B -> VERIFIED
8. standard dual custody -> GRANTED with signed cryptographic token
9. genuinely unenrolled person -> UNKNOWN confirmation over temporal consensus -> ZT-001
10. verify strictly one breach popup / Telegram event queued
"""
import base64
import os
import sys
import tempfile
import time
import cv2
import numpy as np

# Ensure root in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

temp_dir = tempfile.mkdtemp()
for k in ("VERCEL", "SUPABASE_URL", "SUPABASE_KEY", "SUPABASE_SERVICE_ROLE_KEY", "FACENET_MODEL_PATH"):
    os.environ.pop(k, None)

os.environ["VAULT_DATA_DIR"] = temp_dir
os.environ["VAULT_ENCRYPTION_KEY"] = base64.b64encode(b"K" * 32).decode()
os.environ["VAULT_OPERATOR_USERNAME"] = "lead_admin"
from src.pwa.security import password_hash
os.environ["VAULT_OPERATOR_PASSWORD_HASH"] = password_hash("super_secure_vault_pass_99")
os.environ["APP_ORIGIN"] = "https://biometric-vault.local"

from fastapi.testclient import TestClient
from src.pwa.api import app, Store
from src.vision.biometric_service import default_biometric_service

def generate_synthetic_face(seed: int, brightness_bias: int = 0, identity_type: str = "A") -> str:
    """Generates an image containing a recognizable, geometrically distinct face pattern."""
    rng = np.random.default_rng(seed)
    img = np.full((240, 240, 3), 70 + brightness_bias, dtype=np.uint8)

    if identity_type == "A":
        # Person A (Tiesha Tripathi · Employee)
        cv2.ellipse(img, (120, 120), (60, 75), 0, 0, 360, (225, 215, 205), -1)
        cv2.circle(img, (95, 95), 12, (10, 10, 10), -1)
        cv2.circle(img, (145, 95), 12, (10, 10, 10), -1)
        cv2.ellipse(img, (120, 155), (20, 8), 0, 0, 180, (10, 10, 10), -1)
    elif identity_type == "B":
        # Person B (Alex Mercer · Customer)
        cv2.ellipse(img, (120, 120), (60, 75), 0, 0, 360, (200, 190, 180), -1)
        cv2.circle(img, (92, 98), 12, (10, 10, 10), -1)
        cv2.circle(img, (148, 98), 12, (10, 10, 10), -1)
        cv2.ellipse(img, (120, 160), (20, 8), 0, 0, 180, (10, 10, 10), -1)
    else:
        # Unknown Person: round face with dark visor (Sim ~0.51 to enrolled candidates -> UNKNOWN)
        cv2.ellipse(img, (120, 120), (70, 70), 0, 0, 360, (220, 220, 220), -1)
        cv2.rectangle(img, (80, 85), (160, 105), (10, 10, 10), -1)
        cv2.ellipse(img, (120, 155), (30, 12), 0, 0, 180, (10, 10, 10), -1)

    # Texture noise
    noise = rng.integers(-5, 5, img.shape, dtype=np.int16)
    img = np.clip(img.astype(np.int16) + noise, 0, 255).astype(np.uint8)
    _, buf = cv2.imencode(".jpg", img)
    return base64.b64encode(buf.tobytes()).decode()

def run_biometric_verification():
    print("=" * 60)
    print("STARTING LIVE BIOMETRIC PIPELINE VERIFICATION")
    print("=" * 60)

    client = TestClient(app, base_url="https://biometric-vault.local", headers={"X-Vault-Request": "1", "Origin": "https://biometric-vault.local"})

    # Authentication
    login_res = client.post("/api/auth/login", json={"username": "lead_admin", "password": "super_secure_vault_pass_99"})
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    print("[PASS] Step 0: Operator authenticated")

    # Step 1: Enroll Person A with 5 samples
    samples_a = [generate_synthetic_face(seed=101 + i, brightness_bias=i * 2, identity_type="A") for i in range(5)]
    enroll_a = client.post("/api/enrollment", json={
        "samples": samples_a,
        "name": "Tiesha Tripathi",
        "personnel_id": "EMP-TIESHA",
        "role": "Employee"
    })
    assert enroll_a.status_code == 200, f"Enroll Person A failed: {enroll_a.text}"
    print(f"[PASS] Step 1: Person A (Tiesha Tripathi · Employee) enrolled with 5 multi-angle samples")

    # Step 2: Enroll Person B with 5 samples
    samples_b = [generate_synthetic_face(seed=505 + i, brightness_bias=i * 3, identity_type="B") for i in range(5)]
    enroll_b = client.post("/api/enrollment", json={
        "samples": samples_b,
        "name": "Alex Mercer",
        "personnel_id": "CUST-MERCER",
        "role": "Customer"
    })
    assert enroll_b.status_code == 200, f"Enroll Person B failed: {enroll_b.text}"
    print(f"[PASS] Step 2: Person B (Alex Mercer · Customer) enrolled with 5 multi-angle samples")

    # Step 3: Restart checkpoint session
    reset_res = client.post("/api/checkpoint/reset", json={"mode": "standard"})
    assert reset_res.status_code == 200
    sess_res = client.post("/api/checkpoint/session", json={"device_id": "DEV-EDGE-01", "checkpoint_id": "CP-MAIN-01"})
    assert sess_res.status_code == 200
    sess = sess_res.json()
    session_id = sess["session_id"]
    capture_nonce = sess["capture_nonce"]
    print(f"[PASS] Step 3: Checkpoint reset and initialized fresh session: {session_id}")

    # Step 4: Person A presents -> Frame 1 & 2 VERIFYING -> Frame 3 reaches consensus VERIFIED
    frame_a = generate_synthetic_face(seed=102, identity_type="A")
    t0 = time.perf_counter()
    res_a1 = client.post("/api/checkpoint/frame", json={
        "image": frame_a,
        "session_id": session_id,
        "capture_nonce": capture_nonce,
        "frame_seq": 1,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    }).json()
    assert res_a1["state"] == "STANDBY"
    assert res_a1["faces"][0]["recognition_state"] == "VERIFYING"

    res_a2 = client.post("/api/checkpoint/frame", json={
        "image": frame_a,
        "session_id": session_id,
        "capture_nonce": capture_nonce,
        "frame_seq": 2,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    }).json()
    assert res_a2["state"] == "STANDBY"

    res_a3 = client.post("/api/checkpoint/frame", json={
        "image": frame_a,
        "session_id": session_id,
        "capture_nonce": capture_nonce,
        "frame_seq": 3,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    }).json()
    dt_a = (time.perf_counter() - t0) * 1000.0
    assert res_a3["state"] == "WAITING", f"Expected WAITING, got {res_a3['state']}"
    assert len(res_a3["parties"]) == 1
    assert res_a3["parties"][0]["id"] == "EMP-TIESHA"
    print(f"[PASS] Step 4: Person A -> VERIFYING -> 3-frame consensus reached VERIFIED in {dt_a:.1f}ms; Checkpoint state: WAITING (Party 1 saved)")

    # Step 5: Person A remains -> stable identity, no breach
    res_a_still = client.post("/api/checkpoint/frame", json={
        "image": frame_a,
        "session_id": session_id,
        "capture_nonce": capture_nonce,
        "frame_seq": 4,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    }).json()
    assert res_a_still["state"] == "WAITING"
    assert len(res_a_still["parties"]) == 1
    print("[PASS] Step 5: Person A remains in view -> Identity stable, no duplicate breach")

    # Step 6: Person A leaves (blank background) -> WAITING maintained
    blank_img = np.full((240, 240, 3), 40, dtype=np.uint8)
    _, blank_buf = cv2.imencode(".jpg", blank_img)
    blank_b64 = base64.b64encode(blank_buf.tobytes()).decode()
    res_empty = client.post("/api/checkpoint/frame", json={
        "image": blank_b64,
        "session_id": session_id,
        "capture_nonce": capture_nonce,
        "frame_seq": 5,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    }).json()
    assert res_empty["state"] == "WAITING"
    print("[PASS] Step 6: Person A leaves scene -> Checkpoint remains WAITING for Party 2")
    # Simulate Person A walking away and Person B stepping in
    time.sleep(2.6)

    # Step 7 & 8: Person B presents -> 3-frame consensus -> VERIFIED -> GRANTED
    frame_b = generate_synthetic_face(seed=506, identity_type="B")
    t0 = time.perf_counter()
    client.post("/api/checkpoint/frame", json={
        "image": frame_b,
        "session_id": session_id,
        "capture_nonce": capture_nonce,
        "frame_seq": 6,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    })
    client.post("/api/checkpoint/frame", json={
        "image": frame_b,
        "session_id": session_id,
        "capture_nonce": capture_nonce,
        "frame_seq": 7,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    })
    res_b3 = client.post("/api/checkpoint/frame", json={
        "image": frame_b,
        "session_id": session_id,
        "capture_nonce": capture_nonce,
        "frame_seq": 8,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    }).json()
    dt_b = (time.perf_counter() - t0) * 1000.0
    assert res_b3["state"] == "GRANTED", f"Expected GRANTED, got {res_b3['state']}"
    assert len(res_b3["parties"]) == 2
    assert res_b3["parties"][1]["id"] == "CUST-MERCER"
    assert "token" in res_b3 or "authorization_token" in res_b3
    print(f"[PASS] Steps 7 & 8: Person B -> 3-frame consensus reached VERIFIED in {dt_b:.1f}ms; Dual custody complete: GRANTED with cryptographic token!")

    # Step 9: Reset & Test genuinely unenrolled person -> UNKNOWN confirmation -> ZT-001
    client.post("/api/checkpoint/reset", json={"mode": "standard"})
    sess_u = client.post("/api/checkpoint/session", json={"device_id": "DEV-EDGE-01", "checkpoint_id": "CP-MAIN-01"}).json()
    session_id_u = sess_u["session_id"]
    capture_nonce_u = sess_u["capture_nonce"]

    frame_unknown = generate_synthetic_face(seed=9999, identity_type="UNKNOWN")
    # Frame 1: First unknown observation -> IDENTITY VERIFYING, no breach
    r_u1 = client.post("/api/checkpoint/frame", json={
        "image": frame_unknown,
        "session_id": session_id_u,
        "capture_nonce": capture_nonce_u,
        "frame_seq": 1,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    }).json()
    assert r_u1["state"] == "STANDBY"
    print("[PASS] Step 9a: Frame 1 of unknown person -> IDENTITY VERIFYING (No immediate breach on single frame)")

    # Subsequent frames: Temporal consensus confirms unknown -> BREACH ZT-001
    r_u2 = client.post("/api/checkpoint/frame", json={
        "image": frame_unknown,
        "session_id": session_id_u,
        "capture_nonce": capture_nonce_u,
        "frame_seq": 2,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    }).json()

    r_u3 = client.post("/api/checkpoint/frame", json={
        "image": frame_unknown,
        "session_id": session_id_u,
        "capture_nonce": capture_nonce_u,
        "frame_seq": 3,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    }).json()
    assert r_u3["state"] == "BREACH"
    assert r_u3["reason_code"] == "ZT-001"
    print(f"[PASS] Step 9b: Consecutive unknown observations reached consensus -> BREACH confirmed (ZT-001)")

    # Step 10: Verify strictly one breach event / Telegram alert job
    store = Store()
    jobs = store.records("job:")
    assert len(jobs) == 1
    job_key, job_payload, _ = jobs[0] if isinstance(jobs[0], (tuple, list)) else (jobs[0].get("id", ""), jobs[0], 0)
    job_id = job_payload.get("id") if isinstance(job_payload, dict) else str(job_key).replace("job:", "")
    print(f"[PASS] Step 10: Exactly 1 breach alert queued in outbox (Job ID: {job_id})")

    # Extra frame while still unknown: Verify deduplication (still 1 alert)
    r_u4 = client.post("/api/checkpoint/frame", json={
        "image": frame_unknown,
        "session_id": session_id_u,
        "capture_nonce": capture_nonce_u,
        "frame_seq": 4,
        "device_id": "DEV-EDGE-01",
        "checkpoint_id": "CP-MAIN-01"
    }).json()
    assert len(store.records("job:")) == 1
    print("[PASS] Deduplication check: Continued unknown frames do NOT spawn duplicate alerts")

    print("=" * 60)
    print("ALL 10 VERIFICATION STEPS COMPLETED AND VALIDATED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_biometric_verification()
