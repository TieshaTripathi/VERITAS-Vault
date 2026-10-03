import os
import sys
import time
import numpy as np
import cv2
import pytest

# Ensure root directory in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.storage.db import (
    init_db, insert_user, get_all_users, delete_user,
    log_access_event, get_recent_logs, record_diagnostic, db_instance
)
from src.blockchain.crypto_utils import compute_raw_frame_hash, encrypt_frame_aes_gcm
from src.vision.liveness import estimate_liveness, LivenessEstimator
from src.vision.biometrics import (
    enroll_face, recognize_faces, FaceRecognizerPipeline, KNOWN_FACES_DIR
)
from src.vision.auto_capture import is_face_stable, AutoCaptureEngine
from src.daemon.alerts import send_sms_alert, test_sms_alert, format_alert_message
from src.policy.engine import evaluate_access, TwoManPolicyEngine, PolicyState
from src.diagnostics.boot import run_system_diagnostics, BootDiagnostics


def test_storage_subsystem():
    print("Testing storage subsystem...")
    init_db()

    # 1. Test insert user with feature vector
    dummy_img_path = os.path.join(KNOWN_FACES_DIR, "test_alice.jpg")
    dummy_vec = np.ones((128, 128), dtype=np.uint8).tobytes()
    user_id = insert_user(
        name="Test Alice",
        role="Employee",
        image_path=dummy_img_path,
        feature_vector=dummy_vec
    )
    assert user_id != "", "User ID should be returned"

    # 2. Test get all users
    users = get_all_users()
    assert any(u["user_id"] == user_id for u in users), "Inserted user should be in user list"

    # 3. Test log access event
    success = log_access_event(
        mode="Standard Locker Access",
        parties="Test Alice (Employee)",
        verdict="ACCESS GRANTED",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        enc_path="data/encrypted_evidence/test.enc"
    )
    assert success is True

    # 4. Test get recent logs
    logs = get_recent_logs(limit=20)
    assert len(logs) > 0
    assert "sha256_hash" in logs[0]
    assert "status" in logs[0]

    # 5. Test record diagnostic
    diag_ok = record_diagnostic("Unit Test Subsystem", "PASS", "Self-test details")
    assert diag_ok is True

    # 6. Test delete user
    del_ok = delete_user(user_id)
    assert del_ok is True
    print("[PASS] Storage subsystem PASSED")


def test_crypto_pipeline():
    print("Testing crypto pipeline...")
    # 1. Raw buffer hash
    test_bytes = b"VERITAS_TEST_FRAME_BUFFER_12345"
    digest = compute_raw_frame_hash(test_bytes)
    assert len(digest) == 64, "SHA-256 digest should be 64 hex chars"

    # 2. Numpy frame hash
    np_frame = np.zeros((100, 100, 3), dtype=np.uint8)
    np_digest = compute_raw_frame_hash(np_frame)
    assert len(np_digest) == 64

    # 3. AES-GCM encryption
    ciphertext, enc_path = encrypt_frame_aes_gcm(test_bytes)
    assert os.path.exists(enc_path)
    assert len(ciphertext) > len(test_bytes)
    print("[PASS] Crypto pipeline PASSED")


def test_liveness_estimation():
    print("Testing liveness estimation...")
    # 1. Empty frame
    is_live, conf = estimate_liveness(np.array([]))
    assert is_live is False
    assert conf == 0.0

    # 2. Flat/low texture frame (Laplacian variance < 60.0 -> Spoof attempt)
    flat_frame = np.ones((100, 100, 3), dtype=np.uint8) * 128
    is_live, conf = estimate_liveness(flat_frame)
    assert is_live is False
    assert conf < 0.60

    # 3. Simulated realistic textured face frame
    np.random.seed(42)
    textured_crop = np.random.randint(40, 220, (120, 120, 3), dtype=np.uint8)
    is_live, conf = estimate_liveness(textured_crop, threshold=0.80)
    assert 0.0 <= conf <= 1.0
    print("[PASS] Liveness estimation PASSED")


def test_biometrics_enroll_and_recognize():
    print("Testing biometrics enroll and recognize...")
    for u in get_all_users():
        delete_user(u["user_id"])

    dummy_frame = np.zeros((200, 200, 3), dtype=np.uint8)
    recs = recognize_faces(dummy_frame)
    assert recs == []

    test_face = np.ones((200, 200, 3), dtype=np.uint8) * 120
    cv2.circle(test_face, (70, 70), 15, (30, 30, 30), -1)
    cv2.circle(test_face, (130, 70), 15, (30, 30, 30), -1)
    cv2.ellipse(test_face, (100, 140), (40, 20), 0, 0, 180, (30, 30, 30), -1)

    ok, uid = enroll_face(test_face, "Test Officer Bob", "Employee")
    assert ok is True
    assert uid.startswith("user_")

    pipeline = FaceRecognizerPipeline(match_threshold=0.82, error_threshold=0.18)
    users = pipeline.get_enrolled_users()
    assert any(u["user_id"] == uid for u in users)

    pipeline.delete_enrolled_user(uid)
    print("[PASS] Biometrics PASSED")


def test_auto_capture_stability():
    print("Testing auto capture stability & fixation engine...")
    # 1. Test is_face_stable with jitter
    bbox1 = (100, 100, 80, 80)
    bbox2_stable = (103, 102, 81, 79)
    bbox3_jitter = (140, 150, 80, 80)

    assert is_face_stable(bbox1, bbox2_stable, threshold=15) is True
    assert is_face_stable(bbox1, bbox3_jitter, threshold=15) is False

    # 2. Test AutoCaptureEngine fixation trigger
    engine = AutoCaptureEngine(stability_threshold_ms=100.0, jitter_threshold=15)
    trig1, dur1, stat1 = engine.process_face_fixation(bbox1)
    assert trig1 is False
    assert stat1 == "TRACKING_INITIATED"

    # Wait 120ms with stable coordinates
    time.sleep(0.12)
    trig2, dur2, stat2 = engine.process_face_fixation(bbox2_stable)
    assert trig2 is True
    assert stat2 == "AUTO_CAPTURE_TRIGGERED"
    print("[PASS] Auto Capture Engine PASSED")


def test_sms_alert_daemon():
    print("Testing SMS alert daemon & fallback logging...")
    # Test formatting
    msg = format_alert_message("BREACH_ATTEMPT", "Spoof detected", "abc1234567890abcdef1234567890")
    assert "VERITAS-VAULT SECURITY ALERT" in msg
    assert "SOLENOID LOCKED" in msg

    # Test send_sms_alert with graceful local fallback logging
    ok = send_sms_alert("TEST_UNIT_ALERT", "Unit test dispatch details", "unit_test_hash_123")
    assert ok is True

    # Verify log entry in SQLite
    logs = get_recent_logs(limit=5)
    assert any(l["mode"] == "EMERGENCY_SMS_DISPATCH" for l in logs)
    print("[PASS] SMS Alert Daemon PASSED")


def test_policy_engine_standard_mode():
    print("Testing policy engine (Standard mode)...")
    session_state = {}

    res = evaluate_access("Standard Locker Access", [], session_state)
    assert res["status"] == "STANDBY"
    assert res["unlocked"] is False

    unauth_face = [{"name": "Intruder", "role": "Unauthorized", "is_recognized": False, "is_authorized": False}]
    res = evaluate_access("Standard Locker Access", unauth_face, session_state)
    assert res["status"] == "BREACH"
    assert res["unlocked"] is False

    emp_face = [{"name": "Alice", "role": "Employee", "is_recognized": True, "is_authorized": True}]
    res = evaluate_access("Standard Locker Access", emp_face, session_state)
    assert res["status"] == "WAITING"
    assert res["remaining"] <= 5.0
    assert res["unlocked"] is False

    cust_face = [{"name": "Charlie", "role": "Customer", "is_recognized": True, "is_authorized": True}]
    res = evaluate_access("Standard Locker Access", cust_face, session_state)
    assert res["status"] == "GRANTED"
    assert res["unlocked"] is True
    print("[PASS] Policy engine Standard mode PASSED")


def test_policy_engine_high_value_mode():
    print("Testing policy engine (High-Value mode)...")
    session_state = {}

    dual_emp = [
        {"name": "Alice", "role": "Employee", "is_recognized": True, "is_authorized": True},
        {"name": "Bob", "role": "Employee", "is_recognized": True, "is_authorized": True}
    ]
    res = evaluate_access("High-Value Inventory Audit", dual_emp, session_state)
    assert res["status"] == "GRANTED"
    assert res["unlocked"] is True
    print("[PASS] Policy engine High-Value mode PASSED")


def test_diagnostics_subsystem():
    print("Testing diagnostics subsystem...")
    summary = run_system_diagnostics()
    assert "checks" in summary
    assert len(summary["checks"]) >= 4
    assert summary["storage"] == "PASS"
    assert summary["vision"] == "PASS"
    assert summary["crypto"] == "PASS"
    assert summary["blockchain"] in ["PASS", "OFFLINE_BUFFER_READY"]
    print("[PASS] Diagnostics subsystem PASSED")


if __name__ == "__main__":
    test_storage_subsystem()
    test_crypto_pipeline()
    test_liveness_estimation()
    test_biometrics_enroll_and_recognize()
    test_auto_capture_stability()
    test_sms_alert_daemon()
    test_policy_engine_standard_mode()
    test_policy_engine_high_value_mode()
    test_diagnostics_subsystem()
    print("\n========================================")
    print("ALL VERITAS-VAULT TESTS PASSED CLEANLY!")
    print("========================================")
