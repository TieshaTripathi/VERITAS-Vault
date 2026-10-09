"""
Comprehensive Test Suite for VERITAS-Vault Biometric Pipeline Architecture
===========================================================================
Validates:
  1. Enrolled person frontal -> VERIFIED
  2. Enrolled person slight pose / angle -> VERIFIED
  3. One weak / blurry frame -> no breach (stays in current state)
  4. Possible match -> no access authorization granted
  5. 3-frame verified consensus -> VERIFIED
  6. Same face tracked across frames -> stable persistent identity
  7. Unknown person first frame -> VERIFYING (no premature breach)
  8. Repeated unknown (3 consecutive) -> ZT-001 confirmed breach
  9. PAD one-frame fail -> no breach (LIVENESS CHECKING)
 10. Repeated PAD fail (3 consecutive) -> ZT-002 confirmed breach
 11. Dual custody: Employee verified -> WAITING, Employee leaves -> WAITING,
     Customer verified -> GRANTED
 12. Same Employee again in WAITING -> remains WAITING (no breach, duplicate warning)
"""
import base64
import os
import sys
import time
import uuid
import cv2
import numpy as np
import pytest

from fastapi.testclient import TestClient

from src.policy.capture_session import default_capture_manager
from src.pwa.api import app, Store, fresh
from src.pwa.policy import advance, fresh as fresh_policy
from src.pwa.security import password_hash
from src.vision.config import BiometricConfig, default_biometric_config
from src.vision.face_detection import DetectedFace, OpenCVFaceDetector
from src.vision.face_embedding import (
    aggregate_embeddings,
    get_default_embedding_extractor,
    normalize_vector,
)
from src.vision.face_matcher import (
    BiometricMatchResult,
    EnrolledIdentity,
    RecognitionState,
    match_embedding,
)
from src.vision.face_quality import evaluate_quality
from src.vision.face_tracking import FaceTrack, FaceTracker
from src.vision.biometric_service import BiometricService, default_biometric_service


@pytest.fixture
def test_env(tmp_path, monkeypatch):
    for key in ("VERCEL", "SUPABASE_URL", "SUPABASE_KEY", "SUPABASE_SERVICE_ROLE_KEY", "FACENET_MODEL_PATH"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", base64.b64encode(b"B" * 32).decode())
    monkeypatch.setenv("VAULT_OPERATOR_USERNAME", "admin")
    monkeypatch.setenv("VAULT_OPERATOR_PASSWORD_HASH", password_hash("adminpass123"))
    monkeypatch.setenv("APP_ORIGIN", "https://testvault")

    default_biometric_service.invalidate_cache()
    client = TestClient(app, base_url="https://testvault", headers={"X-Vault-Request": "1", "Origin": "https://testvault"})
    login_res = client.post("/api/auth/login", json={"username": "admin", "password": "adminpass123"})
    assert login_res.status_code == 200
    return client, tmp_path


def make_synthetic_face(val=120, noise=0.0):
    """Generates a synthetic 120x120 face crop with eyes and mouth."""
    img = np.full((120, 120, 3), val, dtype=np.uint8)
    cv2.circle(img, (40, 45), 10, (20, 20, 20), -1)
    cv2.circle(img, (80, 45), 10, (20, 20, 20), -1)
    cv2.ellipse(img, (60, 85), (25, 12), 0, 0, 180, (20, 20, 20), -1)
    if noise > 0:
        rng = np.random.default_rng(42)
        n = rng.normal(0, noise, img.shape).astype(np.int16)
        img = np.clip(img.astype(np.int16) + n, 0, 255).astype(np.uint8)
    return img


# 1. Enrolled person frontal -> VERIFIED
def test_biometric_frontal_face_verified():
    extractor = get_default_embedding_extractor()
    face = make_synthetic_face(140)
    emb = extractor.extract_embedding(face)

    identity = EnrolledIdentity(
        id="EMP-01",
        name="Alice Engineer",
        role="Employee",
        identity_embedding=emb,
        representative_embeddings=[emb],
        model_version="v2.0"
    )
    enrolled = {"EMP-01": identity}

    match = match_embedding(emb, enrolled)
    assert match.state == RecognitionState.VERIFIED
    assert match.candidate_id == "EMP-01"
    assert match.similarity >= 0.70


# 2. Enrolled person slight pose / noise -> VERIFIED
def test_biometric_pose_variation_verified():
    extractor = get_default_embedding_extractor()
    samples = [
        make_synthetic_face(140),
        make_synthetic_face(135, noise=5.0),
        make_synthetic_face(145, noise=8.0),
        make_synthetic_face(138),
        make_synthetic_face(142)
    ]
    raw_embs = [extractor.extract_embedding(s) for s in samples]
    id_emb, rep_embs = aggregate_embeddings(raw_embs)

    identity = EnrolledIdentity(
        id="EMP-01",
        name="Alice Engineer",
        role="Employee",
        identity_embedding=id_emb,
        representative_embeddings=rep_embs,
        model_version="v2.0"
    )
    enrolled = {"EMP-01": identity}

    # Query with slight pose/noise probe
    probe = make_synthetic_face(136, noise=6.0)
    probe_emb = extractor.extract_embedding(probe)
    match = match_embedding(probe_emb, enrolled)
    assert match.state == RecognitionState.VERIFIED
    assert match.candidate_id == "EMP-01"


# 3. One weak / blurry frame -> no breach (stays in current state)
def test_weak_frame_no_breach():
    st = fresh_policy("standard")
    # Face currently arbitrated as VERIFYING
    face = [{
        "id": "unknown",
        "name": "Verifying Identity...",
        "role": "Evaluating Clearance",
        "is_recognized": False,
        "is_live": True,
        "recognition_state": "VERIFYING",
        "similarity": 0.40
    }]
    res, terminal = advance(st, face, time.time())
    assert terminal is False
    assert res["state"] == "STANDBY"
    assert "HOLD STILL" in res.get("safe_user_message", "")


# 4. Possible match -> no access authorization
def test_possible_match_no_access():
    st = fresh_policy("standard")
    face = [{
        "id": "EMP-01",
        "name": "Alice Engineer",
        "role": "Employee",
        "is_recognized": False,
        "is_live": True,
        "recognition_state": "POSSIBLE_MATCH",
        "candidate_name": "Alice Engineer",
        "similarity": 0.62
    }]
    res, terminal = advance(st, face, time.time())
    assert terminal is False
    assert res["state"] == "STANDBY"
    assert len(res["parties"]) == 0
    assert "POSSIBLE MATCH" in res.get("safe_user_message", "")


# 5. 3-frame verified consensus -> VERIFIED
def test_three_frame_verified_consensus():
    tracker = FaceTracker()
    box = (50, 50, 80, 80)
    detected = [DetectedFace(bbox=box, crop=np.zeros((80, 80, 3), dtype=np.uint8))]

    tracks = tracker.update_tracks(detected, now=100.0)
    track = tracks[0][1]

    match_good = BiometricMatchResult(
        state=RecognitionState.VERIFIED,
        candidate_id="EMP-01",
        candidate_name="Alice",
        candidate_role="Employee",
        similarity=0.88,
        threshold=0.70,
        is_verified=True
    )

    # Frame 1: 1st observation -> VERIFYING
    track.record_observation(match_good, is_live=True, now=100.0, config=default_biometric_config)
    assert track.consensus_verdict == "VERIFYING"

    # Frame 2: 2nd observation -> VERIFYING
    track.record_observation(match_good, is_live=True, now=101.0, config=default_biometric_config)
    assert track.consensus_verdict == "VERIFYING"

    # Frame 3: 3rd observation -> VERIFIED consensus achieved!
    track.record_observation(match_good, is_live=True, now=102.0, config=default_biometric_config)
    assert track.consensus_verdict == "VERIFIED"
    assert track.confirmed_identity["id"] == "EMP-01"


# 6. Same face tracked across frames -> stable persistent identity
def test_same_face_tracked_stable_identity():
    tracker = FaceTracker()
    box1 = (50, 50, 80, 80)
    face1 = DetectedFace(bbox=box1, crop=np.zeros((80, 80, 3), dtype=np.uint8))
    
    # Frame 1
    t1 = tracker.update_tracks([face1], now=100.0)[0][1]
    track_id = t1.track_id
    assert track_id.startswith("TRACK-")

    # Frame 2 with small movement (dx=4, dy=3)
    box2 = (54, 53, 80, 80)
    face2 = DetectedFace(bbox=box2, crop=np.zeros((80, 80, 3), dtype=np.uint8))
    t2 = tracker.update_tracks([face2], now=100.5)[0][1]
    assert t2.track_id == track_id  # Preserves identical track ID!


# 7. Unknown person first frame -> VERIFYING (no premature breach)
def test_unknown_first_frame_verifying():
    track = FaceTrack("TRACK-01", (50, 50, 80, 80), now=100.0)
    match_unknown = BiometricMatchResult(
        state=RecognitionState.UNKNOWN,
        candidate_id=None,
        candidate_name="Unknown",
        candidate_role="Unauthorized",
        similarity=0.20,
        threshold=0.70,
        is_verified=False
    )
    track.record_observation(match_unknown, is_live=True, now=100.0, config=default_biometric_config)
    assert track.consensus_verdict == "VERIFYING"  # NOT a breach yet!


# 8. Repeated unknown (3 consecutive) -> ZT-001 confirmed breach
def test_repeated_unknown_breach():
    track = FaceTrack("TRACK-01", (50, 50, 80, 80), now=100.0)
    match_unknown = BiometricMatchResult(
        state=RecognitionState.UNKNOWN,
        candidate_id=None,
        candidate_name="Unknown",
        candidate_role="Unauthorized",
        similarity=0.20,
        threshold=0.70,
        is_verified=False
    )
    track.record_observation(match_unknown, is_live=True, now=100.0, config=default_biometric_config)
    track.record_observation(match_unknown, is_live=True, now=101.0, config=default_biometric_config)
    assert track.consensus_verdict == "VERIFYING"

    # 3rd consecutive unknown confirms breach
    track.record_observation(match_unknown, is_live=True, now=102.0, config=default_biometric_config)
    assert track.consensus_verdict == "UNKNOWN_CONFIRMED"

    # Policy transitions to ZT-001
    st = fresh_policy("standard")
    res, terminal = advance(st, [{
        "id": "unknown",
        "is_recognized": False,
        "is_live": True,
        "recognition_state": "UNKNOWN_CONFIRMED"
    }], time.time())
    assert res["state"] == "BREACH"
    assert res["reason_code"] == "ZT-001"
    assert terminal is True


# 9. PAD one-frame fail -> no breach (LIVENESS CHECKING)
def test_pad_one_frame_fail_no_breach():
    track = FaceTrack("TRACK-01", (50, 50, 80, 80), now=100.0)
    match_good = BiometricMatchResult(
        state=RecognitionState.VERIFIED, candidate_id="EMP-01", candidate_name="Alice",
        candidate_role="Employee", similarity=0.85, threshold=0.70, is_verified=True
    )
    track.record_observation(match_good, is_live=False, now=100.0, config=default_biometric_config)
    assert track.pad_status == "LIVENESS CHECKING"

    st = fresh_policy("standard")
    res, terminal = advance(st, [{
        "id": "EMP-01",
        "is_recognized": True,
        "is_live": False,
        "liveness": "CHECKING",
        "recognition_state": "VERIFYING"
    }], time.time())
    assert terminal is False
    assert res["state"] == "STANDBY"


# 10. Repeated PAD fail (3 consecutive) -> ZT-002 confirmed breach
def test_repeated_pad_fail_breach():
    track = FaceTrack("TRACK-01", (50, 50, 80, 80), now=100.0)
    match_good = BiometricMatchResult(
        state=RecognitionState.VERIFIED, candidate_id="EMP-01", candidate_name="Alice",
        candidate_role="Employee", similarity=0.85, threshold=0.70, is_verified=True
    )
    track.record_observation(match_good, is_live=False, now=100.0, config=default_biometric_config)
    track.record_observation(match_good, is_live=False, now=101.0, config=default_biometric_config)
    assert track.pad_status == "LIVENESS CHECKING"

    # 3rd consecutive fail
    track.record_observation(match_good, is_live=False, now=102.0, config=default_biometric_config)
    assert track.pad_status == "LIVENESS FAILED"

    st = fresh_policy("standard")
    res, terminal = advance(st, [{
        "id": "EMP-01",
        "is_recognized": True,
        "is_live": False,
        "liveness": "FAIL"
    }], time.time())
    assert res["state"] == "BREACH"
    assert res["reason_code"] == "ZT-002"
    assert terminal is True


# 11 & 12. Dual custody flow & duplicate first party
def test_dual_custody_full_flow():
    st = fresh_policy("standard")
    now = 100.0

    # Step 1: Employee verified -> WAITING
    emp = [{"id": "EMP-01", "name": "Alice", "role": "Employee", "is_recognized": True, "is_live": True}]
    st_waiting, terminal = advance(st, emp, now)
    assert st_waiting["state"] == "WAITING"
    assert terminal is False
    assert len(st_waiting["parties"]) == 1

    # Step 2: Same Employee remains in frame -> still WAITING (no breach, duplicate warning)
    st_dup, terminal = advance(st_waiting, emp, now + 1.0)
    assert st_dup["state"] == "WAITING"
    assert terminal is False
    assert st_dup["duplicate_first_party"] is True
    assert "DIFFERENT PERSON" in st_dup["safe_user_message"]

    # Step 3: Employee leaves -> empty frame -> still WAITING
    st_empty, terminal = advance(st_dup, [], now + 2.0)
    assert st_empty["state"] == "WAITING"
    assert terminal is False

    # Step 4: Customer enters -> GRANTED
    cust = [{"id": "CUST-02", "name": "Bob", "role": "Customer", "is_recognized": True, "is_live": True}]
    st_granted, terminal = advance(st_empty, cust, now + 3.0)
    assert st_granted["state"] == "GRANTED"
    assert terminal is True
    assert len(st_granted["parties"]) == 2
    assert st_granted["parties"][0]["id"] == "EMP-01"
    assert st_granted["parties"][1]["id"] == "CUST-02"
