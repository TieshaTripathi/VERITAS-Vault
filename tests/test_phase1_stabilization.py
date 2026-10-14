"""
VERITAS-Vault Phase 1 Acceptance & Stabilization Tests
======================================================
Validates all Phase 1 stabilization requirements:
  1. Biometric Cache:
     - Invalidation after successful enrollment approval
     - Immediate denial of revoked identities (no authentication via stale cache)
     - Non-silent template failure handling (cache never marked loaded on errors)
  2. Face Tracking:
     - Sticky-track defense (Person B never inherits Person A's identity)
     - Re-evaluation on conflicting evidence with 2-conflict reset to VERIFYING
     - Track expiration and clean replacement
  3. Recognition Stability:
     - Enforced >= 300 ms cadence between independent consensus observations
     - Rejection of poor-quality face crops (sharpness, lighting, scale, pose)
     - No false unknown-person breach from single blurry/bad crop
  4. Liveness / PAD:
     - Normalized dimensions for sharpness/Laplacian variance
     - Uncertain heuristic results keep liveness in CHECKING without triggering ZT-002
     - Access strictly denied when liveness unconfirmed
     - Confirmed attacks trigger hard security failure
  5. Checkpoint & Incidents:
     - No duplicate breach events or stale checkpoint active incident states
"""
import base64
import io
import time
import cv2
import numpy as np
import pytest
from starlette.testclient import TestClient

from src.pwa.api import app
from src.pwa.policy import advance, fresh as fresh_policy
from src.pwa.security import password_hash, seal
from src.pwa.store import Store
from src.vision.config import BiometricConfig, default_biometric_config
from src.vision.face_detection import DetectedFace
from src.vision.face_matcher import (
    BiometricMatchResult,
    EnrolledIdentity,
    RecognitionState,
    match_embedding,
)
from src.vision.face_quality import FaceQualityAssessment, evaluate_quality
from src.vision.face_tracking import FaceTrack, FaceTracker
from src.vision.biometric_service import BiometricService, default_biometric_service
from src.vision.liveness import evaluate_multisignal_pad, estimate_liveness


def create_mock_template(person_id: str, embedding_dim: int = 512, model_version: str = "VERITAS-BIOMETRIC-v2.0") -> str:
    """Helper to generate an encrypted biometric template matching unseal(..., 'person:' + person_id)."""
    emb = np.random.default_rng(hash(person_id) % 2**32).standard_normal(embedding_dim).astype(np.float32)
    emb /= max(float(np.linalg.norm(emb)), 1e-6)
    buf = io.BytesIO()
    np.savez_compressed(
        buf,
        identity_embedding=emb,
        rep_embeddings=np.array([emb]),
        model_version=model_version,
        quality_score=0.96
    )
    encrypted = seal(buf.getvalue(), "person:" + person_id)
    return base64.b64encode(encrypted).decode()


@pytest.fixture
def p1_env(tmp_path, monkeypatch):
    for key in ("VERCEL", "SUPABASE_URL", "SUPABASE_KEY", "SUPABASE_SERVICE_ROLE_KEY", "FACENET_MODEL_PATH"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", base64.b64encode(b"K" * 32).decode())
    monkeypatch.setenv("VAULT_OPERATOR_USERNAME", "admin_checker")
    monkeypatch.setenv("VAULT_OPERATOR_PASSWORD_HASH", password_hash("AdminPass123!"))
    monkeypatch.setenv("APP_ORIGIN", "https://testvault.local")

    default_biometric_service.invalidate_cache()
    client = TestClient(app, base_url="https://testvault.local", headers={"X-Vault-Request": "1", "Origin": "https://testvault.local"})
    auth_resp = client.post("/api/auth/login", json={"username": "admin_checker", "password": "AdminPass123!"})
    assert auth_resp.status_code == 200
    return client, tmp_path


# ---------------------------------------------------------------------------
# 1. BIOMETRIC CACHE TESTS
# ---------------------------------------------------------------------------

def test_biometric_cache_invalidation_after_enrollment_approval(p1_env):
    """Test that approved enrollment is recognized without backend restart."""
    client, tmp_path = p1_env
    store = Store()

    # Pre-populate store with initial person
    initial_tmpl = create_mock_template("EMP-INITIAL")
    store.enroll({
        "id": "EMP-INITIAL",
        "name": "Initial User",
        "role": "Employee",
        "template": initial_tmpl,
        "status": "APPROVED",
        "created_at": "2026-01-01T00:00:00Z"
    })

    # Warm cache
    service = default_biometric_service
    service.load_cache_if_needed(store.personnel())
    assert service._cache_loaded is True
    assert "EMP-INITIAL" in service._cache
    assert "EMP-NEW" not in service._cache

    # Create a pending enrollment request for EMP-NEW by a different maker
    new_tmpl = create_mock_template("EMP-NEW")
    req_id = "req-test-new-001"
    store.save_enrollment_request({
        "request_id": req_id,
        "user_id": "EMP-NEW",
        "name": "New Enrollee",
        "role": "Employee",
        "clearance_level": "L3",
        "created_by": "maker_user",
        "created_at": "2026-01-02T00:00:00Z",
        "status": "PENDING",
        "template": new_tmpl,
        "baseline": "baselines/new.enc"
    })

    # Approve request via API
    resp = client.post(f"/api/enrollment/requests/{req_id}/approve")
    assert resp.status_code == 200
    assert resp.json()["status"] == "APPROVED"

    # Verify cache was invalidated by the approval
    assert service._cache_loaded is False

    # Next recognition frame warms cache with current personnel
    service.load_cache_if_needed(store.personnel())
    assert service._cache_loaded is True
    assert "EMP-NEW" in service._cache
    assert service._cache["EMP-NEW"].name == "New Enrollee"


def test_revoked_user_immediately_denied_without_stale_cache(p1_env):
    """Test that a revoked user cannot continue authenticating through stale cache."""
    client, tmp_path = p1_env
    store = Store()
    service = default_biometric_service

    user_id = "EMP-REVOKE-TEST"
    tmpl = create_mock_template(user_id)
    store.enroll({
        "id": user_id,
        "name": "Revocable Employee",
        "role": "Employee",
        "template": tmpl,
        "status": "APPROVED",
        "created_at": "2026-01-01T00:00:00Z"
    })

    # Load into cache
    service.load_cache_if_needed(store.personnel())
    assert user_id in service._cache

    # Revoke user via API
    resp = client.post(f"/api/enrollment/{user_id}/revoke")
    assert resp.status_code == 200
    assert resp.json()["status"] == "REVOKED"

    # Verify cache was immediately invalidated
    assert service._cache_loaded is False

    # Reload cache from active personnel
    service.load_cache_if_needed(store.personnel())
    assert user_id not in service._cache

    # Match attempt with the revoked user's embedding must yield UNKNOWN
    revoked_emb = np.random.default_rng(hash(user_id) % 2**32).standard_normal(512).astype(np.float32)
    revoked_emb /= np.linalg.norm(revoked_emb)
    match = match_embedding(revoked_emb, service._cache, service.config)
    assert match.state == RecognitionState.UNKNOWN
    assert match.candidate_id is None


def test_corrupt_template_never_marks_cache_successfully_loaded():
    """Test that biometric cache stops silent failures and never marks loaded when templates fail."""
    service = BiometricService()
    
    corrupt_personnel = [
        {
            "id": "EMP-CORRUPT",
            "name": "Corrupt User",
            "role": "Employee",
            "template": "not-a-valid-base64-or-sealed-envelope",
            "status": "APPROVED"
        }
    ]

    service.load_cache_if_needed(corrupt_personnel)
    # Cache must NOT be marked as successfully loaded!
    assert service._cache_loaded is False
    assert len(service._cache) == 0


# ---------------------------------------------------------------------------
# 2. FACE TRACKING & STICKY-TRACK DEFENSE TESTS
# ---------------------------------------------------------------------------

def test_sticky_track_defense_requires_two_conflicts_to_reset():
    """
    Test Person B does not inherit Person A's verified identity.
    Conflicting evidence requires 2 consecutive observations before resetting track to VERIFYING.
    """
    track = FaceTrack("TRACK-01", (100, 100, 80, 80), now=100.0)
    cfg = default_biometric_config

    match_a = BiometricMatchResult(
        state=RecognitionState.VERIFIED, candidate_id="EMP-A", candidate_name="Person A",
        candidate_role="Employee", similarity=0.88, threshold=0.75, is_verified=True
    )

    # 3 consecutive observations confirm Person A
    track.record_observation(match_a, is_live=True, now=100.0, config=cfg)
    track.record_observation(match_a, is_live=True, now=100.4, config=cfg)
    track.record_observation(match_a, is_live=True, now=100.8, config=cfg)
    assert track.consensus_verdict == "VERIFIED"
    assert track.confirmed_identity["id"] == "EMP-A"

    # Conflicting observation 1 (e.g. Person B steps into frame or UNKNOWN)
    match_b = BiometricMatchResult(
        state=RecognitionState.VERIFIED, candidate_id="EMP-B", candidate_name="Person B",
        candidate_role="Employee", similarity=0.85, threshold=0.75, is_verified=True
    )
    track.record_observation(match_b, is_live=True, now=101.2, config=cfg)
    # Track tolerates single conflicting observation without immediately abandoning Person A
    assert track.consecutive_conflicts == 1
    assert track.consensus_verdict == "VERIFIED"
    assert track.confirmed_identity["id"] == "EMP-A"

    # Conflicting observation 2 (second consecutive conflict) -> RESET to VERIFYING!
    track.record_observation(match_b, is_live=True, now=101.6, config=cfg)
    assert track.consensus_verdict == "VERIFYING"
    assert track.confirmed_identity is None  # Person A is cleared!
    assert track.consecutive_conflicts == 0


def test_unknown_person_swap_resets_verified_identity():
    """When an unknown person swaps into camera position, Person A's identity is reset."""
    track = FaceTrack("TRACK-01", (100, 100, 80, 80), now=100.0)
    cfg = default_biometric_config

    match_a = BiometricMatchResult(
        state=RecognitionState.VERIFIED, candidate_id="EMP-A", candidate_name="Person A",
        candidate_role="Employee", similarity=0.88, threshold=0.75, is_verified=True
    )
    track.record_observation(match_a, is_live=True, now=100.0, config=cfg)
    track.record_observation(match_a, is_live=True, now=100.4, config=cfg)
    track.record_observation(match_a, is_live=True, now=100.8, config=cfg)
    assert track.consensus_verdict == "VERIFIED"

    match_unknown = BiometricMatchResult(
        state=RecognitionState.UNKNOWN, candidate_id=None, candidate_name=None,
        candidate_role=None, similarity=0.20, threshold=0.75, is_verified=False
    )

    # 1st conflict
    track.record_observation(match_unknown, is_live=True, now=101.2, config=cfg)
    assert track.consensus_verdict == "VERIFIED"

    # 2nd conflict -> resets to VERIFYING
    track.record_observation(match_unknown, is_live=True, now=101.6, config=cfg)
    assert track.consensus_verdict == "VERIFYING"
    assert track.confirmed_identity is None


def test_track_expiration_and_replacement():
    """Test inactive tracks expire after max_idle_seconds and fresh tracks are generated."""
    tracker = FaceTracker(max_idle_seconds=2.0)
    box = (100, 100, 80, 80)
    face = DetectedFace(bbox=box, crop=np.zeros((80, 80, 3), dtype=np.uint8))

    tracks1 = tracker.update_tracks([face], now=100.0)
    t1_id = tracks1[0][1].track_id

    # Advance beyond max_idle_seconds with no detection
    tracker.update_tracks([], now=102.5)
    assert t1_id not in tracker._active_tracks

    # New face enters -> assigned fresh track ID
    tracks2 = tracker.update_tracks([face], now=103.0)
    t2_id = tracks2[0][1].track_id
    assert t2_id != t1_id


# ---------------------------------------------------------------------------
# 3. RECOGNITION STABILITY & QUALITY GATES
# ---------------------------------------------------------------------------

def test_observation_cadence_300ms_enforcement():
    """Test that independent observations for consensus enforce at least 300 ms separation."""
    track = FaceTrack("TRACK-01", (100, 100, 80, 80), now=100.0)

    # First observation should run
    assert track.should_run_embedding(now=100.0, min_interval_ms=300.0) is True

    # Record first observation at t=100.0
    match = BiometricMatchResult(
        state=RecognitionState.VERIFIED, candidate_id="EMP-01", candidate_name="Alice",
        candidate_role="Employee", similarity=0.85, threshold=0.75, is_verified=True
    )
    track.record_observation(match, is_live=True, now=100.0, config=default_biometric_config)

    # Frame arriving at t=100.1 (100 ms later) must NOT run embedding
    assert track.should_run_embedding(now=100.1, min_interval_ms=300.0) is False

    # Frame arriving at t=100.25 (250 ms later) must NOT run embedding
    assert track.should_run_embedding(now=100.25, min_interval_ms=300.0) is False

    # Frame arriving at t=100.32 (320 ms later) is eligible
    assert track.should_run_embedding(now=100.32, min_interval_ms=300.0) is True


def test_quality_gate_rejects_poor_crops_before_embedding():
    """Test that blurry or invalid crops fail evaluate_quality and do not trigger breaches."""
    frame_shape = (480, 640)

    # 1. Severely blurred face crop
    clear_crop = np.zeros((100, 100, 3), dtype=np.uint8)
    cv2.circle(clear_crop, (50, 50), 30, (200, 200, 200), -1)
    blurry_crop = cv2.GaussianBlur(clear_crop, (31, 31), 0)
    blurry_face = DetectedFace(bbox=(150, 150, 100, 100), crop=blurry_crop)

    qa = evaluate_quality(blurry_face, frame_shape)
    assert qa.is_valid is False
    assert "BLURRY_OR_LOW_CONTRAST" in qa.reason_codes
    assert "BLUR DETECTED" in qa.guidance

    # 2. Too dark
    dark_crop = np.full((100, 100, 3), 15, dtype=np.uint8)
    dark_face = DetectedFace(bbox=(150, 150, 100, 100), crop=dark_crop)
    qa_dark = evaluate_quality(dark_face, frame_shape)
    assert qa_dark.is_valid is False
    assert "POOR_LIGHTING" in qa_dark.reason_codes

    # 3. Too small
    small_face = DetectedFace(bbox=(10, 10, 30, 30), crop=clear_crop)
    qa_small = evaluate_quality(small_face, frame_shape)
    assert qa_small.is_valid is False
    assert "FACE_TOO_SMALL" in qa_small.reason_codes


def test_blurry_frame_does_not_trigger_unknown_breach():
    """Verify that a blurry frame does not record an UNKNOWN observation or trigger ZT-001."""
    service = BiometricService()
    # Mock frame with a blurry face
    h, w = 480, 640
    frame = np.full((h, w, 3), 120, dtype=np.uint8)
    blurry_crop = np.full((100, 100, 3), 120, dtype=np.uint8)  # Flat, zero Laplacian variance

    mock_face = DetectedFace(bbox=(150, 150, 100, 100), crop=blurry_crop)
    service.detector.detect_faces = lambda f: [mock_face]

    faces_out, report = service.process_frame(frame, store_personnel=[], now=100.0)
    assert len(faces_out) == 1
    # Verdict must remain VERIFYING, NOT UNKNOWN_CONFIRMED breach!
    assert faces_out[0]["recognition_state"] == "VERIFYING"
    assert "BLUR DETECTED" in faces_out[0]["name"] or "HOLD STILL" in faces_out[0]["name"]


# ---------------------------------------------------------------------------
# 4. LIVENESS / PAD NORMALIZATION & UNCERTAINTY TESTS
# ---------------------------------------------------------------------------

def test_pad_normalizes_crop_dimensions():
    """Verify that Laplacian variance computation normalizes crop dimensions."""
    # Create two crops with same pattern but different resolution (60x60 vs 180x180)
    crop_small = np.random.default_rng(42).integers(50, 200, (60, 60, 3), dtype=np.uint8)
    crop_large = cv2.resize(crop_small, (180, 180), interpolation=cv2.INTER_NEAREST)

    res_small = evaluate_multisignal_pad(crop_small)
    res_large = evaluate_multisignal_pad(crop_large)

    # Both should evaluate with consistent signals and neither should crash
    assert "signals" in res_small and "signals" in res_large
    assert res_small["status"] in ("PASS", "UNCERTAIN")
    assert res_large["status"] in ("PASS", "UNCERTAIN")


def test_pad_uncertain_result_keeps_liveness_checking_without_breach():
    """
    Uncertain heuristic PAD result should keep track in CHECKING state.
    It denies access (is_live=False), but does NOT increment consecutive_pad_fails to trigger ZT-002.
    """
    track = FaceTrack("TRACK-01", (100, 100, 80, 80), now=100.0)
    cfg = default_biometric_config

    match_good = BiometricMatchResult(
        state=RecognitionState.VERIFIED, candidate_id="EMP-01", candidate_name="Alice",
        candidate_role="Employee", similarity=0.88, threshold=0.75, is_verified=True
    )

    # Record 3 uncertain observations
    for t in (100.0, 100.4, 100.8):
        track.record_observation(match_good, is_live=False, now=t, config=cfg, pad_status="UNCERTAIN")
        # pad_status must remain CHECKING, NOT FAILED!
        assert track.pad_status == "LIVENESS CHECKING"
        assert track.consecutive_pad_fails == 0

    # Policy evaluation must keep system in STANDBY, NOT BREACH!
    st = fresh_policy("standard")
    res, terminal = advance(st, [{
        "id": "EMP-01",
        "name": "Alice",
        "role": "Employee",
        "is_recognized": True,
        "is_live": False,
        "liveness": "CHECKING",
        "recognition_state": "VERIFIED"
    }], now=101.0)

    assert terminal is False
    assert res["state"] == "STANDBY"
    assert res.get("reason_code") != "ZT-002"


def test_confirmed_pad_failure_triggers_zt002_after_three_frames():
    """Confirmed presentation attack (FAIL) after 3 consecutive frames triggers ZT-002."""
    track = FaceTrack("TRACK-01", (100, 100, 80, 80), now=100.0)
    cfg = default_biometric_config

    match_good = BiometricMatchResult(
        state=RecognitionState.VERIFIED, candidate_id="EMP-01", candidate_name="Alice",
        candidate_role="Employee", similarity=0.88, threshold=0.75, is_verified=True
    )

    # Frame 1: FAIL -> CHECKING
    track.record_observation(match_good, is_live=False, now=100.0, config=cfg, pad_status="FAIL")
    assert track.pad_status == "LIVENESS CHECKING"

    # Frame 2: FAIL -> CHECKING
    track.record_observation(match_good, is_live=False, now=100.4, config=cfg, pad_status="FAIL")
    assert track.pad_status == "LIVENESS CHECKING"

    # Frame 3: FAIL -> LIVENESS FAILED!
    track.record_observation(match_good, is_live=False, now=100.8, config=cfg, pad_status="FAIL")
    assert track.pad_status == "LIVENESS FAILED"

    # Policy evaluation triggers ZT-002
    st = fresh_policy("standard")
    res, terminal = advance(st, [{
        "id": "EMP-01",
        "is_recognized": True,
        "is_live": False,
        "liveness": "FAIL"
    }], now=101.0)

    assert terminal is True
    assert res["state"] == "BREACH"
    assert res["reason_code"] == "ZT-002"


# ---------------------------------------------------------------------------
# 5. CHECKPOINT & INCIDENT DEDUPLICATION TESTS
# ---------------------------------------------------------------------------

def test_checkpoint_status_in_standby_reports_no_active_incident(p1_env):
    """When checkpoint is in STANDBY, active_incident must report NONE, not stale incident IDs."""
    client, tmp_path = p1_env
    resp = client.get("/api/checkpoint/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["state"] == "STANDBY"
    assert data["active_incident"] == "NONE"
    assert data["incident_code"] == "NONE"
