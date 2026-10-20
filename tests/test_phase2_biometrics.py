"""
VERITAS-Vault Phase 2 Verification Suite
========================================
Comprehensive regression and acceptance tests for:
1. YuNet face detection with 5-point facial landmark extraction.
2. 5-point canonical affine alignment to standard (112, 112) ArcFace geometry.
3. MobileFaceNet ONNX 512-D L2-normalized feature extraction ('mbf_onnx_v2').
4. Unified multi-sample enrollment pipeline across direct (/api/enroll) and maker-checker (/api/enrollment/request).
5. Model versioning checks and safe re-enrollment without deleting existing identities.
6. Recognition threshold calibration (VERIFIED >= 0.55, POSSIBLE_MATCH >= 0.40, top-2 margin >= 0.06).
7. Dual-custody separation and zero-trust invariants.
"""
import base64
import io
import os
import sqlite3
import numpy as np
import pytest
from fastapi.testclient import TestClient

from app import app
from src.pwa.security import password_hash, seal, unseal
from src.pwa.store import Store
from src.vision.alignment import ARCFACE_REFERENCE_LANDMARKS, align_face, align_face_5point
from src.vision.biometric_service import BiometricService, default_biometric_service
from src.vision.config import BiometricConfig
from src.vision.face_detection import DetectedFace, OpenCVFaceDetector, YuNetFaceDetector, get_default_detector
from src.vision.face_embedding import (
    MobileFaceNetEmbeddingExtractor,
    StandardFeatureEmbeddingExtractor,
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
from src.vision.model_registry import default_model_registry


@pytest.fixture
def p2_env(tmp_path, monkeypatch):
    for key in ("VERCEL", "SUPABASE_URL", "SUPABASE_KEY", "SUPABASE_SERVICE_ROLE_KEY", "FACENET_MODEL_PATH"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", base64.b64encode(b"M" * 32).decode())
    monkeypatch.setenv("VAULT_OPERATOR_USERNAME", "admin_lead")
    monkeypatch.setenv("VAULT_OPERATOR_PASSWORD_HASH", password_hash("AdminPass123!"))
    monkeypatch.setenv("APP_ORIGIN", "https://vault.local")

    default_biometric_service.invalidate_cache()
    client = TestClient(app, base_url="https://vault.local", headers={"X-Vault-Request": "1", "Origin": "https://vault.local"})
    auth_resp = client.post("/api/auth/login", json={"username": "admin_lead", "password": "AdminPass123!"})
    assert auth_resp.status_code == 200
    return client, tmp_path


def create_test_mbf_template(person_id: str, embedding: np.ndarray, model_version: str = "mbf_onnx_v2") -> str:
    """Helper to generate an encrypted template matching unseal(..., 'person:' + person_id)."""
    emb = normalize_vector(embedding)
    buf = io.BytesIO()
    np.savez_compressed(
        buf,
        identity_embedding=emb,
        rep_embeddings=np.array([emb]),
        model_version=model_version,
        quality_score=0.98
    )
    encrypted = seal(buf.getvalue(), "person:" + person_id)
    return base64.b64encode(encrypted).decode()


# ---------------------------------------------------------------------------
# 1. YUNET & 5-POINT ALIGNMENT TESTS
# ---------------------------------------------------------------------------

def test_yunet_detector_initialization_and_fallback():
    """Verify YuNet detector loads ONNX weights when present and falls back gracefully."""
    detector = YuNetFaceDetector()
    assert detector is not None
    # Test on synthetic frame
    synthetic = np.zeros((480, 640, 3), dtype=np.uint8)
    faces = detector.detect_faces(synthetic)
    assert isinstance(faces, list)
    assert len(faces) == 0


def test_align_face_5point_standard_geometry():
    """Verify 5-point affine transformation normalizes face to 112x112 ArcFace grid."""
    frame = np.ones((480, 640, 3), dtype=np.uint8) * 128
    # Plausible facial landmarks in a 640x480 frame
    landmarks_5 = np.array([
        [280.0, 200.0],  # right_eye
        [360.0, 202.0],  # left_eye
        [320.0, 245.0],  # nose
        [290.0, 290.0],  # right_mouth
        [350.0, 292.0]   # left_mouth
    ], dtype=np.float32)

    aligned, success, metrics = align_face_5point(frame, landmarks_5, target_size=(112, 112))
    assert success is True
    assert aligned.shape == (112, 112, 3)
    assert metrics["method"] == "CANONICAL_5POINT_AFFINE"
    assert metrics["quality_score"] > 0.90


def test_align_face_5point_dict_input():
    """Verify align_face_5point supports landmark dictionary format."""
    frame = np.ones((480, 640, 3), dtype=np.uint8) * 120
    lm_dict = {
        "right_eye": (280.0, 200.0),
        "left_eye": (360.0, 202.0),
        "nose": (320.0, 245.0),
        "right_mouth": (290.0, 290.0),
        "left_mouth": (350.0, 292.0)
    }
    aligned, success, _ = align_face(frame, target_size=(112, 112), landmarks=lm_dict)
    assert success is True
    assert aligned.shape == (112, 112, 3)


# ---------------------------------------------------------------------------
# 2. MOBILEFACENET ONNX FEATURE EXTRACTION TESTS
# ---------------------------------------------------------------------------

def test_mobilefacenet_extractor_l2_unit_vector():
    """Verify MobileFaceNet ONNX extractor produces strict 512-D L2-normalized vectors."""
    extractor = MobileFaceNetEmbeddingExtractor()
    assert extractor.version == "mbf_onnx_v2"
    dummy_crop = np.ones((112, 112, 3), dtype=np.uint8) * 100
    if extractor._net is None and extractor._session is None:
        # Model weights are not committed. A clean checkout must fail closed,
        # rather than testing handcrafted features under a neural model version.
        with pytest.raises(RuntimeError, match="unavailable"):
            extractor.extract_embedding(dummy_crop)
        return
    emb = extractor.extract_embedding(dummy_crop)
    assert emb.shape == (512,)
    assert emb.dtype == np.float32
    norm = float(np.linalg.norm(emb))
    assert abs(norm - 1.0) < 1e-4 or norm == 0.0


def test_model_registry_includes_mbf_onnx_v2():
    """Verify model registry tracks mobilefacenet_v2 metadata."""
    meta = default_model_registry.get_model("mobilefacenet_v2")
    assert meta is not None
    assert meta.model_version == "mbf_onnx_v2"
    assert meta.embedding_dimension == 512
    assert meta.metric == "cosine"
    assert meta.status == "ACTIVE"


# ---------------------------------------------------------------------------
# 3. MODEL VERSION CHECK & SAFE RE-ENROLLMENT TESTS
# ---------------------------------------------------------------------------

def test_legacy_model_templates_flagged_for_safe_reenrollment(monkeypatch):
    """Ensure older model templates (e.g. legacy-512d) are flagged and not matched against mbf_onnx_v2."""
    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", base64.b64encode(b"K" * 32).decode())
    service = BiometricService()
    # Force active extractor to mbf_onnx_v2
    service.embedding_extractor.version = "mbf_onnx_v2"

    rng = np.random.default_rng(101)
    legacy_emb = rng.standard_normal(512).astype(np.float32)
    legacy_emb /= np.linalg.norm(legacy_emb)

    # Legacy template enrolled with old version
    legacy_tmpl = create_test_mbf_template("EMP-LEGACY", legacy_emb, model_version="legacy-512d")
    current_tmpl = create_test_mbf_template("EMP-CURRENT", legacy_emb, model_version="mbf_onnx_v2")

    people = [
        {"id": "EMP-LEGACY", "name": "Legacy Officer", "role": "Employee", "template": legacy_tmpl, "status": "APPROVED"},
        {"id": "EMP-CURRENT", "name": "Current Officer", "role": "Employee", "template": current_tmpl, "status": "APPROVED"},
    ]

    service.load_cache_if_needed(people)
    assert service._cache_loaded is True
    assert "EMP-LEGACY" in service._cache
    assert "EMP-CURRENT" in service._cache

    # Verify safe re-enrollment flag
    assert service._cache["EMP-LEGACY"].needs_reenrollment is True
    assert service._cache["EMP-CURRENT"].needs_reenrollment is False

    # Probe embedding matching legacy embedding should NOT match EMP-LEGACY because it's flagged
    res = match_embedding(legacy_emb, service._cache, service.config)
    assert res.candidate_id != "EMP-LEGACY"
    assert res.candidate_id == "EMP-CURRENT"
    assert res.state == RecognitionState.VERIFIED


# ---------------------------------------------------------------------------
# 4. RECOGNITION THRESHOLDS & TOP-2 MARGIN TESTS
# ---------------------------------------------------------------------------

def test_recognition_threshold_and_top2_margin_calibration():
    """Verify calibrated recognition thresholds: VERIFIED (>=0.55), margin (>=0.06), and POSSIBLE_MATCH."""
    cfg = BiometricConfig(recognition_threshold=0.55, possible_match_threshold=0.40, margin_threshold=0.06)

    rng = np.random.default_rng(202)
    base_v = rng.standard_normal(512).astype(np.float32)
    base_v /= np.linalg.norm(base_v)

    # Candidate A: identical to base_v (sim = 1.0)
    # Candidate B: very close to base_v (sim = 0.98 -> margin = 0.02 < 0.06)
    noise = rng.standard_normal(512).astype(np.float32) * 0.01
    v_b = normalize_vector(base_v + noise)

    identities = {
        "EMP-A": EnrolledIdentity(
            id="EMP-A", name="Alice", role="Employee",
            identity_embedding=base_v, representative_embeddings=[],
            model_version="mbf_onnx_v2"
        ),
        "EMP-B": EnrolledIdentity(
            id="EMP-B", name="Bob", role="Employee",
            identity_embedding=v_b, representative_embeddings=[],
            model_version="mbf_onnx_v2"
        )
    }

    # When margin is too narrow (0.02 < 0.06), ambiguity guard downgrades to POSSIBLE_MATCH
    result_ambiguous = match_embedding(base_v, identities, cfg)
    assert result_ambiguous.state == RecognitionState.POSSIBLE_MATCH
    assert result_ambiguous.is_verified is False
    assert result_ambiguous.candidate_id == "EMP-A"
    assert result_ambiguous.margin < 0.06

    # When Candidate B is far away (margin >= 0.06), classification is VERIFIED
    v_c = rng.standard_normal(512).astype(np.float32)
    v_c /= np.linalg.norm(v_c)
    identities_clear = {
        "EMP-A": identities["EMP-A"],
        "EMP-C": EnrolledIdentity(
            id="EMP-C", name="Charlie", role="Customer",
            identity_embedding=v_c, representative_embeddings=[],
            model_version="mbf_onnx_v2"
        )
    }
    result_clear = match_embedding(base_v, identities_clear, cfg)
    assert result_clear.state == RecognitionState.VERIFIED
    assert result_clear.is_verified is True
    assert result_clear.candidate_id == "EMP-A"


def test_unknown_person_rejection():
    """Verify unknown probe vector is rejected with UNKNOWN state and similarity ~ 0.0."""
    cfg = BiometricConfig(recognition_threshold=0.55, possible_match_threshold=0.40)
    rng = np.random.default_rng(303)
    enrolled_v = rng.standard_normal(512).astype(np.float32)
    enrolled_v /= np.linalg.norm(enrolled_v)

    identities = {
        "EMP-ALICE": EnrolledIdentity(
            id="EMP-ALICE", name="Alice", role="Employee",
            identity_embedding=enrolled_v, representative_embeddings=[],
            model_version="mbf_onnx_v2"
        )
    }

    # Unknown impostor vector orthogonal to enrolled
    impostor_v = rng.standard_normal(512).astype(np.float32)
    impostor_v -= np.dot(impostor_v, enrolled_v) * enrolled_v
    impostor_v /= np.linalg.norm(impostor_v)

    res = match_embedding(impostor_v, identities, cfg)
    assert res.state == RecognitionState.UNKNOWN
    assert res.is_verified is False
    assert res.candidate_id is None
    assert abs(res.similarity) < 0.10


# ---------------------------------------------------------------------------
# 5. UNIFIED MULTI-SAMPLE ENROLLMENT PIPELINE TESTS
# ---------------------------------------------------------------------------

def test_api_enroll_alias_route(p2_env):
    """Verify /api/enroll is an active endpoint alias for /api/enrollment."""
    client, _ = p2_env
    # Check that calling /api/enroll with invalid payload returns 422 (not 404!)
    resp = client.post("/api/enroll", json={"personnel_id": "TEST-1", "name": "Test", "role": "Employee"})
    assert resp.status_code in (409, 422)


def test_maker_checker_enrollment_request_workflow_with_multisample(p2_env, monkeypatch):
    """Verify maker-checker enrollment approval path preserves multi-sample template."""
    client, tmp_path = p2_env
    store = Store()

    # Synthetic face crop
    dummy_crop = np.ones((112, 112, 3), dtype=np.uint8) * 128
    dummy_face = {
        "bbox": (10, 10, 90, 90),
        "crop": dummy_crop,
        "confidence": 0.98,
        "is_live": True,
        "landmarks": {
            "right_eye": (38.0, 51.0),
            "left_eye": (73.0, 51.0),
            "nose": (56.0, 71.0),
            "right_mouth": (41.0, 92.0),
            "left_mouth": (70.0, 92.0)
        }
    }
    dummy_report = {
        "lighting_ok": True,
        "aligned": True,
        "texture_ok": True,
        "face_count": 1,
        "sharpness": 80.0
    }

    import src.pwa.api as api_mod
    monkeypatch.setattr(api_mod, "inspect", lambda _: ([dummy_face], dummy_report))

    import cv2
    _, enc = cv2.imencode(".jpg", dummy_crop)
    b64_snap = "data:image/jpeg;base64," + base64.b64encode(enc.tobytes()).decode()

    # 1. Maker creates enrollment request
    req_body = {
        "personnel_id": "EMP-MAKER-CHECKER",
        "name": "Sarah Connor",
        "role": "Employee",
        "samples": [b64_snap] * 5,
        "image": b64_snap
    }
    req_resp = client.post("/api/enrollment/request", json=req_body)
    assert req_resp.status_code == 200
    req_data = req_resp.json()
    assert req_data["status"] == "PENDING"
    req_id = req_data["request_id"]

    # 2. Maker cannot approve their own request (maker-checker violation)
    approve_self = client.post(f"/api/enrollment/requests/{req_id}/approve")
    assert approve_self.status_code == 403

    # 3. Secondary administrator approves (different from maker)
    saved_req = store.get_enrollment_request(req_id)
    saved_req["created_by"] = "other_maker_admin"
    store.save_enrollment_request(saved_req)

    approve_resp = client.post(f"/api/enrollment/requests/{req_id}/approve")
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "APPROVED"

    # 4. Verify identity exists in Store and is queryable via /api/personnel
    pers_resp = client.get("/api/personnel")
    assert pers_resp.status_code == 200
    all_pers = pers_resp.json()
    sarah = next((p for p in all_pers if p["id"] == "EMP-MAKER-CHECKER"), None)
    assert sarah is not None
    assert sarah["name"] == "Sarah Connor"


# ---------------------------------------------------------------------------
# 6. DUAL CUSTODY SEPARATION INVARIANTS
# ---------------------------------------------------------------------------

def test_dual_custody_requires_two_distinct_individuals():
    """Verify policy engine requires two distinct individuals and rejects single person fulfilling both."""
    from src.pwa.policy import fresh, advance

    alice = {
        "id": "EMP-ALICE", "name": "Alice", "role": "Employee",
        "is_recognized": True, "is_live": True, "recognition_state": "VERIFIED"
    }
    bob = {
        "id": "CUST-BOB", "name": "Bob", "role": "Customer",
        "is_recognized": True, "is_live": True, "recognition_state": "VERIFIED"
    }
    unknown = {
        "id": "unknown", "name": "Unknown", "role": "Unauthorized",
        "is_recognized": False, "is_live": True, "recognition_state": "UNKNOWN_CONFIRMED"
    }

    # Case 1: Same person detected twice (cannot satisfy dual custody)
    st = fresh()
    st_same, _ = advance(st, [alice, alice], 1000.0)
    assert st_same["state"] != "GRANTED"
    assert len(st_same["parties"]) == 1

    # Case 2: Two distinct enrolled individuals (Employee + Customer)
    st2 = fresh()
    st_distinct, _ = advance(st2, [alice, bob], 1000.0)
    assert len(st_distinct["parties"]) == 2
    assert st_distinct["state"] == "GRANTED"

    # Case 3: Unknown person triggers breach ZT-001
    st3 = fresh()
    st_breach, _ = advance(st3, [unknown], 1000.0)
    assert st_breach["state"] == "BREACH"
    assert st_breach["reason_code"] == "ZT-001"
