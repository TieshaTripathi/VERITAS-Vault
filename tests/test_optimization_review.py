"""Regressions for confirmed issues found in the optimization review."""
import base64
import io
from unittest.mock import MagicMock

import numpy as np
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from src.pwa import api as backend
from src.pwa.alerts import push_receipt_token
from src.pwa import alerts
from src.pwa.security import password_hash, seal
from src.pwa.store import Store
from src.vision.biometric_service import BiometricService
from src.vision.face_detection import DetectedFace, OpenCVFaceDetector
from src.vision.face_embedding import MobileFaceNetEmbeddingExtractor


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VAULT_OPERATOR_USERNAME", "review-admin")
    monkeypatch.setenv("VAULT_OPERATOR_PASSWORD_HASH", password_hash("Review-password-123"))
    return TestClient(backend.app, base_url="https://testserver",
                      headers={"X-Vault-Request": "1", "Origin": "https://testserver"})


@pytest.mark.parametrize("origin", ["https://attacker.web.app", "https://localhost.attacker.invalid", "https://attacker.firebaseapp.com"])
def test_origin_must_be_explicitly_trusted(client, origin):
    assert client.post("/api/auth/login", json={"username": "x", "password": "x"},
                       headers={"Origin": origin}).status_code == 403


def test_push_receipt_requires_session_or_event_proof(client):
    store = Store()
    store.put("job:event-review", {"id": "event-review", "status": "SENT"})
    payload = {"event_id": "event-review", "channel": "webpush"}
    assert client.post("/api/push/receipt", json=payload).status_code == 401
    payload["receipt_token"] = push_receipt_token("different-event")
    assert client.post("/api/push/receipt", json=payload).status_code == 401
    assert not store.get("job:event-review")[0].get("device_received")
    payload["receipt_token"] = push_receipt_token("event-review")
    assert client.post("/api/push/receipt", json=payload).status_code == 200
    assert store.get("job:event-review")[0]["pwa_received"] is True


def test_foreign_subscription_cannot_be_disabled_in_cloud(monkeypatch):
    store = MagicMock()
    store.get.return_value = ({"owner": "someone-else", "active": True}, 0)
    monkeypatch.setattr(backend, "Store", lambda: store)
    body = backend.Subscription(endpoint="https://fcm.googleapis.com/fcm/send/test", keys={"p256dh": "x", "auth": "y"})
    with pytest.raises(HTTPException) as exc:
        backend.unsubscribe(body, {"id": "monitor", "role": "monitor"})
    assert exc.value.status_code == 403
    store.cloud.request.assert_not_called()
    store.cas.assert_not_called()


def test_cloud_revocation_updates_existing_enrollment(monkeypatch):
    store = Store.__new__(Store)
    store.cloud = MagicMock()
    monkeypatch.setattr(store, "personnel", lambda: [{"id": "EMP-1", "name": "One", "role": "Employee"}])
    assert store.revoke_user("EMP-1", "admin") is True
    args, kwargs = store.cloud.request.call_args
    assert args == ("PATCH", "/rest/v1/enrolled_users")
    assert kwargs["params"] == {"user_id": "eq.EMP-1"}
    assert kwargs["json"]["pwa_data"]["status"] == "REVOKED"


def test_crop_landmarks_preserve_face_geometry():
    face = DetectedFace((200, 100, 112, 112), np.zeros((112, 112, 3), np.uint8),
                        landmarks={"right_eye": (238, 151), "left_eye": (273, 151)})
    assert face.crop_landmarks == {"right_eye": (38, 51), "left_eye": (73, 51)}
    assert face.landmarks["right_eye"] == (238, 151)


def test_haar_eye_labels_use_same_convention_as_yunet():
    detector = OpenCVFaceDetector()
    detector._face_cascade = MagicMock()
    detector._face_cascade.detectMultiScale.return_value = [(100, 100, 112, 112)]
    detector._eye_cascade = MagicMock()
    detector._eye_cascade.detectMultiScale.return_value = [(20, 20, 16, 16), (70, 20, 16, 16)]
    face = detector.detect_faces(np.full((480, 640, 3), 120, np.uint8))[0]
    assert face.landmarks["right_eye"][0] < face.landmarks["left_eye"][0]


def test_missing_mobilefacenet_never_masquerades_as_deep_features(tmp_path):
    extractor = MobileFaceNetEmbeddingExtractor(str(tmp_path / "missing.onnx"))
    with pytest.raises(RuntimeError, match="unavailable"):
        extractor.extract_embedding(np.full((112, 112, 3), 100, np.uint8))


def test_legacy_normalized_crop_is_never_silently_migrated():
    service = BiometricService()
    payload = io.BytesIO()
    np.savez(payload, norm=np.full((128, 128), 120, np.uint8))
    template = base64.b64encode(seal(payload.getvalue(), "person:LEGACY")).decode()
    service.load_cache_if_needed([{"id": "LEGACY", "template": template}])
    assert service._cache["LEGACY"].needs_reenrollment is True
    assert service._cache["LEGACY"].model_version == "legacy-512d"


def test_receipt_during_delivery_preserves_progress_without_resending(client, monkeypatch):
    store = Store()
    job = {"id": "receipt-race", "reason_code": "ZT-001", "done": False}
    store.put("job:receipt-race", job)
    monkeypatch.setattr(alerts, "ensure_vapid_keys", lambda _: {
        "VAPID_PRIVATE_KEY": "test", "VAPID_PUBLIC_KEY": "test", "VAPID_SUBJECT": "mailto:test@example.com"})
    monkeypatch.setattr(alerts, "get_active_subscriptions", lambda _: [("push:test", {"subscription": {}})])
    calls = []
    def receive(**kwargs):
        calls.append(kwargs)
        current, ver = store.get("job:receipt-race")
        current.update(device_received=True, pwa_received=True)
        assert store.cas("job:receipt-race", ver, current)
    monkeypatch.setattr("pywebpush.webpush", receive)
    alerts.deliver("job:receipt-race", job, 0)
    saved, version = store.get("job:receipt-race")
    assert saved["done"] and saved["pwa_received"]
    assert saved["delivered"] == ["push:test"]
    alerts.deliver("job:receipt-race", saved, version)
    assert len(calls) == 1


@pytest.mark.parametrize("output", [np.ones(128), np.zeros(512), np.full(512, np.nan)])
def test_invalid_model_output_cannot_become_template(tmp_path, output):
    extractor = MobileFaceNetEmbeddingExtractor(str(tmp_path / "missing.onnx"))
    extractor._net = MagicMock()
    extractor._net.forward.return_value = output
    with pytest.raises(RuntimeError, match="invalid embedding"):
        extractor.extract_embedding(np.full((112, 112, 3), 100, np.uint8))
