"""Regression tests for native iPhone Apple Web Push delivery, VAPID key consistency,
safe provider diagnostics, and service worker push notification display compatibility.
"""
import base64
import json
import logging
import pytest
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

from src.pwa.alerts import (
    valid_push_endpoint,
    mask_push_endpoint,
    get_push_provider,
    normalize_vapid_subject,
    verify_vapid_key_consistency,
    parse_webpush_error,
    send_test_push,
    deliver,
    ensure_vapid_keys,
)
from src.pwa.store import Store
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pywebpush import WebPushException


def generate_test_vapid_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_num = priv.private_numbers().private_value
    priv_bytes = priv_num.to_bytes(32, "big")
    priv_b64 = base64.urlsafe_b64encode(priv_bytes).decode("utf-8").rstrip("=")
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    pub_b64 = base64.urlsafe_b64encode(pub_bytes).decode("utf-8").rstrip("=")
    return priv_b64, pub_b64


def clear_push_subscriptions(store):
    with store.db() as conn:
        conn.execute("DELETE FROM records WHERE id LIKE 'push:%'")
        conn.execute("DELETE FROM records WHERE id LIKE 'job:%'")


# ==============================================================================
# 1. Push Endpoint Validation Tests
# ==============================================================================

def test_apple_push_endpoint_subdomain_support():
    """Verifies that all valid Apple Web Push subdomains are accepted while spoofed domains are rejected."""
    # Valid Apple endpoints (production APNs subdomains)
    assert valid_push_endpoint("https://web.push.apple.com/QI01_valid_token_sample_123")
    assert valid_push_endpoint("https://p2.push.apple.com/QI02_valid_token_sample_456")
    assert valid_push_endpoint("https://p25-push.apple.com/QI25_token")
    assert valid_push_endpoint("https://gateway.push.apple.com/gateway_token")
    assert valid_push_endpoint("https://push.apple.com/root_token")

    # Valid non-Apple endpoints
    assert valid_push_endpoint("https://fcm.googleapis.com/fcm/send/abc123token")
    assert valid_push_endpoint("https://updates.push.services.mozilla.com/wpush/v2/xyz")
    assert valid_push_endpoint("https://db5.notify.windows.com/?token=wnstoken")

    # Invalid / Spoofed endpoints (SSRF prevention)
    assert not valid_push_endpoint("http://web.push.apple.com/insecure_http")
    assert not valid_push_endpoint("https://evil.push.apple.com.attacker.com/spoof")
    assert not valid_push_endpoint("https://fake-push.apple.com.attacker.com/spoof")
    assert not valid_push_endpoint("https://not-apple.push.apple.com.evil.com/token")
    assert not valid_push_endpoint("https://127.0.0.1/admin")
    assert not valid_push_endpoint("https://localhost:8502/api/control")
    assert not valid_push_endpoint("")
    assert not valid_push_endpoint(None)


# ==============================================================================
# 2. Endpoint Masking and Provider Classification Tests
# ==============================================================================

def test_endpoint_masking_never_exposes_tokens():
    """Verifies mask_push_endpoint hides raw tokens and paths while preserving hostname and unique trace."""
    apple_ep = "https://web.push.apple.com/QI01_SECRET_TOKEN_DO_NOT_EXPOSE_998877?param=secret"
    masked = mask_push_endpoint(apple_ep)
    assert "web.push.apple.com" in masked
    assert "SECRET_TOKEN" not in masked
    assert "param=secret" not in masked
    assert masked.startswith("https://web.push.apple.com/...[")
    assert masked.endswith("]")

    # Invalid endpoints handled gracefully
    assert mask_push_endpoint("") == "[invalid-endpoint]"
    assert mask_push_endpoint(None) == "[invalid-endpoint]"


def test_push_provider_classification():
    """Verifies accurate categorization of push endpoints into providers."""
    assert get_push_provider("https://web.push.apple.com/token") == "apple"
    assert get_push_provider("https://p2.push.apple.com/token") == "apple"
    assert get_push_provider("https://p25-push.apple.com/token") == "apple"
    assert get_push_provider("https://fcm.googleapis.com/fcm/send/token") == "google"
    assert get_push_provider("https://updates.push.services.mozilla.com/token") == "mozilla"
    assert get_push_provider("https://db5.notify.windows.com/?token=abc") == "windows"
    assert get_push_provider("https://other-service.example.org/token") == "other"
    assert get_push_provider("") == "unknown"


# ==============================================================================
# 3. VAPID Key Consistency & Subject Normalization Tests
# ==============================================================================

def test_vapid_keypair_consistency_validation():
    """Verifies verify_vapid_key_consistency identifies matching vs mismatched EC SECP256R1 pairs."""
    priv_1, pub_1 = generate_test_vapid_keypair()
    priv_2, pub_2 = generate_test_vapid_keypair()

    # Matching pair
    consistent, msg = verify_vapid_key_consistency(priv_1, pub_1)
    assert consistent is True
    assert "consistent" in msg.lower()

    # Mismatched pair (e.g. rotated private key but old public key)
    mismatched, mismatch_msg = verify_vapid_key_consistency(priv_1, pub_2)
    assert mismatched is False
    assert "mismatch" in mismatch_msg.lower() or "does not match" in mismatch_msg.lower()

    # Missing or invalid keys
    empty_consistent, _ = verify_vapid_key_consistency("", pub_1)
    assert empty_consistent is False


def test_vapid_subject_normalization():
    """Verifies normalize_vapid_subject replaces .internal TLDs with valid public TLD for Apple APNs."""
    # .internal default must be normalized to prevent Apple 400 BadVapidSubject
    assert normalize_vapid_subject("mailto:security@veritas-vault.internal") == "mailto:security@veritas-vault.org"
    assert normalize_vapid_subject(None) == "mailto:security@veritas-vault.org"
    assert normalize_vapid_subject("") == "mailto:security@veritas-vault.org"

    # Valid external mailto and https URIs must be preserved
    assert normalize_vapid_subject("mailto:admin@security-audit.com") == "mailto:admin@security-audit.com"
    assert normalize_vapid_subject("https://veritas-vault.org/contact") == "https://veritas-vault.org/contact"

    # Missing mailto: prefix added
    assert normalize_vapid_subject("ops@mycompany.org") == "mailto:ops@mycompany.org"


# ==============================================================================
# 4. Error Parsing & Diagnostic Hints
# ==============================================================================

def test_parse_webpush_error_apple_apns():
    """Verifies parse_webpush_error produces actionable diagnostic hints for Apple APNs status codes."""
    # 400 BadVapidSubject
    mock_resp_400 = MagicMock()
    mock_resp_400.status_code = 400
    mock_resp_400.headers = {"Content-Type": "application/json"}
    mock_resp_400.json.return_value = {"reason": "BadVapidSubject"}
    mock_resp_400.text = '{"reason":"BadVapidSubject"}'
    exc_400 = WebPushException("Push failed", response=mock_resp_400)
    diag_400 = parse_webpush_error(exc_400, "apple")
    assert diag_400["status_code"] == 400
    assert diag_400["reason"] == "BadVapidSubject"
    assert "VAPID subject claim" in diag_400["message"]

    # 403 DeviceTokenNotForTopic
    mock_resp_403 = MagicMock()
    mock_resp_403.status_code = 403
    mock_resp_403.headers = {"Content-Type": "application/json"}
    mock_resp_403.json.return_value = {"reason": "DeviceTokenNotForTopic"}
    mock_resp_403.text = '{"reason":"DeviceTokenNotForTopic"}'
    exc_403 = WebPushException("Push failed", response=mock_resp_403)
    diag_403 = parse_webpush_error(exc_403, "apple")
    assert diag_403["status_code"] == 403
    assert diag_403["reason"] == "DeviceTokenNotForTopic"
    assert "different VAPID public key" in diag_403["message"]

    # 410 Unregistered
    mock_resp_410 = MagicMock()
    mock_resp_410.status_code = 410
    mock_resp_410.headers = {"Content-Type": "application/json"}
    mock_resp_410.json.return_value = {"reason": "Unregistered"}
    exc_410 = WebPushException("Push failed", response=mock_resp_410)
    diag_410 = parse_webpush_error(exc_410, "apple")
    assert diag_410["status_code"] == 410
    assert "Unregistered" in diag_410["reason"]


# ==============================================================================
# 5. send_test_push() Delivery & Diagnostic Reporting Tests
# ==============================================================================

def test_send_test_push_successful_apple_delivery(monkeypatch):
    """Verifies send_test_push sends to Apple Web Push with ttl=86400, Urgency: high, and reports success."""
    store = Store()
    priv_key, pub_key = generate_test_vapid_keypair()
    store.put("vapid:auto_keys", {
        "VAPID_PRIVATE_KEY": priv_key,
        "VAPID_PUBLIC_KEY": pub_key,
        "VAPID_SUBJECT": "mailto:security@veritas-vault.org",
    })

    clear_push_subscriptions(store)

    apple_ep = "https://web.push.apple.com/QI01_test_apple_iphone_token_123"
    sub_key = "push:test_apple"
    store.put(sub_key, {
        "id": "sub-apple-01",
        "subscription": {
            "endpoint": apple_ep,
            "keys": {"p256dh": "test_p256dh", "auth": "test_auth"},
        },
        "owner": "operator",
        "device_label": "iPhone 15 Pro Native PWA",
        "active": True,
    })

    recorded_webpush_calls = []

    def mock_webpush(subscription_info, data, vapid_private_key, vapid_claims, **kwargs):
        recorded_webpush_calls.append({
            "sub": subscription_info,
            "claims": vapid_claims,
            "ttl": kwargs.get("ttl"),
            "headers": kwargs.get("headers"),
        })
        return MagicMock(status_code=201)

    monkeypatch.setattr("pywebpush.webpush", mock_webpush)

    result = send_test_push(store)

    assert result["sent"] == 1
    assert result["failed"] == 0
    assert result["total"] == 1
    assert result["vapid_key_consistent"] is True
    assert "apple" in result["providers"]
    assert result["providers"]["apple"]["sent"] == 1
    assert result["providers"]["apple"]["failed"] == 0

    # Ensure TTL and Urgency headers were provided to wake sleeping iPhone
    assert len(recorded_webpush_calls) == 1
    call = recorded_webpush_calls[0]
    assert call["ttl"] == 86400
    assert call["headers"] == {"Urgency": "high"}
    assert call["claims"]["sub"].startswith("mailto:")
    assert not call["claims"]["sub"].endswith(".internal")


def test_send_test_push_apple_400_bad_vapid_subject_reporting(monkeypatch):
    """Verifies send_test_push captures Apple 400 BadVapidSubject without swallowing and masks endpoint."""
    store = Store()
    priv_key, pub_key = generate_test_vapid_keypair()
    store.put("vapid:auto_keys", {
        "VAPID_PRIVATE_KEY": priv_key,
        "VAPID_PUBLIC_KEY": pub_key,
        "VAPID_SUBJECT": "mailto:security@veritas-vault.org",
    })

    clear_push_subscriptions(store)

    raw_ep = "https://web.push.apple.com/QI01_SECRET_RAW_TOKEN_999"
    store.put("push:apple_fail", {
        "id": "sub-fail-01",
        "subscription": {
            "endpoint": raw_ep,
            "keys": {"p256dh": "dummy", "auth": "dummy"},
        },
        "active": True,
    })

    def mock_webpush_fail(*args, **kwargs):
        resp = MagicMock()
        resp.status_code = 400
        resp.headers = {"Content-Type": "application/json"}
        resp.json.return_value = {"reason": "BadVapidSubject"}
        resp.text = '{"reason":"BadVapidSubject"}'
        raise WebPushException("Push failed", response=resp)

    monkeypatch.setattr("pywebpush.webpush", mock_webpush_fail)

    result = send_test_push(store)

    assert result["sent"] == 0
    assert result["failed"] == 1
    assert result["total"] == 1
    assert "apple" in result["providers"]
    apple_stats = result["providers"]["apple"]
    assert apple_stats["failed"] == 1
    assert len(apple_stats["errors"]) == 1

    err = apple_stats["errors"][0]
    assert err["status_code"] == 400
    assert err["reason"] == "BadVapidSubject"

    # Verify zero secret leakage: raw endpoint and token are masked
    assert "SECRET_RAW_TOKEN" not in json.dumps(result)
    assert raw_ep not in json.dumps(result)
    assert err["endpoint_masked"].startswith("https://web.push.apple.com/...[")

    # Diagnostics contains human readable explanation
    assert len(result["diagnostics"]) > 0
    assert "Apple APNs rejected VAPID subject" in result["diagnostics"][0]


def test_send_test_push_apple_403_key_mismatch_reporting(monkeypatch):
    """Verifies send_test_push captures Apple 403 DeviceTokenNotForTopic and flags key issues."""
    store = Store()
    priv_key, pub_key = generate_test_vapid_keypair()
    store.put("vapid:auto_keys", {
        "VAPID_PRIVATE_KEY": priv_key,
        "VAPID_PUBLIC_KEY": pub_key,
        "VAPID_SUBJECT": "mailto:security@veritas-vault.org",
    })

    clear_push_subscriptions(store)

    store.put("push:apple_mismatch", {
        "id": "sub-mismatch-01",
        "subscription": {
            "endpoint": "https://p2.push.apple.com/QI02_sample_token",
            "keys": {"p256dh": "dummy", "auth": "dummy"},
        },
        "active": True,
    })

    def mock_webpush_403(*args, **kwargs):
        resp = MagicMock()
        resp.status_code = 403
        resp.headers = {"Content-Type": "application/json"}
        resp.json.return_value = {"reason": "DeviceTokenNotForTopic"}
        resp.text = '{"reason":"DeviceTokenNotForTopic"}'
        raise WebPushException("Forbidden", response=resp)

    monkeypatch.setattr("pywebpush.webpush", mock_webpush_403)

    result = send_test_push(store)
    assert result["failed"] == 1
    assert result["providers"]["apple"]["failed"] == 1
    assert "DeviceTokenNotForTopic" in result["diagnostics"][0]


def test_send_test_push_apple_410_disables_subscription(monkeypatch):
    """Verifies send_test_push disables subscription when Apple returns 410 Unregistered."""
    store = Store()
    priv_key, pub_key = generate_test_vapid_keypair()
    store.put("vapid:auto_keys", {
        "VAPID_PRIVATE_KEY": priv_key,
        "VAPID_PUBLIC_KEY": pub_key,
        "VAPID_SUBJECT": "mailto:security@veritas-vault.org",
    })

    clear_push_subscriptions(store)

    sub_key = "push:apple_unregistered"
    store.put(sub_key, {
        "id": "sub-unreg-01",
        "subscription": {
            "endpoint": "https://web.push.apple.com/QI01_expired_token",
            "keys": {"p256dh": "dummy", "auth": "dummy"},
        },
        "active": True,
    })

    def mock_webpush_410(*args, **kwargs):
        resp = MagicMock()
        resp.status_code = 410
        resp.headers = {"Content-Type": "application/json"}
        resp.json.return_value = {"reason": "Unregistered"}
        resp.text = '{"reason":"Unregistered"}'
        raise WebPushException("Gone", response=resp)

    monkeypatch.setattr("pywebpush.webpush", mock_webpush_410)

    result = send_test_push(store)
    assert result["failed"] == 1
    # Verify disabled in store
    saved, _ = store.get(sub_key)
    assert saved["active"] is False


def test_send_test_push_multi_provider_breakdown(monkeypatch):
    """Verifies send_test_push breakdown across multiple concurrent providers (Apple, Google, Windows)."""
    store = Store()
    priv_key, pub_key = generate_test_vapid_keypair()
    store.put("vapid:auto_keys", {
        "VAPID_PRIVATE_KEY": priv_key,
        "VAPID_PUBLIC_KEY": pub_key,
        "VAPID_SUBJECT": "mailto:security@veritas-vault.org",
    })

    clear_push_subscriptions(store)

    # 1 Apple (fails 403), 1 Google (succeeds 201), 1 Windows (succeeds 200)
    store.put("push:apple", {
        "id": "s1",
        "subscription": {"endpoint": "https://web.push.apple.com/QI01_tok", "keys": {"p256dh": "d", "auth": "a"}},
        "active": True,
    })
    store.put("push:google", {
        "id": "s2",
        "subscription": {"endpoint": "https://fcm.googleapis.com/fcm/send/g_tok", "keys": {"p256dh": "d", "auth": "a"}},
        "active": True,
    })
    store.put("push:windows", {
        "id": "s3",
        "subscription": {"endpoint": "https://db5.notify.windows.com/?token=w_tok", "keys": {"p256dh": "d", "auth": "a"}},
        "active": True,
    })

    def mock_webpush_multi(subscription_info, *args, **kwargs):
        ep = subscription_info.get("endpoint", "")
        if "apple.com" in ep:
            resp = MagicMock()
            resp.status_code = 403
            resp.headers = {"Content-Type": "application/json"}
            resp.json.return_value = {"reason": "DeviceTokenNotForTopic"}
            resp.text = '{"reason":"DeviceTokenNotForTopic"}'
            raise WebPushException("Forbidden", response=resp)
        return MagicMock(status_code=201)

    monkeypatch.setattr("pywebpush.webpush", mock_webpush_multi)

    result = send_test_push(store)

    assert result["sent"] == 2
    assert result["failed"] == 1
    assert result["total"] == 3
    assert result["providers"]["apple"]["failed"] == 1
    assert result["providers"]["apple"]["sent"] == 0
    assert result["providers"]["google"]["sent"] == 1
    assert result["providers"]["google"]["failed"] == 0
    assert result["providers"]["windows"]["sent"] == 1
    assert result["providers"]["windows"]["failed"] == 0


# ==============================================================================
# 6. deliver() Web Push Breach Delivery Parameters
# ==============================================================================

def test_deliver_passes_ttl_and_urgency_to_apple(monkeypatch):
    """Verifies deliver() includes ttl=86400 and headers={'Urgency': 'high'} for push alerts."""
    store = Store()
    priv_key, pub_key = generate_test_vapid_keypair()
    store.put("vapid:auto_keys", {
        "VAPID_PRIVATE_KEY": priv_key,
        "VAPID_PUBLIC_KEY": pub_key,
        "VAPID_SUBJECT": "mailto:security@veritas-vault.org",
    })

    clear_push_subscriptions(store)

    sub_key = "push:apple_breach"
    store.put(sub_key, {
        "id": "sub-breach-01",
        "subscription": {
            "endpoint": "https://web.push.apple.com/QI01_breach_token",
            "keys": {"p256dh": "test_p256dh", "auth": "test_auth"},
        },
        "active": True,
    })

    job = {
        "id": "ev-apple-01",
        "reason_code": "ZT-001",
        "verdict": "BREACH",
        "checkpoint": "CP-MAIN-01",
        "attempts": 0,
        "done": False,
        "delivered": [],
    }
    store.put("job:ev-apple-01", job)

    recorded_calls = []

    def mock_webpush_deliver(subscription_info, data, vapid_private_key, vapid_claims, **kwargs):
        recorded_calls.append({
            "sub": subscription_info,
            "ttl": kwargs.get("ttl"),
            "headers": kwargs.get("headers"),
        })
        return MagicMock(status_code=201)

    monkeypatch.setattr("pywebpush.webpush", mock_webpush_deliver)

    deliver("job:ev-apple-01", job, 0)

    assert len(recorded_calls) == 1
    assert recorded_calls[0]["ttl"] == 86400
    assert recorded_calls[0]["headers"] == {"Urgency": "high"}
