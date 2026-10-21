"""Durable alert outbox with bounded concurrent delivery and retry leases.
Native Web Push is preferred; legacy channels remain available when no PWA is registered.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import threading
from typing import Dict, Optional

import httpx
import numpy as np

from src.pwa.security import encryption_key, unseal
from src.pwa.store import Store

logger = logging.getLogger("vault.alerts")


def push_receipt_token(event_id: str) -> str:
    """Event-scoped proof included only in the encrypted push payload."""
    return hmac.new(encryption_key(), ("push-receipt:" + event_id).encode(), hashlib.sha256).hexdigest()

_evidence_photo_cache: Dict[str, bytes] = {}
_evidence_cache_lock = threading.Lock()


def cache_evidence_photo(path: str, raw_bytes: bytes):
    """Retains recent raw encrypted evidence frames in memory for immediate outbox dispatch."""
    if not path or not raw_bytes:
        return
    with _evidence_cache_lock:
        if len(_evidence_photo_cache) > 20:
            _evidence_photo_cache.pop(next(iter(_evidence_photo_cache)), None)
        _evidence_photo_cache[path] = raw_bytes


def get_cached_evidence_photo(path: str) -> Optional[bytes]:
    """Retrieves in-memory frame bytes if available, avoiding cloud storage round-trip."""
    if not path:
        return None
    with _evidence_cache_lock:
        return _evidence_photo_cache.get(path)

CRITICAL_BREACH_CODES = frozenset({"ZT-001", "ZT-002", "ZT-008", "ZT-009", "ZT-013"})


def get_pushover_config() -> dict:
    """Retrieve Pushover credentials strictly from Render environment variables.
    Never expose the App Token or User Key to client storage or frontend overrides.
    """
    token = os.environ.get("PUSHOVER_APP_TOKEN", "").strip()
    user = os.environ.get("PUSHOVER_USER_KEY", "").strip()
    return {
        "token": token,
        "user": user,
        "configured": bool(token and user),
    }


def get_last_pushover_status(store=None) -> str:
    """Returns 'SENT', 'FAILED', or 'NEVER'."""
    store = store or Store()
    record, _ = store.get("pushover:last_status")
    if record and record.get("status"):
        return record["status"]
    return "NEVER"


def record_last_pushover_status(store, status: str):
    store = store or Store()
    store.put("pushover:last_status", {
        "status": status,
        "updated_at": time.time(),
    })


def get_telegram_config() -> dict:
    """Retrieve Telegram credentials ONLY from Render environment variables.
    Never expose the Bot Token to client storage or frontend overrides.
    """
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    return {
        "token": token,
        "chat_id": chat_id,
        "configured": bool(token and chat_id),
    }


def get_last_telegram_status(store=None) -> str:
    """Returns 'SENT', 'FAILED', or 'NEVER'."""
    store = store or Store()
    record, _ = store.get("telegram:last_status")
    if record and record.get("status"):
        return record["status"]
    return "NEVER"


def record_last_telegram_status(store, status: str):
    store = store or Store()
    store.put("telegram:last_status", {
        "status": status,
        "updated_at": time.time(),
    })


def settings(store):
    saved, _ = store.get("config:alerts")
    overrides = json.loads(unseal(base64.b64decode(saved["encrypted"]), "settings")) if saved else {}
    tg = get_telegram_config()
    po = get_pushover_config()
    return {
        "PUSHOVER_APP_TOKEN": po["token"],
        "PUSHOVER_USER_KEY": po["user"],
        "TELEGRAM_BOT_TOKEN": tg["token"],
        "TELEGRAM_CHAT_ID": tg["chat_id"],
        "CALLMEBOT_PHONE": overrides.get("CALLMEBOT_PHONE", os.environ.get("CALLMEBOT_PHONE", "")),
        "CALLMEBOT_API_KEY": overrides.get("CALLMEBOT_API_KEY", os.environ.get("CALLMEBOT_API_KEY", "")),
        "VAPID_PUBLIC_KEY": overrides.get("VAPID_PUBLIC_KEY", os.environ.get("VAPID_PUBLIC_KEY", "")),
        "VAPID_PRIVATE_KEY": overrides.get("VAPID_PRIVATE_KEY", os.environ.get("VAPID_PRIVATE_KEY", "")),
        "VAPID_SUBJECT": overrides.get("VAPID_SUBJECT", os.environ.get("VAPID_SUBJECT", "mailto:security@veritas-vault.org")),
    }


def normalize_vapid_subject(subject: str | None) -> str:
    """Ensure VAPID subject claim is a valid URI conformant with RFC 8292 and Apple APNs requirements.
    Apple rejects non-standard/unaccredited TLDs (such as .internal) with HTTP 400 BadVapidSubject.
    """
    subj = (subject or "").strip()
    if not subj or subj.endswith(".internal") or "@veritas-vault.internal" in subj:
        return "mailto:security@veritas-vault.org"
    if not (subj.startswith("mailto:") or subj.startswith("https://")):
        return f"mailto:{subj}"
    return subj


def verify_vapid_key_consistency(private_key_str: str, public_key_str: str) -> tuple[bool, str]:
    """Verify that VAPID_PUBLIC_KEY matches the EC SECP256R1 public key derived from VAPID_PRIVATE_KEY.
    Apple APNs strictly rejects push requests with 403 DeviceTokenNotForTopic or 401 BadJwtToken
    if the subscription's applicationServerKey does not match the private key signature.
    Returns (is_consistent, status_message).
    """
    if not private_key_str or not public_key_str:
        return False, "Missing VAPID private or public key"
    try:
        from py_vapid import Vapid
        from cryptography.hazmat.primitives import serialization
        import base64

        vapid = Vapid.from_string(private_key_str.strip())
        derived_pub_bytes = vapid.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        derived_b64 = base64.urlsafe_b64encode(derived_pub_bytes).decode("utf-8").rstrip("=")
        expected_b64 = public_key_str.strip().rstrip("=")
        if derived_b64 == expected_b64:
            return True, "VAPID keypair consistent"
        return False, "VAPID public key does not match private key derivation (mismatched keypair)"
    except Exception as exc:
        return False, f"VAPID key validation failed: {str(exc)}"


def mask_push_endpoint(endpoint: str) -> str:
    """Mask a push subscription endpoint for safe logging and diagnostic reporting.
    Never exposes raw subscription tokens, authorization paths, or query parameters.
    Format: https://<hostname>/...[sha256:8]
    """
    if not endpoint or not isinstance(endpoint, str):
        return "[invalid-endpoint]"
    try:
        url = urlparse(endpoint)
        host = url.hostname or "unknown-host"
        fp = hashlib.sha256(endpoint.encode("utf-8")).hexdigest()[:8]
        return f"https://{host}/...[{fp}]"
    except Exception:
        return "[masked-endpoint]"


def get_push_provider(endpoint: str) -> str:
    """Classify push endpoint by provider without revealing endpoint secrets."""
    if not endpoint or not isinstance(endpoint, str):
        return "unknown"
    try:
        host = (urlparse(endpoint).hostname or "").lower()
        if host == "push.apple.com" or host.endswith(".push.apple.com") or host.endswith("-push.apple.com"):
            return "apple"
        if host in ("fcm.googleapis.com",) or host.endswith(".googleapis.com") or host.endswith(".google.com"):
            return "google"
        if host == "updates.push.services.mozilla.com" or host.endswith(".push.services.mozilla.com") or host.endswith(".mozilla.com"):
            return "mozilla"
        if host == "notify.windows.com" or host.endswith(".notify.windows.com"):
            return "windows"
        return "other"
    except Exception:
        return "unknown"


def parse_webpush_error(exc: Exception, provider: str) -> dict:
    """Parse WebPushException or transport error into safe diagnostic dictionary.
    Includes Apple Web Push APNs specific interpretations without leaking tokens.
    """
    status_code = getattr(exc, "status_code", None)
    response = getattr(exc, "response", None)
    raw_reason = ""
    retry_after = getattr(exc, "retry_after", None)

    if response is not None:
        try:
            content_type = getattr(response, "headers", {}).get("Content-Type", "")
            if "application/json" in content_type:
                data = response.json()
                raw_reason = data.get("reason") or data.get("error") or ""
            if not raw_reason:
                text = getattr(response, "text", "")
                if text and len(text) < 256:
                    raw_reason = text.strip()
        except Exception:
            pass

    diagnostic_hint = ""
    if provider == "apple":
        if status_code == 400:
            if "BadVapidSubject" in raw_reason:
                diagnostic_hint = "Apple APNs rejected VAPID subject claim (must be valid mailto: or https: URI with accredited TLD)"
            elif "BadJwtToken" in raw_reason:
                diagnostic_hint = "Apple APNs rejected VAPID JWT token signature"
            elif "MissingTopic" in raw_reason:
                diagnostic_hint = "Apple APNs requires topic matching applicationServerKey"
            else:
                diagnostic_hint = f"Apple APNs 400 Bad Request: {raw_reason or 'Invalid request payload or headers'}"
        elif status_code == 401:
            diagnostic_hint = "Apple APNs 401 Unauthorized (VAPID authorization failed)"
        elif status_code == 403:
            if "DeviceTokenNotForTopic" in raw_reason:
                diagnostic_hint = "Apple APNs 403 DeviceTokenNotForTopic (subscription token was created with a different VAPID public key than current private key)"
            else:
                diagnostic_hint = f"Apple APNs 403 Forbidden: {raw_reason or 'Device token or JWT invalid for push topic'}"
        elif status_code == 404:
            diagnostic_hint = "Apple APNs 404 BadDeviceToken (device token unknown to APNs)"
        elif status_code == 410:
            diagnostic_hint = "Apple APNs 410 Unregistered (subscription expired or user revoked notifications on iPhone)"
        elif status_code == 413:
            diagnostic_hint = "Apple APNs 413 PayloadTooLarge (push payload exceeds APNs Web Push limit of 4096 bytes)"
        elif status_code == 429:
            diagnostic_hint = "Apple APNs 429 TooManyRequests (rate limited by Apple)"
        elif status_code in (500, 502, 503):
            diagnostic_hint = f"Apple APNs server error HTTP {status_code}"
    elif provider == "google":
        if status_code in (404, 410):
            diagnostic_hint = "Google FCM subscription expired or unregistered"
        elif status_code == 401:
            diagnostic_hint = "Google FCM VAPID auth rejected"

    if not diagnostic_hint:
        if status_code:
            diagnostic_hint = f"HTTP {status_code}" + (f" ({raw_reason})" if raw_reason else "")
        else:
            diagnostic_hint = str(exc) or "Network or push delivery failure"

    return {
        "status_code": status_code,
        "reason": raw_reason or (str(status_code) if status_code else "unknown"),
        "message": diagnostic_hint,
        "retry_after": retry_after,
    }


def ensure_vapid_keys(store):
    cfg = settings(store)
    cfg["VAPID_SUBJECT"] = normalize_vapid_subject(cfg.get("VAPID_SUBJECT"))
    if cfg.get("VAPID_PUBLIC_KEY") and cfg.get("VAPID_PRIVATE_KEY"):
        return cfg

    # Check auto-generated keys in store
    saved, _ = store.get("vapid:auto_keys")
    if saved and saved.get("VAPID_PUBLIC_KEY") and saved.get("VAPID_PRIVATE_KEY"):
        cfg["VAPID_PUBLIC_KEY"] = saved["VAPID_PUBLIC_KEY"]
        cfg["VAPID_PRIVATE_KEY"] = saved["VAPID_PRIVATE_KEY"]
        cfg["VAPID_SUBJECT"] = normalize_vapid_subject(cfg.get("VAPID_SUBJECT") or saved.get("VAPID_SUBJECT"))
        return cfg

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    priv = ec.generate_private_key(ec.SECP256R1())
    priv_num = priv.private_numbers().private_value
    priv_bytes = priv_num.to_bytes(32, "big")
    priv_b64 = base64.urlsafe_b64encode(priv_bytes).decode("utf-8").rstrip("=")

    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    pub_b64 = base64.urlsafe_b64encode(pub_bytes).decode("utf-8").rstrip("=")
    subject = normalize_vapid_subject(cfg.get("VAPID_SUBJECT"))

    auto_keys = {
        "VAPID_PUBLIC_KEY": pub_b64,
        "VAPID_PRIVATE_KEY": priv_b64,
        "VAPID_SUBJECT": subject,
    }
    store.put("vapid:auto_keys", auto_keys)
    cfg.update(auto_keys)
    return cfg


def is_valid_push_hostname(host: str) -> bool:
    if not host:
        return False
    host = host.lower()
    if host in ("fcm.googleapis.com", "updates.push.services.mozilla.com", "web.push.apple.com"):
        return True
    if host == "push.apple.com" or host.endswith(".push.apple.com") or host.endswith("-push.apple.com"):
        return True
    if host.endswith(".notify.windows.com"):
        return True
    if host.endswith(".push.services.mozilla.com"):
        return True
    if host.endswith(".googleapis.com"):
        return True
    return False


def valid_push_endpoint(endpoint):
    if not endpoint or not isinstance(endpoint, str):
        return False
    try:
        url = urlparse(endpoint)
        return (
            url.scheme == "https"
            and not url.username
            and not url.password
            and url.port in (None, 443)
            and is_valid_push_hostname(url.hostname or "")
        )
    except Exception:
        return False


def get_active_subscriptions(store):
    """Retrieve active genuine Web Push subscriptions from Supabase and local records.
    Filters out corrupted or dummy tokens and deduplicates subscriptions by endpoint.
    """
    subs = {}
    if getattr(store, "cloud", None):
        try:
            cloud_rows = store.cloud.rows("push_subscriptions", enabled="eq.true")
            for row in cloud_rows:
                ep = row.get("endpoint", "")
                p256dh = row.get("p256dh", "")
                auth = row.get("auth", "")
                if not ep or not valid_push_endpoint(ep) or p256dh == "fcm_token" or auth == "fcm_token" or not p256dh or not auth:
                    continue
                k = "push:" + hashlib.sha256(ep.encode()).hexdigest()
                subs[k] = {
                    "id": row.get("id"),
                    "subscription": {
                        "endpoint": ep,
                        "keys": {
                            "p256dh": p256dh,
                            "auth": auth,
                        },
                    },
                    "owner": row.get("user_id", "operator"),
                    "device_label": row.get("device_label", "Web Device"),
                    "active": True,
                }
        except Exception as exc:
            diag = getattr(exc, "safe_diagnostic", None) or str(exc)
            logger.warning("Failed to fetch push subscriptions from Supabase: %s [%s]", exc, diag)

    for k, v, _ in store.records("push:"):
        if v.get("active") and k not in subs:
            sub_dict = v.get("subscription", {})
            ep = sub_dict.get("endpoint", "")
            keys = sub_dict.get("keys", {})
            p256dh = keys.get("p256dh", "")
            auth = keys.get("auth", "")
            if ep and valid_push_endpoint(ep) and p256dh != "fcm_token" and auth != "fcm_token" and p256dh and auth:
                subs[k] = v
    return list(subs.items())


def disable_subscription(store, sub_key, sub):
    store.put(sub_key, dict(sub, active=False))
    if getattr(store, "cloud", None):
        try:
            ep = sub["subscription"]["endpoint"]
            store.cloud.request("PATCH", f"/rest/v1/push_subscriptions?endpoint=eq.{ep}", json={"enabled": False})
        except Exception as exc:
            logger.warning("Failed to disable subscription in Supabase: %s", exc)


def get_telegram_diagnostic_status(store=None) -> dict:
    """Backend Telegram diagnostic endpoint (admin only).
    Validates token via getMe and chat via getChat without revealing secrets.
    """
    store = store or Store()
    cfg = get_telegram_config()
    last_status = get_last_telegram_status(store)
    if not cfg["configured"]:
        return {
            "configured": False,
            "bot_reachable": False,
            "chat_reachable": False,
            "description": "Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in Render environment variables.",
            "last_telegram_status": last_status,
        }

    token = cfg["token"]
    chat_id = cfg["chat_id"]

    # 1. Real connection validation via getMe
    try:
        res = httpx.get(f"https://api.telegram.org/bot{token}/getMe", timeout=10)
        data = res.json() if res.content else {}
        if res.status_code != 200 or not data.get("ok"):
            desc = data.get("description") or ("Unauthorized" if res.status_code == 401 else f"HTTP {res.status_code}")
            return {
                "configured": True,
                "bot_reachable": False,
                "chat_reachable": False,
                "description": desc,
                "last_telegram_status": last_status,
            }
    except httpx.TimeoutException:
        return {
            "configured": True,
            "bot_reachable": False,
            "chat_reachable": False,
            "description": "Connection timeout to Telegram Bot API",
            "last_telegram_status": last_status,
        }
    except Exception as exc:
        return {
            "configured": True,
            "bot_reachable": False,
            "chat_reachable": False,
            "description": str(exc),
            "last_telegram_status": last_status,
        }

    # 2. Test chat reachability via getChat
    try:
        res_chat = httpx.get(f"https://api.telegram.org/bot{token}/getChat", params={"chat_id": chat_id}, timeout=10)
        chat_data = res_chat.json() if res_chat.content else {}
        if res_chat.status_code != 200 or not chat_data.get("ok"):
            desc = chat_data.get("description") or f"HTTP {res_chat.status_code}"
            return {
                "configured": True,
                "bot_reachable": True,
                "chat_reachable": False,
                "description": desc,
                "last_telegram_status": last_status,
            }
    except Exception as exc:
        return {
            "configured": True,
            "bot_reachable": True,
            "chat_reachable": False,
            "description": str(exc),
            "last_telegram_status": last_status,
        }

    return {
        "configured": True,
        "bot_reachable": True,
        "chat_reachable": True,
        "description": "CONNECTED",
        "last_telegram_status": last_status,
    }


def send_test_telegram(store=None) -> dict:
    """TEST TELEGRAM flow:
    FIRST sends plain text message.
    If text succeeds, generates test JPEG and sends via sendPhoto.
    Returns safe report:
    { "ok": true, "text_sent": true, "photo_sent": true }
    If text succeeds but photo fails, reports that separately.
    """
    store = store or Store()
    cfg = get_telegram_config()
    token = cfg["token"]
    chat_id = cfg["chat_id"]
    if not (token and chat_id):
        return {
            "ok": False,
            "text_sent": False,
            "photo_sent": False,
            "error": "Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in Render environment variables.",
        }

    # 1. Plain text test message
    text = (
        "🚨 VERITAS TEST ALERT\n"
        "Telegram connection successful.\n"
        "Checkpoint: CP-MAIN-01"
    )
    try:
        res = httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=15,
        )
        data = res.json() if res.content else {}
        if res.status_code != 200 or not data.get("ok"):
            desc = data.get("description") or f"HTTP {res.status_code}"
            record_last_telegram_status(store, "FAILED")
            return {
                "ok": False,
                "text_sent": False,
                "photo_sent": False,
                "error": desc,
            }
    except Exception as exc:
        record_last_telegram_status(store, "FAILED")
        return {
            "ok": False,
            "text_sent": False,
            "photo_sent": False,
            "error": str(exc),
        }

    # 2. Generate in-memory test JPEG
    test_photo = None
    try:
        import io
        from PIL import Image, ImageDraw
        img = Image.new("RGB", (640, 360), color="#0b0f19")
        draw = ImageDraw.Draw(img)
        draw.rectangle([(16, 16), (624, 344)], outline="#00f0ff", width=2)
        draw.text((36, 40), "VERITAS VAULT SECURITY SYSTEM", fill="#00f0ff")
        draw.text((36, 80), "LIVE TELEGRAM BOT NOTIFICATION TEST", fill="#ffffff")
        draw.text((36, 120), f"TIMESTAMP: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}", fill="#91a5bc")
        draw.text((36, 160), "CHECKPOINT: CP-MAIN-01", fill="#10b981")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=90)
        test_photo = buf.getvalue()
    except Exception as img_err:
        record_last_telegram_status(store, "FAILED")
        return {
            "ok": False,
            "text_sent": True,
            "photo_sent": False,
            "error": f"Failed to generate test JPEG: {img_err}",
        }

    # 3. Send test photo
    try:
        res_photo = httpx.post(
            f"https://api.telegram.org/bot{token}/sendPhoto",
            data={
                "chat_id": chat_id,
                "caption": "🚨 VERITAS TEST ALERT · Checkpoint: CP-MAIN-01",
            },
            files={"photo": ("test_checkpoint.jpg", test_photo, "image/jpeg")},
            timeout=15,
        )
        photo_data = res_photo.json() if res_photo.content else {}
        if res_photo.status_code != 200 or not photo_data.get("ok"):
            desc = photo_data.get("description") or f"HTTP {res_photo.status_code}"
            record_last_telegram_status(store, "FAILED")
            return {
                "ok": False,
                "text_sent": True,
                "photo_sent": False,
                "error": f"Telegram API rejected photo: {desc}",
            }

        record_last_telegram_status(store, "SENT")
        return {
            "ok": True,
            "text_sent": True,
            "photo_sent": True,
            "recipient": chat_id,
        }
    except Exception as exc:
        record_last_telegram_status(store, "FAILED")
        return {
            "ok": False,
            "text_sent": True,
            "photo_sent": False,
            "error": str(exc),
        }


def send_pushover_alert(
    reason_code: str,
    checkpoint: str,
    timestamp: str,
    event_id: str,
    reason_text: str = None,
    config: dict = None,
) -> dict:
    """Deliver critical breach notification via official Pushover Messages API.
    Never transmits raw biometric data, private keys, or unprotected evidence.
    """
    po_cfg = config or get_pushover_config()
    token = po_cfg.get("token", "").strip()
    user_key = po_cfg.get("user", "").strip()
    if not (token and user_key):
        raise ValueError("Pushover APP token or user key not configured in environment variables")

    base_url = (os.environ.get("APP_ORIGIN") or os.environ.get("APP_BASE_URL") or "https://veritas-vault14.web.app").rstrip("/")
    audit_link = f"{base_url}/audit?event={event_id}" if event_id else f"{base_url}/audit"

    desc = reason_text or f"Critical security breach detected: {reason_code}"
    message = (
        f"🚨 CRITICAL BREACH DETECTED: {reason_code}\n\n"
        f"Checkpoint: {checkpoint}\n"
        f"Timestamp: {timestamp}\n"
        f"Reason: {desc}\n"
        f"Audit Link: {audit_link}"
    )

    data = {
        "token": token,
        "user": user_key,
        "title": f"🚨 VERITAS BREACH: {reason_code}",
        "message": message,
        "url": audit_link,
        "url_title": f"Audit Event {event_id}" if event_id else "View Audit Event",
        "priority": 1,
        "sound": "siren",
    }
    res = httpx.post("https://api.pushover.net/1/messages.json", data=data, timeout=15)
    try:
        resp_json = res.json()
    except Exception:
        resp_json = {}

    if res.status_code != 200 or resp_json.get("status") != 1:
        errors = resp_json.get("errors") or [f"HTTP {res.status_code}"]
        err_msg = ", ".join(errors) if isinstance(errors, list) else str(errors)
        raise ValueError(f"Pushover API rejected alert: {err_msg}")

    return resp_json


def send_test_pushover(store=None) -> dict:
    """Send an authenticated test notification via Pushover Messages API (admin only)."""
    store = store or Store()
    po_cfg = get_pushover_config()
    token = po_cfg["token"]
    user_key = po_cfg["user"]
    if not (token and user_key):
        return {
            "ok": False,
            "sent": False,
            "error": "Set PUSHOVER_APP_TOKEN and PUSHOVER_USER_KEY in Render environment variables.",
        }

    base_url = (os.environ.get("APP_ORIGIN") or os.environ.get("APP_BASE_URL") or "https://veritas-vault14.web.app").rstrip("/")
    audit_link = f"{base_url}/audit"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    data = {
        "token": token,
        "user": user_key,
        "title": "🚨 VERITAS TEST ALERT",
        "message": (
            "🚨 VERITAS TEST ALERT\n\n"
            "Pushover breach notification channel operational.\n"
            "Checkpoint: CP-MAIN-01\n"
            f"Timestamp: {now_iso}\n"
            f"Audit Link: {audit_link}"
        ),
        "url": audit_link,
        "url_title": "Open Vault Audit Ledger",
        "priority": 0,
    }

    try:
        res = httpx.post("https://api.pushover.net/1/messages.json", data=data, timeout=15)
        resp_json = res.json() if res.content else {}
        if res.status_code != 200 or resp_json.get("status") != 1:
            errors = resp_json.get("errors") or [f"HTTP {res.status_code}"]
            desc = ", ".join(errors) if isinstance(errors, list) else str(errors)
            record_last_pushover_status(store, "FAILED")
            return {
                "ok": False,
                "sent": False,
                "error": desc,
            }
        record_last_pushover_status(store, "SENT")
        masked_user = user_key[:4] + "..." + user_key[-4:] if len(user_key) > 8 else "***"
        return {
            "ok": True,
            "sent": True,
            "recipient": masked_user,
            "request": resp_json.get("request"),
        }
    except Exception as exc:
        record_last_pushover_status(store, "FAILED")
        return {
            "ok": False,
            "sent": False,
            "error": str(exc),
        }


def get_pushover_diagnostic_status(store=None) -> dict:
    """Backend Pushover diagnostic endpoint (admin only).
    Validates token and user key via /users/validate.json without revealing secrets.
    """
    store = store or Store()
    cfg = get_pushover_config()
    last_status = get_last_pushover_status(store)
    if not cfg["configured"]:
        return {
            "configured": False,
            "token_valid": False,
            "user_valid": False,
            "description": "Set PUSHOVER_APP_TOKEN and PUSHOVER_USER_KEY in Render environment variables.",
            "last_pushover_status": last_status,
        }

    token = cfg["token"]
    user = cfg["user"]
    try:
        res = httpx.post(
            "https://api.pushover.net/1/users/validate.json",
            data={"token": token, "user": user},
            timeout=10,
        )
        data = res.json() if res.content else {}
        if res.status_code == 200 and data.get("status") == 1:
            return {
                "configured": True,
                "token_valid": True,
                "user_valid": True,
                "description": "CONNECTED",
                "last_pushover_status": last_status,
            }
        errors = data.get("errors") or [f"HTTP {res.status_code}"]
        desc = ", ".join(errors) if isinstance(errors, list) else str(errors)
        return {
            "configured": True,
            "token_valid": "token" not in desc.lower(),
            "user_valid": "user" not in desc.lower(),
            "description": desc,
            "last_pushover_status": last_status,
        }
    except Exception as exc:
        return {
            "configured": True,
            "token_valid": False,
            "user_valid": False,
            "description": str(exc),
            "last_pushover_status": last_status,
        }


def send_telegram_photo_alert(caption: str, photo_bytes: bytes = None, filename: str = "intruder.jpg", config: dict = None):
    """Deliver Telegram breach alert with optional photo attached.
    Decrypted photo bytes are handled in memory only.
    """
    cfg = config or get_telegram_config()
    token = (cfg.get("token") or cfg.get("TELEGRAM_BOT_TOKEN", "")).strip()
    chat_id = (cfg.get("chat_id") or cfg.get("TELEGRAM_CHAT_ID", "")).strip()
    if not (token and chat_id):
        raise ValueError("Telegram Bot Token or Chat ID not configured in Render environment variables")

    if photo_bytes:
        url = f"https://api.telegram.org/bot{token}/sendPhoto"
        files = {"photo": (filename, photo_bytes, "image/jpeg")}
        data = {
            "chat_id": chat_id,
            "caption": caption,
        }
        res = httpx.post(url, data=data, files=files, timeout=15)
        try:
            resp_json = res.json()
        except Exception:
            resp_json = {}
        if res.status_code != 200 or not resp_json.get("ok"):
            desc = resp_json.get("description") or f"HTTP {res.status_code}"
            raise ValueError(f"Telegram API rejected photo: {desc}")
        return resp_json
    else:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = {
            "chat_id": chat_id,
            "text": caption,
        }
        res = httpx.post(url, json=data, timeout=15)
        try:
            resp_json = res.json()
        except Exception:
            resp_json = {}
        if res.status_code != 200 or not resp_json.get("ok"):
            desc = resp_json.get("description") or f"HTTP {res.status_code}"
            raise ValueError(f"Telegram API rejected message: {desc}")
        return resp_json


def deliver(key, job, version):
    """Asynchronously process an outbox alert job.
    Native Web Push takes precedence over configured legacy notification services.
    Failures NEVER break access denial, evidence storage, audit log, or siren.
    Retries failed alerts with bounded exponential backoff.
    """
    store = Store()
    if job.get("done") or job.get("next_at", 0) > time.time() or job.get("lease_until", 0) > time.time():
        return
    claimed_lease = time.time() + 90
    job = dict(job, lease_until=claimed_lease)
    if not store.cas(key, version, job):
        return

    config = ensure_vapid_keys(store)
    delivered = set(job.get("delivered", []))
    errors = []

    # Confirmed breach classification
    is_non_breach = (
        job.get("reason_code") in {"STANDBY", "ZT-007", "GRANTED", "RESET"}
        or job.get("verdict") in {"STANDBY", "WAITING", "GRANTED", "RESET"}
    )
    is_critical_breach = (
        job.get("reason_code") in CRITICAL_BREACH_CODES
        or job.get("verdict") == "BREACH"
        or (not is_non_breach and not job.get("reason_code"))
    )

    subscriptions = get_active_subscriptions(store)
    push_ready = bool(config.get("VAPID_PRIVATE_KEY") and config.get("VAPID_PUBLIC_KEY") and config.get("VAPID_SUBJECT") and subscriptions)
    whatsapp_ready = bool(config.get("CALLMEBOT_API_KEY") and config.get("CALLMEBOT_PHONE"))
    po_cfg = get_pushover_config()
    tg_cfg = get_telegram_config()
    use_pushover = po_cfg["configured"] and not push_ready

    if is_critical_breach and not is_non_breach:
        if use_pushover:
            # Primary channel: Pushover Messages API
            # Safe retry check: only halt Pushover retries if Pushover itself was delivered,
            # or if the device confirmed receipt specifically via Pushover (e.g. user opened the audit link from Pushover).
            # Do NOT assume a generic PWA Web Push receipt confirms Pushover delivery.
            pushover_confirmed_by_device = bool(
                job.get("pushover_received")
                or (job.get("device_received") and not job.get("pwa_received"))
            )
            if pushover_confirmed_by_device:
                delivered.add("pushover")
                record_last_pushover_status(store, "SENT")
            elif "pushover" not in delivered:
                try:
                    send_pushover_alert(
                        reason_code=job.get("reason_code", "ZT-001"),
                        checkpoint=job.get("checkpoint", "CP-MAIN-01"),
                        timestamp=job.get("created_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        event_id=job.get("id", ""),
                        reason_text=job.get("reason"),
                        config=po_cfg,
                    )
                    delivered.add("pushover")
                    record_last_pushover_status(store, "SENT")
                except httpx.TimeoutException as exc:
                    logger.warning("Pushover alert request timed out for event %s (provider may have accepted alert): %s", job.get("id"), exc)
                    errors.append("pushover")
                    job["provider_timeout"] = True
                    record_last_pushover_status(store, "FAILED")
                except Exception as exc:
                    logger.warning("Pushover alert delivery failed: %s", exc)
                    errors.append("pushover")
                    record_last_pushover_status(store, "FAILED")
            # NOTE: When Pushover is configured as primary, Telegram, FCM, and legacy Web Push
            # are bypassed to guarantee exactly one notification per breach and eliminate duplicate alerts.
        else:
            # Fallback alert channels when Pushover is unconfigured:
            # 1. Remote Alert: PWA Push Notifications (Active production channel)
            if push_ready:
                try:
                    from pywebpush import webpush, WebPushException
                except ImportError:
                    webpush = None
                    errors.append("push")
                event_id = job.get("id", "")
                reason_code = job.get("reason_code", "ZT-001")
                cp_id = job.get("checkpoint", "CP-MAIN-01")
                body_text = f"Unauthorized identity detected\nCheckpoint: {cp_id}\nAccess: DENIED"
                if reason_code == "ZT-002":
                    body_text = f"Biometric spoof detected\nCheckpoint: {cp_id}\nAccess: DENIED"
                elif reason_code == "ZT-008":
                    body_text = f"Custody timeout expired\nCheckpoint: {cp_id}\nAccess: DENIED"
                elif reason_code == "ZT-009":
                    body_text = f"Replay attack detected\nCheckpoint: {cp_id}\nAccess: DENIED"
                elif reason_code == "ZT-013":
                    body_text = f"Capture integrity violation\nCheckpoint: {cp_id}\nAccess: DENIED"

                push_payload = json.dumps({
                    "title": "🚨 VERITAS SECURITY BREACH",
                    "body": body_text,
                    "event_id": event_id,
                    "reason_code": reason_code,
                    "checkpoint": cp_id,
                    "url": f"/audit?event={event_id}" if event_id else "/audit",
                    "tag": event_id or "vault-security-breach",
                    "active": True,
                    "receipt_token": push_receipt_token(event_id),
                })
                for sub_key, sub in subscriptions:
                    if sub_key in delivered:
                        continue
                    ep = sub.get("subscription", {}).get("endpoint", "")
                    provider = get_push_provider(ep)
                    masked_ep = mask_push_endpoint(ep)
                    try:
                        webpush(
                            subscription_info=sub["subscription"],
                            data=push_payload,
                            vapid_private_key=config["VAPID_PRIVATE_KEY"],
                            vapid_claims={"sub": config["VAPID_SUBJECT"]},
                            ttl=86400,
                            headers={"Urgency": "high"},
                            timeout=10,
                        )
                        delivered.add(sub_key)
                    except WebPushException as exc:
                        err_diag = parse_webpush_error(exc, provider)
                        logger.warning(
                            "Web Push breach alert delivery failed to %s [%s]: status=%s reason=%s (%s)",
                            provider, masked_ep, getattr(exc, "status_code", None), err_diag["reason"], err_diag["message"]
                        )
                        if exc.response is not None and exc.response.status_code in (404, 410):
                            disable_subscription(store, sub_key, sub)
                        else:
                            errors.append("push")
                    except Exception as exc:
                        logger.warning(
                            "Web Push breach alert delivery error to %s [%s]: %s",
                            provider, masked_ep, exc
                        )
                        errors.append("push")

            # 2. Optional Legacy Telegram Alert (if configured in environment)
            if not push_ready and tg_cfg["configured"] and "telegram" not in delivered:
                photo_bytes = None
                try:
                    ev_path = job.get("evidence_path")
                    ev_hash = job.get("evidence_hash")
                    if not (ev_path and ev_hash):
                        saved_ev, _ = store.get(f"event:{job.get('id', '')}")
                        if saved_ev and saved_ev.get("evidence"):
                            ev_path = saved_ev["evidence"].get("path")
                            ev_hash = saved_ev["evidence"].get("sha256")
                    if ev_path:
                        cached_raw = get_cached_evidence_photo(ev_path)
                        if cached_raw:
                            try:
                                import cv2
                                frame_mat = cv2.imdecode(np.frombuffer(cached_raw, np.uint8), cv2.IMREAD_COLOR) if not isinstance(cached_raw, np.ndarray) else cached_raw
                                if frame_mat is not None:
                                    ok, buf = cv2.imencode(".jpg", frame_mat)
                                    if ok:
                                        photo_bytes = buf.tobytes()
                            except Exception as c_err:
                                logger.warning("Could not encode cached frame: %s", c_err)
                        if not photo_bytes and ev_hash:
                            try:
                                enc_blob = store.read_blob(ev_path)
                                photo_bytes = unseal(enc_blob, "evidence:" + ev_hash)
                            except Exception as dec_err:
                                logger.warning("Could not decrypt evidence frame for Telegram: %s", dec_err)

                    ts = job.get("created_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    reason_txt = job.get("reason", "Unauthorized person detected at vault checkpoint")
                    ev_id = job.get("id", "N/A")

                    caption = (
                        "🚨 VERITAS BREACH ALERT\n\n"
                        "Checkpoint: CP-MAIN-01\n"
                        "Access: DENIED\n"
                        f"Reason: {reason_txt}\n"
                        f"Time: {ts}\n"
                        f"Evidence ID: {ev_id}"
                    )
                    send_telegram_photo_alert(caption, photo_bytes, config=tg_cfg)
                    delivered.add("telegram")
                    record_last_telegram_status(store, "SENT")
                except Exception as exc:
                    logger.warning("Telegram alert delivery failed: %s", exc)
                    errors.append("telegram")
                    record_last_telegram_status(store, "FAILED")
                finally:
                    del photo_bytes
                    photo_bytes = None

            # 3. Optional legacy fallback: WhatsApp notifications via callmebot
            if not push_ready and whatsapp_ready and "whatsapp" not in delivered:
                try:
                    response = httpx.get(
                        "https://api.callmebot.com/whatsapp.php",
                        params={
                            "phone": config["CALLMEBOT_PHONE"],
                            "apikey": config["CALLMEBOT_API_KEY"],
                            "text": f"VERITAS security breach. Event {job.get('id', '')}. Review the secure audit ledger.",
                        },
                        timeout=10,
                    )
                    response.raise_for_status()
                    if "error" in response.text.lower():
                        raise ValueError("Provider rejected the alert")
                    delivered.add("whatsapp")
                except Exception:
                    errors.append("whatsapp")

    attempts = job.get("attempts", 0) + 1
    max_retries = 3
    configured = po_cfg["configured"] or tg_cfg["configured"] or push_ready or whatsapp_ready

    if is_non_breach:
        # Non-breach events (STANDBY, WAITING, GRANTED) do not dispatch alerts
        job_status = "SKIPPED_NOT_BREACH"
        done = True
    elif not configured:
        job_status = "UNCONFIGURED"
        done = False
    elif use_pushover:
        pushover_confirmed_by_device = bool(
            job.get("pushover_received")
            or (job.get("device_received") and not job.get("pwa_received"))
        )
        if "pushover" in delivered or pushover_confirmed_by_device:
            job_status = "PUSHOVER_SENT"
            done = True
        elif attempts < max_retries:
            job_status = "PUSHOVER_RETRYING"
            done = False
        else:
            job_status = "PUSHOVER_FAILED"
            done = True
    elif "telegram" in delivered and not push_ready:
        job_status = "TELEGRAM_SENT"
        done = True
    elif not errors and (push_ready or whatsapp_ready or "telegram" in delivered):
        job_status = "SENT"
        done = True
    elif "telegram" in errors and not push_ready:
        if attempts < max_retries:
            job_status = "TELEGRAM_RETRYING"
            done = False
        else:
            job_status = "TELEGRAM_FAILED"
            done = True
    elif errors:
        job_status = "RETRY" if attempts < max_retries else "FAILED"
        done = attempts >= max_retries
    else:
        job_status = "SENT"
        done = True

    job.update(
        delivered=sorted(delivered),
        done=done,
        attempts=attempts,
        lease_until=0,
        next_at=time.time() + (2 ** min(attempts, 6) * 5) if not done else 0,
        status=job_status,
    )
    if not store.cas(key, version + 1, job):
        # A device receipt can arrive before the push request returns. Preserve
        # that acknowledgement while committing delivery progress under our lease.
        for _ in range(5):
            current, current_version = store.get(key)
            if not current or current.get("lease_until") != claimed_lease:
                return
            merged = dict(current, **job)
            for field in ("device_received", "device_received_at", "device_label",
                          "pwa_received", "pwa_received_at", "pushover_received", "pushover_received_at"):
                if field in current:
                    merged[field] = current[field]
            if store.cas(key, current_version, merged):
                return
        logger.warning("Could not commit delivery progress after concurrent receipt")


def get_outbox_summary(store=None) -> dict:
    """Computes delivery pipeline tracking counts across all outbox alert jobs."""
    store = store or Store()
    jobs = [v for _, v, _ in store.records("job:")]
    queued = sum(1 for j in jobs if not j.get("done") and j.get("status") in ("QUEUED", "PENDING", "UNCONFIGURED"))
    sent = sum(1 for j in jobs if j.get("status") in ("SENT", "TELEGRAM_SENT", "PUSHOVER_SENT", "ACCEPTED_BY_PROVIDER"))
    retrying = sum(1 for j in jobs if j.get("status") in ("RETRY", "RETRYING", "TELEGRAM_RETRYING", "PUSHOVER_RETRYING"))
    failed = sum(1 for j in jobs if j.get("status") in ("FAILED", "TELEGRAM_FAILED", "PUSHOVER_FAILED"))
    device_confirmed = sum(1 for j in jobs if j.get("device_received") is True)
    return {
        "QUEUED": queued,
        "SENT": sent,
        "RETRYING": retrying,
        "FAILED": failed,
        "DEVICE_CONFIRMED": device_confirmed,
        "total": len(jobs),
    }


def send_test_push(store=None):
    store = store or Store()
    config = ensure_vapid_keys(store)
    subscriptions = get_active_subscriptions(store)

    priv_key = config.get("VAPID_PRIVATE_KEY", "")
    pub_key = config.get("VAPID_PUBLIC_KEY", "")
    if not (priv_key and pub_key):
        return {
            "sent": 0,
            "failed": 0,
            "total": len(subscriptions),
            "error": "VAPID keys not configured",
            "vapid_key_consistent": False,
            "providers": {},
            "diagnostics": ["VAPID keys not configured in environment or store"],
        }

    is_consistent, key_msg = verify_vapid_key_consistency(priv_key, pub_key)
    subject = normalize_vapid_subject(config.get("VAPID_SUBJECT"))

    try:
        from pywebpush import webpush, WebPushException
    except ImportError:
        return {
            "sent": 0,
            "failed": 0,
            "total": len(subscriptions),
            "error": "Web Push library (pywebpush) not installed",
            "vapid_key_consistent": is_consistent,
            "providers": {},
            "diagnostics": ["pywebpush is not installed in the python environment"],
        }

    sent = 0
    failed = 0
    providers = {}
    diagnostics = []

    if not is_consistent:
        diagnostics.append(f"VAPID Key Mismatch Warning: {key_msg}")
        logger.warning("VAPID key inconsistency detected: %s", key_msg)

    if not subscriptions:
        return {
            "sent": 0,
            "failed": 0,
            "total": 0,
            "error": "No active push subscriptions found",
            "vapid_key_consistent": is_consistent,
            "vapid_subject": subject,
            "providers": {},
            "diagnostics": diagnostics,
        }

    now_tag = f"test-{int(time.time())}"
    payload = json.dumps({
        "title": "VERITAS TEST ALERT",
        "body": "Push channel operational.",
        "url": "/audit",
        "tag": now_tag,
        "event_id": now_tag,
    })

    for sub_key, sub in subscriptions:
        sub_info = sub.get("subscription", {})
        ep = sub_info.get("endpoint", "")
        provider = get_push_provider(ep)
        masked_ep = mask_push_endpoint(ep)

        if provider not in providers:
            providers[provider] = {"total": 0, "sent": 0, "failed": 0, "errors": []}
        providers[provider]["total"] += 1

        try:
            webpush(
                subscription_info=sub_info,
                data=payload,
                vapid_private_key=priv_key,
                vapid_claims={"sub": subject},
                ttl=86400,
                headers={"Urgency": "high"},
                timeout=10,
            )
            sent += 1
            providers[provider]["sent"] += 1
            logger.info("Web Push test alert delivered successfully to %s [%s]", provider, masked_ep)
        except WebPushException as exc:
            failed += 1
            providers[provider]["failed"] += 1
            err_diag = parse_webpush_error(exc, provider)
            err_diag["endpoint_masked"] = masked_ep
            providers[provider]["errors"].append(err_diag)
            diag_str = f"{provider.capitalize()} ({masked_ep}): HTTP {exc.status_code} - {err_diag['message']}"
            diagnostics.append(diag_str)
            logger.warning(
                "Web Push test alert delivery failed to %s [%s]: status=%s reason=%s message=%s",
                provider, masked_ep, getattr(exc, "status_code", None), err_diag["reason"], err_diag["message"]
            )
            if exc.response is not None and exc.response.status_code in (404, 410):
                disable_subscription(store, sub_key, sub)
        except Exception as exc:
            failed += 1
            providers[provider]["failed"] += 1
            err_diag = {
                "status_code": None,
                "reason": type(exc).__name__,
                "message": str(exc),
                "endpoint_masked": masked_ep,
            }
            providers[provider]["errors"].append(err_diag)
            diag_str = f"{provider.capitalize()} ({masked_ep}): {str(exc)}"
            diagnostics.append(diag_str)
            logger.warning("Web Push test alert delivery exception to %s [%s]: %s", provider, masked_ep, exc)

    return {
        "sent": sent,
        "failed": failed,
        "total": len(subscriptions),
        "providers": providers,
        "vapid_key_consistent": is_consistent,
        "vapid_subject": subject,
        "diagnostics": diagnostics,
    }


def drain_outbox():
    jobs = [(key, value, version) for key, value, version in Store().records("job:")
            if not value.get("done") and value.get("next_at", 0) <= time.time()]
    if not jobs:
        return
    with ThreadPoolExecutor(max_workers=min(4, len(jobs)), thread_name_prefix="vault-alert") as pool:
        list(pool.map(lambda entry: deliver(*entry), jobs[:4]))
