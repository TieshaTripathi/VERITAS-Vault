"""Durable alert outbox with bounded concurrent delivery and retry leases.
Telegram alerts are strictly configured via Render environment variables.
"""
import base64
import hashlib
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import httpx

from src.pwa.security import unseal
from src.pwa.store import Store

logger = logging.getLogger("vault.alerts")

CRITICAL_BREACH_CODES = frozenset({"ZT-001", "ZT-002", "ZT-008", "ZT-009", "ZT-013"})


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
    return {
        "TELEGRAM_BOT_TOKEN": tg["token"],
        "TELEGRAM_CHAT_ID": tg["chat_id"],
        "CALLMEBOT_PHONE": overrides.get("CALLMEBOT_PHONE", os.environ.get("CALLMEBOT_PHONE", "")),
        "CALLMEBOT_API_KEY": overrides.get("CALLMEBOT_API_KEY", os.environ.get("CALLMEBOT_API_KEY", "")),
        "VAPID_PUBLIC_KEY": overrides.get("VAPID_PUBLIC_KEY", os.environ.get("VAPID_PUBLIC_KEY", "")),
        "VAPID_PRIVATE_KEY": overrides.get("VAPID_PRIVATE_KEY", os.environ.get("VAPID_PRIVATE_KEY", "")),
        "VAPID_SUBJECT": overrides.get("VAPID_SUBJECT", os.environ.get("VAPID_SUBJECT", "mailto:security@veritas-vault.internal")),
    }


def ensure_vapid_keys(store):
    cfg = settings(store)
    if cfg.get("VAPID_PUBLIC_KEY") and cfg.get("VAPID_PRIVATE_KEY"):
        if not cfg.get("VAPID_SUBJECT"):
            cfg["VAPID_SUBJECT"] = "mailto:security@veritas-vault.internal"
        return cfg

    # Check auto-generated keys in store
    saved, _ = store.get("vapid:auto_keys")
    if saved and saved.get("VAPID_PUBLIC_KEY") and saved.get("VAPID_PRIVATE_KEY"):
        cfg["VAPID_PUBLIC_KEY"] = saved["VAPID_PUBLIC_KEY"]
        cfg["VAPID_PRIVATE_KEY"] = saved["VAPID_PRIVATE_KEY"]
        cfg["VAPID_SUBJECT"] = cfg.get("VAPID_SUBJECT") or saved.get("VAPID_SUBJECT", "mailto:security@veritas-vault.internal")
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
    subject = cfg.get("VAPID_SUBJECT") or "mailto:security@veritas-vault.internal"

    auto_keys = {
        "VAPID_PUBLIC_KEY": pub_b64,
        "VAPID_PRIVATE_KEY": priv_b64,
        "VAPID_SUBJECT": subject,
    }
    store.put("vapid:auto_keys", auto_keys)
    cfg.update(auto_keys)
    return cfg


def valid_push_endpoint(endpoint):
    url = urlparse(endpoint)
    return url.scheme == "https" and not url.username and not url.password and url.port in (None, 443) and (
        url.hostname in ("fcm.googleapis.com", "updates.push.services.mozilla.com", "web.push.apple.com")
        or (url.hostname or "").endswith(".notify.windows.com"))


def get_active_subscriptions(store):
    """Retrieve active subscriptions from Supabase push_subscriptions table and local records."""
    subs = {}
    if getattr(store, "cloud", None):
        try:
            cloud_rows = store.cloud.rows("push_subscriptions", enabled="eq.true")
            for row in cloud_rows:
                ep = row["endpoint"]
                k = "push:" + hashlib.sha256(ep.encode()).hexdigest()
                subs[k] = {
                    "subscription": {
                        "endpoint": ep,
                        "keys": {
                            "p256dh": row["p256dh"],
                            "auth": row["auth"],
                        },
                    },
                    "owner": row.get("user_id", "operator"),
                    "device_label": row.get("device_label", "Web Device"),
                    "active": True,
                }
        except Exception as exc:
            logger.warning("Failed to fetch push subscriptions from Supabase: %s", exc)

    for k, v, _ in store.records("push:"):
        if v.get("active") and k not in subs:
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
    Telegram failures NEVER break access denial, evidence storage, audit log, or siren.
    Retries failed Telegram alerts with bounded retries.
    Job status is recorded as TELEGRAM_SENT, TELEGRAM_FAILED, or TELEGRAM_RETRYING.
    """
    store = Store()
    if job.get("done") or job.get("next_at", 0) > time.time() or job.get("lease_until", 0) > time.time():
        return
    job = dict(job, lease_until=time.time() + 90)
    if not store.cas(key, version, job):
        return

    config = ensure_vapid_keys(store)
    delivered = set(job.get("delivered", []))
    errors = []

    # Optional Push notifications
    subscriptions = get_active_subscriptions(store)
    push_ready = bool(config["VAPID_PRIVATE_KEY"] and config["VAPID_PUBLIC_KEY"] and config["VAPID_SUBJECT"] and subscriptions)
    if push_ready:
        from pywebpush import webpush, WebPushException
        event_id = job.get("id", "")
        push_payload = json.dumps({
            "title": "VERITAS SECURITY ALERT",
            "body": f"{job.get('reason') or 'Unregistered identity detected at CP-MAIN-01.'} Access remains locked.",
            "event_id": event_id,
            "reason_code": job.get("reason_code", "ZT-001"),
            "url": f"/audit?event={event_id}" if event_id else "/audit",
            "tag": event_id or "vault-security-alert",
        })
        for sub_key, sub in subscriptions:
            if sub_key in delivered:
                continue
            try:
                webpush(subscription_info=sub["subscription"],
                        data=push_payload,
                        vapid_private_key=config["VAPID_PRIVATE_KEY"], vapid_claims={"sub": config["VAPID_SUBJECT"]}, timeout=10)
                delivered.add(sub_key)
            except WebPushException as exc:
                if exc.response is not None and exc.response.status_code in (404, 410):
                    disable_subscription(store, sub_key, sub)
                else:
                    errors.append("push")
            except Exception:
                errors.append("push")

    # Telegram Alert Processing
    tg_cfg = get_telegram_config()
    is_non_breach = (
        job.get("reason_code") in {"STANDBY", "ZT-007", "GRANTED", "RESET"}
        or job.get("verdict") in {"STANDBY", "WAITING", "GRANTED", "RESET"}
    )
    is_critical_breach = (
        job.get("reason_code") in CRITICAL_BREACH_CODES
        or job.get("verdict") == "BREACH"
        or (not is_non_breach and not job.get("reason_code"))
    )

    if tg_cfg["configured"] and is_critical_breach and "telegram" not in delivered:
        photo_bytes = None
        try:
            ev_path = job.get("evidence_path")
            ev_hash = job.get("evidence_hash")
            if not (ev_path and ev_hash):
                saved_ev, _ = store.get(f"event:{job.get('id', '')}")
                if saved_ev and saved_ev.get("evidence"):
                    ev_path = saved_ev["evidence"].get("path")
                    ev_hash = saved_ev["evidence"].get("sha256")
            if ev_path and ev_hash:
                try:
                    enc_blob = store.read_blob(ev_path)
                    photo_bytes = unseal(enc_blob, "evidence:" + ev_hash)
                except Exception as dec_err:
                    logger.warning("Could not decrypt evidence frame for Telegram: %s", dec_err)

            ts = job.get("created_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            reason_txt = job.get("reason", "Unauthorized person detected at vault checkpoint")
            ev_id = job.get("id", "N/A")

            # Exact intruder caption format
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
            # Securely discard decrypted frame bytes from memory immediately
            del photo_bytes
            photo_bytes = None

    # Optional WhatsApp alerts
    whatsapp_ready = bool(config.get("CALLMEBOT_API_KEY") and config.get("CALLMEBOT_PHONE"))
    if whatsapp_ready and "whatsapp" not in delivered and not is_non_breach:
        try:
            response = httpx.get("https://api.callmebot.com/whatsapp.php", params={
                "phone": config["CALLMEBOT_PHONE"], "apikey": config["CALLMEBOT_API_KEY"],
                "text": f"VERITAS security breach. Event {job.get('id', '')}. Review the secure audit ledger."}, timeout=10)
            response.raise_for_status()
            if "error" in response.text.lower():
                raise ValueError("Provider rejected the alert")
            delivered.add("whatsapp")
        except Exception:
            errors.append("whatsapp")

    attempts = job.get("attempts", 0) + 1
    max_retries = 3
    configured = tg_cfg["configured"] or push_ready or whatsapp_ready

    if is_non_breach:
        # Non-breach events (STANDBY, WAITING, GRANTED) do not dispatch alerts
        job_status = "SKIPPED_NOT_BREACH"
        done = True
    elif not configured:
        job_status = "UNCONFIGURED"
        done = False
    elif "telegram" in delivered or (not errors and (push_ready or whatsapp_ready)):
        job_status = "TELEGRAM_SENT" if tg_cfg["configured"] else "ACCEPTED_BY_PROVIDER"
        done = True
    elif "telegram" in errors:
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
        job_status = "TELEGRAM_SENT" if "telegram" in delivered else "ACCEPTED_BY_PROVIDER"
        done = True

    job.update(
        delivered=sorted(delivered),
        done=done,
        attempts=attempts,
        lease_until=0,
        next_at=time.time() + (2 ** min(attempts, 6) * 5) if not done else 0,
        status=job_status,
    )
    store.cas(key, version + 1, job)


def send_test_push(store=None):
    store = store or Store()
    config = ensure_vapid_keys(store)
    subscriptions = get_active_subscriptions(store)
    if not (config.get("VAPID_PRIVATE_KEY") and config.get("VAPID_PUBLIC_KEY")):
        return {"sent": 0, "error": "VAPID keys not configured"}
    from pywebpush import webpush, WebPushException
    sent = 0
    now_tag = f"test-{int(time.time())}"
    payload = json.dumps({
        "title": "VERITAS TEST ALERT",
        "body": "Push channel operational.",
        "url": "/audit",
        "tag": now_tag,
        "event_id": now_tag,
    })
    for sub_key, sub in subscriptions:
        try:
            webpush(
                subscription_info=sub["subscription"],
                data=payload,
                vapid_private_key=config["VAPID_PRIVATE_KEY"],
                vapid_claims={"sub": config["VAPID_SUBJECT"]},
                timeout=10,
            )
            sent += 1
        except WebPushException as exc:
            if exc.response is not None and exc.response.status_code in (404, 410):
                disable_subscription(store, sub_key, sub)
        except Exception:
            pass
    return {"sent": sent, "total": len(subscriptions)}


def drain_outbox():
    jobs = [(key, value, version) for key, value, version in Store().records("job:")
            if not value.get("done") and value.get("next_at", 0) <= time.time()]
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="vault-alert") as pool:
        list(pool.map(lambda entry: deliver(*entry), jobs[:4]))
