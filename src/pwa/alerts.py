"""Durable alert outbox with bounded concurrent delivery and retry leases."""
import base64
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import httpx

from src.pwa.security import unseal
from src.pwa.store import Store


def settings(store):
    saved, _ = store.get("config:alerts")
    overrides = json.loads(unseal(base64.b64decode(saved["encrypted"]), "settings")) if saved else {}
    return {key: overrides.get(key, os.environ.get(key, "")) for key in (
        "CALLMEBOT_PHONE", "CALLMEBOT_API_KEY",
        "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID",
        "VAPID_PUBLIC_KEY", "VAPID_PRIVATE_KEY", "VAPID_SUBJECT")}


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
    # Prevent a submitted subscription from turning the worker into an SSRF proxy.
    return url.scheme == "https" and not url.username and not url.password and url.port in (None, 443) and (
        url.hostname in ("fcm.googleapis.com", "updates.push.services.mozilla.com", "web.push.apple.com")
        or (url.hostname or "").endswith(".notify.windows.com"))


import hashlib
import logging

logger = logging.getLogger("vault.alerts")


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

    # Merge / fallback with records("push:") from store
    for k, v, _ in store.records("push:"):
        if v.get("active") and k not in subs:
            subs[k] = v
    return list(subs.items())


def disable_subscription(store, sub_key, sub):
    """Clean up a dead (404/410) push subscription from both local store and Supabase."""
    store.put(sub_key, dict(sub, active=False))
    if getattr(store, "cloud", None):
        try:
            ep = sub["subscription"]["endpoint"]
            store.cloud.request("PATCH", f"/rest/v1/push_subscriptions?endpoint=eq.{ep}", json={"enabled": False})
        except Exception as exc:
            logger.warning("Failed to disable subscription in Supabase: %s", exc)


def deliver(key, job, version):
    store = Store()
    if job.get("done") or job.get("next_at", 0) > time.time() or job.get("lease_until", 0) > time.time():
        return
    job = dict(job, lease_until=time.time() + 90)
    if not store.cas(key, version, job):
        return
    config = ensure_vapid_keys(store)
    delivered = set(job.get("delivered", []))
    errors = []
    whatsapp_ready = bool(config["CALLMEBOT_API_KEY"] and config["CALLMEBOT_PHONE"])
    subscriptions = get_active_subscriptions(store)
    push_ready = bool(config["VAPID_PRIVATE_KEY"] and config["VAPID_PUBLIC_KEY"] and config["VAPID_SUBJECT"] and subscriptions)
    deadline = time.monotonic() + 30
    if whatsapp_ready and "whatsapp" not in delivered:
        try:
            response = httpx.get("https://api.callmebot.com/whatsapp.php", params={
                "phone": config["CALLMEBOT_PHONE"], "apikey": config["CALLMEBOT_API_KEY"],
                "text": f"VERITAS security breach. Event {job['id']}. Review the secure audit ledger."}, timeout=10)
            response.raise_for_status()
            if "error" in response.text.lower():
                raise ValueError("Provider rejected the alert")
            delivered.add("whatsapp")
        except Exception:
            errors.append("whatsapp")
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
            if time.monotonic() >= deadline:
                errors.append("remaining_push_recipients")
                break
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
    telegram_ready = bool(config.get("TELEGRAM_BOT_TOKEN") and config.get("TELEGRAM_CHAT_ID"))
    if telegram_ready and "telegram" not in delivered:
        try:
            photo_bytes = None
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
            reason_code = job.get("reason_code", "ZT-001")
            cp_name = job.get("checkpoint", "CP-MAIN-01")
            ev_id = job.get("id", "N/A")
            reason_txt = job.get("reason", "Unauthorized person detected at vault checkpoint")

            caption = (
                "🚨 <b>VERITAS BREACH ALERT</b>\n\n"
                f"🏢 <b>Checkpoint:</b> {cp_name}\n"
                f"⏱ <b>Timestamp:</b> {ts}\n"
                f"🔒 <b>Access State:</b> ACCESS DENIED ({reason_code})\n"
                f"🆔 <b>Evidence ID:</b> {ev_id}\n"
                f"⚠️ <b>Reason:</b> {reason_txt}"
            )
            send_telegram_photo_alert(config, caption, photo_bytes)
            delivered.add("telegram")
        except Exception as exc:
            logger.warning("Telegram alert delivery failed: %s", exc)
            errors.append("telegram")

    configured = whatsapp_ready or push_ready or telegram_ready
    attempts = job.get("attempts", 0) + 1
    job.update(delivered=sorted(delivered), done=configured and not errors, attempts=attempts,
               lease_until=0, next_at=time.time() + min(3600, 2 ** min(attempts, 10) * 5),
               status="ACCEPTED_BY_PROVIDER" if configured and not errors else "RETRY" if configured else "UNCONFIGURED")
    store.cas(key, version + 1, job)


def send_telegram_photo_alert(config: dict, caption: str, photo_bytes: bytes = None, filename: str = "intruder.jpg"):
    token = config.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = config.get("TELEGRAM_CHAT_ID", "").strip()
    if not (token and chat_id):
        raise ValueError("Telegram Bot Token or Chat ID not configured")

    if photo_bytes:
        url = f"https://api.telegram.org/bot{token}/sendPhoto"
        files = {"photo": (filename, photo_bytes, "image/jpeg")}
        data = {
            "chat_id": chat_id,
            "caption": caption,
            "parse_mode": "HTML",
        }
        res = httpx.post(url, data=data, files=files, timeout=15)
        res.raise_for_status()
        resp_json = res.json()
        if not resp_json.get("ok"):
            raise ValueError(f"Telegram API rejected photo: {resp_json.get('description', 'Unknown error')}")
        return resp_json
    else:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = {
            "chat_id": chat_id,
            "text": caption,
            "parse_mode": "HTML",
        }
        res = httpx.post(url, json=data, timeout=15)
        res.raise_for_status()
        resp_json = res.json()
        if not resp_json.get("ok"):
            raise ValueError(f"Telegram API rejected message: {resp_json.get('description', 'Unknown error')}")
        return resp_json


def send_test_telegram(store=None):
    import io
    store = store or Store()
    config = settings(store)
    token = config.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = config.get("TELEGRAM_CHAT_ID", "").strip()
    if not (token and chat_id):
        return {"ok": False, "error": "Telegram Bot Token or Chat ID is not configured."}

    caption = (
        "🚨 <b>VERITAS BREACH ALERT</b> [TEST]\n\n"
        "🏢 <b>Checkpoint:</b> CP-MAIN-01\n"
        f"⏱ <b>Timestamp:</b> {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
        "🔒 <b>Access State:</b> SYSTEM OPERATIONAL\n"
        "🆔 <b>Evidence ID:</b> TEST-EVIDENCE-001\n"
        "✅ <b>Status:</b> Telegram Bot API is connected and operational."
    )

    test_photo = None
    try:
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
    except Exception:
        pass

    try:
        send_telegram_photo_alert(config, caption, test_photo, filename="test_alert.jpg")
        return {"ok": True, "recipient": chat_id, "channel": "TELEGRAM"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


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
