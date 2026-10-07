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
        "CALLMEBOT_PHONE", "CALLMEBOT_API_KEY", "VAPID_PUBLIC_KEY", "VAPID_PRIVATE_KEY", "VAPID_SUBJECT")}


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
    subscriptions = [(k, v) for k, v, _ in store.records("push:") if v.get("active")]
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
        push_payload = json.dumps({
            "title": "VERITAS SECURITY ALERT",
            "body": f"{job.get('reason') or 'Unregistered identity detected at CP-MAIN-01.'} Access remains locked.",
            "event_id": job.get("id", ""),
            "reason_code": job.get("reason_code", "ZT-001"),
            "url": "/logs",
            "tag": job.get("id", "vault-security-alert"),
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
                    store.put(sub_key, dict(sub, active=False))
                    if store.cloud:
                        try:
                            ep = sub["subscription"]["endpoint"]
                            store.cloud.request("PATCH", f"/rest/v1/push_subscriptions?endpoint=eq.{ep}", json={"enabled": False})
                        except Exception:
                            pass
                else:
                    errors.append("push")
            except Exception:
                errors.append("push")
    configured = whatsapp_ready or push_ready
    attempts = job.get("attempts", 0) + 1
    job.update(delivered=sorted(delivered), done=configured and not errors, attempts=attempts,
               lease_until=0, next_at=time.time() + min(3600, 2 ** min(attempts, 10) * 5),
               status="ACCEPTED_BY_PROVIDER" if configured and not errors else "RETRY" if configured else "UNCONFIGURED")
    store.cas(key, version + 1, job)


def send_test_push(store=None):
    store = store or Store()
    config = ensure_vapid_keys(store)
    subscriptions = [(k, v) for k, v, _ in store.records("push:") if v.get("active")]
    if not (config.get("VAPID_PRIVATE_KEY") and config.get("VAPID_PUBLIC_KEY")):
        return {"sent": 0, "error": "VAPID keys not configured"}
    from pywebpush import webpush, WebPushException
    sent = 0
    now_tag = f"test-{int(time.time())}"
    payload = json.dumps({
        "title": "VERITAS TEST ALERT",
        "body": "Push channel operational.",
        "url": "/logs",
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
                store.put(sub_key, dict(sub, active=False))
                if store.cloud:
                    try:
                        ep = sub["subscription"]["endpoint"]
                        store.cloud.request("PATCH", f"/rest/v1/push_subscriptions?endpoint=eq.{ep}", json={"enabled": False})
                    except Exception:
                        pass
        except Exception:
            pass
    return {"sent": sent, "total": len(subscriptions)}


def drain_outbox():
    jobs = [(key, value, version) for key, value, version in Store().records("job:")
            if not value.get("done") and value.get("next_at", 0) <= time.time()]
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="vault-alert") as pool:
        list(pool.map(lambda entry: deliver(*entry), jobs[:4]))
