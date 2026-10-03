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
    config = settings(store)
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
        for sub_key, sub in subscriptions:
            if sub_key in delivered:
                continue
            if time.monotonic() >= deadline:
                errors.append("remaining_push_recipients")
                break
            try:
                webpush(subscription_info=sub["subscription"],
                        data=json.dumps({"title": "VERITAS security alert", "body": "A breach requires operator review.", "url": "/logs", "tag": job["id"]}),
                        vapid_private_key=config["VAPID_PRIVATE_KEY"], vapid_claims={"sub": config["VAPID_SUBJECT"]}, timeout=10)
                delivered.add(sub_key)
            except WebPushException as exc:
                if exc.response is not None and exc.response.status_code in (404, 410):
                    store.put(sub_key, dict(sub, active=False))
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


def drain_outbox():
    jobs = [(key, value, version) for key, value, version in Store().records("job:")
            if not value.get("done") and value.get("next_at", 0) <= time.time()]
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="vault-alert") as pool:
        list(pool.map(lambda entry: deliver(*entry), jobs[:4]))
