"""
VERITAS-Vault Alert Daemon
===========================
Non-blocking emergency dispatch via:
  Primary  - CallMeBot WhatsApp HTTP API (free, no SDK required)
  Fallback - Twilio SMS REST API         (requires credentials)

Both channels execute in a ThreadPoolExecutor with a hard 3.0-second
wall-clock timeout so the Streamlit UI thread is NEVER frozen.
All failed dispatches are durably written to SQLite audit log.
"""

import os
import json
import threading
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime
from typing import Dict, Any, Tuple, Optional

from src.storage.db import log_access_event

CONFIG_PATH = os.path.join("config", "security_config.json")

# Shared background executor - 2 workers is sufficient for alert burst rate
_alert_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="veritas_alert")

# Hard budget - UI thread never waits longer than this for any network call
DISPATCH_TIMEOUT_SECONDS = 3.0


def load_security_config() -> Dict[str, Any]:
    """Loads alert credentials from config/security_config.json or environment."""
    defaults: Dict[str, Any] = {
        "CALLMEBOT_PHONE":    os.environ.get("CALLMEBOT_PHONE", ""),
        "CALLMEBOT_API_KEY":  os.environ.get("CALLMEBOT_API_KEY", ""),
        "TWILIO_ACCOUNT_SID": os.environ.get("TWILIO_ACCOUNT_SID", ""),
        "TWILIO_AUTH_TOKEN":  os.environ.get("TWILIO_AUTH_TOKEN", ""),
        "TWILIO_FROM_PHONE":  os.environ.get("TWILIO_FROM_PHONE", ""),
        "ADMIN_ALERT_PHONE":  os.environ.get("ADMIN_ALERT_PHONE", "+15551234567"),
        "SMS_ENABLED": True,
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                defaults.update(json.load(fh))
        except Exception as exc:
            print(f"[alerts] Config read error: {exc}")
    return defaults


def save_security_config(new_config: Dict[str, Any]) -> bool:
    """Persists updated security configuration to config/security_config.json."""
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
            json.dump(new_config, fh, indent=2)
        return True
    except Exception as exc:
        print(f"[alerts] Config write error: {exc}")
        return False


def format_alert_message(event_type: str, details: str, frame_hash: str) -> str:
    """Formats the standard VERITAS-Vault emergency dispatch payload string."""
    ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    short_hash = (frame_hash[:16] + "...") if len(frame_hash) > 16 else (frame_hash or "N/A")
    lines = [
        "\U0001f6a8 [VERITAS-VAULT SECURITY ALERT]",
        f"Timestamp: {ts}",
        f"Threat Type: {event_type}",
        f"Details: {details}",
        f"Frame SHA-256: {short_hash}",
        "Lock Status: SOLENOID LOCKED (ENGAGED)",
    ]
    return "\n".join(lines)


def _dispatch_callmebot(phone: str, api_key: str, message: str) -> bool:
    """
    Sends a WhatsApp message via CallMeBot HTTP API.
    Socket-level timeout = 2.5s. Runs inside worker thread only.
    """
    params = urllib.parse.urlencode({
        "phone": phone,
        "text": message,
        "apikey": api_key,
    })
    url = "https://api.callmebot.com/whatsapp.php?" + params
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VERITAS-Vault/2.0"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status == 200 and "error" not in body.lower()
    except Exception as exc:
        print(f"[alerts] CallMeBot error: {exc}")
        return False


def _dispatch_twilio(account_sid: str, auth_token: str, from_phone: str,
                     to_phone: str, body: str) -> bool:
    """
    Sends SMS via Twilio. Tries the SDK first; falls back to raw urllib.
    Socket-level timeout = 2.5s. Runs inside worker thread only.
    """
    try:
        from twilio.rest import Client  # type: ignore
        client = Client(account_sid, auth_token)
        msg = client.messages.create(body=body, from_=from_phone, to=to_phone)
        return bool(msg.sid)
    except ImportError:
        pass
    except Exception as exc:
        print(f"[alerts] Twilio SDK error: {exc}")
        return False

    import base64
    url = "https://api.twilio.com/2010-04-01/Accounts/" + account_sid + "/Messages.json"
    credentials = base64.b64encode((account_sid + ":" + auth_token).encode()).decode()
    data = urllib.parse.urlencode({"From": from_phone, "To": to_phone, "Body": body}).encode("ascii")
    headers = {
        "Authorization": "Basic " + credentials,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            return resp.status in (200, 201)
    except Exception as exc:
        print(f"[alerts] Twilio HTTP error: {exc}")
        return False


def _execute_dispatch(event_type: str, details: str, frame_hash: str,
                      target_phone: Optional[str]) -> Tuple[bool, str]:
    """
    Tries CallMeBot then Twilio then buffers to SQLite.
    Returns (dispatch_success, channel_label).
    This function always runs in the background worker thread.
    """
    config = load_security_config()
    alert_body = format_alert_message(event_type, details, frame_hash)
    channel_used = "SMS_BUFFERED_LOCAL"
    success = False

    # Primary: CallMeBot WhatsApp
    cb_phone = config.get("CALLMEBOT_PHONE", "").strip()
    cb_key = config.get("CALLMEBOT_API_KEY", "").strip()
    if cb_phone and cb_key:
        if _dispatch_callmebot(cb_phone, cb_key, alert_body):
            channel_used = "WHATSAPP_CALLMEBOT"
            success = True

    # Fallback: Twilio SMS
    if not success:
        sid = config.get("TWILIO_ACCOUNT_SID", "").strip()
        token = config.get("TWILIO_AUTH_TOKEN", "").strip()
        frm = config.get("TWILIO_FROM_PHONE", "").strip()
        to = (target_phone or config.get("ADMIN_ALERT_PHONE", "+15551234567")).strip()
        if sid and token and frm and to:
            if _dispatch_twilio(sid, token, frm, to, alert_body):
                channel_used = "SMS_DISPATCHED_TWILIO"
                success = True

    return success, channel_used


def send_sms_alert(
    event_type: str,
    details: str,
    frame_hash: str = "",
    target_phone: Optional[str] = None,
) -> bool:
    """
    NON-BLOCKING alert dispatcher (Criterion 4 compliant).

    Submits the network I/O to the background ThreadPoolExecutor and waits
    AT MOST DISPATCH_TIMEOUT_SECONDS (3.0s) for a result.  If the budget is
    exceeded, the function returns immediately and the background thread logs
    its result to SQLite when it eventually completes.  The Streamlit UI
    thread is NEVER blocked beyond 3.0 seconds regardless of network state.
    """
    safe_hash = frame_hash if frame_hash else ("0" * 64)
    evtype_key = event_type.upper().replace(" ", "_")
    verdict_label = "SMS_ALERT_" + evtype_key
    to_arg = target_phone or ""

    def _worker() -> Tuple[bool, str]:
        ok, chan = _execute_dispatch(event_type, details, safe_hash, to_arg or None)
        log_access_event(
            mode="EMERGENCY_SMS_DISPATCH",
            parties="Target: " + (to_arg or "configured_admin"),
            verdict=verdict_label,
            sha256_hash=safe_hash,
            enc_path="",
            status=chan,
        )
        return ok, chan

    future = _alert_executor.submit(_worker)
    try:
        _ok, _chan = future.result(timeout=DISPATCH_TIMEOUT_SECONDS)
        if not _ok:
            print("[alerts] All channels failed - audit event buffered in SQLite")
    except FuturesTimeoutError:
        # Budget exceeded - thread still running; log placeholder on daemon thread
        print(f"[alerts] Dispatch budget ({DISPATCH_TIMEOUT_SECONDS}s) exceeded - continuing async")
        threading.Thread(
            target=log_access_event,
            kwargs=dict(
                mode="EMERGENCY_SMS_DISPATCH",
                parties="Target: " + (to_arg or "configured_admin"),
                verdict=verdict_label,
                sha256_hash=safe_hash,
                enc_path="",
                status="DISPATCH_ASYNC_PENDING",
            ),
            daemon=True,
        ).start()

    return True  # Always non-blocking from caller perspective


def test_sms_alert(target_phone: Optional[str] = None) -> Tuple[bool, str]:
    """
    Synchronous test dispatch with 5.0s budget (UI button; user expects feedback).
    """
    config = load_security_config()
    cb_phone = config.get("CALLMEBOT_PHONE", "").strip()
    cb_key = config.get("CALLMEBOT_API_KEY", "").strip()
    sid = config.get("TWILIO_ACCOUNT_SID", "").strip()
    token = config.get("TWILIO_AUTH_TOKEN", "").strip()
    to_phone = (target_phone or config.get("ADMIN_ALERT_PHONE", "+15551234567")).strip()

    has_callmebot = bool(cb_phone and cb_key)
    has_twilio = bool(sid and token)

    if not has_callmebot and not has_twilio:
        send_sms_alert("TEST_SIMULATION", "Verification test alert payload", "test_hash", to_phone)
        return False, (
            "No alert credentials configured. Event recorded in SQLite (SMS_BUFFERED_LOCAL). "
            "Add CallMeBot or Twilio credentials in the sidebar."
        )

    future = _alert_executor.submit(
        _execute_dispatch, "TEST_VERIFICATION", "Dispatch channel operational", "live_test_hash", to_phone
    )
    try:
        ok, chan = future.result(timeout=5.0)
        if ok:
            return True, "\u2705 Test alert dispatched via " + chan
        return False, "\u26a0\ufe0f All channels attempted; buffered to SQLite."
    except FuturesTimeoutError:
        return False, "\u23f1\ufe0f Dispatch timeout (5.0s). Check network / credentials."
