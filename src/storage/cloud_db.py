"""
VERITAS-Vault Cloud Sync & Storage Engine
==========================================
Supabase-backed cloud persistence layer with automatic offline fallback to
the local SQLite database (data/vault_security.db).

Architecture
------------
  supabase-py client -> Supabase Cloud (enrolled_users, access_audit_logs tables
                                        + encrypted-evidence Storage bucket)
  Offline / unconfigured -> silent no-op (local SQLite acts as the primary store)

Credential Resolution Order
---------------------------
  1. Environment variables: SUPABASE_URL, SUPABASE_KEY
  2. config/security_config.json keys: "SUPABASE_URL", "SUPABASE_KEY"
  3. Fallback -> offline mode (all cloud calls return gracefully)

All public functions are non-throwing: errors are printed and False/None is
returned so the dashboard never crashes due to cloud connectivity issues.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Credential Resolution
# ---------------------------------------------------------------------------

_CONFIG_PATH = os.path.join("config", "security_config.json")


def _load_credentials() -> Tuple[Optional[str], Optional[str]]:
    """
    Resolves Supabase credentials from env vars then config file.

    Returns
    -------
    (url, key) or (None, None) when not configured.
    """
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_KEY", "").strip()

    if not (url and key) and os.path.exists(_CONFIG_PATH):
        try:
            with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
                cfg = json.load(fh)
            url = url or cfg.get("SUPABASE_URL", "").strip()
            key = key or cfg.get("SUPABASE_KEY", "").strip()
        except Exception as exc:
            print(f"[cloud_db] Config read error: {exc}")

    return (url or None, key or None)


# ---------------------------------------------------------------------------
# Supabase Client Singleton
# ---------------------------------------------------------------------------

_supabase_client = None
_cloud_online: bool = False  # True once a live client is initialised


def init_supabase_client():
    """
    Initialise (or return cached) Supabase client.

    Handles:
      * Missing supabase-py package  -> offline mode
      * Missing/empty credentials    -> offline mode
      * Network failure on first RPC -> offline mode

    Returns
    -------
    supabase.Client | None
        None signals offline/fallback mode to all callers.
    """
    global _supabase_client, _cloud_online

    if _supabase_client is not None:
        return _supabase_client

    url, key = _load_credentials()
    if not (url and key):
        print("[cloud_db] Supabase credentials not configured - running in LOCAL-ONLY mode.")
        _cloud_online = False
        return None

    try:
        from supabase import create_client, Client  # type: ignore

        client: Client = create_client(url, key)

        # Lightweight connectivity probe (read 1 row from enrolled_users)
        client.table("enrolled_users").select("user_id").limit(1).execute()

        _supabase_client = client
        _cloud_online = True
        print("[cloud_db] Supabase Cloud connected successfully.")
        return client

    except ImportError:
        print("[cloud_db] supabase-py not installed - running in LOCAL-ONLY mode.")
    except Exception as exc:
        print(f"[cloud_db] Connection failed ({exc}) - falling back to LOCAL SQLite buffer.")

    _cloud_online = False
    return None


def is_cloud_online() -> bool:
    """Returns True if the Supabase client is live and connected."""
    return _cloud_online


# ---------------------------------------------------------------------------
# Public Cloud Sync API
# ---------------------------------------------------------------------------

def sync_user_to_cloud(
    user_id: str,
    name: str,
    role: str,
    image_url: str = "",
) -> bool:
    """
    Upsert a personnel record to the Supabase `enrolled_users` table.

    Parameters
    ----------
    user_id   : unique identifier (matches local SQLite user_id)
    name      : display name
    role      : 'Employee' | 'Customer'
    image_url : public URL to the profile image (optional)

    Returns
    -------
    bool  True on success, False on any error or offline.
    """
    client = init_supabase_client()
    if client is None:
        return False

    payload: Dict[str, Any] = {
        "user_id": user_id,
        "name": name,
        "role": role,
        "image_url": image_url,
        "synced_at": datetime.utcnow().isoformat(),
    }

    try:
        client.table("enrolled_users").upsert(payload, on_conflict="user_id").execute()
        print(f"[cloud_db] User '{name}' ({user_id}) synced to cloud.")
        return True
    except Exception as exc:
        print(f"[cloud_db] sync_user_to_cloud error: {exc}")
        return False


def upload_evidence_to_cloud(
    file_bytes: bytes,
    filename: str,
    bucket: str = "encrypted-evidence",
) -> Optional[str]:
    """
    Upload an AES-256-GCM encrypted evidence frame (.enc) to Supabase Storage.

    Parameters
    ----------
    file_bytes : raw bytes of the encrypted evidence file
    filename   : storage object name, e.g. 'frame_abc123.enc'
    bucket     : Supabase Storage bucket name (default: 'encrypted-evidence')

    Returns
    -------
    str   Public URL of the uploaded object on success.
    None  On any error or offline mode.
    """
    client = init_supabase_client()
    if client is None:
        return None

    try:
        client.storage.from_(bucket).upload(
            path=filename,
            file=file_bytes,
            file_options={
                "content-type": "application/octet-stream",
                "upsert": "true",
            },
        )
        public_url: str = client.storage.from_(bucket).get_public_url(filename)
        print(f"[cloud_db] Evidence '{filename}' uploaded to bucket '{bucket}'.")
        return public_url
    except Exception as exc:
        print(f"[cloud_db] upload_evidence_to_cloud error: {exc}")
        return None


def sync_audit_log_to_cloud(log_payload: Dict[str, Any]) -> bool:
    """
    Persist an audit record to the Supabase `access_audit_logs` table.

    Parameters
    ----------
    log_payload : dict with keys matching the table schema:
        timestamp, mode, verified_parties, party_ids, verdict,
        sha256_hash, encrypted_path, status

    Returns
    -------
    bool  True on success, False on any error or offline.
    """
    client = init_supabase_client()
    if client is None:
        return False

    # Ensure a timestamp is present
    if "timestamp" not in log_payload or not log_payload["timestamp"]:
        log_payload = {**log_payload, "timestamp": datetime.utcnow().isoformat()}

    try:
        client.table("access_audit_logs").insert(log_payload).execute()
        print(
            f"[cloud_db] Audit log synced: {log_payload.get('verdict', '?')} "
            f"@ {log_payload.get('timestamp', '?')}"
        )
        return True
    except Exception as exc:
        print(f"[cloud_db] sync_audit_log_to_cloud error: {exc}")
        return False


# ---------------------------------------------------------------------------
# Convenience: cloud status label for UI
# ---------------------------------------------------------------------------

def get_cloud_status_label() -> str:
    """
    Returns a human-readable status string for the top navigation bar.

    Examples
    --------
    'SUPABASE CONNECTED'  when online
    'OFFLINE BUFFER'      when running locally only
    """
    return "SUPABASE CONNECTED" if is_cloud_online() else "OFFLINE BUFFER"
