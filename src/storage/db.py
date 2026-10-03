"""
VERITAS-Vault Persistent Storage Engine
=========================================
SQLite-backed singleton database (data/vault_security.db) with three tables:

  enrolled_users      - biometric identity registry with feature vectors
  access_audit_logs   - immutable event log (GRANTED / DENIED / BREACH)
  system_diagnostics  - subsystem health check records

Thread-safety:
  All public methods acquire the module-level RLock before touching SQLite.
  The connection is opened with check_same_thread=False but all access is
  serialized through the lock, making it safe for Streamlit's multi-thread
  execution model.
"""

import sqlite3
import os
import uuid
from threading import RLock
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_DIR  = "data"
DB_PATH = os.path.join(DB_DIR, "vault_security.db")


class VaultDatabase:
    """Singleton SQLite engine for VERITAS-Vault."""

    _instance = None
    _lock = RLock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                instance = super().__new__(cls)
                try:
                    instance._init_db()
                except Exception as exc:
                    print(f"[db] Initialization error: {exc}")
                cls._instance = instance
        return cls._instance

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        os.makedirs(DB_DIR, exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        with self._lock:
            cur = self.conn.cursor()

            # ---- Enrolled Users ----
            cur.execute("""
                CREATE TABLE IF NOT EXISTS enrolled_users (
                    user_id       TEXT PRIMARY KEY,
                    name          TEXT NOT NULL,
                    role          TEXT NOT NULL,
                    image_path    TEXT NOT NULL,
                    feature_vector BLOB NOT NULL,
                    enrolled_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Migration: add feature_vector column if missing (legacy DBs)
            cur.execute("PRAGMA table_info(enrolled_users)")
            cols = [row[1] for row in cur.fetchall()]
            if "feature_vector" not in cols:
                cur.execute(
                    "ALTER TABLE enrolled_users ADD COLUMN feature_vector BLOB DEFAULT X''"
                )

            # ---- Access Audit Logs ----
            cur.execute("""
                CREATE TABLE IF NOT EXISTS access_audit_logs (
                    log_id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp         TEXT NOT NULL,
                    mode              TEXT NOT NULL,
                    verified_parties  TEXT NOT NULL,
                    party_ids         TEXT NOT NULL DEFAULT '',
                    verdict           TEXT NOT NULL,
                    sha256_hash       TEXT NOT NULL,
                    encrypted_path    TEXT,
                    status            TEXT DEFAULT 'LOCAL_VERIFIED'
                )
            """)
            # Migration: add party_ids column if missing
            cur.execute("PRAGMA table_info(access_audit_logs)")
            log_cols = [row[1] for row in cur.fetchall()]
            if "party_ids" not in log_cols:
                cur.execute(
                    "ALTER TABLE access_audit_logs ADD COLUMN party_ids TEXT NOT NULL DEFAULT ''"
                )

            # ---- System Diagnostics ----
            cur.execute("""
                CREATE TABLE IF NOT EXISTS system_diagnostics (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT NOT NULL,
                    subsystem   TEXT NOT NULL,
                    status      TEXT NOT NULL,
                    details     TEXT
                )
            """)
            self.conn.commit()

    # ------------------------------------------------------------------
    # Enrolled Users CRUD
    # ------------------------------------------------------------------

    def insert_user(
        self,
        name: str,
        role: str,
        image_path: str,
        user_id: Optional[str] = None,
        feature_vector: Optional[bytes] = None,
    ) -> str:
        if not user_id:
            user_id = "user_" + uuid.uuid4().hex[:6]
        if feature_vector is None:
            feature_vector = b""
        with self._lock:
            try:
                cur = self.conn.cursor()
                cur.execute("""
                    INSERT OR REPLACE INTO enrolled_users
                        (user_id, name, role, image_path, feature_vector, enrolled_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (user_id, name, role, image_path, feature_vector,
                      datetime.now().isoformat()))
                self.conn.commit()
                return user_id
            except Exception as exc:
                print(f"[db] insert_user error: {exc}")
                return ""

    def get_all_users(self) -> List[Dict[str, Any]]:
        with self._lock:
            try:
                cur = self.conn.cursor()
                cur.execute("SELECT * FROM enrolled_users ORDER BY enrolled_at DESC")
                return [dict(row) for row in cur.fetchall()]
            except Exception as exc:
                print(f"[db] get_all_users error: {exc}")
                return []

    def delete_user(self, user_id: str) -> bool:
        with self._lock:
            try:
                cur = self.conn.cursor()
                cur.execute("DELETE FROM enrolled_users WHERE user_id = ?", (user_id,))
                self.conn.commit()
                return cur.rowcount > 0
            except Exception as exc:
                print(f"[db] delete_user error: {exc}")
                return False

    # ------------------------------------------------------------------
    # Access Audit Log CRUD
    # ------------------------------------------------------------------

    def log_access_event(
        self,
        mode: str,
        parties: str,
        verdict: str,
        sha256_hash: str,
        enc_path: str = "",
        status: str = "LOCAL_VERIFIED",
        party_ids: str = "",
    ) -> bool:
        """
        Persists an access control event with exact ISO timestamp, party IDs,
        and the SHA-256 hash of the evidence frame.

        Parameters
        ----------
        mode        : active policy mode string
        parties     : comma-separated display names
        verdict     : 'ACCESS GRANTED' | 'ACCESS DENIED' | 'BREACH' | alert label
        sha256_hash : hex SHA-256 of raw frame bytes (computed pre-disk)
        enc_path    : path to AES-256-GCM encrypted evidence file
        status      : 'LOCAL_VERIFIED' | 'SMS_DISPATCHED_TWILIO' | etc.
        party_ids   : comma-separated user_ids of verified parties
        """
        with self._lock:
            try:
                cur = self.conn.cursor()
                cur.execute("""
                    INSERT INTO access_audit_logs
                        (timestamp, mode, verified_parties, party_ids, verdict,
                         sha256_hash, encrypted_path, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now().isoformat(),
                    mode,
                    parties,
                    party_ids,
                    verdict,
                    sha256_hash,
                    enc_path,
                    status,
                ))
                self.conn.commit()
                return True
            except Exception as exc:
                print(f"[db] log_access_event error: {exc}")
                return False

    def get_recent_logs(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            try:
                cur = self.conn.cursor()
                cur.execute(
                    "SELECT * FROM access_audit_logs ORDER BY log_id DESC LIMIT ?",
                    (limit,)
                )
                return [dict(row) for row in cur.fetchall()]
            except Exception as exc:
                print(f"[db] get_recent_logs error: {exc}")
                return []

    # ------------------------------------------------------------------
    # System Diagnostics CRUD
    # ------------------------------------------------------------------

    def record_diagnostic(self, subsystem: str, status: str, details: str = "") -> bool:
        with self._lock:
            try:
                cur = self.conn.cursor()
                cur.execute("""
                    INSERT INTO system_diagnostics (timestamp, subsystem, status, details)
                    VALUES (?, ?, ?, ?)
                """, (datetime.now().isoformat(), subsystem, status, details))
                self.conn.commit()
                return True
            except Exception as exc:
                print(f"[db] record_diagnostic error: {exc}")
                return False


# ---------------------------------------------------------------------------
# Module-level singleton + helper functions (backward compatible API)
# ---------------------------------------------------------------------------

db_instance = VaultDatabase()


def init_db() -> VaultDatabase:
    return VaultDatabase()


def insert_user(
    name: str,
    role: str,
    image_path: str,
    user_id: Optional[str] = None,
    feature_vector: Optional[bytes] = None,
) -> str:
    return db_instance.insert_user(name=name, role=role, image_path=image_path,
                                    user_id=user_id, feature_vector=feature_vector)


def get_all_users() -> List[Dict[str, Any]]:
    return db_instance.get_all_users()


def delete_user(user_id: str) -> bool:
    return db_instance.delete_user(user_id)


def log_access_event(
    mode: str,
    parties: str,
    verdict: str,
    sha256_hash: str,
    enc_path: str = "",
    status: str = "LOCAL_VERIFIED",
    party_ids: str = "",
    **kwargs,
) -> bool:
    """
    Backward-compatible wrapper accepting keyword aliases used by legacy callers.
    """
    # Accept legacy kwargs from old call sites
    effective_parties = kwargs.get("verified_parties", parties)
    effective_enc_path = kwargs.get("encrypted_evidence_path", enc_path)
    effective_ids = kwargs.get("party_ids", party_ids)

    return db_instance.log_access_event(
        mode=mode,
        parties=effective_parties,
        verdict=verdict,
        sha256_hash=sha256_hash,
        enc_path=effective_enc_path,
        status=status,
        party_ids=effective_ids,
    )


def get_recent_logs(limit: int = 20) -> List[Dict[str, Any]]:
    return db_instance.get_recent_logs(limit)


def record_diagnostic(subsystem: str, status: str, details: str = "") -> bool:
    return db_instance.record_diagnostic(subsystem, status, details)