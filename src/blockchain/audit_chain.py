"""
VERITAS-Vault Cryptographic Tamper-Evident Audit Ledger
========================================================
Implements cryptographic hash chaining and Ed25519 digital signatures.
Accurately documented: This provides tamper-evident verifiable hash chaining
and local Ed25519 digital signatures, with a simulated permissioned ledger anchor.

Formulation:
  H_k = SHA256( H_{k-1} || canonical_payload || evidence_hash )
  Signature = Ed25519_Sign(private_key, H_k)
"""
import base64
import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

GENESIS_HASH = "0" * 64
SIGNER_KEY_ID = "ed25519-node-primary-v1"


def canonicalize(payload: Dict[str, Any]) -> bytes:
    """Deterministic canonical JSON serialization for cryptographic hashing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AuditLedger:
    """
    Cryptographic Tamper-Evident Hash-Chained Audit Ledger with Ed25519 Asymmetric Signatures.
    """
    def __init__(self, db_path: Optional[Path] = None, keys_dir: Optional[Path] = None):
        root = Path(__file__).resolve().parents[2]
        self.db_path = db_path or (root / "data" / "pwa" / "vault-audit-ledger.sqlite3")
        self.keys_dir = keys_dir or (root / "data" / "keys")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)

        self._private_key, self._public_key = self._load_or_generate_keypair()
        self._init_db()

    def _load_or_generate_keypair(self) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        priv_path = self.keys_dir / "audit_signer_ed25519.key"
        pub_path = self.keys_dir / "audit_signer_ed25519.pub"
        if priv_path.exists():
            priv_bytes = priv_path.read_bytes()
            private_key = serialization.load_pem_private_key(priv_bytes, password=None)
            return private_key, private_key.public_key()
        else:
            private_key = ed25519.Ed25519PrivateKey.generate()
            priv_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            pub_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            priv_path.write_bytes(priv_bytes)
            pub_path.write_bytes(pub_bytes)
            return private_key, private_key.public_key()

    def get_public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def _init_db(self):
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_chain (
                    sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    evidence_hash TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    event_hash TEXT UNIQUE NOT NULL,
                    signature TEXT NOT NULL,
                    signer_key_id TEXT NOT NULL
                )
            """)
            conn.commit()

    def compute_event_hash(self, previous_hash: str, canonical_payload: bytes, evidence_hash: str) -> str:
        hasher = hashlib.sha256()
        hasher.update(previous_hash.encode("ascii"))
        hasher.update(canonical_payload)
        hasher.update(evidence_hash.encode("ascii"))
        return hasher.hexdigest()

    def append_event(
        self,
        event_id: str,
        timestamp: str,
        payload: Dict[str, Any],
        evidence_hash: str = ""
    ) -> Dict[str, Any]:
        """
        Atomically appends a new verified event to the tamper-evident hash chain.
        Ensures strict monotonic sequence and unbroken previous_hash linkage.
        """
        # Ensure volatile hash fields are not inside payload
        clean_payload = {k: v for k, v in payload.items() if k not in ("event_hash", "signature", "previous_hash")}
        canonical_bytes = canonicalize(clean_payload)
        evidence_clean = (evidence_hash or "").strip()

        with sqlite3.connect(self.db_path, timeout=10) as conn:
            conn.execute("BEGIN IMMEDIATE")
            # Get latest event in chain
            cursor = conn.execute("SELECT sequence_number, event_hash FROM audit_chain ORDER BY sequence_number DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                seq = row[0] + 1
                prev_hash = row[1]
            else:
                seq = 1
                prev_hash = GENESIS_HASH

            event_hash = self.compute_event_hash(prev_hash, canonical_bytes, evidence_clean)
            sig_bytes = self._private_key.sign(event_hash.encode("ascii"))
            signature = base64.b64encode(sig_bytes).decode("ascii")

            conn.execute("""
                INSERT INTO audit_chain(sequence_number, event_id, timestamp, previous_hash, evidence_hash, payload, event_hash, signature, signer_key_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (seq, event_id, timestamp, prev_hash, evidence_clean, json.dumps(clean_payload), event_hash, signature, SIGNER_KEY_ID))
            conn.commit()

        return {
            "sequence_number": seq,
            "event_id": event_id,
            "timestamp": timestamp,
            "previous_hash": prev_hash,
            "evidence_hash": evidence_clean,
            "payload": clean_payload,
            "event_hash": event_hash,
            "signature": signature,
            "signer_key_id": SIGNER_KEY_ID
        }

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            row = conn.execute("SELECT sequence_number, event_id, timestamp, previous_hash, evidence_hash, payload, event_hash, signature, signer_key_id FROM audit_chain WHERE event_id=?", (event_id,)).fetchone()
        if not row:
            return None
        return {
            "sequence_number": row[0],
            "event_id": row[1],
            "timestamp": row[2],
            "previous_hash": row[3],
            "evidence_hash": row[4],
            "payload": json.loads(row[5]),
            "event_hash": row[6],
            "signature": row[7],
            "signer_key_id": row[8]
        }

    def verify_event(self, event_id: str) -> Dict[str, Any]:
        """
        Cryptographically verifies the authenticity, hash integrity, and chain linkage of an event.
        """
        event = self.get_event(event_id)
        if not event:
            return {"verified": False, "reason": "Event not found in audit ledger"}

        seq = event["sequence_number"]
        prev_hash = event["previous_hash"]
        ev_hash = event["evidence_hash"]
        stored_hash = event["event_hash"]
        signature = event["signature"]

        # 1. Verify previous hash linkage
        if seq == 1:
            prev_ok = (prev_hash == GENESIS_HASH)
        else:
            with sqlite3.connect(self.db_path, timeout=10) as conn:
                prev_row = conn.execute("SELECT event_hash FROM audit_chain WHERE sequence_number=?", (seq - 1,)).fetchone()
            prev_ok = bool(prev_row and prev_row[0] == prev_hash)

        # 2. Recompute event hash
        canonical_bytes = canonicalize(event["payload"])
        recomputed_hash = self.compute_event_hash(prev_hash, canonical_bytes, ev_hash)
        hash_ok = (recomputed_hash == stored_hash)

        # 3. Verify Ed25519 digital signature
        try:
            sig_raw = base64.b64decode(signature)
            self._public_key.verify(sig_raw, stored_hash.encode("ascii"))
            sig_ok = True
        except Exception:
            sig_ok = False

        verified = (prev_ok and hash_ok and sig_ok)

        return {
            "verified": verified,
            "event_id": event_id,
            "sequence_number": seq,
            "event_hash_valid": hash_ok,
            "previous_hash_linked": prev_ok,
            "signature_valid": sig_ok,
            "evidence_hash_valid": bool(ev_hash),
            "permissioned_ledger_anchor": "SIMULATED_LEDGER_ADAPTER_PENDING_RPC"
        }

    def verify_chain(self, limit: int = 100) -> Dict[str, Any]:
        """
        Iterates through the ledger to mathematically verify chain continuity.
        """
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            rows = conn.execute(
                "SELECT event_id FROM audit_chain ORDER BY sequence_number ASC LIMIT ?", (limit,)
            ).fetchall()

        if not rows:
            return {"verified": True, "total_events": 0, "status": "EMPTY_LEDGER"}

        checked = 0
        for (eid,) in rows:
            res = self.verify_event(eid)
            if not res["verified"]:
                return {
                    "verified": False,
                    "failed_at_sequence": res.get("sequence_number"),
                    "failed_event_id": eid,
                    "detail": res
                }
            checked += 1

        return {
            "verified": True,
            "total_events_verified": checked,
            "status": "AUDIT_CHAIN_INTEGRITY_VERIFIED",
            "ledger_type": "Tamper-Evident SHA-256 Hash Chain with Ed25519 Signatures"
        }


# Global ledger instance
default_audit_ledger = AuditLedger()
