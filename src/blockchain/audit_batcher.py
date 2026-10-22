"""
VERITAS-Vault Cryptographic Audit Batcher
=========================================
Aggregates persisted, Ed25519-signed, hash-chained audit events into deterministic,
immutable Merkle tree batches.

Architecture & Security Guarantees:
1. Determinism: Given identical contiguous audit sequence bounds, batch IDs,
   Merkle roots, and inclusion proofs are 100% deterministic and reproducible.
2. Zero PII: Batches contain ONLY cryptographic hashes, event UUIDs, and sequence
   bounds. Biometric templates, names, and images are strictly excluded.
3. Cryptographic Verification: Generates logarithmic O(log N) Merkle inclusion
   proofs allowing external parties to verify that any individual audit event
   was anchored on-chain.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from src.blockchain.merkle import MerkleProofStep, MerkleTree


class AuditBatch(BaseModel):
    """
    Immutable representation of an anchored or anchor-ready audit event batch.
    """
    batch_id: str = Field(description="Deterministic 0x-prefixed 32-byte hex string (bytes32 compatible)")
    root_hash: str = Field(description="Merkle tree root hash (SHA-256)")
    first_sequence: int = Field(ge=1, description="First monotonic sequence number in batch")
    last_sequence: int = Field(ge=1, description="Last monotonic sequence number in batch")
    event_count: int = Field(ge=1, description="Total events in batch")
    event_ids: List[str] = Field(default_factory=list, description="Ordered list of event UUIDs")
    leaf_hashes: List[str] = Field(default_factory=list, description="Ordered list of leaf event hashes")
    created_at: str = Field(description="UTC ISO timestamp of batch creation")
    created_at_epoch: float = Field(description="Unix epoch timestamp")


def compute_deterministic_batch_id(first_sequence: int, last_sequence: int, root_hash: str) -> str:
    """
    Generates a deterministic, unique 32-byte hex batchId (0x-prefixed)
    compatible with the Solidity AuditAnchor `bytes32 batchId` parameter.
    """
    clean_root = root_hash.lower().replace("0x", "")
    seed = f"veritas-vault-batch:{first_sequence}:{last_sequence}:{clean_root}".encode("utf-8")
    digest = hashlib.sha256(seed).hexdigest()
    return f"0x{digest}"


def create_batch_from_events(
    events: List[Dict[str, Any]],
    created_at_epoch: Optional[float] = None
) -> AuditBatch:
    """
    Creates an immutable, deterministic AuditBatch from a list of audit events.
    Events must contain:
      - sequence_number (or chain_sequence)
      - id (or event_id)
      - event_hash (or sha256_hash)
    """
    if not events:
        raise ValueError("Cannot create an audit batch from an empty list of events.")

    # Sort events strictly by sequence number
    def get_seq(e: Dict[str, Any]) -> int:
        seq = e.get("sequence_number")
        if seq is None:
            seq = e.get("chain_sequence")
        if seq is None:
            raise ValueError(f"Audit event missing sequence number: {e.get('id', 'unknown')}")
        return int(seq)

    def get_id(e: Dict[str, Any]) -> str:
        eid = e.get("id") or e.get("event_id")
        if not eid or not str(eid).strip():
            raise ValueError("Audit event missing event ID.")
        return str(eid).strip()

    def get_hash(e: Dict[str, Any]) -> str:
        h = e.get("event_hash") or e.get("sha256_hash")
        if not h:
            raise ValueError(f"Audit event missing cryptographic event hash: {e.get('id', 'unknown')}")
        clean = str(h).lower().replace("0x", "")
        if len(clean) != 64 or not all(c in "0123456789abcdef" for c in clean):
            raise ValueError(f"Invalid SHA-256 event hash (expected 64-char hex): {h}")
        return clean

    sorted_events = sorted(events, key=get_seq)

    # Verify contiguous monotonic sequence numbers
    first_seq = get_seq(sorted_events[0])
    last_seq = get_seq(sorted_events[-1])
    expected_count = last_seq - first_seq + 1

    if len(sorted_events) != expected_count:
        raise ValueError(
            f"Non-contiguous sequence detected: expected {expected_count} events from "
            f"sequence {first_seq} to {last_seq}, got {len(sorted_events)}"
        )

    for i, ev in enumerate(sorted_events):
        current_seq = get_seq(ev)
        expected_seq = first_seq + i
        if current_seq != expected_seq:
            raise ValueError(
                f"Sequence gap detected: expected sequence {expected_seq}, found {current_seq}"
            )

    # Build Merkle tree from ordered leaves
    leaves: List[Tuple[str, str]] = [(get_id(e), get_hash(e)) for e in sorted_events]
    tree = MerkleTree(leaves)

    root_clean = tree.root_hash.lower().replace("0x", "")
    root_formatted = f"0x{root_clean}"
    batch_id = compute_deterministic_batch_id(first_seq, last_seq, root_clean)

    now_epoch = float(created_at_epoch) if created_at_epoch is not None else time.time()
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch))

    return AuditBatch(
        batch_id=batch_id,
        root_hash=root_formatted,
        first_sequence=first_seq,
        last_sequence=last_seq,
        event_count=len(sorted_events),
        event_ids=[leaf[0] for leaf in leaves],
        leaf_hashes=[leaf[1] for leaf in leaves],
        created_at=now_iso,
        created_at_epoch=now_epoch,
    )


def get_batch_inclusion_proof(batch: AuditBatch, event_id: str) -> Optional[List[MerkleProofStep]]:
    """
    Computes the Merkle inclusion proof steps for a specific event in the batch.
    """
    if event_id not in batch.event_ids:
        return None

    leaves = list(zip(batch.event_ids, batch.leaf_hashes))
    tree = MerkleTree(leaves)
    return tree.get_merkle_proof(event_id)


def verify_batch_inclusion_proof(
    event_hash: str,
    proof: List[MerkleProofStep],
    root_hash: str
) -> bool:
    """
    Verifies a Merkle inclusion proof against the expected root hash.
    """
    clean_event = event_hash.lower().replace("0x", "")
    clean_root = root_hash.lower().replace("0x", "")
    return MerkleTree.verify_merkle_proof(clean_event, proof, clean_root)
