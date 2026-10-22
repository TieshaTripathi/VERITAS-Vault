"""
VERITAS-Vault Permissioned Ledger Adapter
=========================================
Provides ledger anchor interface for anchoring Merkle tree roots.

IMPORTANT ARCHITECTURAL DESIGNATION:
The active default adapter is `LocalLedgerAdapter`, which is explicitly
SIMULATED / LOCAL. It simulates anchor receipts and block heights for local
development and zero-trust verification pipelines.
It is NOT an external decentralized permissioned blockchain.
"""

from abc import ABC, abstractmethod
import time
import uuid
import hashlib
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

from src.blockchain.merkle import MerkleBatch


class LedgerAnchorRecord(BaseModel):
    batch_id: str
    root_hash: str
    event_count: int
    ledger_type: str  # "SIMULATED / LOCAL", "HYPERLEDGER_FABRIC", "QUORUM"
    anchor_status: str  # "PENDING", "ANCHORED", "FAILED", "VERIFIED"
    tx_id: str
    block_height: int
    timestamp: float
    notes: str = Field(default="Simulated local anchor receipt. No external distributed consensus.")


class LedgerAdapter(ABC):
    """Abstract interface for external/internal ledger root anchoring."""

    @abstractmethod
    def anchor_root(self, batch: MerkleBatch) -> LedgerAnchorRecord:
        """Submit a Merkle batch root to the ledger."""
        pass

    @abstractmethod
    def get_anchor(self, batch_id: str) -> Optional[LedgerAnchorRecord]:
        """Fetch anchor status and transaction details by batch_id."""
        pass

    @abstractmethod
    def verify_anchor(self, batch_id: str) -> bool:
        """Verify that the recorded anchor matches the ledger state."""
        pass


class LocalLedgerAdapter(LedgerAdapter):
    """
    SIMULATED / LOCAL ledger adapter for development and testing.
    Stores anchors in a local deterministic registry.
    """
    def __init__(self):
        self._anchors: Dict[str, LedgerAnchorRecord] = {}
        self._current_block = 1000

    def anchor_root(self, batch: MerkleBatch) -> LedgerAnchorRecord:
        self._current_block += 1
        tx_id = f"0xlocal_{uuid.uuid4().hex[:16]}"
        record = LedgerAnchorRecord(
            batch_id=batch.batch_id,
            root_hash=batch.root_hash,
            event_count=batch.event_count,
            ledger_type="SIMULATED / LOCAL",
            anchor_status="ANCHORED",
            tx_id=tx_id,
            block_height=self._current_block,
            timestamp=time.time(),
            notes="Local simulated ledger anchor. Not external distributed blockchain."
        )
        self._anchors[batch.batch_id] = record
        batch.anchor_status = "ANCHORED"
        return record

    def get_anchor(self, batch_id: str) -> Optional[LedgerAnchorRecord]:
        return self._anchors.get(batch_id)

    def verify_anchor(self, batch_id: str) -> bool:
        anchor = self._anchors.get(batch_id)
        if not anchor:
            return False
        # Anchor is verified if it exists and status is ANCHORED or VERIFIED
        if anchor.anchor_status in ("ANCHORED", "VERIFIED"):
            anchor.anchor_status = "VERIFIED"
            return True
        return False

