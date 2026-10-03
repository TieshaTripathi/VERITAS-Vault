"""
VERITAS-Vault Cryptographic Merkle Tree Batching
=================================================
Constructs binary Merkle trees over batches of audit ledger events.
Provides cryptographic Merkle inclusion proofs (O(log N)) to prove
that any given audit event was included in an anchored batch root.
"""

import hashlib
import time
import uuid
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def hash_pair(left: str, right: str) -> str:
    """Compute parent hash from two child hex strings."""
    return sha256_hex((left + right).encode("utf-8"))


class MerkleProofStep(BaseModel):
    position: str  # "left" or "right" (sibling position relative to current)
    hash: str


class MerkleBatch(BaseModel):
    batch_id: str
    first_event_id: str
    last_event_id: str
    root_hash: str
    event_count: int
    created_at: float
    anchor_status: str = "PENDING"  # PENDING, ANCHORED, FAILED, VERIFIED
    leaf_hashes: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)


class MerkleTree:
    """
    Constructs and verifies Merkle Trees over batches of audit events.
    """
    def __init__(self, leaves: Optional[List[Tuple[str, str]]] = None):
        """
        leaves: List of (event_id, event_hash) tuples.
        """
        self.event_ids: List[str] = []
        self.leaf_hashes: List[str] = []
        self.levels: List[List[str]] = []
        self.root_hash: str = ""
        self.batch: Optional[MerkleBatch] = None

        if leaves:
            self.build_from_leaves(leaves)

    def build_from_leaves(self, leaves: List[Tuple[str, str]]) -> MerkleBatch:
        """
        Build Merkle tree from list of (event_id, leaf_hash).
        Handles odd number of leaves and single event batches cleanly.
        """
        if not leaves:
            raise ValueError("Cannot construct Merkle tree with zero leaves.")

        self.event_ids = [leaf[0] for leaf in leaves]
        self.leaf_hashes = [leaf[1] for leaf in leaves]
        self.levels = [list(self.leaf_hashes)]

        current_level = list(self.leaf_hashes)

        # Single leaf batch edge case
        if len(current_level) == 1:
            self.root_hash = current_level[0]
        else:
            while len(current_level) > 1:
                # If odd number of nodes, duplicate the last node
                if len(current_level) % 2 != 0:
                    current_level.append(current_level[-1])

                next_level = []
                for i in range(0, len(current_level), 2):
                    parent = hash_pair(current_level[i], current_level[i + 1])
                    next_level.append(parent)

                self.levels.append(next_level)
                current_level = next_level

            self.root_hash = current_level[0]

        batch_id = f"batch-{uuid.uuid4().hex[:12]}"
        self.batch = MerkleBatch(
            batch_id=batch_id,
            first_event_id=self.event_ids[0],
            last_event_id=self.event_ids[-1],
            root_hash=self.root_hash,
            event_count=len(self.event_ids),
            created_at=time.time(),
            anchor_status="PENDING",
            leaf_hashes=self.leaf_hashes,
            event_ids=self.event_ids
        )
        return self.batch

    def get_merkle_proof(self, event_id: str) -> Optional[List[MerkleProofStep]]:
        """
        Produce cryptographic inclusion proof for event_id.
        Returns list of (sibling position, sibling hash) from leaf to root.
        """
        if event_id not in self.event_ids:
            return None

        idx = self.event_ids.index(event_id)
        proof: List[MerkleProofStep] = []

        # Single leaf case: no siblings required
        if len(self.leaf_hashes) == 1:
            return proof

        for level in self.levels[:-1]:
            # Adjust level if odd
            working_level = list(level)
            if len(working_level) % 2 != 0:
                working_level.append(working_level[-1])

            if idx % 2 == 0:
                # Current node is left, sibling is right
                sibling_hash = working_level[idx + 1]
                proof.append(MerkleProofStep(position="right", hash=sibling_hash))
            else:
                # Current node is right, sibling is left
                sibling_hash = working_level[idx - 1]
                proof.append(MerkleProofStep(position="left", hash=sibling_hash))

            idx = idx // 2

        return proof

    @staticmethod
    def verify_merkle_proof(leaf_hash: str, proof: List[MerkleProofStep], root_hash: str) -> bool:
        """
        Verify that leaf_hash belongs to the tree with root_hash given proof.
        """
        # If single leaf with empty proof
        if not proof:
            return leaf_hash == root_hash

        current_hash = leaf_hash
        for step in proof:
            if step.position == "right":
                current_hash = hash_pair(current_hash, step.hash)
            elif step.position == "left":
                current_hash = hash_pair(step.hash, current_hash)
            else:
                return False

        return current_hash == root_hash
