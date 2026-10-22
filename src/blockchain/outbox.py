"""
VERITAS-Vault Durable Blockchain Outbox Engine
=============================================
Manages asynchronous, durable outbox queues for anchoring audit Merkle roots
to Ethereum Sepolia and private Hyperledger Besu.

Guarantees:
1. Strict Decoupling: Zero-Trust biometric access control and physical door
   authorizations NEVER wait on or fail due to blockchain outbox processing.
2. Network Independence: Outbox jobs for Sepolia and Besu are isolated;
   an outage or latency spike on Besu does not block Sepolia anchoring.
3. Durable At-Least-Once Delivery: Uses worker leases, exponential backoff,
   and restart recovery to guarantee jobs survive server crashes and restarts.
4. Concurrency Safety: Atomic CAS claims prevent duplicate transaction processing.
5. Zero PII: Payloads contain strictly batch IDs, sequence bounds, and root hashes.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.blockchain.audit_batcher import AuditBatch
from src.pwa.store import Store

logger = logging.getLogger("vault.blockchain.outbox")

DEFAULT_MAX_RETRIES = 5
DEFAULT_BASE_BACKOFF_SECONDS = 2.0
DEFAULT_MAX_BACKOFF_SECONDS = 60.0
DEFAULT_LEASE_DURATION_SECONDS = 30.0

VALID_NETWORKS = frozenset({"sepolia", "besu"})
VALID_STATUSES = frozenset({"PENDING", "SUBMITTED", "CONFIRMED", "RETRY", "FAILED"})


class OutboxJob(BaseModel):
    """
    Durable record of a pending or completed blockchain anchoring job.
    """
    job_id: str
    network: str
    batch_id: str
    root_hash: str
    first_sequence: int
    last_sequence: int
    event_count: int
    status: str = Field(default="PENDING")
    attempts: int = Field(default=0)
    max_retries: int = Field(default=DEFAULT_MAX_RETRIES)
    lease_holder: Optional[str] = None
    lease_expires_at: Optional[float] = None
    next_attempt_at: float = Field(default=0.0)
    last_error: Optional[str] = None
    tx_hash: Optional[str] = None
    block_number: Optional[int] = None
    created_at: str
    updated_at: str


class BlockchainOutboxManager:
    """
    Manages durable outbox queues and worker leases across SQLite and Supabase.
    """

    def __init__(
        self,
        store: Optional[Store] = None,
        base_backoff: float = DEFAULT_BASE_BACKOFF_SECONDS,
        max_backoff: float = DEFAULT_MAX_BACKOFF_SECONDS,
        default_lease_duration: float = DEFAULT_LEASE_DURATION_SECONDS,
    ):
        self.store = store or Store()
        self.base_backoff = base_backoff
        self.max_backoff = max_backoff
        self.default_lease_duration = default_lease_duration

    @staticmethod
    def _job_key(network: str, batch_id: str) -> str:
        clean_batch = batch_id.lower().replace("0x", "")
        return f"anchor_job:{network.lower()}:{clean_batch}"

    @staticmethod
    def _batch_key(batch_id: str) -> str:
        clean_batch = batch_id.lower().replace("0x", "")
        return f"batch:{clean_batch}"

    def persist_batch(self, batch: AuditBatch) -> None:
        """Saves immutable batch record durably."""
        key = self._batch_key(batch.batch_id)
        saved, _ = self.store.get(key)
        if not saved:
            self.store.put(key, batch.model_dump())

    def get_batch(self, batch_id: str) -> Optional[AuditBatch]:
        """Fetches persisted batch record by batch_id."""
        key = self._batch_key(batch_id)
        saved, _ = self.store.get(key)
        if saved:
            return AuditBatch.model_validate(saved)
        return None

    def enqueue_batch(
        self,
        batch: AuditBatch,
        networks: Optional[List[str]] = None,
    ) -> List[OutboxJob]:
        """
        Durably enqueues anchoring jobs for specified networks.
        Idempotent: if a job for (network, batch_id) already exists, returns it.
        """
        self.persist_batch(batch)
        requested_networks = [n.lower() for n in (networks or ["sepolia", "besu"])]
        invalid = [n for n in requested_networks if n not in VALID_NETWORKS]
        if invalid:
            raise ValueError(f"Invalid target network(s): {invalid}. Valid networks: {sorted(VALID_NETWORKS)}")

        target_networks = [n for n in requested_networks if n in VALID_NETWORKS]
        if not target_networks:
            raise ValueError(f"No valid target networks specified. Valid networks: {sorted(VALID_NETWORKS)}")

        now_epoch = time.time()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch))

        enqueued: List[OutboxJob] = []
        for net in target_networks:
            key = self._job_key(net, batch.batch_id)
            existing, _ = self.store.get(key)
            if existing:
                enqueued.append(OutboxJob.model_validate(existing))
                continue

            job = OutboxJob(
                job_id=key,
                network=net,
                batch_id=batch.batch_id,
                root_hash=batch.root_hash,
                first_sequence=batch.first_sequence,
                last_sequence=batch.last_sequence,
                event_count=batch.event_count,
                status="PENDING",
                attempts=0,
                max_retries=DEFAULT_MAX_RETRIES,
                next_attempt_at=now_epoch,
                created_at=now_iso,
                updated_at=now_iso,
            )
            self.store.put(key, job.model_dump())
            enqueued.append(job)

        return enqueued

    def get_job(self, job_id: str) -> Optional[OutboxJob]:
        saved, _ = self.store.get(job_id)
        if saved:
            return OutboxJob.model_validate(saved)
        return None

    def claim_jobs(
        self,
        network: str,
        worker_id: str,
        limit: int = 5,
        lease_duration: Optional[float] = None,
    ) -> List[OutboxJob]:
        """
        Atomically claims available outbox jobs for a worker using CAS.
        Eligible jobs:
        - status == PENDING
        - status == RETRY and next_attempt_at <= now
        - status == SUBMITTED and lease_expires_at < now (expired lease recovery)
        """
        prefix = f"anchor_job:{network.lower()}:"
        records = self.store.records(prefix)
        now = time.time()
        duration = self.default_lease_duration if lease_duration is None else lease_duration

        claimed: List[OutboxJob] = []

        for key, payload, version in records:
            if len(claimed) >= limit:
                break
            if not isinstance(payload, dict):
                continue

            status = payload.get("status")
            lease_expires = payload.get("lease_expires_at") or 0.0
            next_attempt = payload.get("next_attempt_at") or 0.0
            attempts = payload.get("attempts", 0)
            max_retries = payload.get("max_retries", DEFAULT_MAX_RETRIES)

            # Prevent infinite crash loops on poison-pill jobs
            if status == "SUBMITTED" and lease_expires < now and attempts >= max_retries:
                updated_payload = dict(payload)
                updated_payload["status"] = "FAILED"
                updated_payload["lease_holder"] = None
                updated_payload["lease_expires_at"] = None
                updated_payload["last_error"] = f"Lease expired after {attempts} attempts without completion"
                updated_payload["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
                self.store.cas(key, version, updated_payload)
                continue

            is_eligible = (
                (status == "PENDING")
                or (status == "RETRY" and next_attempt <= now)
                or (status == "SUBMITTED" and lease_expires < now and attempts < max_retries)
            )

            if not is_eligible:
                continue

            # Prepare atomic lease acquisition
            updated_payload = dict(payload)
            updated_payload["status"] = "SUBMITTED"
            updated_payload["lease_holder"] = worker_id
            updated_payload["lease_expires_at"] = now + duration
            updated_payload["attempts"] = attempts + 1
            updated_payload["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

            # Attempt atomic CAS claim
            if self.store.cas(key, version, updated_payload):
                claimed.append(OutboxJob.model_validate(updated_payload))
                logger.info("Worker %s successfully claimed job %s (network: %s)", worker_id, key, network)

        return claimed

    def record_success(
        self,
        job_id: str,
        worker_id: str,
        tx_hash: Optional[str] = None,
        block_number: Optional[int] = None,
    ) -> bool:
        """
        Marks an outbox job as CONFIRMED upon successful on-chain anchoring.
        Validates worker lease ownership.
        """
        now = time.time()
        for _ in range(5):
            saved, version = self.store.get(job_id)
            if not saved:
                return False

            # Idempotent confirmation
            if saved.get("status") == "CONFIRMED":
                return True

            # Verify lease ownership: worker must be active lease holder
            if saved.get("lease_holder") != worker_id:
                logger.warning("Rejecting status update for %s: worker %s does not hold active lease", job_id, worker_id)
                return False

            updated = dict(saved)
            updated["status"] = "CONFIRMED"
            updated["lease_holder"] = None
            updated["lease_expires_at"] = None
            updated["tx_hash"] = tx_hash
            updated["block_number"] = block_number
            updated["last_error"] = None
            updated["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

            if self.store.cas(job_id, version, updated):
                logger.info("Job %s confirmed on blockchain (tx: %s, block: %s)", job_id, tx_hash, block_number)
                return True

        return False

    def record_failure(
        self,
        job_id: str,
        worker_id: str,
        error_message: str,
        is_transient: bool = True,
    ) -> bool:
        """
        Records failure and calculates exponential backoff retry.
        If non-transient or max_retries reached, transitions to FAILED.
        """
        now = time.time()
        for _ in range(5):
            saved, version = self.store.get(job_id)
            if not saved:
                return False

            # Stale failure must never un-confirm an already confirmed job
            if saved.get("status") == "CONFIRMED":
                return False

            if saved.get("lease_holder") != worker_id:
                logger.warning("Rejecting failure update for %s: worker %s does not hold active lease", job_id, worker_id)
                return False

            attempts = saved.get("attempts", 1)
            max_retries = saved.get("max_retries", DEFAULT_MAX_RETRIES)

            updated = dict(saved)
            updated["last_error"] = str(error_message)[:256]
            updated["lease_holder"] = None
            updated["lease_expires_at"] = None
            updated["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

            if is_transient and (attempts < max_retries):
                updated["status"] = "RETRY"
                backoff = min(self.max_backoff, self.base_backoff * (2 ** (attempts - 1)))
                updated["next_attempt_at"] = now + backoff
                logger.warning("Job %s scheduled for retry in %.1fs (attempt %d/%d): %s", job_id, backoff, attempts, max_retries, error_message)
            else:
                updated["status"] = "FAILED"
                logger.error("Job %s permanently failed after %d attempts: %s", job_id, attempts, error_message)

            if self.store.cas(job_id, version, updated):
                return True

        return False

    def release_lease(self, job_id: str, worker_id: str) -> bool:
        """
        Releases worker lease early, resetting job status to PENDING.
        Enables clean handover during graceful worker shutdowns.
        """
        now = time.time()
        for _ in range(5):
            saved, version = self.store.get(job_id)
            if not saved or saved.get("lease_holder") != worker_id:
                return False

            updated = dict(saved)
            updated["status"] = "PENDING"
            updated["lease_holder"] = None
            updated["lease_expires_at"] = None
            updated["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

            if self.store.cas(job_id, version, updated):
                return True

        return False

    def recover_expired_leases(self, network: Optional[str] = None) -> int:
        """
        Scans for SUBMITTED jobs whose worker leases expired without confirmation.
        Re-queues them to PENDING for automatic recovery after server crashes or restarts.
        Transitions poison-pill jobs (attempts >= max_retries) to FAILED.
        """
        prefix = f"anchor_job:{network.lower()}:" if network else "anchor_job:"
        records = self.store.records(prefix)
        now = time.time()
        recovered = 0

        for key, payload, version in records:
            if not isinstance(payload, dict):
                continue
            if payload.get("status") == "SUBMITTED":
                lease_expires = payload.get("lease_expires_at") or 0.0
                if lease_expires < now:
                    updated = dict(payload)
                    attempts = updated.get("attempts", 0)
                    max_retries = updated.get("max_retries", DEFAULT_MAX_RETRIES)
                    if attempts >= max_retries:
                        updated["status"] = "FAILED"
                        updated["last_error"] = f"Lease expired after {attempts} attempts without completion"
                    else:
                        updated["status"] = "PENDING"
                    updated["lease_holder"] = None
                    updated["lease_expires_at"] = None
                    updated["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
                    if self.store.cas(key, version, updated):
                        recovered += 1
                        logger.info("Recovered expired lease on job: %s (status: %s)", key, updated["status"])

        return recovered

    def get_diagnostics(self) -> Dict[str, Any]:
        """
        Returns structured health and queue metrics for the blockchain outbox.
        """
        now = time.time()
        try:
            records = self.store.records("anchor_job:")
            batches = self.store.records("batch:")
        except Exception as e:
            logger.error("Failed to fetch outbox diagnostics: %s", e)
            return {
                "total_batches_persisted": 0,
                "outbox_queues": {
                    "sepolia": {"total": 0, "pending": 0, "submitted": 0, "confirmed": 0, "retrying": 0, "failed": 0, "active_leases": 0},
                    "besu": {"total": 0, "pending": 0, "submitted": 0, "confirmed": 0, "retrying": 0, "failed": 0, "active_leases": 0},
                },
                "error": str(e),
                "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            }

        by_network: Dict[str, Dict[str, int]] = {
            "sepolia": {"total": 0, "pending": 0, "submitted": 0, "confirmed": 0, "retrying": 0, "failed": 0, "active_leases": 0},
            "besu": {"total": 0, "pending": 0, "submitted": 0, "confirmed": 0, "retrying": 0, "failed": 0, "active_leases": 0},
        }

        for _, payload, _ in records:
            if not isinstance(payload, dict):
                continue
            net = payload.get("network", "unknown").lower()
            if net not in by_network:
                by_network[net] = {"total": 0, "pending": 0, "submitted": 0, "confirmed": 0, "retrying": 0, "failed": 0, "active_leases": 0}

            counts = by_network[net]
            counts["total"] += 1
            st = payload.get("status", "UNKNOWN")
            if st == "PENDING":
                counts["pending"] += 1
            elif st == "SUBMITTED":
                counts["submitted"] += 1
                if (payload.get("lease_expires_at") or 0) > now:
                    counts["active_leases"] += 1
            elif st == "CONFIRMED":
                counts["confirmed"] += 1
            elif st == "RETRY":
                counts["retrying"] += 1
            elif st == "FAILED":
                counts["failed"] += 1

        return {
            "total_batches_persisted": len(batches),
            "outbox_queues": by_network,
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        }


# Global lazy singleton instance
_outbox_instance: Optional[BlockchainOutboxManager] = None


def get_outbox_manager() -> BlockchainOutboxManager:
    global _outbox_instance
    if _outbox_instance is None:
        _outbox_instance = BlockchainOutboxManager()
    return _outbox_instance


def set_outbox_manager(manager: Optional[BlockchainOutboxManager]) -> None:
    global _outbox_instance
    _outbox_instance = manager
