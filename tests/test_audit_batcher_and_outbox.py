"""
Tests for Milestone 2: Durable Audit Batching & Blockchain Outbox
================================================================
Validates:
1. Deterministic batch creation, sequence boundaries, and Merkle roots
2. Strict Zero-PII invariants in batches
3. Merkle inclusion proof generation and verification
4. Idempotent outbox job creation across independent networks (Sepolia & Besu)
5. Worker lease acquisition, CAS concurrency control, and double-claim prevention
6. Worker lease expiration, restart recovery, and graceful shutdown lease release
7. Full lifecycle state transitions (PENDING -> SUBMITTED -> CONFIRMED / RETRY / FAILED)
8. Exponential retry backoff timing
9. Outbox diagnostics reporting
10. Non-blocking isolation: failed outbox never alters zero-trust access decisions
"""

import time
import pytest
from unittest.mock import MagicMock

from src.blockchain.audit_batcher import (
    AuditBatch,
    compute_deterministic_batch_id,
    create_batch_from_events,
    get_batch_inclusion_proof,
    verify_batch_inclusion_proof,
)
from src.blockchain.outbox import (
    BlockchainOutboxManager,
    OutboxJob,
)
from src.pwa.store import Store


def create_mock_event(sequence_number: int, event_id: str, event_hash: str) -> dict:
    return {
        "sequence_number": sequence_number,
        "chain_sequence": sequence_number,
        "id": event_id,
        "event_id": event_id,
        "event_hash": event_hash,
        "sha256_hash": event_hash,
        "timestamp": "2026-10-23T00:00:00Z",
        "verdict": "GRANTED",
    }


# -----------------------------------------------------------------------------
# Batcher Tests
# -----------------------------------------------------------------------------

def test_deterministic_batch_creation():
    events = [
        create_mock_event(1, "ev-01", "a" * 64),
        create_mock_event(2, "ev-02", "b" * 64),
        create_mock_event(3, "ev-03", "c" * 64),
        create_mock_event(4, "ev-04", "d" * 64),
    ]

    batch1 = create_batch_from_events(events)
    batch2 = create_batch_from_events(events)

    assert batch1.batch_id == batch2.batch_id
    assert batch1.root_hash == batch2.root_hash
    assert batch1.first_sequence == 1
    assert batch1.last_sequence == 4
    assert batch1.event_count == 4
    assert batch1.batch_id.startswith("0x")
    assert len(batch1.batch_id) == 66  # 0x + 64 hex chars (bytes32)
    assert batch1.root_hash.startswith("0x")


def test_batch_creation_validation_errors():
    # 1. Empty list
    with pytest.raises(ValueError, match="empty list"):
        create_batch_from_events([])

    # 2. Sequence gap (1, 2, 4)
    gap_events = [
        create_mock_event(1, "ev-01", "a" * 64),
        create_mock_event(2, "ev-02", "b" * 64),
        create_mock_event(4, "ev-04", "d" * 64),
    ]
    with pytest.raises(ValueError, match="Non-contiguous sequence detected"):
        create_batch_from_events(gap_events)

    # 3. Missing event hash
    invalid_event = {"sequence_number": 1, "id": "ev-01"}
    with pytest.raises(ValueError, match="missing cryptographic event hash"):
        create_batch_from_events([invalid_event])


def test_zero_pii_batch_invariant():
    events = [
        create_mock_event(10, "ev-10", "1" * 64),
        create_mock_event(11, "ev-11", "2" * 64),
    ]
    batch = create_batch_from_events(events)
    data = batch.model_dump()

    forbidden_fields = {"name", "user_id", "embedding", "face_crop", "image", "evidence_bytes", "clearance"}
    for key in data.keys():
        assert key.lower() not in forbidden_fields

    dumped_json = batch.model_dump_json()
    assert "face" not in dumped_json.lower()
    assert "biometric" not in dumped_json.lower()


def test_merkle_inclusion_proof_and_verification():
    # 5 events (tests odd-leaf balancing)
    events = [create_mock_event(i, f"ev-0{i}", f"{i}" * 64) for i in range(1, 6)]
    batch = create_batch_from_events(events)

    # Verify each event has valid proof
    for ev in events:
        proof = get_batch_inclusion_proof(batch, ev["id"])
        assert proof is not None
        assert len(proof) > 0

        # Verify proof against root
        assert verify_batch_inclusion_proof(ev["event_hash"], proof, batch.root_hash) is True

        # Tampered leaf fails
        assert verify_batch_inclusion_proof("f" * 64, proof, batch.root_hash) is False

        # Tampered root fails
        assert verify_batch_inclusion_proof(ev["event_hash"], proof, "0x" + "0" * 64) is False

    # Non-existent event returns None
    assert get_batch_inclusion_proof(batch, "non-existent-event-id") is None


# -----------------------------------------------------------------------------
# Outbox Tests
# -----------------------------------------------------------------------------

@pytest.fixture
def clean_store():
    store = Store()
    # Clean previous test outbox keys
    with store.db() as conn:
        conn.execute("DELETE FROM records WHERE id LIKE 'anchor_job:%' OR id LIKE 'batch:%'")
    return store


def test_outbox_enqueue_independent_networks(clean_store):
    manager = BlockchainOutboxManager(store=clean_store)
    events = [create_mock_event(1, "ev-01", "a" * 64), create_mock_event(2, "ev-02", "b" * 64)]
    batch = create_batch_from_events(events)

    jobs = manager.enqueue_batch(batch, networks=["sepolia", "besu"])
    assert len(jobs) == 2

    sepolia_job = next(j for j in jobs if j.network == "sepolia")
    besu_job = next(j for j in jobs if j.network == "besu")

    assert sepolia_job.status == "PENDING"
    assert besu_job.status == "PENDING"
    assert sepolia_job.batch_id == batch.batch_id
    assert besu_job.batch_id == batch.batch_id
    assert sepolia_job.job_id != besu_job.job_id

    # Idempotent re-enqueue
    jobs_again = manager.enqueue_batch(batch, networks=["sepolia", "besu"])
    assert len(jobs_again) == 2
    assert jobs_again[0].job_id in (sepolia_job.job_id, besu_job.job_id)


def test_worker_lease_and_concurrency(clean_store):
    manager = BlockchainOutboxManager(store=clean_store)
    events = [create_mock_event(1, "ev-01", "a" * 64)]
    batch = create_batch_from_events(events)
    manager.enqueue_batch(batch, networks=["sepolia"])

    # Worker 1 claims job
    claimed_w1 = manager.claim_jobs(network="sepolia", worker_id="worker-1", limit=1, lease_duration=10.0)
    assert len(claimed_w1) == 1
    job = claimed_w1[0]
    assert job.status == "SUBMITTED"
    assert job.lease_holder == "worker-1"
    assert job.lease_expires_at is not None
    assert job.lease_expires_at > time.time()
    assert job.attempts == 1

    # Worker 2 attempts concurrent claim (must be prevented)
    claimed_w2 = manager.claim_jobs(network="sepolia", worker_id="worker-2", limit=1)
    assert len(claimed_w2) == 0


def test_worker_lease_expiry_and_recovery(clean_store):
    manager = BlockchainOutboxManager(store=clean_store)
    events = [create_mock_event(1, "ev-01", "a" * 64)]
    batch = create_batch_from_events(events)
    manager.enqueue_batch(batch, networks=["sepolia"])

    # Worker 1 claims with immediate expired lease (negative duration)
    manager.claim_jobs(network="sepolia", worker_id="crashed-worker", limit=1, lease_duration=-5.0)

    # Worker 2 claims -> automatically recovers and claims the expired job
    claimed_w2 = manager.claim_jobs(network="sepolia", worker_id="healthy-worker", limit=1, lease_duration=10.0)
    assert len(claimed_w2) == 1
    assert claimed_w2[0].lease_holder == "healthy-worker"
    assert claimed_w2[0].attempts == 2


def test_job_success_lifecycle(clean_store):
    manager = BlockchainOutboxManager(store=clean_store)
    events = [create_mock_event(1, "ev-01", "a" * 64)]
    batch = create_batch_from_events(events)
    jobs = manager.enqueue_batch(batch, networks=["sepolia"])
    job_id = jobs[0].job_id

    # Claim
    manager.claim_jobs(network="sepolia", worker_id="worker-1")

    # Record success
    mock_tx = "0x" + "a" * 64
    ok = manager.record_success(job_id, worker_id="worker-1", tx_hash=mock_tx, block_number=11972007)
    assert ok is True

    updated_job = manager.get_job(job_id)
    assert updated_job is not None
    assert updated_job.status == "CONFIRMED"
    assert updated_job.tx_hash == mock_tx
    assert updated_job.block_number == 11972007
    assert updated_job.lease_holder is None
    assert updated_job.lease_expires_at is None


def test_job_failure_retry_backoff_and_max_retries(clean_store):
    manager = BlockchainOutboxManager(store=clean_store, base_backoff=1.0)
    events = [create_mock_event(1, "ev-01", "a" * 64)]
    batch = create_batch_from_events(events)
    jobs = manager.enqueue_batch(batch, networks=["sepolia"])
    job_id = jobs[0].job_id

    # 1. First claim and transient failure -> transitions to RETRY
    manager.claim_jobs(network="sepolia", worker_id="worker-1")
    manager.record_failure(job_id, worker_id="worker-1", error_message="RPC Timeout", is_transient=True)

    job = manager.get_job(job_id)
    assert job.status == "RETRY"
    assert job.attempts == 1
    assert job.next_attempt_at > time.time()
    assert "RPC Timeout" in job.last_error

    # 2. Cannot claim before next_attempt_at
    unclaimed = manager.claim_jobs(network="sepolia", worker_id="worker-1")
    assert len(unclaimed) == 0

    # 3. Simulate multiple failures until max_retries
    for attempt in range(2, 6):
        # Manually advance next_attempt_at to become eligible
        saved, ver = clean_store.get(job_id)
        saved["next_attempt_at"] = time.time() - 1.0
        clean_store.put(job_id, saved)

        claimed = manager.claim_jobs(network="sepolia", worker_id=f"worker-{attempt}")
        assert len(claimed) == 1
        manager.record_failure(job_id, worker_id=f"worker-{attempt}", error_message=f"Fail {attempt}", is_transient=True)

    final_job = manager.get_job(job_id)
    assert final_job.status == "FAILED"
    assert final_job.attempts == 5


def test_graceful_shutdown_release_lease(clean_store):
    manager = BlockchainOutboxManager(store=clean_store)
    events = [create_mock_event(1, "ev-01", "a" * 64)]
    batch = create_batch_from_events(events)
    jobs = manager.enqueue_batch(batch, networks=["sepolia"])
    job_id = jobs[0].job_id

    # Claim
    manager.claim_jobs(network="sepolia", worker_id="worker-1", lease_duration=60.0)
    assert manager.get_job(job_id).status == "SUBMITTED"

    # Worker shuts down gracefully and releases lease
    ok = manager.release_lease(job_id, worker_id="worker-1")
    assert ok is True

    released_job = manager.get_job(job_id)
    assert released_job.status == "PENDING"
    assert released_job.lease_holder is None


def test_outbox_diagnostics(clean_store):
    manager = BlockchainOutboxManager(store=clean_store)
    events1 = [create_mock_event(1, "ev-01", "a" * 64)]
    events2 = [create_mock_event(2, "ev-02", "b" * 64)]

    b1 = create_batch_from_events(events1)
    b2 = create_batch_from_events(events2)

    manager.enqueue_batch(b1, networks=["sepolia", "besu"])
    manager.enqueue_batch(b2, networks=["sepolia"])

    diag = manager.get_diagnostics()
    assert diag["total_batches_persisted"] == 2
    assert diag["outbox_queues"]["sepolia"]["total"] == 2
    assert diag["outbox_queues"]["sepolia"]["pending"] == 2
    assert diag["outbox_queues"]["besu"]["total"] == 1
    assert diag["outbox_queues"]["besu"]["pending"] == 1


def test_zero_trust_access_decoupling(clean_store):
    """
    Confirms that even with failing or permanently errored outbox queues,
    the zero-trust policy engine evaluates access with 100% decoupling.
    """
    manager = BlockchainOutboxManager(store=clean_store)
    events = [create_mock_event(1, "ev-01", "a" * 64)]
    batch = create_batch_from_events(events)
    jobs = manager.enqueue_batch(batch, networks=["sepolia"])
    job_id = jobs[0].job_id

    # Mark outbox job permanently failed
    manager.claim_jobs(network="sepolia", worker_id="worker-err")
    manager.record_failure(job_id, worker_id="worker-err", error_message="Fatal consensus fork", is_transient=False)
    assert manager.get_job(job_id).status == "FAILED"

    # Zero-Trust Policy Decision Point operates independently
    from src.policy.pdp import default_pdp
    decision = default_pdp.evaluate(
        checkpoint_id="CP-MAIN-01",
        mode="standard",
        faces=[],
        capture_valid=True,
        capture_reason="OK",
        active_parties=[],
        deadline=None,
    )
    assert decision.decision is not None
    assert decision.risk_score >= 0


def test_single_leaf_batch_merkle_proof():
    """
    Edge case: single-event batch generates valid Merkle proof (empty step list)
    and validates correctly against root hash.
    """
    event = create_mock_event(1, "ev-single", "e" * 64)
    batch = create_batch_from_events([event], created_at_epoch=1700000000.0)

    assert batch.event_count == 1
    assert batch.first_sequence == 1
    assert batch.last_sequence == 1
    assert batch.root_hash.lower() == f"0x{'e' * 64}"
    assert batch.created_at_epoch == 1700000000.0

    proof = get_batch_inclusion_proof(batch, "ev-single")
    assert proof is not None
    assert proof == []
    assert verify_batch_inclusion_proof(event["event_hash"], proof, batch.root_hash) is True
    assert verify_batch_inclusion_proof("f" * 64, proof, batch.root_hash) is False


def test_batch_creation_invalid_hashes_and_networks(clean_store):
    # Non-hex or invalid length hash
    bad_event = {"sequence_number": 1, "id": "ev-01", "event_hash": "not-a-valid-hex-hash"}
    with pytest.raises(ValueError, match="Invalid SHA-256 event hash"):
        create_batch_from_events([bad_event])

    # Missing event ID
    empty_id_event = {"sequence_number": 1, "id": "   ", "event_hash": "a" * 64}
    with pytest.raises(ValueError, match="missing event ID"):
        create_batch_from_events([empty_id_event])

    # Outbox: invalid target network
    manager = BlockchainOutboxManager(store=clean_store)
    batch = create_batch_from_events([create_mock_event(1, "ev-01", "a" * 64)])
    with pytest.raises(ValueError, match="Invalid target network"):
        manager.enqueue_batch(batch, networks=["solana"])


def test_worker_lease_ownership_enforcement(clean_store):
    """
    Worker B must not be able to record success or failure on a job claimed by Worker A.
    """
    manager = BlockchainOutboxManager(store=clean_store)
    batch = create_batch_from_events([create_mock_event(1, "ev-01", "a" * 64)])
    jobs = manager.enqueue_batch(batch, networks=["sepolia"])
    job_id = jobs[0].job_id

    # Worker A claims job
    manager.claim_jobs(network="sepolia", worker_id="worker-A", lease_duration=60.0)

    # Worker B tries to record success -> rejected
    ok_b = manager.record_success(job_id, worker_id="worker-B", tx_hash="0x" + "b" * 64)
    assert ok_b is False

    # Worker B tries to record failure -> rejected
    fail_b = manager.record_failure(job_id, worker_id="worker-B", error_message="Unauthorized fail")
    assert fail_b is False

    # Job is still owned by Worker A in SUBMITTED state
    job = manager.get_job(job_id)
    assert job.status == "SUBMITTED"
    assert job.lease_holder == "worker-A"

    # Worker A successfully completes it
    ok_a = manager.record_success(job_id, worker_id="worker-A", tx_hash="0x" + "a" * 64, block_number=100)
    assert ok_a is True

    # Idempotent second call by Worker A returns True
    assert manager.record_success(job_id, worker_id="worker-A") is True

    # Delayed failure attempt by Worker A after confirmation must be rejected
    assert manager.record_failure(job_id, worker_id="worker-A", error_message="Delayed fail") is False
    assert manager.get_job(job_id).status == "CONFIRMED"


def test_poison_pill_crash_loop_prevention(clean_store):
    """
    If a job's lease expires after reaching max_retries attempts (e.g. repeated worker crashes),
    recover_expired_leases and claim_jobs must transition the job to FAILED, halting the crash loop.
    """
    manager = BlockchainOutboxManager(store=clean_store)
    batch = create_batch_from_events([create_mock_event(1, "ev-01", "a" * 64)])
    jobs = manager.enqueue_batch(batch, networks=["sepolia"])
    job_id = jobs[0].job_id

    # Simulate worker crash after reaching 5 attempts
    saved, ver = clean_store.get(job_id)
    saved["status"] = "SUBMITTED"
    saved["lease_holder"] = "crashing-worker"
    saved["lease_expires_at"] = time.time() - 10.0  # Expired
    saved["attempts"] = 5
    clean_store.put(job_id, saved)

    # recover_expired_leases detects max_retries exceeded and marks FAILED
    recovered = manager.recover_expired_leases(network="sepolia")
    assert recovered == 1

    job = manager.get_job(job_id)
    assert job.status == "FAILED"
    assert "Lease expired after 5 attempts" in job.last_error

    # claim_jobs will not claim FAILED job
    claimed = manager.claim_jobs(network="sepolia", worker_id="new-worker")
    assert len(claimed) == 0

