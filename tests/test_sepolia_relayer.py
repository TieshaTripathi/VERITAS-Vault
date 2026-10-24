"""
VERITAS-Vault Sepolia Relayer & Proof Verification Tests
========================================================
Validates:
1. Relayer address resolution & contract authorization checks (is_relayer_authorized)
2. Batch creation from unanchored ledger events (batch_unanchored_events)
3. EVM execution with EthereumTesterProvider:
   - Atomic job claiming via BlockchainOutboxManager
   - On-chain anchorBatch invocation & state verification
   - Outbox job status transition to CONFIRMED with tx hash & block number
   - Idempotent deduplication when batch is already anchored
4. Safe dry-run behavior (simulates via eth_call, releases lease, never broadcasts without approval)
5. Protected API endpoints:
   - /api/blockchain/proof/{event_id} (returns Merkle inclusion proof & anchor status)
   - /api/logs/{event_id} (enriched with batch_id, root_hash, and anchor status)
6. Ledger.verify_event integration with blockchain outbox metadata
"""

import json
import time
import uuid
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider

from src.blockchain.audit_batcher import (
    AuditBatch,
    batch_unanchored_events,
    create_batch_from_events,
    verify_batch_inclusion_proof,
)
from src.blockchain.audit_chain import AuditLedger
from src.blockchain.merkle import MerkleProofStep
from src.blockchain.outbox import BlockchainOutboxManager, get_outbox_manager
from src.blockchain.relayer import SepoliaRelayer, set_sepolia_relayer
from src.pwa.api import app
from src.pwa.store import Store

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "contracts" / "build"


@pytest.fixture(scope="module")
def compiled_contract():
    abi_path = BUILD_DIR / "AuditAnchor.abi.json"
    bin_path = BUILD_DIR / "AuditAnchor.bin"
    if not abi_path.exists() or not bin_path.exists():
        from scripts.compile_contracts import compile_contracts
        compile_contracts()
    abi = json.loads(abi_path.read_text(encoding="utf-8"))
    bytecode = bin_path.read_text(encoding="utf-8").strip()
    return {"abi": abi, "bytecode": bytecode}


@pytest.fixture
def relayer_evm_env(compiled_contract, tmp_path):
    """Sets up an in-memory EVM test environment with deployed AuditAnchor contract."""
    w3 = Web3(EthereumTesterProvider())
    accounts = w3.eth.accounts

    owner = accounts[0]
    authorized_relayer = accounts[1]
    unauthorized = accounts[2]

    ContractFactory = w3.eth.contract(
        abi=compiled_contract["abi"],
        bytecode=compiled_contract["bytecode"],
    )
    tx_hash = ContractFactory.constructor(owner).transact({"from": owner})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    contract = w3.eth.contract(address=receipt.contractAddress, abi=compiled_contract["abi"])

    # Authorize relayer account
    contract.functions.setRelayer(authorized_relayer, True).transact({"from": owner})

    store = Store()
    with store.db() as conn:
        conn.execute("DELETE FROM records WHERE id LIKE 'anchor_job:%' OR id LIKE 'batch:%' OR id LIKE 'event_batch:%' OR id = 'audit:batch_progress'")

    outbox = BlockchainOutboxManager(store=store)

    ledger_db = str(tmp_path / "test_audit_ledger.db")
    ledger = AuditLedger(db_path=ledger_db)

    relayer = SepoliaRelayer(
        contract_address=receipt.contractAddress,
        w3_instance=w3,
        outbox_manager=outbox,
    )

    return {
        "w3": w3,
        "contract": contract,
        "owner": owner,
        "relayer_account": authorized_relayer,
        "unauthorized": unauthorized,
        "relayer": relayer,
        "outbox": outbox,
        "store": store,
        "ledger": ledger,
    }


@pytest.fixture
def auth_headers_and_cookies(relayer_evm_env):
    """Creates authenticated operator session in the temporary store."""
    store = relayer_evm_env["store"]
    token = "test-session-" + str(uuid.uuid4())
    import hashlib
    token_hash = "auth:" + hashlib.sha256(token.encode()).hexdigest()
    store.put(token_hash, {
        "id": "operator-test",
        "name": "Operator Alice",
        "role": "operator",
        "expires": time.time() + 3600.0,
    })
    return {"cookies": {"vault_session": token}, "headers": {"x-vault-request": "1"}}


# -----------------------------------------------------------------------------
# 1. Relayer Authorization Tests
# -----------------------------------------------------------------------------

def test_relayer_authorization(relayer_evm_env):
    relayer = relayer_evm_env["relayer"]
    owner = relayer_evm_env["owner"]
    authorized = relayer_evm_env["relayer_account"]
    unauthorized = relayer_evm_env["unauthorized"]

    assert relayer.is_relayer_authorized(owner) is True
    assert relayer.is_relayer_authorized(authorized) is True
    assert relayer.is_relayer_authorized(unauthorized) is False
    assert relayer.is_relayer_authorized(None) is True  # defaults to provider accounts[1] or accounts[0]


# -----------------------------------------------------------------------------
# 2. Batch Unanchored Events Integration
# -----------------------------------------------------------------------------

def test_batch_unanchored_events_lifecycle(relayer_evm_env):
    ledger = relayer_evm_env["ledger"]
    outbox = relayer_evm_env["outbox"]

    # 1. Empty ledger returns None
    assert batch_unanchored_events(ledger=ledger, outbox=outbox, batch_size=5) is None

    # 2. Append 12 events to ledger
    event_ids = []
    for i in range(12):
        eid = str(uuid.uuid4())
        event_ids.append(eid)
        ledger.append_event(
            event_id=eid,
            timestamp=f"2026-10-24T00:{i:02d}:00Z",
            payload={"verdict": "GRANTED", "score": 0.95 + (i * 0.001)},
        )

    assert ledger.get_max_sequence() == 12

    # 3. Batch first 5 events
    batch1 = batch_unanchored_events(ledger=ledger, outbox=outbox, batch_size=5)
    assert batch1 is not None
    assert batch1.first_sequence == 1
    assert batch1.last_sequence == 5
    assert batch1.event_count == 5
    assert len(batch1.event_ids) == 5

    # 4. Batch next 5 events
    batch2 = batch_unanchored_events(ledger=ledger, outbox=outbox, batch_size=5)
    assert batch2 is not None
    assert batch2.first_sequence == 6
    assert batch2.last_sequence == 10
    assert batch2.event_count == 5

    # 5. Batch remaining 2 events
    batch3 = batch_unanchored_events(ledger=ledger, outbox=outbox, batch_size=5)
    assert batch3 is not None
    assert batch3.first_sequence == 11
    assert batch3.last_sequence == 12
    assert batch3.event_count == 2

    # 6. No more events left to batch
    assert batch_unanchored_events(ledger=ledger, outbox=outbox, batch_size=5) is None

    # 7. Check reverse event -> batch lookup
    for eid in batch1.event_ids:
        looked_up = outbox.get_batch_for_event(eid)
        assert looked_up is not None
        assert looked_up.batch_id == batch1.batch_id


# -----------------------------------------------------------------------------
# 3. Relayer Execution with EVM Tester Provider
# -----------------------------------------------------------------------------

def test_relayer_claims_and_anchors_with_evm_tester(relayer_evm_env):
    relayer = relayer_evm_env["relayer"]
    outbox = relayer_evm_env["outbox"]
    contract = relayer_evm_env["contract"]

    # Create and enqueue a test batch
    events = [
        {"sequence_number": 1, "id": str(uuid.uuid4()), "event_hash": "1" * 64},
        {"sequence_number": 2, "id": str(uuid.uuid4()), "event_hash": "2" * 64},
    ]
    batch = create_batch_from_events(events)
    jobs = outbox.enqueue_batch(batch, networks=["sepolia"])
    job_id = jobs[0].job_id

    # Execute relayer
    results = relayer.process_outbox_jobs(worker_id="test-relayer-worker", limit=5)
    assert len(results) == 1
    res = results[0]
    assert res["status"] == "CONFIRMED"
    assert res["tx_hash"].startswith("0x")
    assert res["block_number"] > 0

    # Verify on-chain contract state
    clean_batch = batch.batch_id.lower().replace("0x", "")
    b_bytes = bytes.fromhex(clean_batch)
    assert contract.functions.isBatchAnchored(b_bytes).call() is True

    record = contract.functions.getAnchor(b_bytes).call()
    assert record[0].hex().lower() == batch.root_hash.lower().replace("0x", "")
    assert record[1].hex().lower() == clean_batch
    assert record[2] == 1  # firstSequence
    assert record[3] == 2  # lastSequence
    assert record[4] == 2  # eventCount

    # Outbox status verified as CONFIRMED
    job = outbox.get_job(job_id)
    assert job.status == "CONFIRMED"
    assert job.tx_hash == res["tx_hash"]
    assert job.block_number == res["block_number"]

    # Idempotency: re-running does not fail and detects already anchored
    saved, _ = outbox.store.get(job_id)
    saved["status"] = "PENDING"
    outbox.store.put(job_id, saved)

    dup_results = relayer.process_outbox_jobs(worker_id="test-relayer-worker-2")
    assert len(dup_results) == 1
    assert dup_results[0]["status"] == "CONFIRMED"
    assert outbox.get_job(job_id).status == "CONFIRMED"


# -----------------------------------------------------------------------------
# 4. Safe Dry-Run Simulation (No Gas / No Live Submission)
# -----------------------------------------------------------------------------

def test_relayer_safe_dry_run_behavior(monkeypatch, tmp_path):
    """
    Validates that when dry_run=True, the relayer calls anchorBatch via eth_call
    simulation, marks SIMULATED_SUCCESS, and safely releases the lease without
    broadcasting live transactions.
    """
    mock_w3 = MagicMock()
    mock_w3.provider = MagicMock()  # Not an ethereum_tester provider
    mock_eth = MagicMock()
    mock_contract = MagicMock()
    mock_contract.functions.isBatchAnchored.return_value.call.return_value = False
    mock_contract.functions.anchorBatch.return_value.call.return_value = True
    mock_eth.contract.return_value = mock_contract
    mock_w3.eth = mock_eth

    store = Store()
    with store.db() as conn:
        conn.execute("DELETE FROM records WHERE id LIKE 'anchor_job:%' OR id LIKE 'batch:%' OR id LIKE 'event_batch:%'")
    outbox = BlockchainOutboxManager(store=store)

    batch = create_batch_from_events([
        {"sequence_number": 1, "id": str(uuid.uuid4()), "event_hash": "a" * 64}
    ])
    jobs = outbox.enqueue_batch(batch, networks=["sepolia"])
    job_id = jobs[0].job_id

    relayer = SepoliaRelayer(
        contract_address="0x" + "1" * 40,
        w3_instance=mock_w3,
        outbox_manager=outbox,
    )

    # Process jobs with dry_run=True (default)
    results = relayer.process_outbox_jobs(worker_id="dry-runner", dry_run=True)
    assert len(results) == 1
    assert results[0]["status"] == "SIMULATED_SUCCESS"
    mock_contract.functions.anchorBatch.return_value.call.assert_called_once()
    mock_contract.functions.anchorBatch.return_value.transact.assert_not_called()

    # Job lease must be cleanly released so it's back in PENDING
    job = outbox.get_job(job_id)
    assert job.status == "PENDING"
    assert job.lease_holder is None


# -----------------------------------------------------------------------------
# 5. Merkle Proof & Single Log API Endpoints
# -----------------------------------------------------------------------------

def test_api_blockchain_proof_and_logs(relayer_evm_env, auth_headers_and_cookies, monkeypatch):
    """
    Tests /api/blockchain/proof/{event_id} and enriched /api/logs/{event_id} endpoints.
    """
    ledger = relayer_evm_env["ledger"]
    outbox = relayer_evm_env["outbox"]
    relayer = relayer_evm_env["relayer"]
    store = relayer_evm_env["store"]

    # Inject temporary dependencies into global getters
    monkeypatch.setattr("src.pwa.api.Store", lambda: store)
    monkeypatch.setattr("src.blockchain.outbox.get_outbox_manager", lambda: outbox)
    monkeypatch.setattr("src.blockchain.relayer.get_sepolia_relayer", lambda: relayer)

    # 1. Create event in ledger and store
    eid = str(uuid.uuid4())
    stored_event = {
        "id": eid,
        "event_id": eid,
        "timestamp": "2026-10-24T12:00:00Z",
        "verdict": "GRANTED",
        "evidence_hash": "f" * 64,
        "chain_sequence": 1,
    }
    store.put(f"event:{eid}", stored_event)
    ledger.append_event(event_id=eid, timestamp=stored_event["timestamp"], payload=stored_event)

    client = TestClient(app)

    # 2. Before batching: proof returns QUEUED_FOR_BATCH
    res_before = client.get(
        f"/api/blockchain/proof/{eid}",
        cookies=auth_headers_and_cookies["cookies"],
        headers=auth_headers_and_cookies["headers"],
    )
    assert res_before.status_code == 200
    data_before = res_before.json()
    assert data_before["status"] == "QUEUED_FOR_BATCH"
    assert data_before["anchored"] is False

    # 3. Batch and anchor the event
    batch = batch_unanchored_events(ledger=ledger, outbox=outbox, batch_size=10)
    assert batch is not None
    relayer.process_outbox_jobs(worker_id="api-tester")

    # 4. After anchoring: proof returns CONFIRMED with Merkle steps
    res_after = client.get(
        f"/api/blockchain/proof/{eid}",
        cookies=auth_headers_and_cookies["cookies"],
        headers=auth_headers_and_cookies["headers"],
    )
    assert res_after.status_code == 200
    data_after = res_after.json()
    assert data_after["status"] == "CONFIRMED"
    assert data_after["anchored"] is True
    assert data_after["batch_id"] == batch.batch_id
    assert data_after["root_hash"] == batch.root_hash
    assert data_after["tx_hash"].startswith("0x")
    assert data_after["block_number"] > 0

    # Validate cryptographic proof structure
    proof_steps = [MerkleProofStep.model_validate(p) for p in data_after["merkle_proof"]]
    # Since single event in batch, Merkle proof is empty list (root is event hash), which verifies
    stored_ledger_event = ledger.get_event(eid)
    assert verify_batch_inclusion_proof(stored_ledger_event["event_hash"], proof_steps, batch.root_hash) is True

    # 5. Check enriched /api/logs/{event_id}
    res_log = client.get(
        f"/api/logs/{eid}",
        cookies=auth_headers_and_cookies["cookies"],
        headers=auth_headers_and_cookies["headers"],
    )
    assert res_log.status_code == 200
    log_data = res_log.json()
    assert log_data["batch_id"] == batch.batch_id
    assert log_data["root_hash"] == batch.root_hash
    assert log_data["blockchain_anchor"]["status"] == "CONFIRMED"
    assert log_data["blockchain_anchor"]["network"] == "sepolia"
    assert log_data["blockchain_anchor"]["tx_hash"].startswith("0x")


def test_ledger_verify_event_anchor_enrichment(relayer_evm_env, monkeypatch):
    """
    Validates that Ledger.verify_event correctly reflects the cryptographic
    blockchain anchor status across batching and relayer execution.
    """
    ledger = relayer_evm_env["ledger"]
    outbox = relayer_evm_env["outbox"]
    relayer = relayer_evm_env["relayer"]

    from src.blockchain.outbox import set_outbox_manager
    set_outbox_manager(outbox)

    try:
        eid = str(uuid.uuid4())
        ledger.append_event(
            event_id=eid,
            timestamp="2026-10-24T12:30:00Z",
            payload={"verdict": "DENIED", "reason": "UNMATCHED_BIOMETRIC"},
            evidence_hash="e" * 64,
        )

        # Before batching: QUEUED_FOR_BATCH
        res1 = ledger.verify_event(eid)
        assert res1["verified"] is True
        assert res1["blockchain_anchor"]["status"] == "QUEUED_FOR_BATCH"

        # Batch and anchor
        batch = batch_unanchored_events(ledger=ledger, outbox=outbox, batch_size=10)
        assert batch is not None
        relayer.process_outbox_jobs(worker_id="verify-worker")

        # After anchoring: CONFIRMED
        res2 = ledger.verify_event(eid)
        assert res2["verified"] is True
        assert res2["blockchain_anchor"]["status"] == "CONFIRMED"
        assert res2["blockchain_anchor"]["batch_id"] == batch.batch_id
        assert res2["blockchain_anchor"]["tx_hash"].startswith("0x")
    finally:
        set_outbox_manager(None)

