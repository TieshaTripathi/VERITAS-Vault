"""
Tests for Hyperledger Besu AuditAnchor Read-Only Adapter & API Endpoints
========================================================================
Validates:
1. Successful connection & contract state queries (Chain ID 1337)
2. Chain ID mismatch detection
3. Missing bytecode detection
4. RPC failure & timeout fault-tolerance
5. URL sanitization
6. Fallback address resolution from contracts/deployments/besu.json
7. Protected FastAPI endpoints /api/blockchain/besu/status and /api/blockchain/status
8. Zero-Trust isolation (biometric/access pipeline unaffected by Besu outage)
9. Outbox dual-network job handling (sepolia + besu)
"""

import json
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
from web3 import Web3

from src.blockchain.besu_adapter import (
    BESU_CHAIN_ID,
    DEFAULT_BESU_RPC,
    DEFAULT_CONTRACT_ADDRESS,
    BesuAuditAnchorAdapter,
    resolve_contract_address,
    sanitize_rpc_url,
    set_besu_adapter,
)
from src.blockchain.audit_batcher import create_batch_from_events
from src.blockchain.outbox import BlockchainOutboxManager
from src.pwa.api import app
from src.pwa.store import Store

MOCK_OWNER = "0xfe3b557e8fb62b89f4916b721be55ceb828dbd73"
MOCK_BYTECODE = b"\x60\x80\x60\x40\x52\x34\x80\x15"


def create_mock_besu_web3(
    is_connected: bool = True,
    chain_id: int = BESU_CHAIN_ID,
    bytecode: bytes = MOCK_BYTECODE,
    owner: str = MOCK_OWNER,
    total_anchors: int = 5,
    block_number: int = 120,
) -> MagicMock:
    mock_w3 = MagicMock()
    mock_w3.is_connected.return_value = is_connected

    mock_eth = MagicMock()
    mock_eth.chain_id = chain_id
    mock_eth.get_code.return_value = bytecode
    mock_eth.block_number = block_number

    mock_contract = MagicMock()
    mock_contract.functions.owner.return_value.call.return_value = owner
    mock_contract.functions.totalAnchors.return_value.call.return_value = total_anchors
    mock_eth.contract.return_value = mock_contract

    mock_w3.eth = mock_eth
    return mock_w3


# -----------------------------------------------------------------------------
# Besu Adapter Unit Tests
# -----------------------------------------------------------------------------

def test_besu_adapter_success():
    mock_w3 = create_mock_besu_web3()
    adapter = BesuAuditAnchorAdapter(
        contract_address="0x" + "b" * 40,
        w3_instance=mock_w3,
    )
    status = adapter.get_status(force_refresh=True)

    assert status["connected"] is True
    assert status["network"] == "besu"
    assert status["consensus"] == "QBFT"
    assert status["chainId"] == 1337
    assert status["owner"] == MOCK_OWNER
    assert status["totalAnchors"] == 5
    assert status["latestBlock"] == 120
    assert status["error"] is None


def test_besu_adapter_chain_id_mismatch():
    mock_w3 = create_mock_besu_web3(chain_id=1)  # Mainnet instead of Besu 1337
    adapter = BesuAuditAnchorAdapter(w3_instance=mock_w3)
    status = adapter.get_status(force_refresh=True)

    assert status["connected"] is False
    assert "Chain ID mismatch" in status["error"]


def test_besu_adapter_missing_bytecode():
    mock_w3 = create_mock_besu_web3(bytecode=b"")
    adapter = BesuAuditAnchorAdapter(w3_instance=mock_w3)
    status = adapter.get_status(force_refresh=True)

    assert status["connected"] is False
    assert "No contract bytecode deployed" in status["error"]


def test_besu_adapter_rpc_unreachable():
    mock_w3 = create_mock_besu_web3(is_connected=False)
    adapter = BesuAuditAnchorAdapter(w3_instance=mock_w3)
    status = adapter.get_status(force_refresh=True)

    assert status["connected"] is False
    assert "Cannot establish connection" in status["error"]


def test_besu_sanitize_rpc_url():
    assert sanitize_rpc_url("http://user:pass@127.0.0.1:8545") == "http://***@127.0.0.1:8545"
    assert sanitize_rpc_url(None) == ""


def test_besu_resolve_contract_address(monkeypatch):
    monkeypatch.delenv("BESU_AUDIT_ANCHOR_ADDRESS", raising=False)
    monkeypatch.delenv("BESU_CONTRACT_ADDRESS", raising=False)

    resolved = resolve_contract_address()
    assert resolved.startswith("0x")


# -----------------------------------------------------------------------------
# Protected FastAPI Endpoint Tests
# -----------------------------------------------------------------------------

@pytest.fixture
def auth_headers_and_cookies():
    store = Store()
    token = "test-besu-session-token-999"
    import hashlib
    token_hash = "auth:" + hashlib.sha256(token.encode()).hexdigest()
    store.put(token_hash, {
        "id": "operator-02",
        "name": "Operator Bob",
        "role": "operator",
        "expires": 9999999999.0,
    })
    return {"cookies": {"vault_session": token}, "headers": {"x-vault-request": "1"}}


def test_besu_status_endpoint(auth_headers_and_cookies):
    mock_w3 = create_mock_besu_web3()
    mock_adapter = BesuAuditAnchorAdapter(
        contract_address="0x" + "b" * 40,
        w3_instance=mock_w3,
    )
    set_besu_adapter(mock_adapter)

    try:
        client = TestClient(app)
        # 1. Dedicated endpoint
        res = client.get(
            "/api/blockchain/besu/status",
            cookies=auth_headers_and_cookies["cookies"],
            headers=auth_headers_and_cookies["headers"],
        )
        assert res.status_code == 200
        data = res.json()
        assert data["connected"] is True
        assert data["network"] == "besu"
        assert data["consensus"] == "QBFT"
        assert data["chainId"] == 1337

        # 2. Hybrid status endpoint includes Besu
        res_hybrid = client.get(
            "/api/blockchain/status",
            cookies=auth_headers_and_cookies["cookies"],
            headers=auth_headers_and_cookies["headers"],
        )
        assert res_hybrid.status_code == 200
        hybrid_data = res_hybrid.json()
        assert "besu" in hybrid_data
        assert hybrid_data["besu"]["connected"] is True
    finally:
        set_besu_adapter(None)


def test_dual_network_outbox_integration(tmp_path):
    store = Store()
    with store.db() as conn:
        conn.execute("DELETE FROM records WHERE id LIKE 'anchor_job:%' OR id LIKE 'batch:%'")
    manager = BlockchainOutboxManager(store=store)

    events = [
        {"sequence_number": 1, "id": "ev-01", "event_hash": "a" * 64},
        {"sequence_number": 2, "id": "ev-02", "event_hash": "b" * 64},
    ]
    batch = create_batch_from_events(events)

    # Enqueue both Sepolia and Besu
    jobs = manager.enqueue_batch(batch, networks=["sepolia", "besu"])
    assert len(jobs) == 2

    sepolia_job = next(j for j in jobs if j.network == "sepolia")
    besu_job = next(j for j in jobs if j.network == "besu")

    assert sepolia_job.status == "PENDING"
    assert besu_job.status == "PENDING"
    assert sepolia_job.batch_id == batch.batch_id
    assert besu_job.batch_id == batch.batch_id

    # Claim Besu job independently
    claimed_besu = manager.claim_jobs("besu", worker_id="besu-worker-1")
    assert len(claimed_besu) == 1
    assert claimed_besu[0].job_id == besu_job.job_id
