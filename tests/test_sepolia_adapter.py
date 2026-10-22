"""
Tests for Sepolia AuditAnchor Read-Only Adapter & API Endpoint
=============================================================
Validates:
1. Successful connection & contract state queries
2. Chain ID mismatch detection
3. Missing bytecode detection
4. RPC failure & timeout fault-tolerance
5. URL & secret sanitization
6. Fallback address resolution from contracts/deployments/sepolia.json
7. Protected FastAPI endpoint /api/blockchain/status authorization
8. Zero-Trust isolation (biometric/access pipeline unaffected by RPC outage)
"""

import json
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from web3 import Web3
from web3.exceptions import Web3Exception

from src.blockchain.sepolia_adapter import (
    DEFAULT_CONTRACT_ADDRESS,
    SEPOLIA_CHAIN_ID,
    SepoliaAuditAnchorAdapter,
    resolve_contract_address,
    sanitize_rpc_url,
    set_sepolia_adapter,
)
from src.pwa.api import app
from src.pwa.store import Store


MOCK_OWNER = "0x162c24C889c7315620fA57001BFC26A3B9E4f05f"
MOCK_BYTECODE = b"\x60\x80\x60\x40\x52\x34\x80\x15"


def create_mock_web3(
    is_connected: bool = True,
    chain_id: int = SEPOLIA_CHAIN_ID,
    bytecode: bytes = MOCK_BYTECODE,
    owner: str = MOCK_OWNER,
    total_anchors: int = 0,
    block_number: int = 11972007,
) -> MagicMock:
    """Helper creating a configured mock Web3 instance."""
    mock_w3 = MagicMock(spec=Web3)
    mock_w3.is_connected.return_value = is_connected

    # eth properties and methods
    mock_eth = MagicMock()
    mock_eth.chain_id = chain_id
    mock_eth.get_code.return_value = bytecode
    mock_eth.block_number = block_number

    # Contract mock
    mock_contract = MagicMock()
    mock_contract.functions.owner.return_value.call.return_value = owner
    mock_contract.functions.totalAnchors.return_value.call.return_value = total_anchors
    mock_eth.contract.return_value = mock_contract

    mock_w3.eth = mock_eth
    return mock_w3


# -----------------------------------------------------------------------------
# Adapter Unit Tests
# -----------------------------------------------------------------------------

def test_sepolia_adapter_success():
    mock_w3 = create_mock_web3()
    adapter = SepoliaAuditAnchorAdapter(
        rpc_url="https://ethereum-sepolia-rpc.publicnode.com",
        contract_address=DEFAULT_CONTRACT_ADDRESS,
        w3_instance=mock_w3,
    )

    status = adapter.get_status(force_refresh=True)

    assert status["connected"] is True
    assert status["network"] == "sepolia"
    assert status["chainId"] == SEPOLIA_CHAIN_ID
    assert status["chainIdValid"] is True
    assert status["actualChainId"] == SEPOLIA_CHAIN_ID
    assert status["hasBytecode"] is True
    assert status["bytecodeLength"] == len(MOCK_BYTECODE)
    assert status["owner"] == MOCK_OWNER
    assert status["totalAnchors"] == 0
    assert status["latestBlock"] == 11972007
    assert status["error"] is None
    assert status["latencyMs"] is not None


def test_sepolia_adapter_wrong_chain_id():
    # Simulate Mainnet (chain ID 1) connected by mistake
    mock_w3 = create_mock_web3(chain_id=1)
    adapter = SepoliaAuditAnchorAdapter(
        contract_address=DEFAULT_CONTRACT_ADDRESS,
        w3_instance=mock_w3,
    )

    status = adapter.get_status(force_refresh=True)

    assert status["connected"] is False
    assert status["chainIdValid"] is False
    assert status["actualChainId"] == 1
    assert "Chain ID mismatch" in status["error"]
    assert status["owner"] is None


def test_sepolia_adapter_missing_bytecode():
    # Simulate address with no deployed contract code
    mock_w3 = create_mock_web3(bytecode=b"")
    adapter = SepoliaAuditAnchorAdapter(
        contract_address=DEFAULT_CONTRACT_ADDRESS,
        w3_instance=mock_w3,
    )

    status = adapter.get_status(force_refresh=True)

    assert status["connected"] is False
    assert status["hasBytecode"] is False
    assert status["bytecodeLength"] == 0
    assert "No contract bytecode" in status["error"]
    assert status["owner"] is None


def test_sepolia_adapter_rpc_unreachable():
    # Simulate is_connected() returning False
    mock_w3 = create_mock_web3(is_connected=False)
    adapter = SepoliaAuditAnchorAdapter(
        contract_address=DEFAULT_CONTRACT_ADDRESS,
        w3_instance=mock_w3,
    )

    status = adapter.get_status(force_refresh=True)

    assert status["connected"] is False
    assert "unreachable or offline" in status["error"]
    assert status["hasBytecode"] is False


def test_sepolia_adapter_timeout_handling():
    # Simulate RPC request timeout exception
    mock_w3 = MagicMock(spec=Web3)
    mock_w3.is_connected.side_effect = TimeoutError("Network timed out")
    adapter = SepoliaAuditAnchorAdapter(
        contract_address=DEFAULT_CONTRACT_ADDRESS,
        timeout_seconds=2.0,
        w3_instance=mock_w3,
    )

    status = adapter.get_status(force_refresh=True)

    assert status["connected"] is False
    assert "timed out after 2.0s" in status["error"]


def test_sepolia_adapter_web3_exception():
    # Simulate general Web3Exception
    mock_w3 = MagicMock(spec=Web3)
    mock_w3.is_connected.side_effect = Web3Exception("Provider protocol error")
    adapter = SepoliaAuditAnchorAdapter(
        contract_address=DEFAULT_CONTRACT_ADDRESS,
        w3_instance=mock_w3,
    )

    status = adapter.get_status(force_refresh=True)

    assert status["connected"] is False
    assert "Web3 error: Web3Exception" in status["error"]


def test_sanitize_rpc_url():
    # 1. Public node (no credentials)
    public_url = "https://ethereum-sepolia-rpc.publicnode.com"
    assert sanitize_rpc_url(public_url) == public_url

    # 2. Infura URL with secret key in path
    infura_url = "https://sepolia.infura.io/v3/4f728190c1844bdf98762512a95c8e31"
    sanitized_infura = sanitize_rpc_url(infura_url)
    assert "4f728190c1844bdf98762512a95c8e31" not in sanitized_infura
    assert "4f72...8e31" in sanitized_infura

    # 3. Basic auth credentials
    auth_url = "https://admin:my_secret_pass@rpc.example.com/v1"
    sanitized_auth = sanitize_rpc_url(auth_url)
    assert "my_secret_pass" not in sanitized_auth
    assert "***@rpc.example.com" in sanitized_auth

    # 4. Query string secret
    query_url = "https://rpc.example.com/api?apiKey=secret_token_12345"
    sanitized_query = sanitize_rpc_url(query_url)
    assert "secret_token_12345" not in sanitized_query
    assert "?***" in sanitized_query

    # 5. Empty or None
    assert sanitize_rpc_url(None) == ""
    assert sanitize_rpc_url("") == ""


def test_resolve_contract_address_fallback(monkeypatch):
    monkeypatch.delenv("SEPOLIA_AUDIT_ANCHOR_ADDRESS", raising=False)
    monkeypatch.delenv("AUDIT_ANCHOR_CONTRACT_ADDRESS", raising=False)

    resolved = resolve_contract_address()
    assert resolved == Web3.to_checksum_address(DEFAULT_CONTRACT_ADDRESS)

    # Environment variable override
    override_addr = "0x1111111111111111111111111111111111111111"
    monkeypatch.setenv("SEPOLIA_AUDIT_ANCHOR_ADDRESS", override_addr)
    assert resolve_contract_address() == override_addr


# -----------------------------------------------------------------------------
# Protected FastAPI Endpoint Tests
# -----------------------------------------------------------------------------

@pytest.fixture
def auth_headers_and_cookies():
    """Generates an authenticated operator session token in Store."""
    store = Store()
    token = "test-sepolia-session-token-12345"
    import hashlib
    token_hash = "auth:" + hashlib.sha256(token.encode()).hexdigest()
    store.put(token_hash, {
        "id": "operator-01",
        "name": "Operator Alice",
        "role": "operator",
        "expires": 9999999999.0,
    })
    return {"cookies": {"vault_session": token}, "headers": {"x-vault-request": "1"}}


def test_blockchain_status_endpoint_unauthorized():
    client = TestClient(app)
    response = client.get("/api/blockchain/status", headers={"x-vault-request": "1"})
    assert response.status_code == 401
    assert "Sign in" in response.json().get("detail", "")


def test_blockchain_status_endpoint_authorized(auth_headers_and_cookies):
    mock_w3 = create_mock_web3()
    mock_adapter = SepoliaAuditAnchorAdapter(
        contract_address=DEFAULT_CONTRACT_ADDRESS,
        w3_instance=mock_w3,
    )
    set_sepolia_adapter(mock_adapter)

    try:
        client = TestClient(app)
        response = client.get(
            "/api/blockchain/status",
            cookies=auth_headers_and_cookies["cookies"],
            headers=auth_headers_and_cookies["headers"],
        )
        assert response.status_code == 200
        data = response.json()
        assert data["connected"] is True
        assert data["network"] == "sepolia"
        assert data["chainId"] == 11155111
        assert data["owner"] == MOCK_OWNER
        assert data["totalAnchors"] == 0
        assert data["latestBlock"] == 11972007
    finally:
        set_sepolia_adapter(None)


def test_blockchain_status_endpoint_during_rpc_outage(auth_headers_and_cookies):
    # Adapter reports connection failure
    mock_w3 = create_mock_web3(is_connected=False)
    mock_adapter = SepoliaAuditAnchorAdapter(
        contract_address=DEFAULT_CONTRACT_ADDRESS,
        w3_instance=mock_w3,
    )
    set_sepolia_adapter(mock_adapter)

    try:
        client = TestClient(app)
        response = client.get(
            "/api/blockchain/status",
            cookies=auth_headers_and_cookies["cookies"],
            headers=auth_headers_and_cookies["headers"],
        )
        # Returns 200 with structured diagnostic state (never 500 crashes)
        assert response.status_code == 200
        data = response.json()
        assert data["connected"] is False
        assert "unreachable or offline" in data["error"]
    finally:
        set_sepolia_adapter(None)


def test_zero_trust_access_unaffected_by_blockchain_outage(auth_headers_and_cookies):
    """
    Confirms that even if Sepolia is completely offline or timing out,
    core Zero-Trust physical access challenges and sessions operate with zero impact.
    """
    # 1. Break Sepolia adapter
    mock_w3 = MagicMock(spec=Web3)
    mock_w3.is_connected.side_effect = TimeoutError("Total network black hole")
    set_sepolia_adapter(SepoliaAuditAnchorAdapter(w3_instance=mock_w3))

    try:
        client = TestClient(app)

        # 2. Issue a checkpoint session challenge (core access workflow)
        session_resp = client.post(
            "/api/checkpoint/session",
            json={"device_id": "DEV-EDGE-01", "checkpoint_id": "CP-MAIN-01"},
            cookies=auth_headers_and_cookies["cookies"],
            headers=auth_headers_and_cookies["headers"],
        )
        assert session_resp.status_code == 200
        session_data = session_resp.json()
        assert "session_id" in session_data
        assert "capture_nonce" in session_data

        # 3. Check /api/checkpoint/status
        status_resp = client.get(
            "/api/checkpoint/status",
            cookies=auth_headers_and_cookies["cookies"],
            headers=auth_headers_and_cookies["headers"],
        )
        assert status_resp.status_code == 200
        status_data = status_resp.json()
        assert "state" in status_data
        assert status_data["state"] in ("STANDBY", "ARMED", "GRANTED")

    finally:
        set_sepolia_adapter(None)
