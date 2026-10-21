"""
Unit tests for VERITAS-Vault AuditAnchor Solidity Smart Contract.
Uses web3.py with in-memory EthereumTesterProvider (Py-EVM) to execute
real EVM transactions and verify access control, duplicate prevention,
malformed input rejection, event emissions, and Ownable2Step governance.
"""
import json
import pytest
from pathlib import Path
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
from web3.exceptions import ContractCustomError, ContractLogicError
from eth_tester.exceptions import TransactionFailed

REVERT_EXCEPTIONS = (TransactionFailed, ContractCustomError, ContractLogicError)

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "contracts" / "build"


@pytest.fixture(scope="module")
def compiled_contract():
    """Load compiled AuditAnchor ABI and bytecode."""
    abi_path = BUILD_DIR / "AuditAnchor.abi.json"
    bin_path = BUILD_DIR / "AuditAnchor.bin"

    if not abi_path.exists() or not bin_path.exists():
        from scripts.compile_contracts import compile_contracts
        compile_contracts()

    abi = json.loads(abi_path.read_text(encoding="utf-8"))
    bytecode = bin_path.read_text(encoding="utf-8").strip()
    return {"abi": abi, "bytecode": bytecode}


@pytest.fixture
def evm_env(compiled_contract):
    """Set up Web3 with in-memory EthereumTesterProvider."""
    w3 = Web3(EthereumTesterProvider())
    accounts = w3.eth.accounts

    owner = accounts[0]
    relayer = accounts[1]
    unauthorized = accounts[2]
    new_owner = accounts[3]

    ContractFactory = w3.eth.contract(
        abi=compiled_contract["abi"],
        bytecode=compiled_contract["bytecode"]
    )

    # Deploy contract with owner
    tx_hash = ContractFactory.constructor(owner).transact({"from": owner})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    contract = w3.eth.contract(
        address=tx_receipt.contractAddress,
        abi=compiled_contract["abi"]
    )

    return {
        "w3": w3,
        "contract": contract,
        "owner": owner,
        "relayer": relayer,
        "unauthorized": unauthorized,
        "new_owner": new_owner,
    }


# ==============================================================================
# 1. Deployment & Initialization
# ==============================================================================

def test_deployment_initialization(evm_env):
    contract = evm_env["contract"]
    owner = evm_env["owner"]

    assert contract.functions.owner().call() == owner
    assert contract.functions.pendingOwner().call() == "0x" + "0" * 40
    assert contract.functions.totalAnchors().call() == 0


def test_deployment_default_owner(compiled_contract):
    w3 = Web3(EthereumTesterProvider())
    deployer = w3.eth.accounts[4]

    ContractFactory = w3.eth.contract(
        abi=compiled_contract["abi"],
        bytecode=compiled_contract["bytecode"]
    )
    # Passing zero address should default to msg.sender
    zero_addr = "0x" + "0" * 40
    tx_hash = ContractFactory.constructor(zero_addr).transact({"from": deployer})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    deployed = w3.eth.contract(address=receipt.contractAddress, abi=compiled_contract["abi"])
    assert deployed.functions.owner().call() == deployer


# ==============================================================================
# 2. Relayer Management & Access Control
# ==============================================================================

def test_relayer_authorization_flow(evm_env):
    contract = evm_env["contract"]
    owner = evm_env["owner"]
    relayer = evm_env["relayer"]
    unauthorized = evm_env["unauthorized"]

    assert contract.functions.isRelayer(relayer).call() is False

    # Owner authorizes relayer
    tx = contract.functions.setRelayer(relayer, True).transact({"from": owner})
    receipt = evm_env["w3"].eth.wait_for_transaction_receipt(tx)
    assert receipt.status == 1
    assert contract.functions.isRelayer(relayer).call() is True

    # Unauthorized caller cannot authorize relayers
    with pytest.raises(REVERT_EXCEPTIONS):
        contract.functions.setRelayer(unauthorized, True).transact({"from": unauthorized})

    # Cannot authorize zero address
    with pytest.raises(REVERT_EXCEPTIONS):
        contract.functions.setRelayer("0x" + "0" * 40, True).transact({"from": owner})

    # Revoking relayer
    contract.functions.setRelayer(relayer, False).transact({"from": owner})
    assert contract.functions.isRelayer(relayer).call() is False


def test_unauthorized_caller_rejection(evm_env):
    contract = evm_env["contract"]
    unauthorized = evm_env["unauthorized"]

    batch_id = b"batch-test-unauth-00000000000000"
    root_hash = b"\x11" * 32

    # Unauthorized caller cannot anchor
    with pytest.raises(REVERT_EXCEPTIONS):
        contract.functions.anchorBatch(batch_id, root_hash, 10, 1, 10).transact({"from": unauthorized})

    # Unauthorized caller cannot anchor with ref
    with pytest.raises(REVERT_EXCEPTIONS):
        contract.functions.anchorBatchWithRef(batch_id, root_hash, 10, 1, 10, b"\x22" * 32).transact({"from": unauthorized})


# ==============================================================================
# 3. Anchoring Lifecycle & Event Verification
# ==============================================================================

def test_successful_batch_anchoring(evm_env):
    contract = evm_env["contract"]
    owner = evm_env["owner"]
    relayer = evm_env["relayer"]
    w3 = evm_env["w3"]

    # Authorize relayer
    contract.functions.setRelayer(relayer, True).transact({"from": owner})

    batch_id = b"batch-20261022-00100000000000000"
    root_hash = Web3.keccak(text="merkle-root-batch-001")
    event_count = 5
    first_seq = 101
    last_seq = 105

    # Relayer submits anchor
    tx_hash = contract.functions.anchorBatch(
        batch_id, root_hash, event_count, first_seq, last_seq
    ).transact({"from": relayer})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt.status == 1

    # Verify state updates
    assert contract.functions.isBatchAnchored(batch_id).call() is True
    assert contract.functions.isRootAnchored(root_hash).call() is True
    assert contract.functions.totalAnchors().call() == 1

    # Verify retrieved record
    record = contract.functions.getAnchor(batch_id).call()
    assert record[0] == root_hash
    assert record[1] == batch_id
    assert record[2] == first_seq
    assert record[3] == last_seq
    assert record[4] == event_count
    assert record[5] > 0  # block timestamp
    assert record[6] == relayer
    assert record[7] == b"\x00" * 32  # empty crossChainRef

    # Verify event emission
    events = contract.events.BatchAnchored().process_receipt(receipt)
    assert len(events) == 1
    event_args = events[0]["args"]
    assert event_args["batchId"] == batch_id
    assert event_args["rootHash"] == root_hash
    assert event_args["eventCount"] == event_count
    assert event_args["firstSequence"] == first_seq
    assert event_args["lastSequence"] == last_seq
    assert event_args["anchoredBy"] == relayer
    assert event_args["crossChainRef"] == b"\x00" * 32


def test_anchoring_with_cross_chain_ref(evm_env):
    contract = evm_env["contract"]
    owner = evm_env["owner"]
    w3 = evm_env["w3"]

    batch_id = b"batch-sepolia-002000000000000000"
    root_hash = Web3.keccak(text="merkle-root-sepolia-002")
    besu_tx_ref = Web3.keccak(text="besu-tx-hash-0x9999999999999999")

    # Owner anchors directly with cross-chain reference
    tx_hash = contract.functions.anchorBatchWithRef(
        batch_id, root_hash, 12, 201, 220, besu_tx_ref
    ).transact({"from": owner})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt.status == 1

    record = contract.functions.getAnchor(batch_id).call()
    assert record[7] == besu_tx_ref

    events = contract.events.BatchAnchored().process_receipt(receipt)
    assert events[0]["args"]["crossChainRef"] == besu_tx_ref


# ==============================================================================
# 4. Security & Revert Testing: Duplicates & Malformed Inputs
# ==============================================================================

def test_prevent_duplicate_batch_ids(evm_env):
    contract = evm_env["contract"]
    owner = evm_env["owner"]

    batch_id = b"batch-dup-check-0000000000000000"
    root_hash = Web3.keccak(text="unique-root-1")

    # First anchor succeeds
    contract.functions.anchorBatch(batch_id, root_hash, 3, 1, 3).transact({"from": owner})

    # Second anchor with identical batch_id reverts
    different_root = Web3.keccak(text="unique-root-2")
    with pytest.raises(REVERT_EXCEPTIONS):
        contract.functions.anchorBatch(batch_id, different_root, 3, 4, 6).transact({"from": owner})


def test_reject_zero_batch_id(evm_env):
    contract = evm_env["contract"]
    owner = evm_env["owner"]
    zero_bytes = b"\x00" * 32
    valid_root = Web3.keccak(text="valid-root")

    with pytest.raises(REVERT_EXCEPTIONS):
        contract.functions.anchorBatch(zero_bytes, valid_root, 1, 1, 1).transact({"from": owner})


def test_reject_zero_root_hash(evm_env):
    contract = evm_env["contract"]
    owner = evm_env["owner"]
    valid_batch = b"valid-batch-id-00000000000000000"
    zero_bytes = b"\x00" * 32

    with pytest.raises(REVERT_EXCEPTIONS):
        contract.functions.anchorBatch(valid_batch, zero_bytes, 1, 1, 1).transact({"from": owner})


def test_reject_zero_event_count(evm_env):
    contract = evm_env["contract"]
    owner = evm_env["owner"]
    valid_batch = b"valid-batch-id-00000000000000001"
    valid_root = Web3.keccak(text="valid-root")

    with pytest.raises(REVERT_EXCEPTIONS):
        contract.functions.anchorBatch(valid_batch, valid_root, 0, 1, 1).transact({"from": owner})


def test_reject_invalid_sequence_range(evm_env):
    contract = evm_env["contract"]
    owner = evm_env["owner"]
    valid_batch = b"valid-batch-id-00000000000000002"
    valid_root = Web3.keccak(text="valid-root")

    # firstSequence > lastSequence
    with pytest.raises(REVERT_EXCEPTIONS):
        contract.functions.anchorBatch(valid_batch, valid_root, 5, 100, 90).transact({"from": owner})


def test_reject_invalid_sequence_span(evm_env):
    contract = evm_env["contract"]
    owner = evm_env["owner"]
    valid_batch = b"valid-batch-id-00000000000000003"
    valid_root = Web3.keccak(text="valid-root")

    # Range 10 to 12 only has 3 slots, but eventCount declared is 10
    with pytest.raises(REVERT_EXCEPTIONS):
        contract.functions.anchorBatch(valid_batch, valid_root, 10, 10, 12).transact({"from": owner})


def test_get_nonexistent_anchor_reverts(evm_env):
    contract = evm_env["contract"]
    nonexistent = b"non-existent-batch-0000000000000"

    with pytest.raises(REVERT_EXCEPTIONS):
        contract.functions.getAnchor(nonexistent).call()


# ==============================================================================
# 5. Ownable2Step Governance
# ==============================================================================

def test_ownable_2step_transfer(evm_env):
    contract = evm_env["contract"]
    owner = evm_env["owner"]
    new_owner = evm_env["new_owner"]
    unauthorized = evm_env["unauthorized"]
    w3 = evm_env["w3"]

    # Step 1: Owner proposes new owner
    tx1 = contract.functions.transferOwnership(new_owner).transact({"from": owner})
    receipt1 = w3.eth.wait_for_transaction_receipt(tx1)
    assert receipt1.status == 1
    assert contract.functions.pendingOwner().call() == new_owner
    assert contract.functions.owner().call() == owner  # still original owner

    # Unauthorized party cannot accept ownership
    with pytest.raises(REVERT_EXCEPTIONS):
        contract.functions.acceptOwnership().transact({"from": unauthorized})

    # Step 2: Pending owner accepts ownership
    tx2 = contract.functions.acceptOwnership().transact({"from": new_owner})
    receipt2 = w3.eth.wait_for_transaction_receipt(tx2)
    assert receipt2.status == 1

    # Verify ownership moved
    assert contract.functions.owner().call() == new_owner
    assert contract.functions.pendingOwner().call() == "0x" + "0" * 40

    # Old owner no longer has owner privileges
    with pytest.raises(REVERT_EXCEPTIONS):
        contract.functions.setRelayer(unauthorized, True).transact({"from": owner})

    # New owner now has owner privileges
    tx3 = contract.functions.setRelayer(unauthorized, True).transact({"from": new_owner})
    assert w3.eth.wait_for_transaction_receipt(tx3).status == 1
    assert contract.functions.isRelayer(unauthorized).call() is True


def test_transfer_ownership_validations(evm_env):
    contract = evm_env["contract"]
    owner = evm_env["owner"]

    # Cannot propose zero address
    with pytest.raises(REVERT_EXCEPTIONS):
        contract.functions.transferOwnership("0x" + "0" * 40).transact({"from": owner})

    # Cannot propose self
    with pytest.raises(REVERT_EXCEPTIONS):
        contract.functions.transferOwnership(owner).transact({"from": owner})


# ==============================================================================
# 6. Zero PII & Data Minimization Verification
# ==============================================================================

def test_zero_pii_contract_invariant(compiled_contract):
    """
    Asserts that contract functions, events, and inputs do not accept or store
    any biometric images, embeddings, names, or unencrypted evidence fields.
    """
    forbidden_terms = ["face", "biometric", "embedding", "image", "vector", "name", "evidence_blob"]
    abi = compiled_contract["abi"]

    for item in abi:
        item_name = item.get("name", "").lower()
        for term in forbidden_terms:
            assert term not in item_name, f"Forbidden term '{term}' found in ABI item: {item_name}"

        for inp in item.get("inputs", []):
            input_name = inp.get("name", "").lower()
            for term in forbidden_terms:
                assert term not in input_name, f"Forbidden term '{term}' found in input: {input_name}"
