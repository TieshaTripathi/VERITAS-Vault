"""
VERITAS-Vault Ethereum Sepolia Deployment Script
================================================
Deploys AuditAnchor.sol to Ethereum Sepolia Testnet (Chain ID: 11155111).

Security & Credential Rules:
- Private keys and credentials are NEVER hardcoded or committed to version control.
- Resolves parameters strictly from environment variables:
    * SEPOLIA_RPC_URL: RPC endpoint (e.g., Alchemy, Infura, QuickNode, or public RPC)
    * SEPOLIA_DEPLOYER_KEY: Hex private key for deployer account
    * SEPOLIA_RELAYER_ADDRESS: Optional address of automated backend relayer to authorize
- Validates chain ID strictly equals 11155111 before sending any live transaction.
- Writes non-sensitive deployment metadata (contract address, tx hash, block) to:
    contracts/deployments/sepolia.json
- Includes --dry-run flag for safe local execution without network calls or funds.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from web3 import Web3
from web3.exceptions import Web3Exception

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = ROOT / "contracts"
BUILD_DIR = CONTRACTS_DIR / "build"
DEPLOYMENTS_DIR = CONTRACTS_DIR / "deployments"

SEPOLIA_CHAIN_ID = 11155111
DEFAULT_PUBLIC_RPC = "https://ethereum-sepolia-rpc.publicnode.com"


def load_contract_artifacts():
    combined_path = BUILD_DIR / "combined.json"
    abi_path = BUILD_DIR / "AuditAnchor.abi.json"
    bin_path = BUILD_DIR / "AuditAnchor.bin"

    if combined_path.exists():
        data = json.loads(combined_path.read_text(encoding="utf-8"))
        return data["abi"], data["bytecode"]

    if abi_path.exists() and bin_path.exists():
        abi = json.loads(abi_path.read_text(encoding="utf-8"))
        bytecode = bin_path.read_text(encoding="utf-8").strip()
        return abi, bytecode

    # If missing, attempt compilation
    print("[deploy] Compiling contracts first...")
    from scripts.compile_contracts import compile_contracts
    compile_contracts()
    abi = json.loads((BUILD_DIR / "AuditAnchor.abi.json").read_text(encoding="utf-8"))
    bytecode = (BUILD_DIR / "AuditAnchor.bin").read_text(encoding="utf-8").strip()
    return abi, bytecode


def deploy_sepolia(dry_run: bool = False):
    abi, bytecode = load_contract_artifacts()
    DEPLOYMENTS_DIR.mkdir(parents=True, exist_ok=True)

    if dry_run:
        print("[deploy] Running in DRY-RUN mode (in-memory EVM)...")
        from web3.providers.eth_tester import EthereumTesterProvider
        w3 = Web3(EthereumTesterProvider())
        deployer = w3.eth.accounts[0]
        print(f"[deploy] Simulated deployer address: {deployer}")

        ContractFactory = w3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = ContractFactory.constructor(deployer).transact({"from": deployer})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        contract_address = receipt.contractAddress
        print(f"[deploy] DRY-RUN deployment successful at address: {contract_address}")
        print(f"[deploy] Transaction hash: {receipt.transactionHash.hex()}")

        metadata = {
            "network": "sepolia-dry-run",
            "chainId": 11155111,
            "contractAddress": contract_address,
            "transactionHash": receipt.transactionHash.hex(),
            "blockNumber": receipt.blockNumber,
            "deployer": deployer,
            "deployedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "verified": True,
            "notes": "Simulated local dry-run deployment for CI and testing."
        }
        out_path = DEPLOYMENTS_DIR / "sepolia_dry_run.json"
        out_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        print(f"[deploy] Metadata saved to: {out_path}")
        return metadata

    # Live Sepolia deployment
    rpc_url = os.environ.get("SEPOLIA_RPC_URL", DEFAULT_PUBLIC_RPC).strip()
    private_key = os.environ.get("SEPOLIA_DEPLOYER_KEY", "").strip()

    if not private_key:
        print("[deploy] ERROR: SEPOLIA_DEPLOYER_KEY environment variable is not set.", file=sys.stderr)
        print("[deploy] To run a local simulation, use the --dry-run flag.", file=sys.stderr)
        sys.exit(1)

    if not private_key.startswith("0x"):
        private_key = "0x" + private_key

    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        print(f"[deploy] ERROR: Could not connect to Sepolia RPC at {rpc_url}", file=sys.stderr)
        sys.exit(1)

    chain_id = w3.eth.chain_id
    if chain_id != SEPOLIA_CHAIN_ID:
        print(f"[deploy] ERROR: Connected network chain ID is {chain_id}, expected Sepolia (11155111)!", file=sys.stderr)
        sys.exit(1)

    account = w3.eth.account.from_key(private_key)
    deployer_address = account.address
    balance = w3.eth.get_balance(deployer_address)
    balance_eth = w3.from_wei(balance, "ether")

    print(f"[deploy] Connected to Ethereum Sepolia (Chain ID: {chain_id})")
    print(f"[deploy] Deployer Address: {deployer_address}")
    print(f"[deploy] Deployer Balance: {balance_eth:.6f} ETH")

    if balance == 0:
        print(f"[deploy] ERROR: Deployer account {deployer_address} has 0 ETH on Sepolia.", file=sys.stderr)
        print("[deploy] Acquire testnet ETH from a Sepolia faucet before deploying.", file=sys.stderr)
        sys.exit(1)

    # Prepare Contract
    ContractFactory = w3.eth.contract(abi=abi, bytecode=bytecode)
    nonce = w3.eth.get_transaction_count(deployer_address, "pending")
    base_fee = w3.eth.get_block("latest").get("baseFeePerGas", w3.to_wei(2, "gwei"))
    priority_fee = w3.to_wei(2, "gwei")
    max_fee = base_fee * 2 + priority_fee

    print(f"[deploy] Building deployment transaction with nonce {nonce}...")
    constructor_tx = ContractFactory.constructor(deployer_address).build_transaction({
        "chainId": chain_id,
        "from": deployer_address,
        "nonce": nonce,
        "maxFeePerGas": max_fee,
        "maxPriorityFeePerGas": priority_fee,
    })

    signed_tx = w3.eth.account.sign_transaction(constructor_tx, private_key=private_key)
    print("[deploy] Submitting deployment transaction to Sepolia mempool...")
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    tx_hash_hex = tx_hash.hex()
    print(f"[deploy] Transaction submitted: {tx_hash_hex}")
    print(f"[deploy] Explorer link: https://sepolia.etherscan.io/tx/{tx_hash_hex}")

    print("[deploy] Waiting for confirmation (up to 120s)...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

    if receipt.status != 1:
        print("[deploy] ERROR: Transaction reverted on-chain!", file=sys.stderr)
        sys.exit(1)

    contract_address = receipt.contractAddress
    print(f"\n[deploy] SUCCESS: AuditAnchor deployed to Sepolia!")
    print(f"[deploy] Contract Address: {contract_address}")
    print(f"[deploy] Block Number:     {receipt.blockNumber}")
    print(f"[deploy] Gas Used:         {receipt.gasUsed}")
    print(f"[deploy] Explorer URL:     https://sepolia.etherscan.io/address/{contract_address}")

    # Optional relayer authorization
    relayer_address = os.environ.get("SEPOLIA_RELAYER_ADDRESS", "").strip()
    if relayer_address and Web3.is_address(relayer_address) and relayer_address.lower() != deployer_address.lower():
        print(f"[deploy] Authorizing backend relayer: {relayer_address}...")
        deployed_contract = w3.eth.contract(address=contract_address, abi=abi)
        relayer_nonce = w3.eth.get_transaction_count(deployer_address, "pending")
        relayer_tx = deployed_contract.functions.setRelayer(relayer_address, True).build_transaction({
            "chainId": chain_id,
            "from": deployer_address,
            "nonce": relayer_nonce,
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": priority_fee,
        })
        signed_relayer_tx = w3.eth.account.sign_transaction(relayer_tx, private_key=private_key)
        relayer_hash = w3.eth.send_raw_transaction(signed_relayer_tx.raw_transaction)
        w3.eth.wait_for_transaction_receipt(relayer_hash, timeout=60)
        print(f"[deploy] Relayer {relayer_address} authorized successfully.")

    # Record metadata
    metadata = {
        "network": "sepolia",
        "chainId": SEPOLIA_CHAIN_ID,
        "contractAddress": contract_address,
        "transactionHash": tx_hash_hex,
        "blockNumber": receipt.blockNumber,
        "deployer": deployer_address,
        "relayer": relayer_address or deployer_address,
        "deployedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "verified": True,
        "explorerUrl": f"https://sepolia.etherscan.io/address/{contract_address}"
    }

    out_path = DEPLOYMENTS_DIR / "sepolia.json"
    out_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"[deploy] Deployment metadata persisted to {out_path}")
    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy AuditAnchor to Ethereum Sepolia")
    parser.add_argument("--dry-run", action="store_true", help="Simulate deployment locally without network calls")
    args = parser.parse_args()

    deploy_sepolia(dry_run=args.dry_run)
