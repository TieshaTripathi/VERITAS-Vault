"""
VERITAS-Vault Hyperledger Besu Private QBFT Deployment Script
=============================================================
Deploys AuditAnchor.sol to a private Hyperledger Besu QBFT network (Chain ID: 1337).

Features:
- Connects to local Besu JSON-RPC endpoint (default: http://127.0.0.1:8545).
- Verifies network connectivity and Chain ID 1337.
- Zero gas fee configuration compatible with private QBFT consensus.
- Saves deployment metadata to contracts/deployments/besu.json.
- Full --dry-run support for offline CI/CD and pre-flight validation.
"""

from __future__ import annotations

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

BESU_CHAIN_ID = 1337
DEFAULT_BESU_RPC = "http://127.0.0.1:8545"

# Dev key pre-funded in genesis.json (standard Besu dev key)
DEV_VALIDATOR_KEY = os.environ.get("BESU_DEPLOYER_KEY") or "0xc87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3"


def load_artifacts():
    abi_path = BUILD_DIR / "AuditAnchor.abi.json"
    bin_path = BUILD_DIR / "AuditAnchor.bin"
    if not abi_path.exists() or not bin_path.exists():
        from scripts.compile_contracts import compile_contracts
        compile_contracts()
    abi = json.loads(abi_path.read_text(encoding="utf-8"))
    bytecode = bin_path.read_text(encoding="utf-8").strip()
    return abi, bytecode


def deploy_besu(rpc_url: str = DEFAULT_BESU_RPC, dry_run: bool = False) -> dict:
    abi, bytecode = load_artifacts()
    DEPLOYMENTS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = DEPLOYMENTS_DIR / "besu.json"

    if dry_run:
        meta = {
            "network": "besu",
            "chainId": BESU_CHAIN_ID,
            "contractAddress": "0x" + "b" * 40,
            "transactionHash": "0x" + "d" * 64,
            "blockNumber": 1,
            "deployer": "0xfe3b557e8fb62b89f4916b721be55ceb828dbd73",
            "owner": "0xfe3b557e8fb62b89f4916b721be55ceb828dbd73",
            "relayer": "0xfe3b557e8fb62b89f4916b721be55ceb828dbd73",
            "deployedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "verified": True,
            "simulated": True,
        }
        out_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        print(f"[DRY-RUN] Besu deployment simulated. Metadata saved to {out_file}")
        return meta

    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 5}))
    if not w3.is_connected():
        raise ConnectionError(f"Cannot connect to Besu JSON-RPC at {rpc_url}")

    chain_id = w3.eth.chain_id
    if chain_id != BESU_CHAIN_ID:
        raise ValueError(f"Chain ID mismatch: expected {BESU_CHAIN_ID}, got {chain_id}")

    acct = w3.eth.account.from_key(DEV_VALIDATOR_KEY)
    factory = w3.eth.contract(abi=abi, bytecode=bytecode)

    nonce = w3.eth.get_transaction_count(acct.address, "pending")
    tx = factory.constructor(acct.address).build_transaction({
        "from": acct.address,
        "nonce": nonce,
        "gasPrice": 0,
        "gas": 3000000,
        "chainId": BESU_CHAIN_ID,
    })

    signed = w3.eth.account.sign_transaction(tx, private_key=DEV_VALIDATOR_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)

    meta = {
        "network": "besu",
        "chainId": BESU_CHAIN_ID,
        "contractAddress": receipt.contractAddress,
        "transactionHash": receipt.transactionHash.hex(),
        "blockNumber": receipt.blockNumber,
        "deployer": acct.address,
        "owner": acct.address,
        "relayer": acct.address,
        "deployedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "verified": True,
        "simulated": False,
    }
    out_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[SUCCESS] AuditAnchor deployed to Besu at {receipt.contractAddress}")
    return meta


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy AuditAnchor to Hyperledger Besu QBFT")
    parser.add_argument("--dry-run", action="store_true", help="Simulate deployment without live node")
    parser.add_argument("--rpc", default=DEFAULT_BESU_RPC, help="Besu JSON-RPC endpoint")
    args = parser.parse_args()

    try:
        deploy_besu(rpc_url=args.rpc, dry_run=args.dry_run)
    except Exception as exc:
        print(f"[ERROR] Besu deployment failed: {exc}", file=sys.stderr)
        sys.exit(1)
