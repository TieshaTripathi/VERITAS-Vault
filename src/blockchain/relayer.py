"""
VERITAS-Vault Ethereum Sepolia Relayer
======================================
Automated agent that claims pending blockchain outbox anchoring jobs and submits
Merkle roots to the Ethereum Sepolia AuditAnchor smart contract.

Guarantees & Constraints:
1. Approval Boundary: Never submits live blockchain transactions without explicit
   parameter approval (`dry_run=False`) AND `SUBMIT_LIVE_TRANSACTIONS=true` environment flag.
2. Zero-Trust Access Decoupling: Relayer runs purely asynchronously; access decisions
   and door releases NEVER wait on or block on relayer execution.
3. Concurrency Safe: Uses atomic worker claims from BlockchainOutboxManager (CAS/SKIP LOCKED).
4. Full Testability: Transparently supports both EthereumTesterProvider and JSON-RPC.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from web3 import Web3
from web3.exceptions import Web3Exception
from web3.providers.eth_tester import EthereumTesterProvider

from src.blockchain.audit_batcher import AuditBatch
from src.blockchain.outbox import BlockchainOutboxManager, OutboxJob, get_outbox_manager
from src.blockchain.sepolia_adapter import (
    DEFAULT_CONTRACT_ADDRESS,
    DEFAULT_SEPOLIA_RPC,
    load_audit_anchor_abi,
    resolve_contract_address,
    resolve_rpc_url,
    resolve_timeout,
    sanitize_rpc_url,
)

logger = logging.getLogger("vault.blockchain.relayer")


class SepoliaRelayer:
    """
    Automated relayer for anchoring audit batches to Ethereum Sepolia.
    """

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        contract_address: Optional[str] = None,
        relayer_key: Optional[str] = None,
        w3_instance: Optional[Web3] = None,
        outbox_manager: Optional[BlockchainOutboxManager] = None,
        timeout_seconds: Optional[float] = None,
    ):
        self._rpc_url = rpc_url or resolve_rpc_url()
        self._contract_address = (
            Web3.to_checksum_address(contract_address)
            if contract_address
            else resolve_contract_address()
        )
        self._timeout_seconds = timeout_seconds if timeout_seconds is not None else resolve_timeout()
        self._relayer_key = relayer_key or os.environ.get("SEPOLIA_RELAYER_KEY") or os.environ.get("SEPOLIA_DEPLOYER_KEY")
        self._abi = load_audit_anchor_abi()
        self._w3 = w3_instance
        self.outbox = outbox_manager or get_outbox_manager()

    def _get_w3(self) -> Web3:
        if self._w3 is None:
            provider = Web3.HTTPProvider(
                self._rpc_url,
                request_kwargs={"timeout": self._timeout_seconds},
            )
            self._w3 = Web3(provider)
        return self._w3

    def get_relayer_address(self) -> Optional[str]:
        """Resolves the Ethereum address corresponding to the relayer key or provider account."""
        if self._w3 and isinstance(getattr(self._w3, "provider", None), EthereumTesterProvider):
            accounts = self._w3.eth.accounts
            if len(accounts) > 1:
                return accounts[1]
            if accounts:
                return accounts[0]

        if self._relayer_key:
            try:
                w3 = self._get_w3()
                account = w3.eth.account.from_key(self._relayer_key)
                return account.address
            except Exception:
                pass
        return None

    def is_relayer_authorized(self, address: Optional[str] = None) -> bool:
        """Verifies if the relayer address is authorized on the AuditAnchor contract."""
        relayer_addr = address or self.get_relayer_address()
        if not relayer_addr:
            return False
        try:
            w3 = self._get_w3()
            contract = w3.eth.contract(address=self._contract_address, abi=self._abi)
            owner = contract.functions.owner().call()
            if Web3.to_checksum_address(relayer_addr) == Web3.to_checksum_address(owner):
                return True
            return bool(contract.functions.isRelayer(Web3.to_checksum_address(relayer_addr)).call())
        except Exception as exc:
            logger.warning("Error checking relayer authorization: %s", exc)
            return False

    def process_outbox_jobs(
        self,
        worker_id: str = "sepolia-relayer-01",
        limit: int = 5,
        dry_run: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Claims eligible Sepolia anchoring jobs and anchors them to the AuditAnchor contract.

        Safety Rules:
        - When dry_run=True (default), does NOT broadcast live transactions or consume gas.
        - When running in local EVM tester mode, executes transactions directly for integration validation.
        - Live broadcasts require dry_run=False AND SUBMIT_LIVE_TRANSACTIONS=true.
        """
        results: List[Dict[str, Any]] = []
        claimed = self.outbox.claim_jobs("sepolia", worker_id=worker_id, limit=limit)
        if not claimed:
            return results

        w3 = self._get_w3()
        contract = w3.eth.contract(address=self._contract_address, abi=self._abi)
        relayer_addr = self.get_relayer_address()
        is_tester = isinstance(getattr(w3, "provider", None), EthereumTesterProvider)

        # Explicit live submission guard
        allow_live = (not dry_run) and (os.environ.get("SUBMIT_LIVE_TRANSACTIONS", "").lower() == "true")

        for job in claimed:
            summary = {
                "job_id": job.job_id,
                "batch_id": job.batch_id,
                "status": "PROCESSING",
                "tx_hash": None,
                "block_number": None,
                "error": None,
            }

            clean_batch = job.batch_id.lower().replace("0x", "")
            clean_root = job.root_hash.lower().replace("0x", "")

            try:
                b_bytes = bytes.fromhex(clean_batch)
                r_bytes = bytes.fromhex(clean_root)
            except ValueError as ve:
                err = f"Malformed hex in batch_id or root_hash: {ve}"
                self.outbox.record_failure(job.job_id, worker_id, err, is_transient=False)
                summary["status"] = "FAILED"
                summary["error"] = err
                results.append(summary)
                continue

            # Idempotency check: is this batch already anchored on-chain?
            try:
                if contract.functions.isBatchAnchored(b_bytes).call():
                    logger.info("Batch %s is already anchored on-chain. Marking CONFIRMED.", job.batch_id)
                    self.outbox.record_success(job.job_id, worker_id, tx_hash="0x_already_anchored", block_number=None)
                    summary["status"] = "CONFIRMED"
                    results.append(summary)
                    continue
            except Exception as exc:
                logger.warning("Could not check isBatchAnchored for %s: %s", job.batch_id, exc)

            # Test environment execution (in-memory EVM)
            if is_tester:
                try:
                    caller = relayer_addr or w3.eth.accounts[0]
                    tx_hash = contract.functions.anchorBatch(
                        b_bytes, r_bytes, job.event_count, job.first_sequence, job.last_sequence
                    ).transact({"from": caller})
                    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                    if receipt.status == 1:
                        raw_h = receipt.transactionHash.hex()
                        tx_hex = raw_h if raw_h.startswith("0x") else f"0x{raw_h}"
                        self.outbox.record_success(job.job_id, worker_id, tx_hash=tx_hex, block_number=receipt.blockNumber)
                        summary["status"] = "CONFIRMED"
                        summary["tx_hash"] = tx_hex
                        summary["block_number"] = receipt.blockNumber
                    else:
                        err = f"EVM tester transaction reverted: {tx_hash.hex()}"
                        self.outbox.record_failure(job.job_id, worker_id, err, is_transient=False)
                        summary["status"] = "FAILED"
                        summary["error"] = err
                except Exception as exc:
                    err = str(exc)
                    self.outbox.record_failure(job.job_id, worker_id, err, is_transient=True)
                    summary["status"] = "RETRY"
                    summary["error"] = err
                results.append(summary)
                continue

            # Safe Dry-Run Simulation on live RPC
            if not allow_live:
                try:
                    caller = relayer_addr or "0x0000000000000000000000000000000000000000"
                    # eth_call simulation
                    contract.functions.anchorBatch(
                        b_bytes, r_bytes, job.event_count, job.first_sequence, job.last_sequence
                    ).call({"from": caller})
                    logger.info("DRY-RUN simulation for batch %s succeeded (no live transaction sent).", job.batch_id)
                    summary["status"] = "SIMULATED_SUCCESS"
                    summary["notes"] = "eth_call passed; live broadcast skipped without explicit approval."
                    # Release lease cleanly so job remains eligible for live processing when approved
                    self.outbox.release_lease(job.job_id, worker_id)
                except Exception as exc:
                    err = f"Simulation call reverted: {exc}"
                    logger.warning("Dry-run simulation failed for %s: %s", job.batch_id, err)
                    self.outbox.record_failure(job.job_id, worker_id, err, is_transient=True)
                    summary["status"] = "RETRY"
                    summary["error"] = err
                results.append(summary)
                continue

            # Live Transaction Execution (only when explicitly approved)
            try:
                if not self._relayer_key:
                    raise ValueError("SEPOLIA_RELAYER_KEY is not configured for live broadcast.")

                account = w3.eth.account.from_key(self._relayer_key)
                nonce = w3.eth.get_transaction_count(account.address, "pending")
                gas_price = w3.eth.gas_price

                tx_data = contract.functions.anchorBatch(
                    b_bytes, r_bytes, job.event_count, job.first_sequence, job.last_sequence
                ).build_transaction({
                    "from": account.address,
                    "nonce": nonce,
                    "gasPrice": int(gas_price * 1.15),
                    "chainId": 11155111,
                })

                signed = w3.eth.account.sign_transaction(tx_data, private_key=self._relayer_key)
                raw_tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
                raw_hex = raw_tx_hash.hex()
                tx_hex = raw_hex if raw_hex.startswith("0x") else f"0x{raw_hex}"
                logger.info("Broadcasted live Sepolia anchor transaction %s for batch %s", tx_hex, job.batch_id)

                receipt = w3.eth.wait_for_transaction_receipt(raw_tx_hash, timeout=120)
                if receipt.status == 1:
                    self.outbox.record_success(job.job_id, worker_id, tx_hash=tx_hex, block_number=receipt.blockNumber)
                    summary["status"] = "CONFIRMED"
                    summary["tx_hash"] = tx_hex
                    summary["block_number"] = receipt.blockNumber
                else:
                    err = f"Sepolia transaction reverted: {tx_hex}"
                    self.outbox.record_failure(job.job_id, worker_id, err, is_transient=False)
                    summary["status"] = "FAILED"
                    summary["error"] = err

            except Web3Exception as we:
                err = f"Web3 error during live broadcast: {we}"
                self.outbox.record_failure(job.job_id, worker_id, err, is_transient=True)
                summary["status"] = "RETRY"
                summary["error"] = err
            except Exception as exc:
                err = f"Live broadcast failure: {exc}"
                self.outbox.record_failure(job.job_id, worker_id, err, is_transient=True)
                summary["status"] = "RETRY"
                summary["error"] = err

            results.append(summary)

        return results


# Global lazy singleton
_relayer_instance: Optional[SepoliaRelayer] = None


def get_sepolia_relayer() -> SepoliaRelayer:
    """Returns the process-wide SepoliaRelayer instance."""
    global _relayer_instance
    if _relayer_instance is None:
        _relayer_instance = SepoliaRelayer()
    return _relayer_instance


def set_sepolia_relayer(relayer: Optional[SepoliaRelayer]) -> None:
    """Allows testing harnesses to inject mock or tester relayers."""
    global _relayer_instance
    _relayer_instance = relayer
