"""
VERITAS-Vault Hyperledger Besu Read-Only Audit Anchor Adapter
=============================================================
Provides read-only connection verification, state inspection, and anchor status
queries against the deployed AuditAnchor smart contract on private Hyperledger
Besu QBFT network (Chain ID: 1337).

Guarantees:
1. Zero Side-Effects: Strictly read-only calls (eth_call, eth_getCode, eth_chainId).
2. Non-Blocking / Fault-Tolerant: Outages or RPC timeouts fail safely and cleanly
   without affecting zero-trust access decisions or biometric verification.
3. Secret-Safe: Cleanses and sanitizes RPC endpoints to prevent credential leakage.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

from web3 import Web3
from web3.exceptions import Web3Exception

logger = logging.getLogger("vault.blockchain.besu")

ROOT_DIR = Path(__file__).resolve().parents[2]
BUILD_DIR = ROOT_DIR / "contracts" / "build"
DEPLOYMENTS_DIR = ROOT_DIR / "contracts" / "deployments"

BESU_CHAIN_ID = 1337
DEFAULT_BESU_RPC = "http://127.0.0.1:8545"
DEFAULT_CONTRACT_ADDRESS = "0x" + "b" * 40
DEFAULT_TIMEOUT_SECONDS = 5.0
CACHE_TTL_SECONDS = 5.0


def sanitize_rpc_url(url: Optional[str]) -> str:
    """Masks secret API tokens or credentials from RPC endpoints."""
    if not url:
        return ""
    try:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc
        if "@" in netloc:
            netloc = "***@" + netloc.split("@")[-1]
        return urllib.parse.urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))
    except Exception:
        return "<invalid-url>"


def load_audit_anchor_abi() -> List[Dict[str, Any]]:
    abi_path = BUILD_DIR / "AuditAnchor.abi.json"
    if abi_path.exists():
        try:
            return json.loads(abi_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", abi_path, exc)
    raise FileNotFoundError("AuditAnchor ABI not found in contracts/build/AuditAnchor.abi.json")


def resolve_contract_address() -> str:
    env_addr = os.environ.get("BESU_AUDIT_ANCHOR_ADDRESS") or os.environ.get("BESU_CONTRACT_ADDRESS")
    if env_addr:
        return Web3.to_checksum_address(env_addr)

    deploy_file = DEPLOYMENTS_DIR / "besu.json"
    if deploy_file.exists():
        try:
            data = json.loads(deploy_file.read_text(encoding="utf-8"))
            if "contractAddress" in data:
                return Web3.to_checksum_address(data["contractAddress"])
        except Exception as exc:
            logger.warning("Failed to read Besu deployment metadata: %s", exc)

    return Web3.to_checksum_address(DEFAULT_CONTRACT_ADDRESS)


def resolve_rpc_url() -> str:
    return os.environ.get("BESU_RPC_URL") or DEFAULT_BESU_RPC


class BesuAuditAnchorAdapter:
    def __init__(
        self,
        rpc_url: Optional[str] = None,
        contract_address: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        w3_instance: Optional[Web3] = None,
    ):
        self._rpc_url = rpc_url or resolve_rpc_url()
        self._contract_address = (
            Web3.to_checksum_address(contract_address)
            if contract_address
            else resolve_contract_address()
        )
        self._timeout_seconds = timeout_seconds if timeout_seconds is not None else DEFAULT_TIMEOUT_SECONDS
        self._w3 = w3_instance
        self._abi = load_audit_anchor_abi()
        self._cached_status: Optional[Dict[str, Any]] = None
        self._last_checked_at: float = 0.0

    def _get_w3(self) -> Web3:
        if self._w3 is None:
            provider = Web3.HTTPProvider(
                self._rpc_url,
                request_kwargs={"timeout": self._timeout_seconds},
            )
            self._w3 = Web3(provider)
        return self._w3

    def get_status(self, force_refresh: bool = False) -> Dict[str, Any]:
        now = time.time()
        if not force_refresh and self._cached_status is not None:
            if (now - self._last_checked_at) < CACHE_TTL_SECONDS:
                return dict(self._cached_status)

        status: Dict[str, Any] = {
            "network": "besu",
            "consensus": "QBFT",
            "connected": False,
            "chainId": BESU_CHAIN_ID,
            "contractAddress": self._contract_address,
            "sanitizedRpcUrl": sanitize_rpc_url(self._rpc_url),
            "owner": None,
            "totalAnchors": None,
            "latestBlock": None,
            "latencyMs": None,
            "error": None,
            "checkedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        }

        t_start = time.perf_counter()
        try:
            w3 = self._get_w3()
            if not w3.is_connected():
                status["error"] = "Cannot establish connection to Besu JSON-RPC"
                self._cached_status = status
                self._last_checked_at = now
                return status

            chain_id = w3.eth.chain_id
            status["chainId"] = chain_id
            if chain_id != BESU_CHAIN_ID:
                status["error"] = f"Chain ID mismatch: expected {BESU_CHAIN_ID}, got {chain_id}"
                self._cached_status = status
                self._last_checked_at = now
                return status

            code = w3.eth.get_code(self._contract_address)
            if not code or code == b"" or code == b"\x00":
                status["error"] = f"No contract bytecode deployed at {self._contract_address}"
                self._cached_status = status
                self._last_checked_at = now
                return status

            status["latestBlock"] = w3.eth.block_number

            contract = w3.eth.contract(address=self._contract_address, abi=self._abi)
            status["owner"] = contract.functions.owner().call()
            status["totalAnchors"] = int(contract.functions.totalAnchors().call())
            status["connected"] = True

        except (Web3Exception, Exception) as exc:
            status["error"] = str(exc)
            status["connected"] = False

        status["latencyMs"] = round((time.perf_counter() - t_start) * 1000, 2)
        self._cached_status = status
        self._last_checked_at = now
        return status

    def is_batch_anchored(self, batch_id: str) -> bool:
        try:
            w3 = self._get_w3()
            clean = batch_id.lower().replace("0x", "")
            b_bytes = bytes.fromhex(clean)
            contract = w3.eth.contract(address=self._contract_address, abi=self._abi)
            return bool(contract.functions.isBatchAnchored(b_bytes).call())
        except Exception as exc:
            logger.warning("Besu isBatchAnchored check failed for %s: %s", batch_id, exc)
            return False

    def get_anchor(self, batch_id: str) -> Optional[Dict[str, Any]]:
        try:
            w3 = self._get_w3()
            clean = batch_id.lower().replace("0x", "")
            b_bytes = bytes.fromhex(clean)
            contract = w3.eth.contract(address=self._contract_address, abi=self._abi)
            if not contract.functions.isBatchAnchored(b_bytes).call():
                return None
            res = contract.functions.getAnchor(b_bytes).call()
            return {
                "root_hash": f"0x{res[0].hex()}",
                "batch_id": f"0x{res[1].hex()}",
                "first_sequence": int(res[2]),
                "last_sequence": int(res[3]),
                "event_count": int(res[4]),
                "timestamp": int(res[5]),
                "anchored_by": str(res[6]),
                "cross_chain_ref": f"0x{res[7].hex()}",
            }
        except Exception as exc:
            logger.warning("Besu getAnchor check failed for %s: %s", batch_id, exc)
            return None


# Global lazy singleton instance
_besu_adapter_instance: Optional[BesuAuditAnchorAdapter] = None


def get_besu_adapter() -> BesuAuditAnchorAdapter:
    global _besu_adapter_instance
    if _besu_adapter_instance is None:
        _besu_adapter_instance = BesuAuditAnchorAdapter()
    return _besu_adapter_instance


def set_besu_adapter(adapter: Optional[BesuAuditAnchorAdapter]) -> None:
    global _besu_adapter_instance
    _besu_adapter_instance = adapter
