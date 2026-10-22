"""
VERITAS-Vault Sepolia Read-Only Audit Anchor Adapter
===================================================
Provides read-only connection verification, state inspection, and anchor status
queries against the deployed AuditAnchor smart contract on Ethereum Sepolia.

Guarantees:
1. Zero Side-Effects: Strictly read-only calls (eth_call, eth_getCode, eth_chainId).
   Never sends transactions, signs data, or manages private keys.
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

logger = logging.getLogger("vault.blockchain.sepolia")

ROOT_DIR = Path(__file__).resolve().parents[2]
BUILD_DIR = ROOT_DIR / "contracts" / "build"
DEPLOYMENTS_DIR = ROOT_DIR / "contracts" / "deployments"

SEPOLIA_CHAIN_ID = 11155111
DEFAULT_SEPOLIA_RPC = "https://ethereum-sepolia-rpc.publicnode.com"
DEFAULT_CONTRACT_ADDRESS = "0x64A6542aeaCC89a15106fF414e70B4942D782995"
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

        path_parts = parsed.path.split("/")
        sanitized_parts = []
        for part in path_parts:
            # Mask alphanumeric tokens of 16+ characters (common in Infura/Alchemy URLs)
            if len(part) >= 16 and any(c.isdigit() for c in part) and any(c.isalpha() for c in part):
                sanitized_parts.append(part[:4] + "..." + part[-4:])
            else:
                sanitized_parts.append(part)
        clean_path = "/".join(sanitized_parts)

        clean_query = "?***" if parsed.query else ""
        return urllib.parse.urlunparse(
            (parsed.scheme, netloc, clean_path, parsed.params, clean_query, parsed.fragment)
        )
    except Exception:
        return "https://***"


def load_audit_anchor_abi() -> List[Dict[str, Any]]:
    """Loads compiled AuditAnchor contract ABI from contracts/build directory."""
    abi_path = BUILD_DIR / "AuditAnchor.abi.json"
    if abi_path.exists():
        try:
            return json.loads(abi_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to parse AuditAnchor.abi.json: %s", exc)

    combined_path = BUILD_DIR / "combined.json"
    if combined_path.exists():
        try:
            data = json.loads(combined_path.read_text(encoding="utf-8"))
            return data.get("abi", [])
        except Exception as exc:
            logger.warning("Failed to parse combined.json: %s", exc)

    return []


def resolve_contract_address() -> str:
    """
    Resolves the AuditAnchor address from environment variables or deployment metadata.
    Priority:
    1. SEPOLIA_AUDIT_ANCHOR_ADDRESS / AUDIT_ANCHOR_CONTRACT_ADDRESS
    2. contracts/deployments/sepolia.json -> contractAddress
    3. Hardcoded verified Sepolia contract address
    """
    env_addr = os.environ.get("SEPOLIA_AUDIT_ANCHOR_ADDRESS") or os.environ.get("AUDIT_ANCHOR_CONTRACT_ADDRESS")
    if env_addr and env_addr.strip():
        try:
            return Web3.to_checksum_address(env_addr.strip())
        except Exception as exc:
            logger.warning("Invalid contract address in environment: %s", exc)

    metadata_path = DEPLOYMENTS_DIR / "sepolia.json"
    if metadata_path.exists():
        try:
            data = json.loads(metadata_path.read_text(encoding="utf-8"))
            addr = data.get("contractAddress")
            if addr:
                return Web3.to_checksum_address(addr.strip())
        except Exception as exc:
            logger.warning("Failed to parse contracts/deployments/sepolia.json: %s", exc)

    return Web3.to_checksum_address(DEFAULT_CONTRACT_ADDRESS)


def resolve_rpc_url() -> str:
    """Resolves Sepolia RPC URL from environment or defaults."""
    env_rpc = os.environ.get("SEPOLIA_RPC_URL") or os.environ.get("ETHEREUM_SEPOLIA_RPC_URL")
    if env_rpc and env_rpc.strip():
        return env_rpc.strip()
    return DEFAULT_SEPOLIA_RPC


def resolve_timeout() -> float:
    """Resolves RPC timeout from environment or default."""
    raw = os.environ.get("SEPOLIA_RPC_TIMEOUT_SECONDS")
    if raw:
        try:
            val = float(raw)
            if val > 0:
                return val
        except ValueError:
            pass
    return DEFAULT_TIMEOUT_SECONDS


class SepoliaAuditAnchorAdapter:
    """
    Read-only adapter for inspecting AuditAnchor state on Ethereum Sepolia.
    """

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
        self._timeout_seconds = timeout_seconds if timeout_seconds is not None else resolve_timeout()
        self._abi = load_audit_anchor_abi()
        self._w3 = w3_instance

        # Cached status
        self._cached_status: Optional[Dict[str, Any]] = None
        self._last_checked_at: float = 0.0

    @property
    def rpc_url(self) -> str:
        return self._rpc_url

    @property
    def contract_address(self) -> str:
        return self._contract_address

    @property
    def sanitized_rpc_url(self) -> str:
        return sanitize_rpc_url(self._rpc_url)

    def _get_w3(self) -> Web3:
        if self._w3 is None:
            provider = Web3.HTTPProvider(
                self._rpc_url,
                request_kwargs={"timeout": self._timeout_seconds},
            )
            self._w3 = Web3(provider)
        return self._w3

    def get_status(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Performs a full read-only verification pass of Sepolia connection and contract state.
        Results are cached for CACHE_TTL_SECONDS unless force_refresh=True.
        Guaranteed not to raise unhandled exceptions.
        """
        now = time.time()
        if not force_refresh and self._cached_status and (now - self._last_checked_at < CACHE_TTL_SECONDS):
            return self._cached_status

        checked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        status: Dict[str, Any] = {
            "connected": False,
            "network": "sepolia",
            "chainId": SEPOLIA_CHAIN_ID,
            "chainIdValid": False,
            "actualChainId": None,
            "contractAddress": self._contract_address,
            "hasBytecode": False,
            "bytecodeLength": 0,
            "owner": None,
            "totalAnchors": None,
            "latestBlock": None,
            "rpcUrlSanitized": self.sanitized_rpc_url,
            "error": None,
            "latencyMs": None,
            "checkedAt": checked_at,
        }

        start_time = time.perf_counter()
        try:
            w3 = self._get_w3()
            if not w3.is_connected():
                status["error"] = "RPC endpoint unreachable or offline"
                self._cached_status = status
                self._last_checked_at = now
                return status

            # 1. Chain ID Verification
            actual_chain_id = w3.eth.chain_id
            status["actualChainId"] = actual_chain_id
            if actual_chain_id != SEPOLIA_CHAIN_ID:
                status["chainIdValid"] = False
                status["error"] = (
                    f"Chain ID mismatch: expected {SEPOLIA_CHAIN_ID} (Sepolia), got {actual_chain_id}"
                )
                self._cached_status = status
                self._last_checked_at = now
                return status
            status["chainIdValid"] = True

            # 2. Bytecode Verification
            bytecode = w3.eth.get_code(self._contract_address)
            bytecode_len = len(bytecode) if bytecode else 0
            status["bytecodeLength"] = bytecode_len
            if bytecode_len == 0 or bytecode in (b"", b"\x00", "0x", "0x0"):
                status["hasBytecode"] = False
                status["error"] = f"No contract bytecode deployed at {self._contract_address}"
                self._cached_status = status
                self._last_checked_at = now
                return status
            status["hasBytecode"] = True

            # 3. Contract State Queries
            contract = w3.eth.contract(address=self._contract_address, abi=self._abi)
            owner = contract.functions.owner().call()
            total_anchors = contract.functions.totalAnchors().call()
            latest_block = w3.eth.block_number

            status["owner"] = owner
            status["totalAnchors"] = int(total_anchors)
            status["latestBlock"] = int(latest_block)
            status["connected"] = True

            latency = (time.perf_counter() - start_time) * 1000.0
            status["latencyMs"] = round(latency, 2)

        except TimeoutError:
            status["error"] = f"RPC request timed out after {self._timeout_seconds}s"
            logger.warning("Sepolia RPC timed out: %s", status["error"])
        except Web3Exception as exc:
            status["error"] = f"Web3 error: {type(exc).__name__}"
            logger.warning("Sepolia Web3 exception: %s", exc)
        except Exception as exc:
            err_msg = str(exc)
            # Never expose long stack traces or potential tokens in status error
            clean_err = err_msg.split("\n")[0][:120] if err_msg else type(exc).__name__
            status["error"] = f"Connection error: {clean_err}"
            logger.warning("Sepolia connection error: %s", clean_err)

        self._cached_status = status
        self._last_checked_at = now
        return status


# Global lazy singleton instance
_adapter_instance: Optional[SepoliaAuditAnchorAdapter] = None


def get_sepolia_adapter() -> SepoliaAuditAnchorAdapter:
    """Returns the process-wide SepoliaAuditAnchorAdapter instance."""
    global _adapter_instance
    if _adapter_instance is None:
        _adapter_instance = SepoliaAuditAnchorAdapter()
    return _adapter_instance


def set_sepolia_adapter(adapter: Optional[SepoliaAuditAnchorAdapter]) -> None:
    """Allows testing harnesses to inject mock adapters."""
    global _adapter_instance
    _adapter_instance = adapter
