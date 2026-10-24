"""
Autonomous verification script for VERITAS-Vault:
1. Reload .env & verify Supabase authentication (production project ppnfoogpapokpgmarttl)
2. Cryptographically reverify signed audit events 1-10
3. Recompute and validate deterministic Merkle batch ID and root
4. Persist batch to public.audit_batches & job to public.blockchain_outbox idempotently
5. Read back directly from Supabase, asserting zero SQLite fallback
6. Verify Sepolia contract, chain ID 11155111, simulate anchor transaction
7. Prepare MetaMask transaction payload and stop before signing
"""
import os
import sys
import json
import base64
import hashlib
import requests
from pathlib import Path
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from web3 import Web3
from eth_abi import encode

# Ensure root directory is in sys.path
ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from src.blockchain.audit_batcher import compute_deterministic_batch_id, create_batch_from_events
from src.blockchain.audit_chain import AuditLedger, GENESIS_HASH, canonicalize

def http_request_with_retry(method: str, url: str, **kwargs):
    import time
    for attempt in range(5):
        try:
            return requests.request(method, url, **kwargs)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            if attempt == 4:
                raise
            time.sleep(1.0 * (attempt + 1))

def run_verification():
    print("=" * 80)
    print("VERITAS-Vault: Execution Verification & Readiness Test")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # 1. Reload .env & Test Supabase Authentication
    # -------------------------------------------------------------------------
    print("\n[Step 1] Reloading .env and verifying Supabase authentication...")
    env_path = ROOT_DIR / ".env"
    load_dotenv(dotenv_path=env_path, override=True)

    supabase_url = os.getenv("SUPABASE_URL", "").strip()
    supabase_key = (os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY") or "").strip()

    assert supabase_url, "ERROR: SUPABASE_URL is missing in .env"
    assert "ppnfoogpapokpgmarttl" in supabase_url, f"ERROR: Expected project ppnfoogpapokpgmarttl, got {supabase_url}"
    assert supabase_key, "ERROR: SUPABASE_SERVICE_ROLE_KEY is missing in .env"

    headers = {
        "apikey": supabase_key,
        "Authorization": f"Bearer {supabase_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    test_url = f"{supabase_url}/rest/v1/audit_batches?select=batch_id&limit=1"
    resp = http_request_with_retry("GET", test_url, headers=headers, timeout=10)
    if resp.status_code not in (200, 206):
        raise RuntimeError(f"Supabase authentication failed with HTTP {resp.status_code}: {resp.text}")

    print(f"  -> SUCCESS: Supabase authenticated (HTTP {resp.status_code}) against {supabase_url}")
    print(f"  -> Project ID: ppnfoogpapokpgmarttl")
    print("  -> Credential check: Key loaded and validated (redacted)")

    # -------------------------------------------------------------------------
    # 2. Cryptographically Reverify Signed Audit Events (Sequences 1-10)
    # -------------------------------------------------------------------------
    print("\n[Step 2] Cryptographically reverifying signed audit events (seq 1-10)...")
    ledger = AuditLedger()
    events = ledger.get_events_range(1, 10)
    assert len(events) == 10, f"ERROR: Expected 10 events, retrieved {len(events)}"

    # Load public key
    pub_key_path = ROOT_DIR / "data" / "keys" / "audit_signer_ed25519.pub"
    assert pub_key_path.exists(), f"ERROR: Public key not found at {pub_key_path}"
    public_key = serialization.load_pem_public_key(pub_key_path.read_bytes())

    for idx, ev in enumerate(events):
        seq = ev["sequence_number"]
        prev_h = ev["previous_hash"]
        ev_h = ev["evidence_hash"]
        stored_h = ev["event_hash"]
        sig = ev["signature"]

        # Linkage check
        if seq == 1:
            assert prev_h == GENESIS_HASH, f"Seq 1 previous_hash mismatch: {prev_h}"
        else:
            expected_prev = events[idx - 1]["event_hash"]
            assert prev_h == expected_prev, f"Seq {seq} broken chain linkage! Expected {expected_prev}, got {prev_h}"

        # Hash integrity check
        canonical_bytes = canonicalize(ev["payload"])
        hasher = hashlib.sha256()
        hasher.update(prev_h.encode("ascii"))
        hasher.update(canonical_bytes)
        hasher.update(ev_h.encode("ascii"))
        recomputed_hash = hasher.hexdigest()
        assert recomputed_hash == stored_h, f"Seq {seq} hash mismatch: {recomputed_hash} != {stored_h}"

        # Digital signature check
        sig_raw = base64.b64decode(sig)
        public_key.verify(sig_raw, stored_h.encode("ascii"))

    print(f"  -> SUCCESS: Sequences 1 through 10 cryptographically verified.")
    print(f"  -> Linkage: Unbroken previous_hash chain from GENESIS to seq 10.")
    print(f"  -> Integrity: SHA-256 digests match canonical payload.")
    print(f"  -> Signatures: Ed25519 signatures verified against {pub_key_path.name}.")

    # -------------------------------------------------------------------------
    # 3. Recompute and Validate Deterministic Merkle Batch ID and Root
    # -------------------------------------------------------------------------
    print("\n[Step 3] Recomputing deterministic Merkle batch ID and root...")
    batch = create_batch_from_events(events)

    EXPECTED_BATCH_ID = "0xe06fe0aa802b7e80d22398e0aacd9d5c679b6fdc2b5e23734ea8f2905ecce350"
    EXPECTED_ROOT = "0x01bd9482277a9bd2666f80a08ff7e3d1ed1791cc73e222d8171fb09da2e88096"

    assert batch.batch_id == EXPECTED_BATCH_ID, f"Batch ID mismatch: {batch.batch_id} != {EXPECTED_BATCH_ID}"
    assert batch.root_hash == EXPECTED_ROOT, f"Merkle Root mismatch: {batch.root_hash} != {EXPECTED_ROOT}"
    assert batch.first_sequence == 1, f"First seq mismatch: {batch.first_sequence}"
    assert batch.last_sequence == 10, f"Last seq mismatch: {batch.last_sequence}"
    assert batch.event_count == 10, f"Event count mismatch: {batch.event_count}"

    print(f"  -> SUCCESS: Deterministic Merkle batch parameters verified.")
    print(f"  -> Batch ID: {batch.batch_id}")
    print(f"  -> Root Hash: {batch.root_hash}")
    print(f"  -> Bounds: Sequences {batch.first_sequence}..{batch.last_sequence} ({batch.event_count} events)")

    # -------------------------------------------------------------------------
    # 4. Persist Batch and Outbox Job to Production Supabase Idempotently
    # -------------------------------------------------------------------------
    print("\n[Step 4] Persisting batch and outbox job to production Supabase...")
    upsert_headers = {
        **headers,
        "Prefer": "resolution=merge-duplicates,return=representation"
    }

    # 4a. Persist to public.audit_batches
    batch_payload = {
        "batch_id": batch.batch_id,
        "root_hash": batch.root_hash,
        "first_sequence": batch.first_sequence,
        "last_sequence": batch.last_sequence,
        "event_count": batch.event_count,
        "event_ids": batch.event_ids,
        "leaf_hashes": batch.leaf_hashes,
        "created_at": batch.created_at,
    }
    b_resp = http_request_with_retry(
        "POST",
        f"{supabase_url}/rest/v1/audit_batches",
        headers=upsert_headers,
        json=batch_payload,
        timeout=10
    )
    if b_resp.status_code not in (200, 201):
        raise RuntimeError(f"Failed to persist batch to Supabase: {b_resp.status_code} - {b_resp.text}")
    print(f"  -> SUCCESS: Batch persisted to public.audit_batches (HTTP {b_resp.status_code})")

    # 4b. Persist to public.blockchain_outbox
    job_id = f"anchor_job:sepolia:{batch.batch_id.lower().replace('0x', '')}"
    outbox_payload = {
        "job_id": job_id,
        "network": "sepolia",
        "batch_id": batch.batch_id,
        "status": "PENDING",
        "attempts": 0,
        "max_retries": 5,
        "created_at": batch.created_at,
        "updated_at": batch.created_at,
    }
    o_resp = http_request_with_retry(
        "POST",
        f"{supabase_url}/rest/v1/blockchain_outbox",
        headers=upsert_headers,
        json=outbox_payload,
        timeout=10
    )
    if o_resp.status_code not in (200, 201):
        raise RuntimeError(f"Failed to persist outbox job to Supabase: {o_resp.status_code} - {o_resp.text}")
    print(f"  -> SUCCESS: Exactly one Sepolia job persisted to public.blockchain_outbox (HTTP {o_resp.status_code})")

    # -------------------------------------------------------------------------
    # 5. Read Back Directly From Supabase & Confirm No SQLite Fallback
    # -------------------------------------------------------------------------
    print("\n[Step 5] Reading both records back directly from Supabase...")
    # Verify directly via HTTP request (independent of local store)
    b_read = http_request_with_retry(
        "GET",
        f"{supabase_url}/rest/v1/audit_batches?batch_id=eq.{batch.batch_id}",
        headers=headers,
        timeout=10
    )
    assert b_read.status_code == 200, f"Read batch failed: {b_read.status_code}"
    b_data = b_read.json()
    assert len(b_data) == 1, f"Expected 1 batch record, got {len(b_data)}"
    rec_b = b_data[0]
    assert rec_b["batch_id"] == EXPECTED_BATCH_ID
    assert rec_b["root_hash"] == EXPECTED_ROOT
    assert rec_b["first_sequence"] == 1
    assert rec_b["last_sequence"] == 10
    assert rec_b["event_count"] == 10
    assert len(rec_b["event_ids"]) == 10
    print("  -> Verified direct Supabase read of public.audit_batches:")
    print(f"     batch_id: {rec_b['batch_id']}")
    print(f"     root_hash: {rec_b['root_hash']}")
    print(f"     event_count: {rec_b['event_count']}")

    o_read = http_request_with_retry(
        "GET",
        f"{supabase_url}/rest/v1/blockchain_outbox?job_id=eq.{job_id}",
        headers=headers,
        timeout=10
    )
    assert o_read.status_code == 200, f"Read outbox failed: {o_read.status_code}"
    o_data = o_read.json()
    assert len(o_data) == 1, f"Expected 1 outbox record, got {len(o_data)}"
    rec_o = o_data[0]
    assert rec_o["job_id"] == job_id
    assert rec_o["network"] == "sepolia"
    assert rec_o["batch_id"] == EXPECTED_BATCH_ID
    assert rec_o["status"] in ("PENDING", "SUBMITTED")
    print("  -> Verified direct Supabase read of public.blockchain_outbox:")
    print(f"     job_id: {rec_o['job_id']}")
    print(f"     network: {rec_o['network']}")
    print(f"     status: {rec_o['status']}")
    print("  -> ZERO SQLite fallback confirmed: Verified via direct HTTPS REST to ppnfoogpapokpgmarttl.supabase.co")

    # -------------------------------------------------------------------------
    # 6. Verify Sepolia Contract, Chain ID, and Simulate Anchor Transaction
    # -------------------------------------------------------------------------
    print("\n[Step 6] Verifying Sepolia contract & simulating anchor transaction...")
    CONTRACT_ADDRESS = "0x64A6542aeaCC89a15106fF414e70B4942D782995"
    CHAIN_ID = 11155111
    AUTHORIZED_WALLET = "0x162c24C889c7315620fA57001BFC26A3B9E4f05f"

    rpc_urls = [
        os.getenv("SEPOLIA_RPC_URL", "").strip(),
        "https://ethereum-sepolia-rpc.publicnode.com",
        "https://rpc.sepolia.org",
        "https://1rpc.io/sepolia",
        "https://gateway.tenderly.co/public/sepolia"
    ]
    rpc_urls = [u for u in rpc_urls if u]

    w3 = None
    for rpc in rpc_urls:
        try:
            cand = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 10}))
            if cand.is_connected() and cand.eth.chain_id == CHAIN_ID:
                w3 = cand
                print(f"  -> Connected to Sepolia RPC: {rpc}")
                break
        except Exception:
            continue

    assert w3 is not None, "ERROR: Could not connect to any Sepolia RPC"

    # Check contract code
    code = w3.eth.get_code(Web3.to_checksum_address(CONTRACT_ADDRESS))
    assert len(code) > 0, f"ERROR: Contract bytecode empty at {CONTRACT_ADDRESS}"
    print(f"  -> Contract bytecode verified ({len(code)} bytes) at {CONTRACT_ADDRESS}")

    # Check authorized wallet balance
    bal_wei = w3.eth.get_balance(Web3.to_checksum_address(AUTHORIZED_WALLET))
    bal_eth = w3.from_wei(bal_wei, "ether")
    print(f"  -> Authorized wallet: {AUTHORIZED_WALLET} (Balance: {bal_eth:.5f} SepoliaETH)")

    # Prepare calldata for anchorBatch(bytes32,bytes32,uint64,uint64,uint64)
    selector = bytes.fromhex("b4743b6b")  # keccak256("anchorBatch(bytes32,bytes32,uint64,uint64,uint64)")[:4]
    b_id_bytes = bytes.fromhex(batch.batch_id.replace("0x", ""))
    root_bytes = bytes.fromhex(batch.root_hash.replace("0x", ""))
    encoded_args = encode(
        ["bytes32", "bytes32", "uint64", "uint64", "uint64"],
        [b_id_bytes, root_bytes, batch.event_count, batch.first_sequence, batch.last_sequence]
    )
    calldata = "0x" + (selector + encoded_args).hex()

    # Load contract ABI
    abi_path = ROOT_DIR / "contracts" / "build" / "AuditAnchor.abi.json"
    assert abi_path.exists(), f"ABI file missing at {abi_path}"
    abi = json.loads(abi_path.read_text(encoding="utf-8"))
    contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=abi)

    # Verify contract owner & relayer authorization
    contract_owner = contract.functions.owner().call()
    print(f"  -> Contract owner: {contract_owner}")
    is_relayer = contract.functions.isRelayer(Web3.to_checksum_address(AUTHORIZED_WALLET)).call()
    print(f"  -> Authorized wallet isRelayer: {is_relayer}")

    # Check if batch is already anchored
    is_anchored = contract.functions.isBatchAnchored(b_id_bytes).call()
    print(f"  -> Contract isBatchAnchored({batch.batch_id}): {is_anchored}")
    assert not is_anchored, f"ERROR: Batch {batch.batch_id} is already anchored on-chain!"

    # Simulate anchorBatch transaction using eth_call
    tx_params = {
        "from": Web3.to_checksum_address(AUTHORIZED_WALLET),
        "to": Web3.to_checksum_address(CONTRACT_ADDRESS),
        "data": calldata,
        "value": 0,
    }

    sim_res = w3.eth.call(tx_params)
    print("  -> eth_call contract simulation: SUCCESS (Zero revert)")

    # Estimate gas
    try:
        gas_est = w3.eth.estimate_gas(tx_params)
        print(f"  -> Gas estimate: {gas_est} units")
    except Exception as e:
        gas_est = 69579
        print(f"  -> Gas estimation fallback to tested baseline: {gas_est} units ({e})")

    # -------------------------------------------------------------------------
    # 7. Prepare MetaMask Transaction Approval Payload (STOP BEFORE SIGNING)
    # -------------------------------------------------------------------------
    print("\n[Step 7] Preparing MetaMask transaction approval parameters...")
    print("=" * 80)
    print("METAMASK TRANSACTION APPROVAL PAYLOAD (STOPPING BEFORE SIGNING/BROADCASTING)")
    print("=" * 80)
    metamask_tx = {
        "from": AUTHORIZED_WALLET,
        "to": CONTRACT_ADDRESS,
        "data": calldata,
        "value": "0x0",
        "chainId": hex(CHAIN_ID),
        "gas": hex(gas_est),
    }
    print(json.dumps(metamask_tx, indent=2))
    print("=" * 80)
    print("Transaction is ready for user manual approval. NO private keys requested or exposed.")
    print("=" * 80)

if __name__ == "__main__":
    run_verification()
