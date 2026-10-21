"""
Build script to compile Solidity smart contracts for VERITAS-Vault using solc.
Outputs clean ABI and bytecode artifacts to contracts/build/.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = ROOT / "contracts"
BUILD_DIR = CONTRACTS_DIR / "build"


def compile_contracts():
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    
    audit_anchor_path = CONTRACTS_DIR / "AuditAnchor.sol"
    iaudit_anchor_path = CONTRACTS_DIR / "IAuditAnchor.sol"

    if not audit_anchor_path.exists():
        raise FileNotFoundError(f"Contract not found: {audit_anchor_path}")

    # Use npx solc (solcjs) with base-path at project root
    cmd = [
        "npx", "solc",
        "--bin", "--abi",
        "--base-path", str(ROOT),
        "-o", str(BUILD_DIR),
        str(audit_anchor_path)
    ]

    print(f"Executing: {' '.join(cmd)}")
    res = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, shell=True)
    if res.returncode != 0:
        print("Compilation failed:")
        print(res.stderr)
        sys.exit(res.returncode)

    # Standardize artifact filenames
    raw_anchor_abi = BUILD_DIR / "contracts_AuditAnchor_sol_AuditAnchor.abi"
    raw_anchor_bin = BUILD_DIR / "contracts_AuditAnchor_sol_AuditAnchor.bin"
    raw_interface_abi = BUILD_DIR / "contracts_IAuditAnchor_sol_IAuditAnchor.abi"

    if raw_anchor_abi.exists():
        abi_data = json.loads(raw_anchor_abi.read_text(encoding="utf-8"))
        (BUILD_DIR / "AuditAnchor.abi.json").write_text(json.dumps(abi_data, indent=2), encoding="utf-8")

    if raw_anchor_bin.exists():
        bin_data = raw_anchor_bin.read_text(encoding="utf-8").strip()
        (BUILD_DIR / "AuditAnchor.bin").write_text(bin_data, encoding="utf-8")

    if raw_interface_abi.exists():
        iface_data = json.loads(raw_interface_abi.read_text(encoding="utf-8"))
        (BUILD_DIR / "IAuditAnchor.abi.json").write_text(json.dumps(iface_data, indent=2), encoding="utf-8")

    # Clean up raw solcjs mangled filenames
    for raw_f in (raw_anchor_abi, raw_anchor_bin, raw_interface_abi, BUILD_DIR / "contracts_IAuditAnchor_sol_IAuditAnchor.bin"):
        if raw_f.exists():
            raw_f.unlink()

    # Combined bundle for easy web3.py consumption
    combined = {
        "contractName": "AuditAnchor",
        "abi": json.loads((BUILD_DIR / "AuditAnchor.abi.json").read_text(encoding="utf-8")),
        "bytecode": (BUILD_DIR / "AuditAnchor.bin").read_text(encoding="utf-8").strip(),
        "compiler": "solc ^0.8.24",
    }
    (BUILD_DIR / "combined.json").write_text(json.dumps(combined, indent=2), encoding="utf-8")

    print("Contracts compiled successfully.")
    print(f"ABI: {BUILD_DIR / 'AuditAnchor.abi.json'}")
    print(f"Bytecode: {BUILD_DIR / 'AuditAnchor.bin'}")
    print(f"Interface ABI: {BUILD_DIR / 'IAuditAnchor.abi.json'}")
    print(f"Combined artifact: {BUILD_DIR / 'combined.json'}")


if __name__ == "__main__":
    compile_contracts()
