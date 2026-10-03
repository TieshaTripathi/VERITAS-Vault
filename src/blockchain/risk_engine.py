"""
Heuristic & Risk Engine for Blockchain Forensic AI Side-Panel.

Ingests raw blockchain data (mocked GoPlus Security API / Alchemy Web3 data),
evaluates behavioral patterns (peel chains, mixing pool proximity, rapid token velocity),
computes a composite risk score (0-100), outputs specific threat flags, and generates
a structured node graph payload for React Flow rendering.
"""

from typing import Dict, List, Any, Optional
import re
import math
try:
    from eth_utils import is_checksum_address, to_checksum_address
except ImportError:
    try:
        from web3 import Web3
        to_checksum_address = Web3.to_checksum_address
    except ImportError:
        def to_checksum_address(addr: str) -> str:
            return addr.strip()



class RiskEngine:
    def __init__(self):
        # Known privacy mixer contracts (e.g., Tornado Cash, Railgun, etc.)
        self.known_mixers = {
            "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc": "Tornado.Cash: 0.1 ETH",
            "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado.Cash: 1 ETH",
            "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado.Cash: 10 ETH",
            "0xa160cd31f2177a11b3329fe70a3ae5feb8951674": "Tornado.Cash: 100 ETH",
            "0xfa243627fe04421e4817386f210ea307f9c264bf": "Railgun Privacy Contract",
        }

    def validate_address_or_tx(self, target: str) -> Dict[str, Any]:
        """
        Validates target format (Ethereum Checksum Address or Transaction Hash).
        """
        clean_target = target.strip()

        # Check TxHash pattern (66 chars, 0x + 64 hex)
        if re.match(r"^0x[a-fA-F0-9]{64}$", clean_target):
            return {
                "valid": True,
                "type": "tx_hash",
                "formatted": clean_target.lower()
            }

        # Check EVM Wallet Address pattern (42 chars, 0x + 40 hex)
        if re.match(r"^0x[a-fA-F0-9]{40}$", clean_target):
            try:
                checksummed = to_checksum_address(clean_target)
                return {
                    "valid": True,
                    "type": "wallet",
                    "formatted": checksummed
                }
            except Exception:
                return {
                    "valid": True,
                    "type": "wallet",
                    "formatted": clean_target
                }

        return {
            "valid": False,
            "type": "unknown",
            "error": f"Invalid Ethereum address or TxHash format: {target}"
        }

    def fetch_heuristics_data(self, target: str, target_type: str = "wallet") -> Dict[str, Any]:
        """
        Mocks real-time data pulling from Alchemy (chain history) & GoPlus Security API.
        In production, this replaces mock dictionary with async HTTP calls to Alchemy & GoPlus APIs.
        """
        address_lower = target.lower()

        # Check for zero-history / safe test address simulation
        if address_lower.endswith("0000") or address_lower == "0x0000000000000000000000000000000000000000":
            return {
                "target": target,
                "target_type": target_type,
                "tx_count": 0,
                "first_seen": None,
                "last_seen": None,
                "eth_balance": 0.0,
                "goplus_security": {
                    "is_honeypot": False,
                    "is_blacklisted": False,
                    "is_proxy": False,
                    "sanctioned_entity": False,
                    "trust_score": 100
                },
                "behavioral_patterns": {
                    "peel_chain_count": 0,
                    "mixing_hops": 999,
                    "token_velocity_per_min": 0.0,
                    "rapid_fan_out": False
                },
                "recent_transfers": []
            }

        # Deterministic heuristic generator based on address hash string for realistic testing
        hash_val = sum(ord(c) for c in address_lower)
        is_high_risk = (hash_val % 3 == 0) or "dead" in address_lower or "bad" in address_lower

        tx_count = 142 if is_high_risk else 12
        mixer_distance = 1 if is_high_risk else 4
        peel_chains = 7 if is_high_risk else 0
        token_velocity = 18.4 if is_high_risk else 0.5

        return {
            "target": target,
            "target_type": target_type,
            "tx_count": tx_count,
            "first_seen": "2024-01-15T08:22:10Z",
            "last_seen": "2026-08-15T21:40:00Z",
            "eth_balance": 42.85 if is_high_risk else 1.25,
            "goplus_security": {
                "is_honeypot": False,
                "is_blacklisted": is_high_risk,
                "is_proxy": is_high_risk,
                "sanctioned_entity": is_high_risk,
                "trust_score": 15 if is_high_risk else 92
            },
            "behavioral_patterns": {
                "peel_chain_count": peel_chains,
                "mixing_hops": mixer_distance,
                "token_velocity_per_min": token_velocity,
                "rapid_fan_out": is_high_risk
            },
            "recent_transfers": [
                {
                    "from": target,
                    "to": "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc" if is_high_risk else "0x71c7656ec7ab88b098defb751b7401b5f6d8976f",
                    "value_eth": 10.0 if is_high_risk else 0.5,
                    "label": "Tornado Cash 0.1 ETH Pool" if is_high_risk else "Standard Transfer",
                    "timestamp": "2026-08-15T21:30:00Z"
                },
                {
                    "from": "0x8888888888888888888888888888888888888888",
                    "to": target,
                    "value_eth": 25.0 if is_high_risk else 1.0,
                    "label": "Peel Chain Intermediate Node" if is_high_risk else "DEX Swap",
                    "timestamp": "2026-08-15T21:15:00Z"
                }
            ]
        }

    def evaluate_risk(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates risk score (0-100) and triggers specific threat flags.
        """
        goplus = raw_data.get("goplus_security", {})
        behavior = raw_data.get("behavioral_patterns", {})

        score = 0
        flags: List[Dict[str, str]] = []

        # Zero transactions check
        if raw_data.get("tx_count", 0) == 0:
            return {
                "composite_score": 0,
                "risk_level": "LOW",
                "flags": [{
                    "severity": "INFO",
                    "code": "NO_ONCHAIN_HISTORY",
                    "message": "Target address has 0 on-chain transactions."
                }],
                "metrics_summary": {
                    "peel_chains_detected": 0,
                    "mixer_proximity_hops": "N/A",
                    "velocity_tx_per_min": 0.0
                }
            }

        # 1. Blacklist & Sanction Check (+40 points)
        if goplus.get("is_blacklisted") or goplus.get("sanctioned_entity"):
            score += 40
            flags.append({
                "severity": "CRITICAL",
                "code": "OFAC_BLACK_LIST",
                "message": "Target address is linked to OFAC sanctions or known malicious threat actor registry."
            })

        # 2. Mixing Pool Proximity (+30 points if 1-hop, +15 if 2-hop)
        mixing_hops = behavior.get("mixing_hops", 999)
        if mixing_hops == 1:
            score += 30
            flags.append({
                "severity": "HIGH",
                "code": "DIRECT_MIXER_HOP",
                "message": "Direct (1-hop) interaction with a privacy mixer contract (Tornado Cash / Railgun)."
            })
        elif mixing_hops == 2:
            score += 15
            flags.append({
                "severity": "MEDIUM",
                "code": "INDIRECT_MIXER_HOP",
                "message": "Indirect (2-hop) deposit/withdrawal pipeline from privacy protocol."
            })

        # 3. Peel Chain Pattern (+20 points)
        peel_count = behavior.get("peel_chain_count", 0)
        if peel_count > 0:
            score += min(25, peel_count * 5)
            flags.append({
                "severity": "HIGH",
                "code": "PEEL_CHAIN_DETECTED",
                "message": f"Detected {peel_count} peel chain transactions (layering strategy to obfuscate funds)."
            })

        # 4. Rapid Token Velocity (+15 points)
        velocity = behavior.get("token_velocity_per_min", 0.0)
        if velocity > 10.0:
            score += 15
            flags.append({
                "severity": "MEDIUM",
                "code": "HIGH_TOKEN_VELOCITY",
                "message": f"Abnormal velocity of {velocity:.1f} tx/min detected (potential automated draining bot)."
            })

        # Cap score between 0 and 100
        final_score = max(0, min(100, score))

        if final_score >= 70:
            risk_level = "CRITICAL"
        elif final_score >= 40:
            risk_level = "HIGH"
        elif final_score >= 20:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "composite_score": final_score,
            "risk_level": risk_level,
            "flags": flags,
            "metrics_summary": {
                "peel_chains_detected": peel_count,
                "mixer_proximity_hops": mixing_hops if mixing_hops < 999 else "None",
                "velocity_tx_per_min": velocity,
                "trust_score": goplus.get("trust_score", 100)
            }
        }

    def generate_node_graph_context(self, target: str, raw_data: Dict[str, Any], risk_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Formats network graph payload compatible with React Flow for visualization.
        """
        nodes = []
        edges = []

        # Target center node
        nodes.append({
            "id": "target-node",
            "type": "targetNode",
            "data": {
                "label": target[:8] + "..." + target[-6:],
                "fullAddress": target,
                "riskScore": risk_analysis["composite_score"],
                "riskLevel": risk_analysis["risk_level"]
            },
            "position": {"x": 250, "y": 150}
        })

        transfers = raw_data.get("recent_transfers", [])
        for idx, tx in enumerate(transfers):
            node_id = f"hop-node-{idx}"
            counterparty = tx["to"] if tx["from"].lower() == target.lower() else tx["from"]
            label = tx.get("label", counterparty[:8] + "...")

            nodes.append({
                "id": node_id,
                "type": "counterpartyNode",
                "data": {
                    "label": label,
                    "fullAddress": counterparty,
                    "amountEth": tx.get("value_eth", 0.0),
                    "timestamp": tx.get("timestamp")
                },
                "position": {"x": 100 + (idx * 300), "y": 320}
            })

            edges.append({
                "id": f"edge-{idx}",
                "source": "target-node" if tx["from"].lower() == target.lower() else node_id,
                "target": node_id if tx["from"].lower() == target.lower() else "target-node",
                "animated": True,
                "label": f"{tx.get('value_eth', 0.0)} ETH",
                "style": {"stroke": "#EF4444" if risk_analysis["composite_score"] >= 50 else "#3B82F6"}
            })

        return {
            "nodes": nodes,
            "edges": edges
        }
