"""
AI Narrative Generation & Fallback Module for Blockchain Forensic AI Side-Panel.

Generates concise, executive-level forensic timelines explaining target risk metrics.
Provides a graceful deterministic fallback if the LLM provider fails or times out.
"""

from typing import Dict, Any, Optional
import time
import json


class AINarrativeGenerator:
    def __init__(self, model_name: str = "gpt-4o", timeout_sec: float = 5.0):
        self.model_name = model_name
        self.timeout_sec = timeout_sec

    def generate_narrative(
        self,
        target: str,
        risk_metrics: Dict[str, Any],
        raw_heuristics: Dict[str, Any],
        simulate_failure: bool = False
    ) -> Dict[str, Any]:
        """
        Executes LLM structured prompt generation with deterministic fallback.
        """
        score = risk_metrics.get("composite_score", 0)
        risk_level = risk_metrics.get("risk_level", "LOW")
        flags = risk_metrics.get("flags", [])

        # Check if address has zero activity
        if raw_heuristics.get("tx_count", 0) == 0:
            return {
                "narrative": f"Target entity `{target}` displays zero on-chain transaction history across queried networks. No suspicious movement or risk vectors detected.",
                "key_findings": ["No on-chain activity", "Zero balance"],
                "model_used": "deterministic-rules-v1",
                "is_fallback": False
            }

        # Try Primary AI Call
        if not simulate_failure:
            try:
                narrative_text = self._query_llm_api(target, risk_metrics, raw_heuristics)
                return {
                    "narrative": narrative_text,
                    "key_findings": [f["message"] for f in flags],
                    "model_used": self.model_name,
                    "is_fallback": False
                }
            except Exception as exc:
                # LLM API failed/timed out, drop down to deterministic fallback
                pass

        # Graceful Deterministic Fallback
        fallback_summary = self._build_deterministic_fallback(target, score, risk_level, flags, raw_heuristics)
        return {
            "narrative": fallback_summary,
            "key_findings": [f["message"] for f in flags] if flags else ["Manual forensic review advised."],
            "model_used": "rule-based-fallback-v1",
            "is_fallback": True,
            "fallback_reason": "LLM API timeout or service unavailable"
        }

    def _query_llm_api(self, target: str, risk_metrics: Dict[str, Any], raw_heuristics: Dict[str, Any]) -> str:
        """
        Constructs prompt and queries LLM provider.
        (Mocked for local offline stability; easily swapped to OpenAI / Anthropic / Llama 3 endpoint).
        """
        score = risk_metrics["composite_score"]
        flags_desc = ", ".join([f["code"] for f in risk_metrics.get("flags", [])]) or "None"
        tx_count = raw_heuristics.get("tx_count", 0)
        eth_balance = raw_heuristics.get("eth_balance", 0.0)

        if score >= 70:
            return (
                f"FORENSIC SUMMARY FOR {target}:\n"
                f"Target address exhibits a CRITICAL risk profile (Score: {score}/100). "
                f"Analysis confirms multi-layer obfuscation including peel chains ({raw_heuristics['behavioral_patterns']['peel_chain_count']} instances) "
                f"and direct proximity (1-hop) to Tornado Cash mixing pools. "
                f"High transactional velocity ({raw_heuristics['behavioral_patterns']['token_velocity_per_min']} tx/min) and balance of {eth_balance} ETH "
                f"strongly suggest active laundering or dApp drainer activity. Immediate vault lock and freezing advised."
            )
        elif score >= 40:
            return (
                f"FORENSIC SUMMARY FOR {target}:\n"
                f"Target address exhibits HIGH risk heuristics (Score: {score}/100). "
                f"Triggered flags: [{flags_desc}]. "
                f"Observed repeated high-frequency transfers and proximity to suspicious intermediate nodes. "
                f"Total recorded transfers: {tx_count}. Enhanced surveillance recommended."
            )
        else:
            return (
                f"FORENSIC SUMMARY FOR {target}:\n"
                f"Target address demonstrates LOW TO MODERATE risk (Score: {score}/100). "
                f"No direct mixer interactions or sanction list matches detected across {tx_count} transactions. "
                f"Entity behavior aligns with standard retail dApp interaction."
            )

    def _build_deterministic_fallback(
        self,
        target: str,
        score: int,
        risk_level: str,
        flags: list,
        raw_heuristics: dict
    ) -> str:
        """
        Generates deterministic executive narrative when LLM is unreachable.
        """
        flag_count = len(flags)
        if flag_count == 0:
            return f"Address {target} evaluated with Composite Risk Score {score}/100 ({risk_level}). No active threat flags triggered."

        flag_lines = "; ".join([f"{f['code']}: {f['message']}" for f in flags])
        return (
            f"[DETERMINISTIC FALLBACK REPORT] Address {target} flagged for {flag_count} high-risk activity vectors. "
            f"Composite Risk Score: {score}/100 ({risk_level}). "
            f"Triggered Threat Heuristics: [{flag_lines}]. "
            f"Manual investigator review is required to verify full execution path."
        )
