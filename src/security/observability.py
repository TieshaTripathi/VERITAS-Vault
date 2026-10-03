"""
VERITAS-Vault Security Observability & Internal Telemetry
=========================================================
Tracks operational counters and latency histograms across the zero-trust pipeline.
Strict privacy rule: NEVER record raw biometric templates, face crops, or cryptographic secrets.
"""

import time
from typing import Dict, Any, List
import numpy as np


class TelemetryCollector:
    """Structured internal telemetry collector."""

    COUNTER_KEYS = [
        "checkpoint_requests_total",
        "capture_replay_rejections_total",
        "pad_failures_total",
        "biometric_mismatches_total",
        "pep_replay_rejections_total",
        "door_unlocks_total",
        "door_faults_total",
        "audit_verification_failures_total"
    ]

    HISTOGRAM_KEYS = [
        "capture_processing_ms",
        "pad_processing_ms",
        "biometric_processing_ms",
        "pdp_processing_ms",
        "pep_processing_ms",
        "end_to_end_decision_ms"
    ]

    def __init__(self):
        self._counters: Dict[str, int] = {k: 0 for k in self.COUNTER_KEYS}
        self._histograms: Dict[str, List[float]] = {k: [] for k in self.HISTOGRAM_KEYS}

    def inc(self, metric: str, amount: int = 1):
        if metric in self._counters:
            self._counters[metric] += amount

    def record_latency(self, metric: str, duration_ms: float):
        if metric in self._histograms:
            self._histograms[metric].append(duration_ms)

    def get_metrics(self) -> Dict[str, Any]:
        """Compute summary statistics for counters and histograms."""
        hist_stats = {}
        for k, samples in self._histograms.items():
            if not samples:
                hist_stats[k] = {
                    "count": 0,
                    "min": 0.0,
                    "median": 0.0,
                    "p95": 0.0,
                    "p99": 0.0,
                    "max": 0.0
                }
            else:
                arr = np.array(samples)
                hist_stats[k] = {
                    "count": len(samples),
                    "min": round(float(np.min(arr)), 2),
                    "median": round(float(np.median(arr)), 2),
                    "p95": round(float(np.percentile(arr, 95)), 2),
                    "p99": round(float(np.percentile(arr, 99)), 2),
                    "max": round(float(np.max(arr)), 2)
                }

        return {
            "counters": dict(self._counters),
            "latency_histograms": hist_stats,
            "timestamp": time.time()
        }

    def reset(self):
        self._counters = {k: 0 for k in self.COUNTER_KEYS}
        self._histograms = {k: [] for k in self.HISTOGRAM_KEYS}


# Default global telemetry instance
telemetry = TelemetryCollector()
