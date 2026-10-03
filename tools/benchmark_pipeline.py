"""
VERITAS-Vault Local Pipeline Benchmark Tool
===========================================
Empirically measures actual local execution latency across all zero-trust pipeline stages:
1. Capture decode
2. Face quality gate
3. Presentation attack detection (PAD)
4. Biometric template extraction / embedding
5. Biometric comparison
6. ZeroTrustPDP evaluation
7. Edge PEP authorization token verification
8. Audit ledger append & Ed25519 signature

STRICT REQUIREMENT: Never hardcode benchmark values. Only report empirically measured stats.
Output: artifacts/pipeline_benchmark.json
"""

import sys
import os
import time
import json
import logging
from pathlib import Path
from typing import Dict, Any, List
import numpy as np
import cv2

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.vision.quality import FaceQualityGate
from src.vision.pad_provider import HeuristicPADProvider
from src.vision.biometric_provider import TemplateMatchingProvider
from src.policy.pdp import ZeroTrustPDP
from src.blockchain.audit_chain import AuditLedger

logger = logging.getLogger("VERITAS.Benchmark")


def run_pipeline_benchmark(iterations: int = 30, output_path: str = "artifacts/pipeline_benchmark.json") -> Dict[str, Any]:
    """Execute local benchmark and compute empirical latency distributions."""
    print(f"Starting VERITAS-Vault pipeline benchmark ({iterations} iterations)...")

    # Initialize components
    quality_gate = FaceQualityGate()
    pad_provider = HeuristicPADProvider()
    bio_provider = TemplateMatchingProvider()
    pdp = ZeroTrustPDP()

    temp_db = PROJECT_ROOT / "data" / "pwa" / "benchmark_audit.sqlite3"
    temp_keys = PROJECT_ROOT / "data" / "keys"
    audit_ledger = AuditLedger(db_path=temp_db, keys_dir=temp_keys)

    # Prepare synthetic test face frame
    test_frame = np.ones((480, 640, 3), dtype=np.uint8) * 128
    cv2.circle(test_frame, (320, 240), 90, (180, 160, 140), -1)
    cv2.circle(test_frame, (285, 210), 12, (50, 40, 30), -1)
    cv2.circle(test_frame, (355, 210), 12, (50, 40, 30), -1)
    cv2.ellipse(test_frame, (320, 270), (35, 18), 0, 0, 180, (40, 30, 25), 3)

    _, encoded_bytes = cv2.imencode(".jpg", test_frame)
    frame_bytes = encoded_bytes.tobytes()

    # Pre-enroll a baseline template for biometric comparison
    baseline_template = bio_provider.enroll(test_frame)

    stage_timings: Dict[str, List[float]] = {
        "capture_decode_ms": [],
        "face_quality_ms": [],
        "pad_evaluation_ms": [],
        "biometric_embedding_ms": [],
        "biometric_comparison_ms": [],
        "pdp_evaluation_ms": [],
        "pep_verification_ms": [],
        "audit_append_ms": [],
        "end_to_end_ms": []
    }

    # Warmup 3 iterations
    for _ in range(3):
        nparr = np.frombuffer(frame_bytes, np.uint8)
        frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        _ = quality_gate.evaluate_quality(frame)
        _ = pad_provider.evaluate(frame)
        tmpl = bio_provider.enroll(frame)
        _ = bio_provider.verify(frame, baseline_template)

    # Benchmark loop
    for i in range(iterations):
        t0 = time.perf_counter()

        # 1. Capture decode
        s_start = time.perf_counter()
        nparr = np.frombuffer(frame_bytes, np.uint8)
        frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        s_end = time.perf_counter()
        stage_timings["capture_decode_ms"].append((s_end - s_start) * 1000.0)

        # 2. Face quality
        s_start = time.perf_counter()
        qual_res = quality_gate.evaluate_quality(frame)
        s_end = time.perf_counter()
        stage_timings["face_quality_ms"].append((s_end - s_start) * 1000.0)

        # 3. PAD
        s_start = time.perf_counter()
        pad_res = pad_provider.evaluate(frame)
        s_end = time.perf_counter()
        stage_timings["pad_evaluation_ms"].append((s_end - s_start) * 1000.0)

        # 4. Biometric template embedding
        s_start = time.perf_counter()
        current_template = bio_provider.enroll(frame)
        s_end = time.perf_counter()
        stage_timings["biometric_embedding_ms"].append((s_end - s_start) * 1000.0)

        # 5. Biometric comparison
        s_start = time.perf_counter()
        verif_res = bio_provider.verify(frame, baseline_template)
        s_end = time.perf_counter()
        stage_timings["biometric_comparison_ms"].append((s_end - s_start) * 1000.0)

        # 6. PDP evaluation
        s_start = time.perf_counter()
        faces = [{
            "id": "EMP-BENCH-01",
            "name": "Benchmark User",
            "role": "Employee",
            "is_recognized": verif_res.matched,
            "is_live": pad_res.status == "PASS",
            "confidence": verif_res.similarity,
            "pad_confidence": pad_res.confidence
        }]
        pdp_res = pdp.evaluate(
            checkpoint_id="CP-MAIN-01",
            mode="standard",
            faces=faces,
            capture_valid=qual_res.status == "PASS",
            capture_reason="CAPTURE_VALIDATED" if qual_res.status == "PASS" else "QUALITY_GATE_FAILED",
            active_parties=[],
            deadline=None
        )
        s_end = time.perf_counter()
        stage_timings["pdp_evaluation_ms"].append((s_end - s_start) * 1000.0)

        # 7. PEP token verification
        s_start = time.perf_counter()
        if pdp_res.authorization_token:
            _, _ = pdp.verify_authorization_token(pdp_res.authorization_token, expected_checkpoint_id="CP-MAIN-01")
        s_end = time.perf_counter()
        stage_timings["pep_verification_ms"].append((s_end - s_start) * 1000.0)

        # 8. Audit ledger append & signature
        s_start = time.perf_counter()
        audit_record = audit_ledger.append_event(
            event_id=f"evt-bench-{i}-{int(time.time() * 1000)}",
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            payload={
                "session_id": f"sess-bench-{i}",
                "checkpoint_id": "CP-MAIN-01",
                "subject_id": "EMP-BENCH-01",
                "decision": pdp_res.decision,
                "reason_code": pdp_res.reason_code,
                "risk_score": pdp_res.risk_score,
                "biometric_score": verif_res.similarity,
                "pad_score": pad_res.pad_score,
                "policy_version": pdp_res.policy_version,
            },
            evidence_hash=""
        )
        s_end = time.perf_counter()
        stage_timings["audit_append_ms"].append((s_end - s_start) * 1000.0)

        t_total = time.perf_counter() - t0
        stage_timings["end_to_end_ms"].append(t_total * 1000.0)

    # Compute summary statistics
    results: Dict[str, Any] = {
        "timestamp": time.time(),
        "iterations": iterations,
        "stages": {},
        "biometric_provider": bio_provider.get_model_info().provider,
        "pad_engine": pad_provider.get_engine_info()["engine"],
        "status": "EMPIRICAL_MEASUREMENT_COMPLETE"
    }

    for stage, times in stage_timings.items():
        arr = np.array(times)
        results["stages"][stage] = {
            "median": round(float(np.median(arr)), 2),
            "p95": round(float(np.percentile(arr, 95)), 2),
            "p99": round(float(np.percentile(arr, 99)), 2),
            "min": round(float(np.min(arr)), 2),
            "max": round(float(np.max(arr)), 2),
            "sample_count": len(times)
        }

    # Clean up benchmark sqlite db
    if temp_db.exists():
        try:
            temp_db.unlink(missing_ok=True)
        except Exception:
            pass

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"Benchmark completed successfully. Results saved to {output_path}")
    print(f"End-to-End Latency: Median = {results['stages']['end_to_end_ms']['median']} ms | P95 = {results['stages']['end_to_end_ms']['p95']} ms")
    return results


if __name__ == "__main__":
    run_pipeline_benchmark()
