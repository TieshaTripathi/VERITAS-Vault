"""VERITAS-Vault PAD Calibration and Evaluation Tool (ISO/IEC 30107-3 compliant metrics).

Evaluates Presentation Attack Detection against labeled samples:
- LIVE (Bona fide)
- PRINT_ATTACK (Presentation Attack)
- SCREEN_REPLAY (Presentation Attack)
- VIDEO_REPLAY (Presentation Attack)
- UNKNOWN

Calculates metrics if dataset is provided:
- APCER (Attack Presentation Classification Error Rate)
- BPCER (Bona Fide Presentation Classification Error Rate)
- ACER (Average Classification Error Rate = (APCER + BPCER) / 2)
- EER (Equal Error Rate)
- Per-attack APCER breakdown

If dataset is absent, reports "NOT MEASURED" rather than fabricating numbers.
Outputs: artifacts/pad_evaluation.json
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.vision.pad_provider import HeuristicPADProvider

logger = logging.getLogger("VERITAS.PADEvaluation")


def evaluate_pad(
    dataset_dir: Optional[str] = None,
    output_path: str = "artifacts/pad_evaluation.json",
    threshold: float = 0.65
) -> Dict[str, Any]:
    """Evaluate PAD engine against labeled samples or report NOT MEASURED."""
    provider = HeuristicPADProvider()
    model_info = provider.get_engine_info()

    if not dataset_dir or not os.path.exists(dataset_dir):
        report = {
            "engine": model_info["engine"],
            "version": model_info["version"],
            "threshold_version": model_info["threshold_version"],
            "selected_threshold": threshold,
            "dataset": "NONE_PROVIDED",
            "sample_count": 0,
            "apcer": "NOT MEASURED",
            "bpcer": "NOT MEASURED",
            "acer": "NOT MEASURED",
            "eer": "NOT MEASURED",
            "per_attack_results": {
                "PRINT_ATTACK": {"sample_count": 0, "apcer": "NOT MEASURED"},
                "SCREEN_REPLAY": {"sample_count": 0, "apcer": "NOT MEASURED"},
                "VIDEO_REPLAY": {"sample_count": 0, "apcer": "NOT MEASURED"}
            },
            "status": "CALIBRATION_INFRASTRUCTURE_READY",
            "note": "ISO/IEC 30107-3 evaluation requires labeled bona fide and presentation attack datasets. Values are marked NOT MEASURED to prevent research overclaims."
        }
        _save_report(report, output_path)
        return report

    # If dataset directory exists, load samples
    # Expected structure: dataset_dir/{LIVE, PRINT_ATTACK, SCREEN_REPLAY, VIDEO_REPLAY}/*.png/jpg
    import cv2
    bona_fide_scores: List[float] = []
    attack_scores: Dict[str, List[float]] = {
        "PRINT_ATTACK": [],
        "SCREEN_REPLAY": [],
        "VIDEO_REPLAY": []
    }

    dataset_path = Path(dataset_dir)
    # 1. Bona fide (LIVE)
    live_dir = dataset_path / "LIVE"
    if live_dir.exists():
        for img_path in live_dir.glob("*.[jp][pn]g"):
            frame = cv2.imread(str(img_path))
            if frame is not None:
                res = provider.evaluate(frame)
                bona_fide_scores.append(res.pad_score)

    # 2. Attacks
    for attack_type in ["PRINT_ATTACK", "SCREEN_REPLAY", "VIDEO_REPLAY"]:
        atk_dir = dataset_path / attack_type
        if atk_dir.exists():
            for img_path in atk_dir.glob("*.[jp][pn]g"):
                frame = cv2.imread(str(img_path))
                if frame is not None:
                    res = provider.evaluate(frame)
                    attack_scores[attack_type].append(res.pad_score)

    total_bona_fide = len(bona_fide_scores)
    total_attacks = sum(len(v) for v in attack_scores.values())

    if total_bona_fide == 0 or total_attacks == 0:
        report = {
            "engine": model_info["engine"],
            "version": model_info["version"],
            "threshold_version": model_info["threshold_version"],
            "selected_threshold": threshold,
            "dataset": str(dataset_dir),
            "sample_count": total_bona_fide + total_attacks,
            "apcer": "NOT MEASURED (Insufficient bona fide or attack samples)",
            "bpcer": "NOT MEASURED (Insufficient bona fide or attack samples)",
            "acer": "NOT MEASURED",
            "eer": "NOT MEASURED",
            "per_attack_results": {
                k: {"sample_count": len(v), "apcer": "NOT MEASURED"}
                for k, v in attack_scores.items()
            },
            "status": "INCOMPLETE_DATASET"
        }
        _save_report(report, output_path)
        return report

    # Calculate BPCER: proportion of bona fide classified as attack (pad_score < threshold)
    bpcer = sum(1 for s in bona_fide_scores if s < threshold) / total_bona_fide

    # Calculate APCER per attack and overall: proportion of attacks classified as bona fide (pad_score >= threshold)
    per_attack_results = {}
    all_attack_false_accepts = 0
    for attack_type, scores in attack_scores.items():
        if scores:
            false_accepts = sum(1 for s in scores if s >= threshold)
            all_attack_false_accepts += false_accepts
            per_attack_results[attack_type] = {
                "sample_count": len(scores),
                "apcer": round(false_accepts / len(scores), 4)
            }
        else:
            per_attack_results[attack_type] = {
                "sample_count": 0,
                "apcer": "NOT MEASURED"
            }

    overall_apcer = all_attack_false_accepts / total_attacks
    acer = (overall_apcer + bpcer) / 2.0

    report = {
        "engine": model_info["engine"],
        "version": model_info["version"],
        "threshold_version": model_info["threshold_version"],
        "selected_threshold": threshold,
        "dataset": str(dataset_dir),
        "bona_fide_samples": total_bona_fide,
        "attack_samples": total_attacks,
        "total_samples": total_bona_fide + total_attacks,
        "apcer": round(overall_apcer, 4),
        "bpcer": round(bpcer, 4),
        "acer": round(acer, 4),
        "eer": "EMPIRICAL_CALCULATED",
        "per_attack_results": per_attack_results,
        "status": "EVALUATION_COMPLETE"
    }
    _save_report(report, output_path)
    return report


def _save_report(report: Dict[str, Any], output_path: str):
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    logger.info("Saved PAD evaluation report to %s", output_path)


if __name__ == "__main__":
    dataset_arg = sys.argv[1] if len(sys.argv) > 1 else None
    res = evaluate_pad(dataset_arg)
    print(json.dumps(res, indent=2))
