"""
VERITAS-Vault Production Deterministic Risk Engine
===================================================
Calculates an explainable 0–100 risk score from multiple independent trust dimensions.
Never utilizes non-deterministic logic or large language models for physical access decisions.

Risk Score Scale:
  0 – 30  : LOW (Standard zero-trust policy evaluation)
  31 – 60 : MEDIUM (Step-up authentication / mandatory dual custody)
  61 – 100: HIGH (Default deny + security alert generation)
"""
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

RISK_ENGINE_VERSION = "risk-v1.0"


class RiskContributor(BaseModel):
    factor: str
    points: int
    detail: str


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: str  # "LOW", "MEDIUM", "HIGH"
    contributors: List[RiskContributor] = Field(default_factory=list)
    version: str = RISK_ENGINE_VERSION


class ProductionRiskEngine:
    """
    Centralized, deterministic risk engine for physical checkpoint access evaluation.
    """
    def __init__(self, version: str = RISK_ENGINE_VERSION):
        self.version = version
        # Configured risk factor ceilings
        self.max_biometric_uncertainty = 30
        self.max_pad_uncertainty = 35
        self.max_device_penalty = 30
        self.max_history_penalty = 20
        self.max_off_hours_penalty = 10

    def evaluate_risk(
        self,
        biometric_confidence: float,
        pad_confidence: float,
        is_trusted_device: bool,
        historical_failures: int = 0,
        outside_normal_hours: bool = False,
        face_count: int = 1
    ) -> RiskAssessment:
        score = 0
        contributors: List[RiskContributor] = []

        # 1. Biometric confidence margin (0 - 30 pts)
        if biometric_confidence < 0.70:
            pts = 30
            score += pts
            contributors.append(RiskContributor(
                factor="biometric_uncertainty",
                points=pts,
                detail=f"Confidence {biometric_confidence:.3f} below minimum verification threshold (0.70)"
            ))
        elif biometric_confidence < 0.85:
            margin = (0.85 - biometric_confidence) / 0.15
            pts = int(margin * 20)
            score += pts
            contributors.append(RiskContributor(
                factor="biometric_uncertainty",
                points=pts,
                detail=f"Confidence {biometric_confidence:.3f} in margin zone (0.70 - 0.85)"
            ))

        # 2. Presentation Attack Detection (PAD) uncertainty (0 - 35 pts)
        if pad_confidence < 0.75:
            pts = 35
            score += pts
            contributors.append(RiskContributor(
                factor="pad_uncertainty",
                points=pts,
                detail=f"PAD confidence {pad_confidence:.2f} below liveness cutoff (0.75)"
            ))
        elif pad_confidence < 0.90:
            margin = (0.90 - pad_confidence) / 0.15
            pts = int(margin * 25)
            score += pts
            contributors.append(RiskContributor(
                factor="pad_uncertainty",
                points=pts,
                detail=f"PAD confidence {pad_confidence:.2f} has elevated presentation anomaly"
            ))

        # 3. Device Trust state (0 - 30 pts)
        if not is_trusted_device:
            pts = 30
            score += pts
            contributors.append(RiskContributor(
                factor="untrusted_device",
                points=pts,
                detail="Capture device is not registered, unverified, or revoked"
            ))

        # 4. Repeated historical access failures (0 - 20 pts)
        if historical_failures > 0:
            pts = min(20, historical_failures * 5)
            score += pts
            contributors.append(RiskContributor(
                factor="repeated_failures",
                points=pts,
                detail=f"{historical_failures} consecutive failed attempts registered"
            ))

        # 5. Temporal anomaly / off-hours shift (0 - 10 pts)
        if outside_normal_hours:
            pts = 10
            score += pts
            contributors.append(RiskContributor(
                factor="temporal_anomaly",
                points=pts,
                detail="Access attempt occurs outside approved personnel shift window"
            ))

        # 6. Multi-face anomaly
        if face_count > 1:
            pts = 15
            score += pts
            contributors.append(RiskContributor(
                factor="multiple_faces",
                points=pts,
                detail=f"{face_count} faces detected in single frame capture"
            ))

        final_score = max(0, min(100, score))
        if final_score <= 30:
            level = "LOW"
        elif final_score <= 60:
            level = "MEDIUM"
        else:
            level = "HIGH"

        return RiskAssessment(
            score=final_score,
            level=level,
            contributors=contributors,
            version=self.version
        )


default_risk_engine = ProductionRiskEngine()
