"""
VERITAS-Vault Tailgating Detection Architecture
===============================================
Defines software abstraction for detecting unauthorized trailing entries.

IMPORTANT ARCHITECTURAL DESIGNATION:
The active implementation is `SimulatedTailgatingDetector`, which correlates
authorized badge/biometric grants against simulated optical/beam passage counters.
Secondary camera optical flow, infrared light curtain beams, and 3D time-of-flight
sensors are structured as future hardware integration backends.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class TailgatingStatus:
    CLEAR = "CLEAR"
    SUSPECTED = "SUSPECTED"
    BREACH = "BREACH"
    UNKNOWN = "UNKNOWN"


class TailgatingResult(BaseModel):
    status: str  # CLEAR, SUSPECTED, BREACH, UNKNOWN
    checkpoint_id: str
    authorized_entry_count: int
    observed_person_crossings: int
    discrepancy: int
    confidence: float
    detector_type: str
    reason: str


class TailgatingDetector(ABC):
    """Abstract interface for tailgating and piggybacking detection."""

    @abstractmethod
    def detect(
        self,
        authorized_entry_count: int,
        observed_person_crossings: int,
        time_window: float,
        checkpoint_id: str
    ) -> TailgatingResult:
        """
        Evaluate crossing counts against authorizations in the given time window.
        """
        pass


class SimulatedTailgatingDetector(TailgatingDetector):
    """
    Simulation / logic correlator for tailgating detection.
    Accurately labeled: Software logic correlation prototype.
    """
    def __init__(self):
        self.detector_type = "SIMULATED_LOGIC_CORRELATOR"

    def detect(
        self,
        authorized_entry_count: int,
        observed_person_crossings: int,
        time_window: float,
        checkpoint_id: str
    ) -> TailgatingResult:
        if observed_person_crossings < 0 or authorized_entry_count < 0:
            return TailgatingResult(
                status=TailgatingStatus.UNKNOWN,
                checkpoint_id=checkpoint_id,
                authorized_entry_count=authorized_entry_count,
                observed_person_crossings=observed_person_crossings,
                discrepancy=0,
                confidence=0.0,
                detector_type=self.detector_type,
                reason="Invalid negative sensor telemetry"
            )

        discrepancy = observed_person_crossings - authorized_entry_count

        if discrepancy <= 0:
            return TailgatingResult(
                status=TailgatingStatus.CLEAR,
                checkpoint_id=checkpoint_id,
                authorized_entry_count=authorized_entry_count,
                observed_person_crossings=observed_person_crossings,
                discrepancy=discrepancy,
                confidence=0.95,
                detector_type=self.detector_type,
                reason="Observed crossings match or are within authorized count"
            )
        elif discrepancy == 1:
            return TailgatingResult(
                status=TailgatingStatus.SUSPECTED,
                checkpoint_id=checkpoint_id,
                authorized_entry_count=authorized_entry_count,
                observed_person_crossings=observed_person_crossings,
                discrepancy=discrepancy,
                confidence=0.85,
                detector_type=self.detector_type,
                reason="Single unauthorized trailing crossing detected in time window"
            )
        else:
            return TailgatingResult(
                status=TailgatingStatus.BREACH,
                checkpoint_id=checkpoint_id,
                authorized_entry_count=authorized_entry_count,
                observed_person_crossings=observed_person_crossings,
                discrepancy=discrepancy,
                confidence=0.98,
                detector_type=self.detector_type,
                reason=f"Multiple unauthorized crossings detected ({discrepancy} unauthorized persons)"
            )


class SecondaryCameraTailgatingDetector(TailgatingDetector):
    """Reserved for future overhead optical flow / YOLO person tracking."""
    def detect(self, authorized_entry_count: int, observed_person_crossings: int, time_window: float, checkpoint_id: str) -> TailgatingResult:
        raise NotImplementedError("Overhead secondary camera optical tracking pipeline not initialized.")


class InfraredBeamTailgatingDetector(TailgatingDetector):
    """Reserved for future physical infrared light curtain beam arrays."""
    def detect(self, authorized_entry_count: int, observed_person_crossings: int, time_window: float, checkpoint_id: str) -> TailgatingResult:
        raise NotImplementedError("Physical infrared light curtain hardware interface not initialized.")


# Default instance
default_tailgating_detector = SimulatedTailgatingDetector()
