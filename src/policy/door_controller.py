"""
VERITAS-Vault Hardware Relay & Door State Controller Abstraction
================================================================
Defines physical and simulated Policy Enforcement Point (PEP) door controller interface.
Never assumes "relay signal sent" equals "door behaved correctly".
Tracks contact sensors, lock states, tamper states, and pulses hardware actuators.
"""
from abc import ABC, abstractmethod
from enum import Enum
import time
from typing import Dict, Any, Optional


class DoorSecurityState(str, Enum):
    SECURED = "SECURED"
    UNLOCKED = "UNLOCKED"
    FORCED_OPEN = "FORCED_OPEN"
    HELD_OPEN = "HELD_OPEN"
    TAMPER = "TAMPER"


class DoorController(ABC):
    @abstractmethod
    def pulse_unlock(self, authorization_id: str, duration_ms: int = 3000) -> Dict[str, Any]:
        """Pulse the physical or simulated lock relay upon valid PEP authorization."""
        pass

    @abstractmethod
    def lock(self) -> Dict[str, Any]:
        """Immediately re-engage physical locking mechanism."""
        pass

    @abstractmethod
    def get_telemetry(self) -> Dict[str, Any]:
        """Read sensor state: door contact sensor, lock feedback, tamper switch."""
        pass


class SimulatedDoorController(DoorController):
    """
    Clearly labeled simulation controller for edge deployments without physical GPIO relays.
    Logs hardware actuation metrics and simulates contact sensor timing.
    """
    def __init__(self, checkpoint_id: str = "CP-MAIN-01"):
        self.checkpoint_id = checkpoint_id
        self.is_locked = True
        self.contact_closed = True
        self.tamper_ok = True
        self.unlock_expiry: float = 0.0
        self.last_actuation_id: Optional[str] = None
        self.last_actuation_time: float = 0.0

    def pulse_unlock(self, authorization_id: str, duration_ms: int = 3000) -> Dict[str, Any]:
        now = time.time()
        self.is_locked = False
        self.unlock_expiry = now + (duration_ms / 1000.0)
        self.last_actuation_id = authorization_id
        self.last_actuation_time = now
        return {
            "status": "RELAY_ACTUATED",
            "controller_type": "SIMULATED_PEP_RELAY",
            "checkpoint_id": self.checkpoint_id,
            "authorization_id": authorization_id,
            "duration_ms": duration_ms,
            "lock_state": "UNLOCKED",
            "sensor_contact": "CLOSED",
            "timestamp": now
        }

    def lock(self) -> Dict[str, Any]:
        self.is_locked = True
        self.unlock_expiry = 0.0
        return {
            "status": "SECURED",
            "lock_state": "LOCKED",
            "timestamp": time.time()
        }

    def get_telemetry(self) -> Dict[str, Any]:
        now = time.time()
        # Auto re-lock when pulse expires
        if not self.is_locked and now >= self.unlock_expiry:
            self.is_locked = True

        state = DoorSecurityState.SECURED if self.is_locked else DoorSecurityState.UNLOCKED
        if not self.tamper_ok:
            state = DoorSecurityState.TAMPER

        return {
            "checkpoint_id": self.checkpoint_id,
            "state": state.value,
            "relay_engaged": not self.is_locked,
            "contact_sensor": "CLOSED" if self.contact_closed else "OPEN",
            "lock_sensor": "LOCKED" if self.is_locked else "UNLOCKED",
            "tamper_switch": "SECURE" if self.tamper_ok else "TAMPER_DETECTED",
            "last_actuation_id": self.last_actuation_id,
            "is_simulation": True
        }


# Global default controller for edge node
default_door_controller = SimulatedDoorController(checkpoint_id="CP-MAIN-01")


class SensorContactState(str, Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    UNKNOWN = "UNKNOWN"
    TAMPERED = "TAMPERED"


class DoorSensorProvider(ABC):
    """Abstract interface for physical/simulated door sensors and contact monitors."""

    @abstractmethod
    def get_sensor_state(self) -> Dict[str, Any]:
        """Read instantaneous hardware/simulated sensor registers."""
        pass

    @abstractmethod
    def check_anomalies(self, timeout_sec: float = 10.0) -> List[Dict[str, Any]]:
        """Evaluate sensor states against authorization state to detect security anomalies."""
        pass


class SimulatedDoorSensorProvider(DoorSensorProvider):
    """
    Simulated door sensor provider for testing and software-only edge deployments.
    Accurately labeled: SIMULATED contact, tamper, and relay telemetry.
    """
    def __init__(self, checkpoint_id: str = "CP-MAIN-01", controller: Optional[SimulatedDoorController] = None):
        self.checkpoint_id = checkpoint_id
        self.controller = controller or default_door_controller
        self.door_contact = SensorContactState.CLOSED
        self.tamper_state = "SECURE"  # SECURE, TAMPERED, OFFLINE
        self.is_online = True
        self.opened_at: Optional[float] = None
        self.active_authorization_id: Optional[str] = None

    def trigger_authorized_open(self, authorization_id: str):
        now = time.time()
        self.controller.pulse_unlock(authorization_id)
        self.door_contact = SensorContactState.OPEN
        self.opened_at = now
        self.active_authorization_id = authorization_id

    def trigger_close(self):
        self.door_contact = SensorContactState.CLOSED
        self.opened_at = None
        self.active_authorization_id = None
        self.controller.lock()

    def simulate_forced_open(self):
        """Simulate door contact opening without prior authorization."""
        self.door_contact = SensorContactState.OPEN
        self.opened_at = time.time()
        self.active_authorization_id = None

    def simulate_tamper(self):
        self.tamper_state = "TAMPERED"

    def simulate_offline(self):
        self.is_online = False
        self.tamper_state = "OFFLINE"
        self.door_contact = SensorContactState.UNKNOWN

    def get_sensor_state(self) -> Dict[str, Any]:
        ctrl_tel = self.controller.get_telemetry()
        return {
            "checkpoint_id": self.checkpoint_id,
            "relay_state": "ENERGIZED" if ctrl_tel.get("relay_engaged") else "DE_ENERGIZED",
            "lock_state": ctrl_tel.get("lock_sensor", "LOCKED"),
            "door_contact": self.door_contact.value,
            "tamper_state": self.tamper_state,
            "is_online": self.is_online,
            "opened_at": self.opened_at,
            "active_authorization_id": self.active_authorization_id,
            "is_simulation": True
        }

    def check_anomalies(self, timeout_sec: float = 10.0) -> List[Dict[str, Any]]:
        now = time.time()
        anomalies: List[Dict[str, Any]] = []

        if not self.is_online:
            anomalies.append({
                "type": "SENSOR_OFFLINE",
                "checkpoint_id": self.checkpoint_id,
                "severity": "HIGH",
                "message": "Door sensor provider is offline or unreachable",
                "timestamp": now
            })
            return anomalies

        if self.tamper_state == "TAMPERED":
            anomalies.append({
                "type": "SENSOR_TAMPER",
                "checkpoint_id": self.checkpoint_id,
                "severity": "CRITICAL",
                "message": "Physical tamper switch triggered on sensor housing",
                "timestamp": now
            })

        # Check FORCED_OPEN: door is open, but controller was never unlocked / no active auth
        if self.door_contact == SensorContactState.OPEN and not self.active_authorization_id:
            anomalies.append({
                "type": "FORCED_OPEN",
                "checkpoint_id": self.checkpoint_id,
                "severity": "CRITICAL",
                "message": "Door forced open without authorized unlock pulse",
                "timestamp": now
            })

        # Check DOOR_HELD_OPEN: door opened with auth, but stayed open longer than timeout_sec
        if self.door_contact == SensorContactState.OPEN and self.opened_at and (now - self.opened_at > timeout_sec):
            anomalies.append({
                "type": "DOOR_HELD_OPEN",
                "checkpoint_id": self.checkpoint_id,
                "severity": "MEDIUM",
                "duration_seconds": round(now - self.opened_at, 2),
                "message": f"Door held open beyond configured timeout ({timeout_sec}s)",
                "timestamp": now
            })

        # Check LOCK_FAILURE: relay de-energized but lock indicates UNLOCKED
        ctrl_tel = self.controller.get_telemetry()
        if not ctrl_tel.get("relay_engaged") and ctrl_tel.get("lock_sensor") == "UNLOCKED":
            anomalies.append({
                "type": "LOCK_FAILURE",
                "checkpoint_id": self.checkpoint_id,
                "severity": "HIGH",
                "message": "Relay de-energized but mechanical lock remains unbolted",
                "timestamp": now
            })

        return anomalies


# Global default sensor provider
default_door_sensor_provider = SimulatedDoorSensorProvider()

