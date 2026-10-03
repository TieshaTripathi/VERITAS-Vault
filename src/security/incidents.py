"""
VERITAS-Vault Security Incident Engine
======================================
Formalized lifecycle management for physical access and cryptographic security incidents.
Categorizes severity deterministically and manages incident lifecycle:
  OPEN -> ACKNOWLEDGED -> RESOLVED
"""

import time
import uuid
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class IncidentType:
    PAD_ATTACK = "PAD_ATTACK"
    UNKNOWN_IDENTITY = "UNKNOWN_IDENTITY"
    REPLAY_ATTACK = "REPLAY_ATTACK"
    DEVICE_AUTH_FAILURE = "DEVICE_AUTH_FAILURE"
    HIGH_RISK_ACCESS = "HIGH_RISK_ACCESS"
    FORCED_OPEN = "FORCED_OPEN"
    DOOR_HELD_OPEN = "DOOR_HELD_OPEN"
    TAILGATING = "TAILGATING"
    AUDIT_INTEGRITY_FAILURE = "AUDIT_INTEGRITY_FAILURE"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    ADMIN_SECURITY_EVENT = "ADMIN_SECURITY_EVENT"


class IncidentSeverity:
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus:
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


# Default baseline severities (denials are NOT all marked CRITICAL)
DEFAULT_SEVERITY_MAP = {
    IncidentType.UNKNOWN_IDENTITY: IncidentSeverity.LOW,
    IncidentType.POLICY_VIOLATION: IncidentSeverity.MEDIUM,
    IncidentType.DOOR_HELD_OPEN: IncidentSeverity.MEDIUM,
    IncidentType.HIGH_RISK_ACCESS: IncidentSeverity.HIGH,
    IncidentType.DEVICE_AUTH_FAILURE: IncidentSeverity.HIGH,
    IncidentType.PAD_ATTACK: IncidentSeverity.HIGH,
    IncidentType.REPLAY_ATTACK: IncidentSeverity.HIGH,
    IncidentType.TAILGATING: IncidentSeverity.HIGH,
    IncidentType.FORCED_OPEN: IncidentSeverity.CRITICAL,
    IncidentType.AUDIT_INTEGRITY_FAILURE: IncidentSeverity.CRITICAL,
    IncidentType.ADMIN_SECURITY_EVENT: IncidentSeverity.INFO
}


class SecurityIncident(BaseModel):
    incident_id: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    checkpoint_id: str
    event_id: Optional[str] = None
    type: str  # from IncidentType
    reason_codes: List[str] = Field(default_factory=list)
    description: str
    created_at: float
    status: str = IncidentStatus.OPEN
    acknowledged_at: Optional[float] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[float] = None
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None


class IncidentEngine:
    """Manages security incident creation, state transitions, and audit records."""

    def __init__(self):
        self._incidents: Dict[str, SecurityIncident] = {}

    def create_incident(
        self,
        incident_type: str,
        checkpoint_id: str,
        description: str,
        event_id: Optional[str] = None,
        reason_codes: Optional[List[str]] = None,
        severity: Optional[str] = None
    ) -> SecurityIncident:
        assigned_severity = severity or DEFAULT_SEVERITY_MAP.get(incident_type, IncidentSeverity.MEDIUM)
        incident_id = f"inc-{uuid.uuid4().hex[:12]}"
        now = time.time()

        incident = SecurityIncident(
            incident_id=incident_id,
            severity=assigned_severity,
            checkpoint_id=checkpoint_id,
            event_id=event_id,
            type=incident_type,
            reason_codes=reason_codes or [],
            description=description,
            created_at=now,
            status=IncidentStatus.OPEN
        )
        self._incidents[incident_id] = incident
        return incident

    def acknowledge_incident(self, incident_id: str, operator_id: str) -> Optional[SecurityIncident]:
        incident = self._incidents.get(incident_id)
        if not incident:
            return None
        incident.status = IncidentStatus.ACKNOWLEDGED
        incident.acknowledged_at = time.time()
        incident.acknowledged_by = operator_id
        return incident

    def resolve_incident(
        self,
        incident_id: str,
        operator_id: str,
        resolution_notes: str
    ) -> Optional[SecurityIncident]:
        incident = self._incidents.get(incident_id)
        if not incident:
            return None
        incident.status = IncidentStatus.RESOLVED
        incident.resolved_at = time.time()
        incident.resolved_by = operator_id
        incident.resolution_notes = resolution_notes
        return incident

    def get_incident(self, incident_id: str) -> Optional[SecurityIncident]:
        return self._incidents.get(incident_id)

    def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        checkpoint_id: Optional[str] = None
    ) -> List[SecurityIncident]:
        results = list(self._incidents.values())
        if status:
            results = [inc for inc in results if inc.status == status]
        if severity:
            results = [inc for inc in results if inc.severity == severity]
        if checkpoint_id:
            results = [inc for inc in results if inc.checkpoint_id == checkpoint_id]
        return sorted(results, key=lambda x: x.created_at, reverse=True)


# Default global incident engine
default_incident_engine = IncidentEngine()
