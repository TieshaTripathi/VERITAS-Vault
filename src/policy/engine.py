"""
VERITAS-Vault Zero-Trust Policy Engine
========================================
Implements a temporal sliding window (delta_t <= 5.0s) two-man rule:

  Mode 1 - Standard Locker Access:
    Requires 1 Employee AND 1 Customer (distinct) verified within 5.0s.
    Single custody (Employee-only or Customer-only) triggers WAITING.
    Timer expiry without second party -> BREACH.

  Mode 2 - High-Value Inventory Audit:
    Requires 2 DISTINCT Employees (P1 != P2) verified within 5.0s.
    Single employee triggers WAITING.  Timer expiry -> BREACH.

Design principles:
  - first_seen timestamps are immutable once recorded; re-scanning the same
    person does NOT reset the timer.
  - Unauthorized or unrecognized individuals immediately trigger BREACH and
    reset all state.
  - Liveness failures are treated as BREACH at the dashboard layer; the
    policy engine only evaluates role/identity, not liveness directly.
"""

import time
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from src.policy.two_man import PolicyState, TwoManPolicyRules

WINDOW_SECONDS = 5.0  # Immutable sliding window budget (delta_t)


class EvaluationResult(BaseModel):
    state: PolicyState
    remaining_timer_seconds: float
    reason_text: str
    event_details: Dict[str, Any] = Field(default_factory=dict)
    unlocked: bool = False


def _fresh_state() -> Dict[str, Any]:
    """Returns a new, empty policy session state dict."""
    return {
        "policy_timer_start": 0.0,           # Epoch of FIRST verified party
        "policy_validated_parties": {},       # name -> {role, first_seen}
    }


def evaluate_access(
    active_mode: str,
    detected_faces: List[Dict[str, Any]],
    session_state: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Zero-Trust Policy Engine - temporal sliding window validation.

    Parameters
    ----------
    active_mode    : 'Standard Locker Access' or 'High-Value Inventory Audit'
    detected_faces : list of face dicts from recognize_faces() / override
    session_state  : mutable dict persisted between Streamlit reruns
                     (use st.session_state or a class-level dict)

    Returns
    -------
    dict with keys: status, msg, unlocked, remaining
    """
    # Initialise or repair session state
    if session_state is None:
        session_state = _fresh_state()
    if "policy_timer_start" not in session_state:
        session_state["policy_timer_start"] = 0.0
    if "policy_validated_parties" not in session_state:
        session_state["policy_validated_parties"] = {}

    now = time.time()

    # ------------------------------------------------------------------
    # 1. BREACH: any unrecognized / unauthorized individual detected
    # ------------------------------------------------------------------
    unauthorized = [
        f for f in detected_faces
        if not f.get("is_recognized", f.get("is_authorized", False))
        or f.get("role") in ("Unauthorized", "Unknown", None, "")
    ]
    if unauthorized:
        session_state["policy_timer_start"] = 0.0
        session_state["policy_validated_parties"] = {}
        return {
            "status": "BREACH",
            "msg": "Access Denied: Unauthorized Individual Detected",
            "unlocked": False,
            "remaining": 0.0,
        }

    # ------------------------------------------------------------------
    # 2. STANDBY / WAITING if timer was active but no faces present now
    # ------------------------------------------------------------------
    auth_faces = [
        f for f in detected_faces
        if f.get("is_recognized", f.get("is_authorized", False))
        and f.get("role") not in ("Unauthorized", "Unknown", None, "")
    ]

    if not auth_faces:
        timer_start = session_state["policy_timer_start"]
        if timer_start > 0.0:
            elapsed = now - timer_start
            if elapsed > WINDOW_SECONDS:
                # Timer expired with no second party -> BREACH
                session_state["policy_timer_start"] = 0.0
                session_state["policy_validated_parties"] = {}
                return {
                    "status": "BREACH",
                    "msg": "Temporal Window Expired: Single Custody Breach",
                    "unlocked": False,
                    "remaining": 0.0,
                }
            remaining = max(0.0, WINDOW_SECONDS - elapsed)
            return {
                "status": "WAITING",
                "msg": "Waiting for second party...",
                "remaining": round(remaining, 1),
                "unlocked": False,
            }
        # No active timer, no faces
        return {
            "status": "STANDBY",
            "msg": "Monitoring Vault Chamber",
            "unlocked": False,
            "remaining": WINDOW_SECONDS,
        }

    # ------------------------------------------------------------------
    # 3. Purge stale parties from the sliding window.
    #    IMPORTANT: use first_seen, not re-stamped on each frame.
    # ------------------------------------------------------------------
    parties = session_state["policy_validated_parties"]
    parties = {
        name: data
        for name, data in parties.items()
        if now - data["first_seen"] <= WINDOW_SECONDS
    }

    # ------------------------------------------------------------------
    # 4. Register new authorized faces (immutable first_seen timestamp)
    # ------------------------------------------------------------------
    for face in auth_faces:
        name = face.get("name", "Unknown")
        role = face.get("role", "Unknown")
        if name not in parties:
            # First time we see this person in this window
            parties[name] = {"role": role, "first_seen": now}
            if session_state["policy_timer_start"] == 0.0:
                # Anchor the window clock to the very first verified party
                session_state["policy_timer_start"] = now

    session_state["policy_validated_parties"] = parties

    # ------------------------------------------------------------------
    # 5. Evaluate policy
    # ------------------------------------------------------------------
    timer_start = session_state["policy_timer_start"]
    elapsed = now - timer_start if timer_start > 0.0 else 0.0
    remaining = max(0.0, round(WINDOW_SECONDS - elapsed, 1))

    is_high_value = "High-Value" in active_mode or "Dual-Employee" in active_mode

    if is_high_value:
        # ---- Mode 2: 2 distinct Employees within 5.0s ----
        employees = [name for name, d in parties.items() if d["role"] == "Employee"]

        if len(set(employees)) >= 2:
            # SUCCESS
            e1, e2 = list(set(employees))[:2]
            session_state["policy_timer_start"] = 0.0
            session_state["policy_validated_parties"] = {}
            return {
                "status": "GRANTED",
                "msg": f"Vault Unlocked: Dual-Employee Authorization ({e1} & {e2})",
                "unlocked": True,
                "remaining": 0.0,
            }

        if elapsed > WINDOW_SECONDS:
            session_state["policy_timer_start"] = 0.0
            session_state["policy_validated_parties"] = {}
            return {
                "status": "BREACH",
                "msg": "Temporal Window Expired: Second Officer Did Not Arrive",
                "unlocked": False,
                "remaining": 0.0,
            }

        if len(employees) == 1:
            return {
                "status": "WAITING",
                "msg": f"Officer {employees[0]} verified. Awaiting 2nd Officer ({remaining}s)",
                "remaining": remaining,
                "unlocked": False,
            }

        return {
            "status": "WAITING",
            "msg": "Awaiting 2 Enrolled Employees",
            "remaining": remaining,
            "unlocked": False,
        }

    else:
        # ---- Mode 1: 1 Employee + 1 Customer within 5.0s ----
        employees = [name for name, d in parties.items() if d["role"] == "Employee"]
        customers = [name for name, d in parties.items() if d["role"] == "Customer"]

        if employees and customers:
            # SUCCESS
            session_state["policy_timer_start"] = 0.0
            session_state["policy_validated_parties"] = {}
            return {
                "status": "GRANTED",
                "msg": f"Vault Unlocked: Dual Authorization ({employees[0]} & {customers[0]})",
                "unlocked": True,
                "remaining": 0.0,
            }

        if elapsed > WINDOW_SECONDS:
            session_state["policy_timer_start"] = 0.0
            session_state["policy_validated_parties"] = {}
            return {
                "status": "BREACH",
                "msg": "Temporal Window Expired: Second Party Did Not Arrive",
                "unlocked": False,
                "remaining": 0.0,
            }

        if employees:
            return {
                "status": "WAITING",
                "msg": f"Employee {employees[0]} verified. Awaiting Customer ({remaining}s)",
                "remaining": remaining,
                "unlocked": False,
            }

        if customers:
            return {
                "status": "WAITING",
                "msg": f"Customer {customers[0]} verified. Awaiting Employee ({remaining}s)",
                "remaining": remaining,
                "unlocked": False,
            }

        return {
            "status": "WAITING",
            "msg": "Awaiting Employee and Customer",
            "remaining": remaining,
            "unlocked": False,
        }


class TwoManPolicyEngine:
    """
    Stateful engine instance with isolated session state.
    Use one instance per active camera session to avoid cross-session bleed.
    """

    def __init__(self, window_seconds: float = WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self.session_state = _fresh_state()

    def reset(self) -> None:
        self.session_state = _fresh_state()

    def evaluate(self, mode: str, detected_faces: List[Dict[str, Any]]) -> EvaluationResult:
        res = evaluate_access(mode, detected_faces, self.session_state)
        status = res["status"]

        state_map = {
            "STANDBY": PolicyState.STANDBY,
            "WAITING": PolicyState.WAITING,
            "GRANTED": PolicyState.GRANTED,
            "BREACH":  PolicyState.BREACH,
        }
        policy_state = state_map.get(status, PolicyState.STANDBY)

        evt_type = None
        if status == "GRANTED":
            evt_type = "VAULT_ACCESS_GRANTED"
        elif status == "BREACH":
            evt_type = "ALERT_UNAUTHORIZED_BREACH"

        event_details = {"event_type": evt_type} if evt_type else {}

        return EvaluationResult(
            state=policy_state,
            remaining_timer_seconds=res.get("remaining", WINDOW_SECONDS),
            reason_text=res["msg"],
            event_details=event_details,
            unlocked=res.get("unlocked", False),
        )

    async def async_evaluate(self, mode: str,
                             detected_faces: List[Dict[str, Any]]) -> EvaluationResult:
        """Async wrapper - evaluation itself is synchronous (in-memory state machine)."""
        return self.evaluate(mode, detected_faces)


# Module-level default engine (used when session_state is passed externally)
default_policy_engine = TwoManPolicyEngine(window_seconds=WINDOW_SECONDS)