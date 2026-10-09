"""Pure dual-custody state machine; persistence performs a CAS commit."""
import copy

WINDOW_SECONDS = 15.0


def fresh(mode="standard"):
    return {"state": "STANDBY", "mode": mode, "deadline": None, "parties": [],
            "reason": "Ready for a verified identity", "seen": [], "last_event": None}


def advance(state, faces, now, digest=None):
    from src.policy.pdp import default_pdp
    result = copy.deepcopy(state)
    if result["state"] in ("GRANTED", "BREACH", "DENIED"):
        return result, False  # Explicit reset required; cannot replay a terminal frame.

    # 1. Temporal Window Expiry
    if result["deadline"] is not None and now >= result["deadline"]:
        result.update(
            state="BREACH",
            reason=f"{int(WINDOW_SECONDS)}-second custody window expired",
            reason_code="ZT-008",
            safe_user_message="SECURITY ALERT: Custody window expired",
            risk_score=85,
            policy_version="VAULT-ZT-v1.0"
        )
        return result, True

    if digest and digest in result["seen"]:
        return result, False
    if digest:
        result["seen"] = (result["seen"] + [digest])[-32:]

    # 2. Multi-Signal PAD Check
    if any(not f.get("is_live") for f in faces):
        result.update(
            state="BREACH",
            reason="Presentation spoof rejected",
            reason_code="ZT-002",
            safe_user_message="ACCESS DENIED: Biometric verification failed",
            risk_score=99,
            policy_version="VAULT-ZT-v1.0"
        )
        return result, True

    # 3. Identity Verification Check
    if any(not f.get("is_recognized") for f in faces):
        result.update(
            state="BREACH",
            reason="Unregistered identity detected",
            reason_code="ZT-001",
            safe_user_message="ACCESS DENIED: Contact Security",
            risk_score=80,
            policy_version="VAULT-ZT-v1.0"
        )
        return result, True

    # 4. Identity Registration & Custody Window Start
    duplicate_first = False
    new_faces = []
    for face in faces:
        if any(p["id"] == face["id"] for p in result["parties"]):
            duplicate_first = True
        else:
            new_faces.append(face)

    for face in new_faces:
        result["parties"].append({k: face[k] for k in ("id", "name", "role")})
        if result["deadline"] is None:
            result["deadline"] = now + WINDOW_SECONDS

    # 5. Continuous Risk Calculation
    best_bio = max((f.get("confidence", 0.0) for f in faces), default=0.85)
    best_pad = max((f.get("pad_confidence", 0.90) for f in faces), default=0.90)
    risk = default_pdp.risk_engine.compute_risk(best_bio, best_pad, is_trusted_device=True)
    result["risk_score"] = risk
    result["policy_version"] = "VAULT-ZT-v1.0"

    roles = [p["role"] for p in result["parties"]]
    valid = roles.count("Employee") >= 2 if result["mode"] == "high-value" else (
        "Employee" in roles and "Customer" in roles)

    if valid:
        result.update(
            state="GRANTED",
            reason=f"Distinct identities verified within {int(WINDOW_SECONDS)} seconds",
            safe_user_message="ACCESS GRANTED: Proceed to vault entry",
            duplicate_first_party=False
        )
        return result, True

    if result["parties"]:
        result.update(
            state="WAITING",
            reason="First identity verified; awaiting second party",
            reason_code="ZT-007"
        )
        if duplicate_first and not new_faces:
            result["safe_user_message"] = "ALREADY VERIFIED — WAITING FOR DIFFERENT PERSON"
            result["duplicate_first_party"] = True
        else:
            result["safe_user_message"] = "PRIMARY VERIFIED: Awaiting second authorized party"
            result["duplicate_first_party"] = False
    return result, False
