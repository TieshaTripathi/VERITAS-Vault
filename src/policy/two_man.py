from enum import Enum
from typing import List, Dict, Any, Tuple
from pydantic import BaseModel

class PolicyState(str, Enum):
    STANDBY = "STANDBY"
    WAITING = "WAITING"
    WAITING_SECOND_PARTY = "WAITING"
    WAITING_FOR_SECOND_PARTY = "WAITING"
    GRANTED = "GRANTED"
    ACCESS_GRANTED = "GRANTED"
    VAULT_UNLOCKED = "GRANTED"
    BREACH = "BREACH"
    BREACH_TRIGGERED = "BREACH"
    BREACH_DETECTED = "BREACH"
    TIMEOUT_BREACH = "TIMEOUT_BREACH"

class FaceRecord(BaseModel):
    name: str
    role: str
    is_authorized: bool

class TwoManPolicyRules:
    @staticmethod
    def evaluate(mode: str, detected_faces: List[Dict[str, Any]]) -> Tuple[bool, bool, str]:
        if not detected_faces:
            return False, False, "STANDBY: Monitoring Vault Chamber"

        unauthorized = [
            f for f in detected_faces
            if not f.get("is_authorized", f.get("is_recognized", False)) or f.get("role") in ["Unknown", "Unauthorized"]
        ]
        if unauthorized:
            return False, True, "Unauthorized Individual Detected"

        roles = [f.get("role") for f in detected_faces if f.get("is_authorized", f.get("is_recognized", False))]
        names = [f.get("name") for f in detected_faces if f.get("is_authorized", f.get("is_recognized", False))]

        if "High-Value" in mode or "Dual-Employee" in mode:
            employees = [f for f in detected_faces if f.get("role") == "Employee"]
            distinct_employee_names = set(f.get("name") for f in employees)

            if len(distinct_employee_names) >= 2:
                names_str = " & ".join(list(distinct_employee_names)[:2])
                return True, False, f"Dual Authorization Verified ({names_str})"
            elif len(distinct_employee_names) == 1:
                emp_name = list(distinct_employee_names)[0]
                return False, False, f"Officer {emp_name} verified. Waiting for 2nd Officer"
            else:
                return False, False, "Waiting for 2 Enrolled Employees"
        else:
            has_employee = "Employee" in roles
            has_customer = "Customer" in roles

            if has_employee and has_customer:
                emp_names = [f["name"] for f in detected_faces if f.get("role") == "Employee"]
                cust_names = [f["name"] for f in detected_faces if f.get("role") == "Customer"]
                return True, False, f"Dual Authorization Verified ({emp_names[0]} & {cust_names[0]})"
            elif has_employee:
                emp_names = [f["name"] for f in detected_faces if f.get("role") == "Employee"]
                return False, False, f"Employee {emp_names[0]} verified. Waiting for Customer"
            elif has_customer:
                cust_names = [f["name"] for f in detected_faces if f.get("role") == "Customer"]
                return False, False, f"Customer {cust_names[0]} verified. Waiting for Employee"
            else:
                return False, False, "Waiting for Employee & Customer"
