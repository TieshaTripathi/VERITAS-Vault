"""Dashboard state regressions, isolated from alerts, evidence, and cloud writes."""
import io
import sys
import time
from pathlib import Path
from unittest.mock import Mock

import cv2
import numpy as np
import pytest
from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"


@pytest.fixture
def dashboard(monkeypatch):
    # AppTest creates a new Streamlit runtime/registry for each fixture.
    monkeypatch.delitem(sys.modules, "dashboard.ui_components", raising=False)
    from src.storage import db, cloud_db
    from src.daemon import alerts
    from src.diagnostics import boot
    from src.blockchain import crypto_utils

    mocks = {}
    for module, name, value in [
        (db, "get_all_users", []), (db, "get_recent_logs", []),
        (db, "log_access_event", True),
        (cloud_db, "init_supabase_client", None),
        (cloud_db, "sync_audit_log_to_cloud", None),
        (cloud_db, "upload_evidence_to_cloud", None),
        (cloud_db, "is_cloud_online", False),
        (cloud_db, "get_cloud_status_label", "LOCAL BUFFER"),
        (alerts, "send_sms_alert", None), (alerts, "load_security_config", {}),
        (boot, "run_system_diagnostics", {"checks": []}),
        (crypto_utils, "encrypt_frame_aes_gcm", ("hash", "")),
    ]:
        mocks[name] = Mock(return_value=value)
        monkeypatch.setattr(module, name, mocks[name])
    app = AppTest.from_file(str(APP), default_timeout=15)
    for key, value in dict(authenticated=True, username="test", user_role="Operator", user_id="test").items():
        app.session_state[key] = value
    app.run()
    assert not app.exception
    return app, mocks


def click(app, label):
    next(button for button in app.button if label in button.label).click().run()
    assert not app.exception


def test_simulation_states_and_timeout(dashboard):
    app, mocks = dashboard
    assert app.session_state.ui_policy_result["status"] == "STANDBY"
    click(app, "Simulate Valid Dual Access")
    assert app.session_state.ui_policy_result["status"] == "GRANTED"
    assert len(app.session_state.ui_verified_parties) == 2
    event = app.session_state.sound_event
    app.run()
    assert app.session_state.sound_event == event
    click(app, "Simulate Party 1")
    assert app.session_state.ui_policy_result["status"] == "WAITING"
    app.session_state.policy_timer_start = time.time() - 5.1
    app.run()
    assert app.session_state.ui_policy_result["status"] == "BREACH"
    app.run()
    assert app.session_state.ui_policy_result["status"] == "BREACH"
    click(app, "Spoof Attack")
    assert app.session_state.ui_policy_result["status"] == "BREACH"
    click(app, "Simulate Unauthorized Intruder")
    assert app.session_state.ui_policy_result["status"] == "BREACH"
    app.radio[0].set_value("High-Value Inventory Audit").run()
    click(app, "Simulate Valid Dual Access")
    assert app.session_state.ui_policy_result["status"] == "GRANTED"
    assert all(party["role"] == "Employee" for party in app.session_state.ui_verified_parties.values())
    click(app, "Reset Live Simulation")
    assert app.session_state.ui_policy_result["status"] == "STANDBY"
    mocks["send_sms_alert"].assert_not_called()
    mocks["sync_audit_log_to_cloud"].assert_not_called()
    mocks["log_access_event"].assert_not_called()


def test_capture_reruns_do_not_duplicate_ingestion_or_audit(dashboard, monkeypatch):
    import streamlit as st
    from src.vision import biometrics
    app, mocks = dashboard
    _, encoded = cv2.imencode(".jpg", np.full((64, 64, 3), 120, dtype=np.uint8))
    monkeypatch.setattr(st, "camera_input", lambda *args, **kwargs: io.BytesIO(encoded.tobytes()))
    monkeypatch.setattr(biometrics, "recognize_faces", lambda frame: [
        {"name": "Alice", "role": "Employee", "is_recognized": True, "is_live": True, "liveness": .97},
        {"name": "John", "role": "Customer", "is_recognized": True, "is_live": True, "liveness": .97},
    ])
    app.run()
    assert not app.exception
    assert app.session_state.ui_policy_result["status"] == "GRANTED"
    assert app.session_state.total_scans_today == 1
    for _ in range(2):
        app.run()
        assert not app.exception
    assert app.session_state.total_scans_today == 1
    assert app.session_state.liveness_total_count == 1
    mocks["log_access_event"].assert_called_once()
    mocks["encrypt_frame_aes_gcm"].assert_called_once()


def test_ledger_handles_untrusted_text(dashboard):
    app, mocks = dashboard
    mocks["get_recent_logs"].return_value = [{
        "timestamp": "2026-09-25 12:00:00", "mode": "Standard",
        "verified_parties": "<script>alert(1)</script>", "verdict": "ACCESS GRANTED",
        "sha256_hash": "a" * 64, "status": "LOCAL_VERIFIED",
    }]
    app.run()
    assert not app.exception
    next(w for w in app.selectbox if w.label == "Verdict").select("BREACH").run()
    assert not app.exception
    assert any("No events match" in message.value for message in app.info)
