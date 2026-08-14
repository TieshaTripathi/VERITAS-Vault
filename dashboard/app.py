import streamlit as st
import numpy as np
import cv2
import hashlib
import os
import time
from datetime import datetime
import yaml
from PIL import Image

# Page Config - High Security Dark Theme Command Center
st.set_page_config(
    page_title="Vault Surveillance Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom High-Tech Dark Mode CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Inter:wght@300;400;600;700&display=swap');

    /* Global Dark Theme Overrides */
    .stApp {
        background-color: #070A11;
        color: #E2E8F0;
        font-family: 'Inter', sans-serif;
    }

    /* Main Container Padding */
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        max-width: 96%;
    }

    /* Command Center Header */
    .header-box {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(10, 15, 29, 0.95) 100%);
        border: 1px solid rgba(0, 240, 255, 0.25);
        border-radius: 10px;
        padding: 18px 24px;
        margin-bottom: 20px;
        box-shadow: 0 8px 32px 0 rgba(0, 240, 255, 0.08);
        backdrop-filter: blur(10px);
    }
    
    .header-title {
        font-family: 'Share Tech Mono', monospace;
        font-size: 26px;
        font-weight: 700;
        color: #00F0FF;
        letter-spacing: 1.5px;
        margin: 0;
        text-transform: uppercase;
        text-shadow: 0 0 10px rgba(0, 240, 255, 0.4);
    }

    /* Status Tags */
    .status-tag {
        display: inline-block;
        font-family: 'Share Tech Mono', monospace;
        font-size: 11px;
        font-weight: 600;
        padding: 4px 10px;
        border-radius: 4px;
        margin-right: 8px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .tag-operational {
        background: rgba(0, 255, 102, 0.12);
        color: #00FF66;
        border: 1px solid rgba(0, 255, 102, 0.4);
    }

    .tag-zerotrust {
        background: rgba(0, 240, 255, 0.12);
        color: #00F0FF;
        border: 1px solid rgba(0, 240, 255, 0.4);
    }

    .tag-blockchain {
        background: rgba(168, 85, 247, 0.12);
        color: #C084FC;
        border: 1px solid rgba(168, 85, 247, 0.4);
    }

    .tag-threat {
        background: rgba(255, 0, 85, 0.15);
        color: #FF0055;
        border: 1px solid rgba(255, 0, 85, 0.5);
    }

    /* Metric Cards */
    .metric-card {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.8) 0%, rgba(20, 30, 50, 0.8) 100%);
        border: 1px solid rgba(0, 240, 255, 0.15);
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
        box-shadow: 0 4px 16px rgba(0,0,0,0.4);
    }

    .metric-label {
        font-size: 12px;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-family: 'Share Tech Mono', monospace;
    }

    .metric-value {
        font-size: 24px;
        font-weight: 700;
        color: #F8FAFC;
        margin-top: 4px;
        font-family: 'Share Tech Mono', monospace;
    }

    .metric-sub {
        font-size: 11px;
        margin-top: 4px;
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #0B0F19;
        border-right: 1px solid rgba(0, 240, 255, 0.15);
    }

    /* Custom Streamlit Buttons */
    .stButton>button {
        width: 100%;
        border-radius: 6px;
        font-family: 'Share Tech Mono', monospace;
        font-weight: 600;
        letter-spacing: 0.5px;
        transition: all 0.3s ease;
    }

    /* Section Headers */
    .section-header {
        font-family: 'Share Tech Mono', monospace;
        font-size: 16px;
        color: #00F0FF;
        border-bottom: 1px solid rgba(0, 240, 255, 0.2);
        padding-bottom: 6px;
        margin-bottom: 14px;
        letter-spacing: 1px;
        text-transform: uppercase;
    }
</style>
""", unsafe_allow_html=True)

# Load Configuration if available
def load_config():
    config_path = os.path.join("config", "settings.yaml")
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    return {
        "camera_id": 0,
        "liveness_threshold": 0.85,
        "two_man_window_seconds": 5,
        "blockchain_rpc": "http://127.0.0.1:8545"
    }

config = load_config()

# Initialize Session State
if "audit_logs" not in st.session_state:
    st.session_state.audit_logs = [
        {
            "Event ID": "EVT-9041",
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Event Type": "SYSTEM_INITIALIZED",
            "SHA-256 Frame Hash": hashlib.sha256(b"init_frame_0").hexdigest()[:16] + "...",
            "AES Encrypted Blob ID": "BLOB-88401-A",
            "Blockchain Tx Hash": "0x3f8a92..." + hashlib.sha256(b"tx_0").hexdigest()[:10],
            "Status": "NOTARIZED"
        }
    ]

if "biometric_state" not in st.session_state:
    st.session_state.biometric_state = {
        "mode": "Standard Locker Access",
        "status": "NORMAL",
        "liveness_score": 0.98,
        "identified_roles": ["Vault Officer #804 (Senior Guard)"],
        "two_man_status": "PASSED (1/1 Required)",
        "alert": None,
        "active_sessions": 1,
        "verification_timer": "0.4s / 5.0s",
        "daemon_status": "SYNCED [Block #19482910]"
    }

# Function to generate high-tech synthetic feed frame
def generate_synthetic_frame(state):
    width, height = 720, 480
    img = np.zeros((height, width, 3), dtype=np.uint8)
    
    # Create dark grid surveillance background
    grid_size = 40
    for x in range(0, width, grid_size):
        cv2.line(img, (x, 0), (x, height), (15, 25, 40), 1)
    for y in range(0, height, grid_size):
        cv2.line(img, (0, y), (width, y), (15, 25, 40), 1)

    # Outer CCTV Frame & Corner Reticles
    cv2.rectangle(img, (10, 10), (width - 10, height - 10), (0, 240, 255), 1)
    reticle_len = 20
    # Top-Left
    cv2.line(img, (10, 10), (10 + reticle_len, 10), (0, 240, 255), 3)
    cv2.line(img, (10, 10), (10, 10 + reticle_len), (0, 240, 255), 3)
    # Top-Right
    cv2.line(img, (width - 10, 10), (width - 10 - reticle_len, 10), (0, 240, 255), 3)
    cv2.line(img, (width - 10, 10), (width - 10, 10 + reticle_len), (0, 240, 255), 3)
    # Bottom-Left
    cv2.line(img, (10, height - 10), (10 + reticle_len, height - 10), (0, 240, 255), 3)
    cv2.line(img, (10, height - 10), (10, height - 10 - reticle_len), (0, 240, 255), 3)
    # Bottom-Right
    cv2.line(img, (width - 10, height - 10), (width - 10 - reticle_len, height - 10), (0, 240, 255), 3)
    cv2.line(img, (width - 10, height - 10), (width - 10, height - 10 - reticle_len), (0, 240, 255), 3)

    # Telemetry Overlays
    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    cv2.putText(img, f"CAM-01 [VAULT-ALPHA] | {current_time_str} | 30 FPS", (20, 35), 
                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 240, 255), 1, cv2.LINE_AA)
    
    # Rec indicator
    cv2.circle(img, (width - 30, 30), 6, (0, 0, 255), -1)
    cv2.putText(img, "REC", (width - 65, 34), cv2.FONT_HERSHEY_SIMPLEX, 0.4, (255, 255, 255), 1, cv2.LINE_AA)

    status_type = state["status"]
    
    if status_type == "NORMAL" or status_type == "VALID_ACCESS":
        # Draw 1 or 2 verified face boxes
        if "High-Value" in state["mode"]:
            # Officer 1
            cv2.rectangle(img, (160, 120), (320, 340), (0, 255, 102), 2)
            cv2.circle(img, (240, 200), 40, (0, 255, 102), 1)
            cv2.putText(img, "OFFICER #804 [SENIOR]", (150, 110), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 102), 1)
            cv2.putText(img, "LIVENESS: 98.6%", (150, 360), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 102), 1)

            # Officer 2
            cv2.rectangle(img, (400, 120), (560, 340), (0, 255, 102), 2)
            cv2.circle(img, (480, 200), 40, (0, 255, 102), 1)
            cv2.putText(img, "OFFICER #412 [JUNIOR]", (390, 110), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 102), 1)
            cv2.putText(img, "LIVENESS: 96.4%", (390, 360), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 102), 1)

            # Access Badge
            cv2.rectangle(img, (220, 410), (500, 450), (0, 255, 102), -1)
            cv2.putText(img, "TWO-MAN AUTHENTICATED - VAULT UNLOCKED", (230, 435), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 0, 0), 2)
        else:
            # Single officer
            cv2.rectangle(img, (270, 120), (450, 340), (0, 255, 102), 2)
            cv2.circle(img, (360, 200), 50, (0, 255, 102), 1)
            cv2.putText(img, "OFFICER #804 [SENIOR]", (270, 110), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 102), 1)
            cv2.putText(img, f"LIVENESS: {int(state['liveness_score']*100)}%", (270, 360), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 102), 1)
            
            # Access Granted
            cv2.rectangle(img, (240, 410), (480, 450), (0, 255, 102), -1)
            cv2.putText(img, "ACCESS GRANTED - SINGLE LOCKER", (250, 435), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 0, 0), 2)

    elif status_type == "TWO_MAN_BREACH":
        # Only 1 officer present in High Value mode
        cv2.rectangle(img, (270, 120), (450, 340), (0, 0, 255), 2)
        cv2.circle(img, (360, 200), 50, (0, 0, 255), 1)
        cv2.putText(img, "OFFICER #804 ONLY", (270, 110), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 0, 255), 1)
        cv2.putText(img, "MISSING 2ND AUTHORIZED OFFICER", (240, 360), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 0, 255), 1)

        # Alarm Banner
        cv2.rectangle(img, (120, 400), (600, 450), (0, 0, 255), -1)
        cv2.putText(img, "ALERT: TWO-MAN RULE VIOLATION DETECTED!", (140, 432), 
                    cv2.FONT_HERSHEY_SIMPLEX, 0.55, (255, 255, 255), 2)

    elif status_type == "SPOOF_ATTEMPT":
        # Fake face detected (low liveness score)
        cv2.rectangle(img, (270, 120), (450, 340), (255, 0, 85), 2)
        cv2.line(img, (270, 120), (450, 340), (255, 0, 85), 2)
        cv2.line(img, (450, 120), (270, 340), (255, 0, 85), 2)
        cv2.putText(img, "UNKNOWN / 2D PRINTOUT", (260, 110), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (255, 0, 85), 1)
        cv2.putText(img, f"LIVENESS: {int(state['liveness_score']*100)}% (REQ >= 85%)", (220, 360), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (255, 0, 85), 1)

        # Alarm Banner
        cv2.rectangle(img, (140, 400), (580, 450), (255, 0, 85), -1)
        cv2.putText(img, "CRITICAL: BIOMETRIC SPOOFING REJECTED", (160, 432), 
                    cv2.FONT_HERSHEY_SIMPLEX, 0.55, (255, 255, 255), 2)

    return img

# --- HEADER SECTION ---
st.markdown("""
<div class="header-box">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <h1 class="header-title">🛡️ Zero-Trust Edge-AI & Blockchain Vault Command Center</h1>
            <div style="margin-top: 10px;">
                <span class="status-tag tag-operational">● SYSTEM ONLINE</span>
                <span class="status-tag tag-zerotrust">🔒 ZERO-TRUST POLICY ACTIVE</span>
                <span class="status-tag tag-blockchain">🔗 ETHEREUM L2 ANCHORED</span>
                <span class="status-tag tag-operational">📷 CAM-01 ONLINE</span>
            </div>
        </div>
        <div style="text-align: right; font-family: 'Share Tech Mono', monospace; font-size: 13px; color: #00F0FF;">
            <div>NODE ID: <b>EDGE-VAULT-01</b></div>
            <div>LATENCY: <b>4.2ms</b></div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# --- SIDEBAR CONTROLS ---
with st.sidebar:
    st.markdown('<div class="section-header">⚙️ Vault Policy Configuration</div>', unsafe_allow_html=True)
    
    vault_mode = st.radio(
        "Select Vault Access Policy:",
        ["Standard Locker Access", "High-Value Inventory Audit"],
        index=0 if st.session_state.biometric_state["mode"] == "Standard Locker Access" else 1,
        help="High-Value Inventory Audit strictly enforces the two-man authentication policy."
    )
    
    # Sync mode state
    if vault_mode != st.session_state.biometric_state["mode"]:
        st.session_state.biometric_state["mode"] = vault_mode
        if vault_mode == "High-Value Inventory Audit":
            st.session_state.biometric_state["two_man_status"] = "REQUIRED (2 Officers Needed)"
        else:
            st.session_state.biometric_state["two_man_status"] = "N/A (Standard Access)"
    
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="section-header">🧪 Threat Simulation Panel</div>', unsafe_allow_html=True)
    st.caption("Trigger real-time edge AI biometric policy evaluations:")

    # Simulation Button 1: Valid Officer Access
    if st.button("🟢 Simulate Valid Officer Access", type="primary", use_container_width=True):
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        evt_id = f"EVT-{np.random.randint(1000, 9999)}"
        frame_hash = hashlib.sha256(f"valid_{time.time()}".encode()).hexdigest()
        tx_hash = "0x" + hashlib.sha256(f"tx_{time.time()}".encode()).hexdigest()[:40]
        
        if vault_mode == "High-Value Inventory Audit":
            st.session_state.biometric_state.update({
                "status": "VALID_ACCESS",
                "liveness_score": 0.98,
                "identified_roles": ["Officer #804 (Senior)", "Officer #412 (Junior)"],
                "two_man_status": "PASSED (2/2 Verified)",
                "active_sessions": 2,
                "verification_timer": "1.2s / 5.0s"
            })
            evt_type = "AUTH_TWO_MAN_GRANTED"
        else:
            st.session_state.biometric_state.update({
                "status": "VALID_ACCESS",
                "liveness_score": 0.97,
                "identified_roles": ["Officer #804 (Senior Guard)"],
                "two_man_status": "PASSED (1/1 Required)",
                "active_sessions": 1,
                "verification_timer": "0.6s / 5.0s"
            })
            evt_type = "AUTH_SINGLE_OFFICER_GRANTED"

        st.session_state.audit_logs.insert(0, {
            "Event ID": evt_id,
            "Timestamp": now_str,
            "Event Type": evt_type,
            "SHA-256 Frame Hash": frame_hash[:16] + "...",
            "AES Encrypted Blob ID": f"BLOB-{np.random.randint(10000, 99999)}-OK",
            "Blockchain Tx Hash": tx_hash[:16] + "...",
            "Status": "NOTARIZED"
        })

    # Simulation Button 2: Two-Man Rule Breach
    if st.button("🔴 Simulate Two-Man Rule Breach", use_container_width=True):
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        evt_id = f"EVT-{np.random.randint(1000, 9999)}"
        frame_hash = hashlib.sha256(f"breach_{time.time()}".encode()).hexdigest()
        tx_hash = "0x" + hashlib.sha256(f"tx_{time.time()}".encode()).hexdigest()[:40]
        
        st.session_state.biometric_state.update({
            "status": "TWO_MAN_BREACH",
            "liveness_score": 0.96,
            "identified_roles": ["Officer #804 (Senior) - Single"],
            "two_man_status": "FAILED (1/2 Present - Breach!)",
            "active_sessions": 1,
            "verification_timer": "TIMEOUT (5.0s Exceeded)"
        })

        st.session_state.audit_logs.insert(0, {
            "Event ID": evt_id,
            "Timestamp": now_str,
            "Event Type": "ALERT_TWO_MAN_RULE_BREACH",
            "SHA-256 Frame Hash": frame_hash[:16] + "...",
            "AES Encrypted Blob ID": f"BLOB-{np.random.randint(10000, 99999)}-ALERT",
            "Blockchain Tx Hash": tx_hash[:16] + "...",
            "Status": "NOTARIZED"
        })

    # Simulation Button 3: Liveness Spoofing Attempt
    if st.button("⚠️ Simulate Liveness Spoofing Attempt", use_container_width=True):
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        evt_id = f"EVT-{np.random.randint(1000, 9999)}"
        frame_hash = hashlib.sha256(f"spoof_{time.time()}".encode()).hexdigest()
        tx_hash = "0x" + hashlib.sha256(f"tx_{time.time()}".encode()).hexdigest()[:40]
        
        st.session_state.biometric_state.update({
            "status": "SPOOF_ATTEMPT",
            "liveness_score": 0.23,
            "identified_roles": ["UNAUTHORIZED (2D Photo Printout)"],
            "two_man_status": "REJECTED (Liveness Failed)",
            "active_sessions": 0,
            "verification_timer": "0.1s REJECTED"
        })

        st.session_state.audit_logs.insert(0, {
            "Event ID": evt_id,
            "Timestamp": now_str,
            "Event Type": "ALERT_SPOOFING_REJECTED",
            "SHA-256 Frame Hash": frame_hash[:16] + "...",
            "AES Encrypted Blob ID": f"BLOB-{np.random.randint(10000, 99999)}-REJECT",
            "Blockchain Tx Hash": tx_hash[:16] + "...",
            "Status": "NOTARIZED"
        })

    st.markdown("<br><hr style='border-color: rgba(0,240,255,0.15);'><br>", unsafe_allow_html=True)
    st.markdown('<div class="section-header">⚙️ System Parameters</div>', unsafe_allow_html=True)
    st.json(config)

# --- MAIN LAYOUT GRID ---
col_left, col_right = st.columns([1.6, 1.0], gap="medium")

with col_left:
    st.markdown('<div class="section-header">📷 Live Biometric Surveillance Feed</div>', unsafe_allow_html=True)
    
    # Generate and display synthetic video frame
    frame_np = generate_synthetic_frame(st.session_state.biometric_state)
    frame_pil = Image.fromarray(cv2.cvtColor(frame_np, cv2.COLOR_BGR2RGB))
    st.image(frame_pil, use_container_width=True)

    # Real-time biometric state badges under the video
    bstate = st.session_state.biometric_state
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"**Liveness Score:** `{int(bstate['liveness_score']*100)}%` (Threshold: 85%)")
    with c2:
        roles_str = ", ".join(bstate['identified_roles'])
        st.markdown(f"**Identified Role:** `{roles_str}`")
    with c3:
        status_color = "green" if "PASSED" in bstate['two_man_status'] else "red"
        st.markdown(f"**Two-Man Rule:** :{status_color}[`{bstate['two_man_status']}`]")

with col_right:
    st.markdown('<div class="section-header">📊 Security Telemetry & Metrics</div>', unsafe_allow_html=True)
    
    # Metric 1: Active Sessions
    sessions = bstate["active_sessions"]
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Active Authenticated Sessions</div>
        <div class="metric-value">{sessions} OFFICERS</div>
        <div class="metric-sub" style="color: #00FF66;">● Real-time Biometric Tracking</div>
    </div>
    """, unsafe_allow_html=True)

    # Metric 2: Liveness Confidence
    liv_val = f"{int(bstate['liveness_score'] * 100)}%"
    liv_color = "#00FF66" if bstate['liveness_score'] >= 0.85 else "#FF0055"
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Liveness Confidence Score</div>
        <div class="metric-value" style="color: {liv_color};">{liv_val}</div>
        <div class="metric-sub" style="color: #94A3B8;">Target Threshold >= 85.0%</div>
    </div>
    """, unsafe_allow_html=True)

    # Metric 3: Verification Window Timer
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Two-Man Verification Window</div>
        <div class="metric-value">{bstate['verification_timer']}</div>
        <div class="metric-sub" style="color: #00F0FF;">Max Window: {config['two_man_window_seconds']} Seconds</div>
    </div>
    """, unsafe_allow_html=True)

    # Metric 4: Heartbeat Daemon Status
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Blockchain Heartbeat Daemon</div>
        <div class="metric-value" style="font-size: 16px; color: #C084FC;">{bstate['daemon_status']}</div>
        <div class="metric-sub" style="color: #94A3B8;">RPC: {config['blockchain_rpc']}</div>
    </div>
    """, unsafe_allow_html=True)

# --- BOTTOM PANEL: INTERACTIVE AUDIT TRAIL TABLE ---
st.markdown("<br>", unsafe_allow_html=True)
st.markdown('<div class="section-header">📜 Immutable Blockchain Audit Trail (Notarized Event Log)</div>', unsafe_allow_html=True)

import pandas as pd
df_audit = pd.DataFrame(st.session_state.audit_logs)

st.dataframe(
    df_audit,
    use_container_width=True,
    hide_index=True,
    column_config={
        "Event ID": st.column_config.TextColumn("Event ID", width="small"),
        "Timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
        "Event Type": st.column_config.TextColumn("Event Type", width="medium"),
        "SHA-256 Frame Hash": st.column_config.TextColumn("SHA-256 Frame Hash", width="large"),
        "AES Encrypted Blob ID": st.column_config.TextColumn("AES Encrypted Blob ID", width="medium"),
        "Blockchain Tx Hash": st.column_config.TextColumn("Blockchain Tx Hash", width="large"),
        "Status": st.column_config.TextColumn("Status", width="small")
    }
)
