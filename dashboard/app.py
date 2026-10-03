import streamlit as st
st.set_page_config(
    page_title="VERITAS-VAULT | Zero-Trust Physical Access Control System",
    page_icon="\U0001f6e1\ufe0f",
    layout="wide",
    initial_sidebar_state="expanded",
)

import sys
import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import numpy as np
import cv2
import time
from datetime import datetime
import threading
import hashlib
import json
from html import escape

from dashboard.ui_components import audit_ledger, countdown, metric_tile, play_sound

from src.storage.db import (
    db_instance, get_all_users, delete_user, get_recent_logs, log_access_event,
)
from src.storage.cloud_db import (
    init_supabase_client, get_cloud_status_label, is_cloud_online,
    sync_user_to_cloud, upload_evidence_to_cloud, sync_audit_log_to_cloud,
)
from src.blockchain.crypto_utils import compute_raw_frame_hash, encrypt_frame_aes_gcm
from src.vision.liveness import estimate_liveness
from src.vision.biometrics import enroll_face, recognize_faces, FaceRecognizerPipeline, default_face_recognizer, _get_cascade_classifier
from src.vision.auto_capture import (
    is_face_stable, AutoCaptureEngine, default_auto_capture,
    FaceStabilityTracker, draw_cyan_target_brackets, draw_hud_overlay,
    HUD_SCANNING, HUD_FIXATING, HUD_VERIFYING, HUD_GRANTED, HUD_BREACH
)
from src.daemon.alerts import (
    send_sms_alert, test_sms_alert, load_security_config, save_security_config,
)
from src.policy.engine import evaluate_access, TwoManPolicyEngine, PolicyState
from src.diagnostics.boot import run_system_diagnostics

# ============================================================
# COMMERCIAL-GRADE SAAS CSS — Cyber Carbon Theme
# ============================================================
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Inter:wght@300;400;500;600;700;800;900&display=swap');

  /* ---- Base ---- */
  .stApp {
    background: linear-gradient(160deg, #0b0f19 0%, #0d1424 40%, #111827 100%);
    color: #E2E8F0;
    font-family: 'Inter', sans-serif;
  }
  .block-container { padding-top: 0.4rem; padding-bottom: 2rem; max-width: 98%; }

  /* ---- Keyframes ---- */
  @keyframes pulse-green {
    0%  { box-shadow: 0 0 0 0 rgba(16,185,129,.5); }
    70% { box-shadow: 0 0 0 18px rgba(16,185,129,0); }
    100%{ box-shadow: 0 0 0 0 rgba(16,185,129,0); }
  }
  @keyframes pulse-red {
    0%  { box-shadow: 0 0 0 0 rgba(239,68,68,.6); }
    70% { box-shadow: 0 0 0 22px rgba(239,68,68,0); }
    100%{ box-shadow: 0 0 0 0 rgba(239,68,68,0); }
  }
  @keyframes pulse-cyan {
    0%  { box-shadow: 0 0 0 0 rgba(0,240,255,.4); }
    70% { box-shadow: 0 0 0 16px rgba(0,240,255,0); }
    100%{ box-shadow: 0 0 0 0 rgba(0,240,255,0); }
  }
  @keyframes pulse-amber {
    0%  { box-shadow: 0 0 0 0 rgba(245,158,11,.4); }
    70% { box-shadow: 0 0 0 16px rgba(245,158,11,0); }
    100%{ box-shadow: 0 0 0 0 rgba(245,158,11,0); }
  }
  @keyframes fadeInDown {
    from { opacity: 0; transform: translateY(-10px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @keyframes shimmer {
    0%   { background-position: -200% center; }
    100% { background-position: 200% center; }
  }
  @keyframes spin-ring {
    to { transform: rotate(360deg); }
  }
  @keyframes tick {
    0%, 49% { opacity: 1; }
    50%, 100%{ opacity: 0; }
  }

  /* ---- Top Nav Bar ---- */
  .top-nav {
    background: rgba(11,15,25,.92);
    backdrop-filter: blur(20px);
    border-bottom: 1px solid rgba(0,240,255,.18);
    border-radius: 14px;
    padding: 12px 22px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 18px;
    animation: fadeInDown .5s ease;
    box-shadow: 0 4px 32px rgba(0,0,0,.45);
  }
  .nav-brand {
    font-family: 'Share Tech Mono', monospace;
    font-size: 15px;
    font-weight: 700;
    color: #00F0FF;
    letter-spacing: 1.4px;
    text-shadow: 0 0 14px rgba(0,240,255,.6);
  }
  .nav-brand span { color: #94A3B8; font-size: 11px; display: block;
                    letter-spacing: 2px; margin-top: 2px; }
  .nav-status-group { display: flex; gap: 14px; align-items: center; }
  .status-pill {
    display: inline-flex; align-items: center; gap: 7px;
    padding: 5px 13px; border-radius: 20px;
    font-family: 'Share Tech Mono', monospace; font-size: 11px;
    font-weight: 600; letter-spacing: 1px;
  }
  .pill-green  { background: rgba(16,185,129,.15); border: 1px solid #10B981;
                 color: #10B981; animation: pulse-green 2.5s infinite; }
  .pill-cyan   { background: rgba(0,240,255,.10); border: 1px solid rgba(0,240,255,.5);
                 color: #00F0FF; animation: pulse-cyan 3s infinite; }
  .pill-amber  { background: rgba(245,158,11,.12); border: 1px solid #F59E0B;
                 color: #F59E0B; }
  .pill-dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
  .nav-clock {
    font-family: 'Share Tech Mono', monospace; font-size: 13px;
    color: #CBD5E1; letter-spacing: 1px;
  }

  /* ---- State Banners ---- */
  .banner-unlocked {
    background: linear-gradient(135deg,rgba(16,185,129,.22) 0%,rgba(11,15,25,.97) 100%);
    backdrop-filter: blur(14px);
    border: 2px solid #10B981; color: #10B981;
    padding: 18px 24px; border-radius: 14px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 18px; font-weight: 700; text-align: center;
    letter-spacing: 2px; margin-bottom: 16px;
    box-shadow: 0 8px 40px rgba(16,185,129,.3), inset 0 1px 0 rgba(16,185,129,.2);
    animation: pulse-green 2s infinite;
  }
  .banner-waiting {
    background: linear-gradient(135deg,rgba(245,158,11,.20) 0%,rgba(11,15,25,.97) 100%);
    backdrop-filter: blur(14px);
    border: 2px solid #F59E0B; color: #F59E0B;
    padding: 18px 24px; border-radius: 14px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 18px; font-weight: 700; text-align: center;
    letter-spacing: 2px; margin-bottom: 16px;
    box-shadow: 0 8px 40px rgba(245,158,11,.25);
    animation: pulse-amber 2.5s infinite;
  }
  .banner-breach {
    background: linear-gradient(135deg,rgba(239,68,68,.28) 0%,rgba(11,15,25,.97) 100%);
    backdrop-filter: blur(14px);
    border: 2px solid #EF4444; color: #EF4444;
    padding: 18px 24px; border-radius: 14px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 18px; font-weight: 700; text-align: center;
    letter-spacing: 2px; margin-bottom: 16px;
    box-shadow: 0 8px 40px rgba(239,68,68,.4), inset 0 1px 0 rgba(239,68,68,.2);
    animation: pulse-red 1.2s infinite;
  }
  .banner-standby {
    background: linear-gradient(135deg,rgba(0,240,255,.08) 0%,rgba(11,15,25,.97) 100%);
    backdrop-filter: blur(14px);
    border: 2px solid rgba(0,240,255,.45); color: #00F0FF;
    padding: 18px 24px; border-radius: 14px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 18px; font-weight: 700; text-align: center;
    letter-spacing: 2px; margin-bottom: 16px;
    animation: pulse-cyan 3.5s infinite;
  }

  /* ---- Glassmorphism Cards ---- */
  .glass-card {
    background: rgba(15,23,42,.75);
    backdrop-filter: blur(18px);
    border: 1px solid rgba(0,240,255,.18);
    border-radius: 14px; padding: 20px 22px; margin-bottom: 14px;
    box-shadow: 0 8px 32px rgba(0,0,0,.55), inset 0 1px 0 rgba(255,255,255,.04);
    transition: transform .22s ease, border-color .22s ease, box-shadow .22s ease;
  }
  .glass-card:hover {
    border-color: rgba(0,240,255,.55);
    transform: translateY(-3px);
    box-shadow: 0 14px 44px rgba(0,0,0,.65), 0 0 22px rgba(0,240,255,.12);
  }
  .card-label {
    font-size: 10px; color: #64748B; text-transform: uppercase;
    font-family: 'Share Tech Mono', monospace; letter-spacing: 2px; margin-bottom: 6px;
  }
  .card-value {
    font-size: 26px; font-weight: 800; color: #F8FAFC;
    font-family: 'Share Tech Mono', monospace; line-height: 1.1;
  }
  .card-sub { font-size: 11px; margin-top: 6px; color: #475569; }

  /* ---- Metric Grid Cards ---- */
  .metric-card {
    background: rgba(15,23,42,.8);
    backdrop-filter: blur(16px);
    border: 1px solid rgba(0,240,255,.14);
    border-radius: 12px; padding: 16px 18px;
    box-shadow: 0 4px 20px rgba(0,0,0,.5);
    transition: transform .2s ease, border-color .2s ease;
    text-align: center;
  }
  .metric-card:hover {
    border-color: rgba(0,240,255,.4); transform: translateY(-2px);
  }
  .metric-icon { font-size: 22px; margin-bottom: 6px; }
  .metric-num  { font-family: 'Share Tech Mono', monospace; font-size: 28px;
                 font-weight: 800; color: #F8FAFC; }
  .metric-lbl  { font-size: 10px; color: #64748B; text-transform: uppercase;
                 letter-spacing: 1.5px; margin-top: 4px; font-family: 'Share Tech Mono', monospace; }

  /* ---- Verification Party Cards ---- */
  .party-card {
    background: rgba(15,23,42,.82);
    backdrop-filter: blur(18px);
    border-radius: 14px; padding: 18px;
    box-shadow: 0 6px 28px rgba(0,0,0,.5);
    transition: all .25s ease;
    position: relative; overflow: hidden;
  }
  .party-card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, currentColor, transparent);
    opacity: .6;
  }
  .party-card-waiting { border: 1px solid rgba(245,158,11,.4); color: #F59E0B; }
  .party-card-granted { border: 1px solid rgba(16,185,129,.5); color: #10B981; }
  .party-card-breach  { border: 1px solid rgba(239,68,68,.5);  color: #EF4444; }
  .party-card-empty   { border: 1px dashed rgba(0,240,255,.25); color: #334155; }
  .party-slot-label {
    font-family: 'Share Tech Mono', monospace; font-size: 9px;
    letter-spacing: 2px; text-transform: uppercase; opacity: .7; margin-bottom: 8px;
  }
  .party-avatar {
    width: 52px; height: 52px; border-radius: 50%;
    background: rgba(0,240,255,.08); border: 2px solid rgba(0,240,255,.25);
    display: inline-flex; align-items: center; justify-content: center;
    font-size: 22px; margin-bottom: 8px;
  }
  .party-name {
    font-family: 'Inter', sans-serif; font-weight: 700; font-size: 14px;
    color: #F1F5F9; margin-bottom: 3px;
  }
  .party-role-badge {
    display: inline-block; padding: 2px 9px; border-radius: 4px;
    font-family: 'Share Tech Mono', monospace; font-size: 10px; font-weight: 600;
    letter-spacing: 1px;
  }
  .role-emp  { background: rgba(0,240,255,.12); border: 1px solid rgba(0,240,255,.5); color: #00F0FF; }
  .role-cust { background: rgba(245,158,11,.12); border: 1px solid rgba(245,158,11,.5); color: #F59E0B; }
  .party-check {
    position: absolute; top: 14px; right: 14px;
    width: 22px; height: 22px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 12px;
  }
  .check-ok     { background: rgba(16,185,129,.2); border: 1.5px solid #10B981; }
  .check-wait   { background: rgba(245,158,11,.15); border: 1.5px solid #F59E0B; }
  .check-breach { background: rgba(239,68,68,.15);  border: 1.5px solid #EF4444; }
  .check-empty  { background: rgba(71,85,105,.15);  border: 1.5px dashed #475569; }

  /* ---- Sliding Window Progress Bar ---- */
  .window-bar-wrap {
    background: rgba(15,23,42,.9);
    backdrop-filter: blur(14px);
    border: 1px solid rgba(0,240,255,.2);
    border-radius: 12px; padding: 16px 20px; margin-bottom: 14px;
  }
  .window-bar-track {
    background: rgba(51,65,85,.6); border-radius: 6px; height: 10px;
    overflow: hidden; margin: 10px 0;
  }
  .window-bar-fill {
    height: 100%; border-radius: 6px;
    transition: width .5s ease;
  }
  .window-bar-fill-green  { background: linear-gradient(90deg,#10B981,#34D399); }
  .window-bar-fill-amber  { background: linear-gradient(90deg,#F59E0B,#FCD34D); }
  .window-bar-fill-red    { background: linear-gradient(90deg,#EF4444,#F87171); }
  .window-bar-fill-cyan   { background: linear-gradient(90deg,#00F0FF,#67E8F9); }
  .window-bar-meta {
    display: flex; justify-content: space-between;
    font-family: 'Share Tech Mono', monospace; font-size: 11px; color: #64748B;
  }

  /* ---- Threat Level Gauge ---- */
  .threat-gauge {
    background: rgba(15,23,42,.8);
    backdrop-filter: blur(16px);
    border-radius: 14px; padding: 18px 20px; margin-bottom: 14px;
    text-align: center;
  }
  .threat-gauge-title {
    font-family: 'Share Tech Mono', monospace; font-size: 10px;
    color: #64748B; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 12px;
  }
  .threat-level-indicator {
    font-family: 'Share Tech Mono', monospace; font-size: 22px; font-weight: 900;
    letter-spacing: 2px; margin: 8px 0;
  }
  .threat-low      { color: #10B981; border: 2px solid rgba(16,185,129,.4); }
  .threat-elevated { color: #F59E0B; border: 2px solid rgba(245,158,11,.4);
                     animation: pulse-amber 2s infinite; }
  .threat-critical { color: #EF4444; border: 2px solid rgba(239,68,68,.4);
                     animation: pulse-red 1s infinite; }

  /* ---- Audit Ledger ---- */
  .audit-section-header {
    font-family: 'Share Tech Mono', monospace; font-size: 13px;
    color: #00F0FF; letter-spacing: 1.5px; padding-bottom: 8px;
    border-bottom: 1px solid rgba(0,240,255,.2); margin-bottom: 14px;
  }
  .badge-granted { background: rgba(16,185,129,.15); border: 1px solid #10B981;
                   color: #10B981; padding: 2px 8px; border-radius: 4px;
                   font-family: 'Share Tech Mono', monospace; font-size: 10px; }
  .badge-denied  { background: rgba(239,68,68,.12); border: 1px solid #EF4444;
                   color: #EF4444; padding: 2px 8px; border-radius: 4px;
                   font-family: 'Share Tech Mono', monospace; font-size: 10px; }
  .badge-breach  { background: rgba(239,68,68,.2); border: 1px solid #EF4444;
                   color: #EF4444; padding: 2px 9px; border-radius: 4px;
                   font-family: 'Share Tech Mono', monospace; font-size: 10px; font-weight: 700; }
  .badge-cloud   { background: rgba(0,240,255,.1); border: 1px solid rgba(0,240,255,.5);
                   color: #00F0FF; padding: 2px 7px; border-radius: 4px;
                   font-family: 'Share Tech Mono', monospace; font-size: 10px; }
  .hash-pill {
    background: rgba(71,85,105,.4); border: 1px solid rgba(100,116,139,.4);
    color: #94A3B8; padding: 2px 7px; border-radius: 4px;
    font-family: 'Share Tech Mono', monospace; font-size: 9px;
    cursor: pointer; display: inline-block;
    transition: background .2s ease;
  }
  .hash-pill:hover { background: rgba(0,240,255,.1); color: #00F0FF; }

  /* ---- Sidebar ---- */
  section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #060A12 0%, #080C16 100%);
    border-right: 1px solid rgba(0,240,255,.15);
  }
  section[data-testid="stSidebar"] .block-container { padding-top: 1rem; }

  /* ---- Buttons ---- */
  .stButton > button {
    background: rgba(0,240,255,.06); border: 1px solid rgba(0,240,255,.35);
    color: #00F0FF; border-radius: 9px; font-family: 'Inter', sans-serif;
    font-weight: 500; transition: all .2s ease;
  }
  .stButton > button:hover {
    background: rgba(0,240,255,.14); border-color: #00F0FF;
    box-shadow: 0 0 18px rgba(0,240,255,.3);
    transform: translateY(-1px);
  }

  /* ---- Streamlit overrides ---- */
  .stProgress > div > div > div { background-color: #00F0FF !important; border-radius: 4px; }
  .stDataFrame { border: 1px solid rgba(0,240,255,.18) !important; border-radius: 10px !important; }
  div[data-testid="stMetricValue"] { color: #F8FAFC; }

  /* Command center motion system */
  @keyframes scanline {
    from { top: 0; opacity: 0; }
    8%, 92% { opacity: .85; }
    to { top: 100%; opacity: 0; }
  }
  @keyframes radar-pulse {
    0% { transform: scale(.94); opacity: .45; }
    100% { transform: scale(1.08); opacity: 0; }
  }
  @keyframes corner-snap {
    from { transform: scale(1.25); opacity: 0; }
    to { transform: scale(1); opacity: 1; }
  }
  @keyframes card-hover {
    to { transform: translateY(-5px); box-shadow: 0 10px 25px -5px rgba(0, 240, 255, .25); }
  }
  @keyframes status-slide-in {
    from { opacity: 0; transform: translateY(-10px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .stApp {
    background: radial-gradient(ellipse at 60% 0%, #10304055, transparent 48%),
      linear-gradient(135deg,#070d16,#0b1320 70%,#09131c);
  }
  .block-container { max-width: 1600px; padding-top: 2.5rem; }
  .top-nav { background: #0c1925b3; border:1px solid #1c3447; padding:18px 22px; }
  .nav-brand { font-size:20px; letter-spacing:2px; text-shadow:none; }
  .nav-brand span { font-size:9px; letter-spacing:2px; margin-top:6px; }
  .pill-green, .pill-cyan { animation:none; }
  .nav-clock { font-size:11px; }
  .command-heading { display:flex; justify-content:space-between; align-items:end; margin:10px 0 18px; gap:16px; }
  .command-heading h1 { font:600 30px/1.2 'Inter',sans-serif; letter-spacing:-1px; margin:5px 0 8px; padding:0; }
  .eyebrow { font:10px 'Share Tech Mono',monospace; letter-spacing:2px; color:#00f0ff; }
  .command-heading p { color:#91a6bd; font-size:12px; margin:0; }
  .sector-tag { color:#91a6bd; font:10px/1.8 monospace; text-align:right; }
  .metric-card { text-align:left; padding:18px 20px 12px; background:linear-gradient(130deg,#142337bb,#0c1624dd);
    position:relative; overflow:hidden; border-color:#26384c; min-height:160px; }
  .metric-top { display:flex;justify-content:space-between;color:#9eb1c6;font:10px monospace;letter-spacing:1px; }
  .metric-index { color:#50657d; }
  .metric-num { font-size:26px; margin:14px 0 0; line-height:1.2; }
  .metric-note { color:#8ba0b8; font:10px monospace; }
  .micro-sparkline { display:block; width:100%;height:32px;margin:6px 0;opacity:.85; }
  .sparkline-empty { height:38px;display:flex;align-items:center;color:#6c8098;font:8px monospace;letter-spacing:1px; }
  .metric-card, .glass-card, .party-card { transition: all .3s cubic-bezier(.4,0,.2,1); }
  .metric-card:hover, .glass-card:hover, .party-card:hover {
    transform:translateY(-5px);box-shadow:0 10px 25px -5px rgba(0,240,255,.25);border-color:#00f0ff66;
    animation:card-hover .3s cubic-bezier(.4,0,.2,1) both;
  }
  .glass-card { padding:16px 20px;margin:0 0 12px; }
  .card-label, .card-sub, .metric-lbl, .threat-gauge-title { color:#91a6bd; }
  .card-value { font-size:23px; }
  .party-card { padding:15px 18px; }
  .party-card-empty { color:#91a6bd; }
  .party-avatar { width:36px;height:36px;font-size:16px;float:left;margin:0 12px 0 0; }
  .party-card-waiting::after, .party-card-granted::after {
    content:'';position:absolute;inset:3px;border:1px solid currentColor;border-radius:12px;
    pointer-events:none;animation:radar-pulse 2.5s ease-out infinite;
  }
  .banner-unlocked,.banner-waiting,.banner-breach,.banner-standby {
    font-size:12px;text-align:left;padding:14px 18px;letter-spacing:1px;border-width:1px;
    animation:status-slide-in .4s ease-out;box-shadow:none;border-radius:9px;margin:0 0 8px;
  }
  .st-key-hud_camera { position:relative;border:1px solid var(--hud-color,#00f0ff);
    background:linear-gradient(145deg,#112234aa,#060c17ee);border-radius:14px;
    padding:18px;box-shadow:0 0 28px color-mix(in srgb,var(--hud-color,#00f0ff) 10%,transparent);
    transition:border-color .35s,box-shadow .35s;isolation:isolate; }
  /* REMOVE MANUAL BUTTONS: Hide Take Photo / Capture snapshot buttons */
  [data-testid="stCameraInput"] button,
  [data-testid="stCameraInput"] [data-testid="stBaseButton-secondary"],
  .stCameraInput button,
  .stCameraInput [data-testid="stBaseButton-secondary"] {
    display: none !important;
    visibility: hidden !important;
    pointer-events: none !important;
  }
  .st-key-hud_camera::before { content:'';position:absolute;inset:0;border:1px solid var(--hud-color,#00f0ff);
    border-radius:14px;pointer-events:none;animation:radar-pulse 3s ease-out infinite;z-index:-1; }
  /* A native Streamlit container owns the camera; this absolute HTML layer overlays it.
     Separate markdown tags cannot wrap a native widget in Streamlit's React tree. */
  .st-key-hud_camera [data-testid="stElementContainer"]:has(.hud-camera-wrapper) { position:static; height:0; min-height:0; }
  .hud-camera-wrapper { position:absolute;inset:7px;pointer-events:none;z-index:5;border-radius:10px;overflow:hidden; }
  .hud-corner { position:absolute;width:25px;height:25px;border:2px solid var(--hud-color,#00f0ff);
    filter:drop-shadow(0 0 5px var(--hud-color,#00f0ff));animation:corner-snap .55s cubic-bezier(.16,1,.3,1) both; }
  .top-left { top:0;left:0;border-right:0;border-bottom:0; }
  .top-right { top:0;right:0;border-left:0;border-bottom:0; }
  .bottom-left { bottom:0;left:0;border-right:0;border-top:0; }
  .bottom-right { bottom:0;right:0;border-left:0;border-top:0; }
  .hud-scanline { position:absolute;left:0;right:0;height:3px;background:#00f0ff;
    box-shadow:0 0 14px 3px #00f0ff88;animation:scanline 2.5s linear infinite;display:none; }
  .st-key-hud_camera:has(.ingesting) .hud-scanline,
  .st-key-hud_camera:has([data-testid="stCameraInput"] [data-testid="stSpinner"]) .hud-scanline { display:block; }
  .feed-label { display:flex;justify-content:space-between;font:10px monospace;letter-spacing:1px;color:#b3c7da; }
  .feed-label span { color:var(--hud-color,#00f0ff); }
  .hud-foot { font:9px monospace;color:#8ba0b8;letter-spacing:1px; }
  .st-key-hud_camera [data-testid="stCameraInput"] { max-width:100%; }
  .st-key-hud_camera video { border-radius:8px; }
  .st-key-hud_camera [data-testid="stImage"] img { border-radius:8px; }
  .section-title { color:#c7d5e6;font:11px monospace;letter-spacing:1.4px;margin:6px 0 14px; }
  button:focus-visible { outline:2px solid #00f0ff!important;outline-offset:3px; }
  .audit-section-header { color:#c7d5e6; margin-top:24px;font-size:12px; }
  .threat-gauge { margin-top:12px; }
  @media (max-width:900px) {
    .top-nav,.nav-status-group { flex-wrap:wrap;gap:12px; }
    .command-heading { align-items:start; }.sector-tag { display:none; }
    .block-container { padding-left:1rem;padding-right:1rem; }
  }
  @media (prefers-reduced-motion:reduce) {
    *,*::before,*::after { animation:none!important;transition:none!important;scroll-behavior:auto!important; }
    .hud-scanline { display:none!important; }.metric-card:hover,.glass-card:hover,.party-card:hover { transform:none; }
  }
</style>
""", unsafe_allow_html=True)

# ============================================================
# SESSION STATE INIT
# ============================================================
_SS_DEFAULTS = {
    "authenticated": False,
    "username": None,
    "user_role": None,
    "user_id": None,
    "diagnostics_summary": None,
    "override_faces": None,
    "policy_timer_start": 0.0,
    "policy_validated_parties": {},
    "last_logged_hash": None,
    "auto_capture_engine": None,
    "last_alert_ts": 0.0,
    "cloud_init_done": False,
    "total_scans_today": 0,
    "liveness_pass_count": 0,
    "liveness_total_count": 0,
    "sound_enabled": False,
    "last_input_token": None,
    "last_scan_digest": None,
    "ui_policy_result": None,
    "ui_verified_parties": {},
    "simulation_generation": 0,
    "last_sound_status": "STANDBY",
    "sound_event": "",
    "sound_kind": None,
    "telemetry_history": [],
    "last_audit_event": None,
    "last_policy_mode": None,
    "last_telemetry_sample": None,
}
for k, v in _SS_DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

if st.session_state.diagnostics_summary is None:
    st.session_state.diagnostics_summary = run_system_diagnostics()
if st.session_state.auto_capture_engine is None:
    st.session_state.auto_capture_engine = AutoCaptureEngine(
        stability_threshold_ms=300.0, jitter_threshold=15
    )
if st.session_state.get("face_stability_tracker") is None:
    st.session_state.face_stability_tracker = FaceStabilityTracker(
        stability_threshold_ms=300.0, jitter_threshold=15.0, cooldown_seconds=2.0
    )

# Initialise Supabase client once (background-safe)
if not st.session_state.cloud_init_done:
    threading.Thread(target=init_supabase_client, daemon=True).start()
    st.session_state.cloud_init_done = True

# ============================================================
# 1. CREDENTIAL LOGIN GATE
# ============================================================
if not st.session_state.authenticated:
    st.markdown("""
    <div style="display:flex;flex-direction:column;align-items:center;
    justify-content:center;padding:40px 20px;">
    <div style="font-family:'Share Tech Mono',monospace;font-size:11px;color:#334155;
    letter-spacing:4px;text-transform:uppercase;margin-bottom:24px;">
    VERITAS SECURITY SYSTEMS · EST. 2026</div></div>
    """, unsafe_allow_html=True)

    st.markdown(
        "<h1 style='text-align:center;color:#00F0FF;"
        "font-family:\"Share Tech Mono\",monospace;"
        "font-size:32px;letter-spacing:2px;text-shadow:0 0 24px rgba(0,240,255,.5);'>"
        "\U0001f510 VERITAS-VAULT</h1>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<p style='text-align:center;color:#475569;font-size:13px;"
        "letter-spacing:1px;margin-bottom:36px;'>"
        "Zero-Trust Physical Access Control System · Production v2.0</p>",
        unsafe_allow_html=True,
    )

    col1, col2, col3 = st.columns([1, 1.6, 1])
    with col2:
        with st.container(border=True):
            st.markdown(
                "<div style='font-family:\"Share Tech Mono\",monospace;"
                "color:#00F0FF;font-size:11px;letter-spacing:2px;"
                "text-transform:uppercase;margin-bottom:14px;'>"
                "OPERATOR AUTHENTICATION</div>",
                unsafe_allow_html=True,
            )
            user_input = st.text_input("Username", placeholder="admin  or  officer",
                                       key="login_user")
            pass_input = st.text_input("Passphrase", type="password",
                                       key="login_pass")
            if st.button("\U0001f513 Authenticate & Enter Command Center",
                         use_container_width=True):
                if user_input == "admin" and pass_input == "vault@2026":
                    st.session_state.authenticated = True
                    st.session_state.username      = "admin"
                    st.session_state.user_role     = "Vault Administrator"
                    st.session_state.user_id       = "admin_001"
                    st.rerun()
                elif user_input == "officer" and pass_input == "secure@2026":
                    st.session_state.authenticated = True
                    st.session_state.username      = "officer"
                    st.session_state.user_role     = "Security Officer"
                    st.session_state.user_id       = "officer_804"
                    st.rerun()
                else:
                    st.error(
                        "\u274c Access Denied — Invalid credentials. "
                        "Use admin / vault@2026  or  officer / secure@2026"
                    )
        st.markdown(
            "<p style='text-align:center;color:#1E293B;font-size:10px;"
            "margin-top:12px;letter-spacing:1px;'>"
            "PROTECTED BY AES-256-GCM · SHA-256 NOTARIZATION · ZERO-TRUST POLICY</p>",
            unsafe_allow_html=True,
        )
    st.stop()

# ============================================================
# 2. SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown(
        f"""<div style="background:rgba(0,240,255,.07);border:1px solid rgba(0,240,255,.25);
        border-radius:10px;padding:14px;margin-bottom:16px;">
        <div style="font-size:9px;color:#475569;font-family:'Share Tech Mono',monospace;
        letter-spacing:2px;">AUTHENTICATED OPERATOR</div>
        <div style="font-size:14px;font-weight:700;color:#00F0FF;text-transform:uppercase;
        margin-top:4px;">\U0001f464 {st.session_state.user_role}</div>
        <div style="font-size:11px;color:#10B981;font-family:'Share Tech Mono',monospace;
        margin-top:3px;">ID: {st.session_state.user_id} &middot; {st.session_state.username}</div>
        </div>""",
        unsafe_allow_html=True,
    )

    st.toggle("🔊 Sound Effects (ON/OFF)", key="sound_enabled",
              help="Short verdict cues. Your browser may ask you to enable audio.")
    st.caption("Sound is off by default. Motion follows your device preferences.")
    st.markdown("### \u2699\ufe0f Operational Policy")
    policy_mode = st.radio(
        "Access Protocol Mode:",
        ["Standard Locker Access", "High-Value Inventory Audit"],
        index=0,
        help="Standard: 1 Employee + 1 Customer within 5s. High-Value: 2 distinct Employees.",
    )
    if st.session_state.last_policy_mode not in (None, policy_mode):
        st.session_state.policy_timer_start = 0.0
        st.session_state.policy_validated_parties = {}
    st.session_state.last_policy_mode = policy_mode

    st.markdown("<br>", unsafe_allow_html=True)
    with st.expander("\u26a1 Quick Threat Simulation", expanded=True):
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            if st.button("\U0001f4f8 Spoof Attack", use_container_width=True):
                st.session_state.simulation_generation += 1
                st.session_state.override_faces = [{
                    "name": "Photo Spoof Attack", "role": "Unauthorized",
                    "is_authorized": False, "is_recognized": False,
                    "bbox": (180, 100, 160, 200), "spoof": True,
                }]
                st.session_state.policy_timer_start = 0.0
                st.session_state.policy_validated_parties = {}
                st.rerun()
        with col_s2:
            if st.button("\u23f1\ufe0f Timer Timeout", use_container_width=True):
                st.session_state.simulation_generation += 1
                st.session_state.override_faces = []
                st.session_state.policy_timer_start = time.time() - 6.0
                st.session_state.policy_validated_parties = {
                    "Officer Alice": {"role": "Employee", "first_seen": time.time() - 6.0}
                }
                st.rerun()

        if st.button("\U0001f534 Simulate Unauthorized Intruder", use_container_width=True):
            st.session_state.simulation_generation += 1
            st.session_state.override_faces = [{
                "name": "Unknown Intruder", "role": "Unauthorized",
                "is_authorized": False, "is_recognized": False,
                "bbox": (180, 100, 160, 200),
            }]
            st.session_state.policy_timer_start = 0.0
            st.session_state.policy_validated_parties = {}
            st.rerun()

        if st.button("\U0001f7e2 Simulate Valid Dual Access", use_container_width=True):
            st.session_state.simulation_generation += 1
            if "High-Value" in policy_mode:
                st.session_state.override_faces = [
                    {"name": "Officer Alice", "role": "Employee",
                     "is_authorized": True, "is_recognized": True,
                     "bbox": (100, 100, 150, 180), "liveness": 0.97, "is_live": True},
                    {"name": "Officer Bob", "role": "Employee",
                     "is_authorized": True, "is_recognized": True,
                     "bbox": (320, 100, 150, 180), "liveness": 0.95, "is_live": True},
                ]
            else:
                st.session_state.override_faces = [
                    {"name": "Officer Alice", "role": "Employee",
                     "is_authorized": True, "is_recognized": True,
                     "bbox": (100, 100, 150, 180), "liveness": 0.97, "is_live": True},
                    {"name": "Customer John", "role": "Customer",
                     "is_authorized": True, "is_recognized": True,
                     "bbox": (320, 100, 150, 180), "liveness": 0.94, "is_live": True},
                ]
            st.session_state.policy_timer_start = 0.0
            st.session_state.policy_validated_parties = {}
            st.rerun()

        if st.button("◷ Simulate Party 1 / Start 5s Window", use_container_width=True):
            st.session_state.simulation_generation += 1
            st.session_state.override_faces = [{
                "name": "Officer Alice", "role": "Employee",
                "is_authorized": True, "is_recognized": True,
                "bbox": (180, 100, 160, 200), "liveness": .97, "is_live": True,
            }]
            st.session_state.policy_timer_start = 0.0
            st.session_state.policy_validated_parties = {}
            st.rerun()
        st.caption("Preview only · no SMS, cloud writes, or production audit entries.")

        if st.button("\U0001f504 Reset Live Simulation", use_container_width=True):
            st.session_state.simulation_generation += 1
            st.session_state.override_faces = None
            st.session_state.policy_timer_start = 0.0
            st.session_state.policy_validated_parties = {}
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)
    with st.expander("\U0001f4f1 Alert Dispatch Config", expanded=False):
        sec_cfg = load_security_config()
        st.markdown(
            "<div style='font-size:10px;color:#64748B;font-family:\"Share Tech Mono\","
            "monospace;margin-bottom:6px;letter-spacing:1px;'>PRIMARY: CallMeBot WhatsApp</div>",
            unsafe_allow_html=True,
        )
        cb_phone = st.text_input("WhatsApp Phone (intl format)",
                                 value=sec_cfg.get("CALLMEBOT_PHONE", ""),
                                 placeholder="+12125551234", key="cb_phone")
        cb_key   = st.text_input("CallMeBot API Key",
                                 value=sec_cfg.get("CALLMEBOT_API_KEY", ""),
                                 type="password", key="cb_key")
        st.caption("Free key: https://callmebot.com/blog/free-api-whatsapp-messages/")
        st.markdown(
            "<div style='font-size:10px;color:#64748B;font-family:\"Share Tech Mono\","
            "monospace;margin:8px 0 4px;letter-spacing:1px;'>FALLBACK: Twilio SMS</div>",
            unsafe_allow_html=True,
        )
        sms_sid   = st.text_input("Twilio Account SID",
                                  value=sec_cfg.get("TWILIO_ACCOUNT_SID", ""), type="password")
        sms_token = st.text_input("Twilio Auth Token",
                                  value=sec_cfg.get("TWILIO_AUTH_TOKEN", ""), type="password")
        sms_from  = st.text_input("Twilio From Number",
                                  value=sec_cfg.get("TWILIO_FROM_PHONE", ""),
                                  placeholder="+15550001122")
        sms_admin = st.text_input("Admin Alert Recipient",
                                  value=sec_cfg.get("ADMIN_ALERT_PHONE", "+15551234567"))
        col_save, col_test = st.columns(2)
        with col_save:
            if st.button("\U0001f4be Save Config", use_container_width=True):
                save_security_config({
                    "CALLMEBOT_PHONE":    cb_phone,
                    "CALLMEBOT_API_KEY":  cb_key,
                    "TWILIO_ACCOUNT_SID": sms_sid,
                    "TWILIO_AUTH_TOKEN":  sms_token,
                    "TWILIO_FROM_PHONE":  sms_from,
                    "ADMIN_ALERT_PHONE":  sms_admin,
                    "SMS_ENABLED": True,
                })
                st.success("Configuration saved!")
        with col_test:
            if st.button("\U0001f4e8 Test Alert", use_container_width=True):
                ok, msg = test_sms_alert(sms_admin)
                if ok:
                    st.success(msg)
                else:
                    st.info(msg)

    st.markdown("<br>", unsafe_allow_html=True)
    with st.expander("\U0001f4f8 Face Enrollment & Registration", expanded=False):
        enroll_name = st.text_input("Personnel Name:", value="Officer Alice",
                                    key="enroll_name_field")
        enroll_role = st.selectbox("Assign Role:", ["Employee", "Customer"],
                                   index=0, key="enroll_role_field")
        enroll_btn  = st.button("\U0001f4f8 Enroll from Snapshot", use_container_width=True)

        st.markdown("<hr style='border-color:rgba(0,240,255,.12);margin:10px 0;'>",
                    unsafe_allow_html=True)
        st.markdown("**Enrolled Personnel Profiles:**")
        enrolled_users = get_all_users()
        if not enrolled_users:
            st.caption("No personnel profiles enrolled yet.")
        else:
            for u in enrolled_users:
                col_u1, col_u2 = st.columns([3, 1])
                badge_cls = "role-emp" if u["role"] == "Employee" else "role-cust"
                col_u1.markdown(
                    f"**{u['name']}** <span class='{badge_cls} party-role-badge'>{u['role']}</span>",
                    unsafe_allow_html=True,
                )
                if col_u2.button("\U0001f5d1\ufe0f", key=f"del_{u['user_id']}",
                                 help="Delete Profile"):
                    delete_user(u["user_id"])
                    if u.get("image_path") and os.path.exists(u["image_path"]):
                        try:
                            os.remove(u["image_path"])
                        except Exception:
                            pass
                    st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)
    with st.expander("\U0001f9ba Subsystem Diagnostics", expanded=False):
        if st.button("\U0001f504 Rerun Diagnostics", use_container_width=True):
            st.session_state.diagnostics_summary = run_system_diagnostics()
            st.rerun()
        for diag in st.session_state.diagnostics_summary.get("checks", []):
            icon = "\U0001f7e2" if diag["status"] == "PASS" else (
                "\U0001f7e1" if "BUFFER" in diag["status"] or diag["status"] == "WARN"
                else "\U0001f534"
            )
            st.markdown(f"{icon} **{diag['subsystem']}**: `{diag['status']}`")
            st.caption(diag["details"])

    st.markdown("<br><hr style='border-color:rgba(0,240,255,.12);'>", unsafe_allow_html=True)
    if st.button("\U0001f6aa Log Out", use_container_width=True):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()

# ============================================================
# 3. TOP NAVIGATION & LIVE STATUS BAR
# ============================================================
cloud_label  = get_cloud_status_label()
cloud_pill   = "pill-cyan" if is_cloud_online() else "pill-amber"
cloud_icon   = "☁" if is_cloud_online() else "⚡"
now_str      = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

st.markdown(f"""
<div class="top-nav">
  <div>
    <div class="nav-brand">
      🛡 VERITAS-VAULT
      <span>ZERO-TRUST PHYSICAL ACCESS CONTROL SYSTEM</span>
    </div>
  </div>
  <div class="nav-status-group">
    <div class="status-pill pill-green">
      <span class="pill-dot"></span> OPERATIONAL
    </div>
    <div class="status-pill {cloud_pill}">
      <span class="pill-dot"></span> {cloud_icon} {cloud_label}
    </div>
    <div class="nav-clock">{now_str}</div>
  </div>
</div>
""", unsafe_allow_html=True)

# ============================================================
# 4. CAMERA SNAPSHOT INPUT
# ============================================================
st.markdown("""<div class="command-heading"><div>
  <div class="eyebrow">SECURITY OPERATIONS / VAULT 01</div>
  <h1>Vault command center<span style="color:#00f0ff">.</span></h1>
  <p>Identity verified. Evidence sealed. Every access accounted for.</p>
</div><div class="sector-tag">DUAL-CUSTODY PROTOCOL<br>Δt ≤ 5.0s · ZERO TRUST</div></div>""", unsafe_allow_html=True)
banner_slot = st.empty()
metrics_slot = st.container()
st.markdown('<div style="height:6px"></div>', unsafe_allow_html=True)
col_cam, col_verify = st.columns([1.55, 1.0], gap="medium")
with col_cam:
    st.markdown('<div class="section-title">01 / BIOMETRIC CAPTURE</div>', unsafe_allow_html=True)
    with st.container(key="hud_camera"):
        camera_style = st.empty()
        camera_overlay = st.empty()
        feed_label = st.empty()
        live_stream_view = st.empty()
        cam_file = st.camera_input("Hands-Free Face Checkpoint", key="vault_camera")
        analyzed_slot = st.empty()
        st.markdown('<div class="hud-foot">CAM 01 / AUTONOMOUS HANDS-FREE FIXATION · SHA-256 INTEGRITY</div>', unsafe_allow_html=True)
    live_feed_active = st.toggle("Autonomous Hands-Free Stream (CAM 01)", value=True, key="live_hands_free_feed")

frame_raw = None
new_snapshot = False
capture_digest = None
is_testing = "pytest" in sys.modules or os.environ.get("PYTEST_CURRENT_TEST") is not None
tracker = st.session_state.face_stability_tracker
auto_triggered = False
detected_faces = []
fixation_status = HUD_SCANNING
fixation_ms = 0.0

# ---- 1. Autonomous Live Camera Stream Loop ----
if live_feed_active and not is_testing and st.session_state.override_faces is None and cam_file is None:
    cap = cv2.VideoCapture(0)
    if cap.isOpened():
        cascade = _get_cascade_classifier()
        # Ingest live camera stream
        for _ in range(30):
            ret, frame = cap.read()
            if not ret:
                break

            display_frame = frame.copy()
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=6, minSize=(60, 60))

            if len(faces) == 0:
                tracker.check_fixation(None)
                draw_hud_overlay(display_frame, HUD_SCANNING, color=(255, 255, 0))
            else:
                primary_bbox = tuple(int(v) for v in faces[0])
                # Draw cyan target HUD brackets and track centroid stability
                draw_cyan_target_brackets(display_frame, primary_bbox, color=(255, 255, 0))

                is_fixed = tracker.check_fixation(primary_bbox, duration_ms=300.0)
                is_cool = tracker.cooldown_active(cooldown_seconds=2.0)

                if is_cool:
                    rem = max(0.0, 2.0 - (time.time() - tracker.last_capture_time))
                    draw_hud_overlay(display_frame, f"COOLDOWN LOCK ({rem:.1f}s)", color=(0, 240, 255))
                elif not is_fixed:
                    dur_ms = tracker.get_fixation_ms()
                    prog = min(1.0, dur_ms / 300.0)
                    draw_hud_overlay(display_frame, HUD_FIXATING, color=(255, 255, 0), progress=prog)
                else:
                    # FIXATION MET (>300ms) AND COOLDOWN EXPIRED!
                    # Automatically freeze frame in memory
                    frozen_frame = frame.copy()
                    draw_hud_overlay(display_frame, HUD_VERIFYING, color=(0, 255, 255))
                    live_stream_view.image(display_frame, channels="BGR", use_container_width=True)

                    # Trigger process_frame() for biometrics (NCC matching + Laplacian liveness)
                    detected_faces = default_face_recognizer.process_frame(frozen_frame)

                    # Start 2.0-second cooldown buffer
                    tracker.record_capture()

                    frame_raw = frozen_frame
                    capture_bytes = cv2.imencode(".jpg", frozen_frame)[1].tobytes()
                    capture_digest = hashlib.sha256(capture_bytes).hexdigest()
                    new_snapshot = True
                    auto_triggered = True
                    fixation_status = HUD_VERIFYING
                    fixation_ms = 300.0
                    st.session_state.total_scans_today += 1
                    st.session_state.last_scan_digest = capture_digest
                    break

            live_stream_view.image(display_frame, channels="BGR", use_container_width=True)
            time.sleep(0.02)

        cap.release()

if cam_file is not None and frame_raw is None:
    capture_bytes = cam_file.getvalue()
    capture_digest = hashlib.sha256(capture_bytes).hexdigest()
    new_snapshot = capture_digest != st.session_state.last_scan_digest
    img_bytes = np.frombuffer(capture_bytes, dtype=np.uint8)
    frame_raw = cv2.imdecode(img_bytes, cv2.IMREAD_COLOR)
    if frame_raw is not None and new_snapshot:
        st.session_state.total_scans_today += 1
        st.session_state.last_scan_digest = capture_digest
        camera_overlay.markdown('<div class="hud-camera-wrapper ingesting"><i class="hud-scanline"></i></div>', unsafe_allow_html=True)
    elif frame_raw is None:
        st.error("Snapshot could not be decoded. Please capture another image.")
elif not auto_triggered and cam_file is None and frame_raw is None:
    st.session_state.last_scan_digest = None

# ---- Enroll if requested ----
if enroll_btn:
    if frame_raw is not None:
        ok, res_msg = enroll_face(frame_raw, enroll_name, enroll_role)
        if ok:
            st.sidebar.success(f"✅ Enrolled {enroll_name} ({enroll_role})!")
            all_users = get_all_users()
            uid = next((u["user_id"] for u in all_users if u["name"] == enroll_name), "")
            if uid:
                threading.Thread(
                    target=sync_user_to_cloud,
                    args=(uid, enroll_name, enroll_role, ""),
                    daemon=True,
                ).start()
            st.rerun()
        else:
            st.sidebar.error(f"❌ Enrollment failed: {res_msg}")
    else:
        st.sidebar.warning("⚠️ Capture a snapshot first.")

# ---- Fallback synthetic standby frame ----
if frame_raw is None:
    w, h = 640, 440
    frame_raw = np.zeros((h, w, 3), dtype=np.uint8)
    for x in range(0, w, 35):
        cv2.line(frame_raw, (x, 0), (x, h), (14, 22, 38), 1)
    for y in range(0, h, 35):
        cv2.line(frame_raw, (0, y), (w, y), (14, 22, 38), 1)
    cv2.putText(frame_raw, "[STANDBY: AUTONOMOUS SURVEILLANCE ARMED]",
                (65, 220), cv2.FONT_HERSHEY_SIMPLEX, 0.58, (0, 240, 255), 1)
    standby_display = frame_raw.copy()
    draw_hud_overlay(standby_display, HUD_SCANNING, color=(255, 255, 0))
    live_stream_view.image(standby_display, channels="BGR", use_container_width=True)

# ---- Face detection ----
if st.session_state.override_faces is not None:
    detected_faces = st.session_state.override_faces
elif not auto_triggered:
    detected_faces = default_face_recognizer.process_frame(frame_raw) if (cam_file is not None or frame_raw is not None) else []

# ---- Hands-free fixation tracking ----
primary_bbox = detected_faces[0].get("bbox") if detected_faces else None
if not auto_triggered:
    if primary_bbox:
        is_fixed = tracker.check_fixation(primary_bbox, duration_ms=300.0)
        fixation_ms = tracker.get_fixation_ms()
        if tracker.cooldown_active():
            rem = max(0.0, 2.0 - (time.time() - tracker.last_capture_time))
            fixation_status = f"COOLDOWN LOCK ({rem:.1f}s)"
        elif is_fixed:
            fixation_status = HUD_VERIFYING
        else:
            fixation_status = HUD_FIXATING
    else:
        tracker.check_fixation(None)
        fixation_ms = 0.0
        fixation_status = HUD_SCANNING
else:
    fixation_ms = 300.0
    fixation_status = HUD_VERIFYING

# ---- Liveness evaluation ----
if detected_faces:
    first_face = detected_faces[0]
    if first_face.get("spoof", False):
        is_live, liveness_val = False, 0.38
    elif first_face.get("is_live") is not None:
        is_live      = bool(first_face["is_live"])
        liveness_val = float(first_face.get("liveness", 0.97 if is_live else 0.38))
    else:
        x_b, y_b, w_b, h_b = first_face.get("bbox", (0, 0, 50, 50))
        face_crop = frame_raw[max(0, y_b): y_b + h_b, max(0, x_b): x_b + w_b]
        if face_crop.size > 0:
            is_live, liveness_val = estimate_liveness(face_crop)
        else:
            is_live, liveness_val = True, 0.96
else:
    is_live, liveness_val = True, 0.98

# Track liveness pass rate
if new_snapshot and detected_faces and st.session_state.override_faces is None:
    st.session_state.liveness_total_count += 1
    if is_live:
        st.session_state.liveness_pass_count += 1

# ---- Annotate frame ----
frame_annotated = frame_raw.copy()
for f in detected_faces:
    bx, by, bw, bh = f.get("bbox", (150, 100, 150, 180))
    is_rec  = f.get("is_recognized", f.get("is_authorized", False)) and is_live
    p_name  = f.get("name", "Unknown Intruder")
    p_role  = f.get("role", "Unauthorized")
    box_col = (0, 255, 102) if is_rec else (51, 51, 255)
    # Draw cyan target HUD brackets
    draw_cyan_target_brackets(frame_annotated, (bx, by, bw, bh), color=(255, 255, 0) if not is_rec else (0, 255, 102))
    cv2.rectangle(frame_annotated, (bx, by), (bx + bw, by + bh), box_col, 1)
    label = f"[{p_name}] ({p_role})" if is_rec else f"[BREACH: {p_name}]"
    cv2.rectangle(frame_annotated, (bx, max(0, by - 24)), (bx + bw, by), box_col, -1)
    cv2.putText(frame_annotated, label, (bx + 4, max(12, by - 6)),
                cv2.FONT_HERSHEY_SIMPLEX, 0.40, (0, 0, 0), 1)

# Dynamic HUD status overlay over the video feed
hud_col = (255, 255, 0)
if fixation_status == HUD_VERIFYING:
    hud_col = (0, 255, 255)
draw_hud_overlay(frame_annotated, fixation_status, color=hud_col, progress=min(1.0, fixation_ms / 300.0) if fixation_status == HUD_FIXATING else None)
live_stream_view.image(frame_annotated, channels="BGR", use_container_width=True)

_, frame_jpeg = cv2.imencode(".jpg", frame_annotated, [cv2.IMWRITE_JPEG_QUALITY, 85])
frame_bytes   = frame_jpeg.tobytes()

# ---- Zero-Trust Policy Evaluation ----
simulation_active = st.session_state.override_faces is not None
input_token = hashlib.sha256(json.dumps({
    "capture": capture_digest,
    "simulation": st.session_state.override_faces,
    "generation": st.session_state.simulation_generation,
    "mode": policy_mode,
}, sort_keys=True).encode()).hexdigest()
new_input = input_token != st.session_state.last_input_token
previous_result = st.session_state.ui_policy_result
if new_input:
    # Preserve verified parties for presentation: the policy engine clears them on success.
    previous_parties = dict(st.session_state.policy_validated_parties)
    if not is_live:
        st.session_state.policy_timer_start = 0.0
        st.session_state.policy_validated_parties = {}
        policy_result = {"status": "BREACH", "msg": "Biometric spoof detected", "remaining": 0.0, "unlocked": False}
    else:
        policy_result = evaluate_access(policy_mode, detected_faces, st.session_state)
    if policy_result["status"] == "GRANTED":
        previous_parties.update({f["name"]: {"role": f["role"]} for f in detected_faces if f.get("name")})
        st.session_state.ui_verified_parties = previous_parties
    else:
        st.session_state.ui_verified_parties = dict(st.session_state.policy_validated_parties)
    st.session_state.last_input_token = input_token
    st.session_state.ui_policy_result = policy_result
elif previous_result and previous_result["status"] == "WAITING":
    # A rerun is not a fresh biometric observation. Only advance the existing deadline.
    policy_result = evaluate_access(policy_mode, [], st.session_state)
    st.session_state.ui_policy_result = policy_result
else:
    policy_result = previous_result or {"status": "STANDBY", "msg": "Monitoring Vault Chamber", "remaining": 5.0, "unlocked": False}
policy_status = policy_result["status"]
policy_msg = policy_result["msg"]
vault_unlocked = policy_result.get("unlocked", False) and is_live
remaining_secs = policy_result.get("remaining", 5.0)

hud_color = {"STANDBY": "#00f0ff", "WAITING": "#f59e0b", "GRANTED": "#10b981", "BREACH": "#ef4444"}[policy_status]
camera_style.markdown(f'<style>.st-key-hud_camera {{ --hud-color:{hud_color}; }}</style>', unsafe_allow_html=True)
camera_overlay.markdown('<div class="hud-camera-wrapper" aria-hidden="true">'
    '<i class="hud-corner top-left"></i><i class="hud-corner top-right"></i>'
    '<i class="hud-corner bottom-left"></i><i class="hud-corner bottom-right"></i>'
    '<i class="hud-scanline"></i></div>', unsafe_allow_html=True)
feed_label.markdown(f'<div class="feed-label">{"SIMULATION PREVIEW" if simulation_active else "VAULT CHAMBER / CAM 01"}<span>● {policy_status}</span></div>', unsafe_allow_html=True)
if cam_file is not None or simulation_active:
    with analyzed_slot.container():
        with st.expander("Analyzed snapshot / detection overlay", expanded=simulation_active):
            st.image(frame_bytes, use_container_width=True)
            st.caption("Simulated detections · local preview only" if simulation_active else "Last ingested snapshot · not a continuous video stream")

if policy_status != st.session_state.last_sound_status:
    st.session_state.last_sound_status = policy_status
    st.session_state.sound_kind = policy_status.lower() if policy_status in ("GRANTED", "BREACH") else None
    st.session_state.sound_event = f"{input_token}:{policy_status}:{time.time_ns()}"
play_sound(st.session_state.sound_kind, st.session_state.sound_event,
           st.session_state.sound_enabled and st.session_state.sound_kind is not None)

# ---- Cryptographic Notarization + Audit Logging ----
now_ts = time.time()
should_log = (
    policy_status in ("GRANTED", "BREACH")
    or not is_live
    or (detected_faces and policy_status == "BREACH")
)

if should_log and not simulation_active:
    frame_hash       = compute_raw_frame_hash(frame_raw)
    effective_status = "BREACH" if not is_live else policy_status
    verdict_str      = "ACCESS GRANTED" if effective_status == "GRANTED" else "ACCESS DENIED"

    audit_event = (input_token, effective_status)
    if st.session_state.last_audit_event != audit_event:
        _, enc_path = encrypt_frame_aes_gcm(frame_raw)

        parties_list, ids_list = [], []
        for f in detected_faces:
            parties_list.append(f"{f.get('name','?')} ({f.get('role','?')})")
            uid = f.get("user_id", "")
            if uid:
                ids_list.append(uid)

        parties_str = ", ".join(parties_list) if parties_list else "None"
        ids_str     = ", ".join(ids_list) if ids_list else ""

        log_access_event(
            mode=policy_mode, parties=parties_str, verdict=verdict_str,
            sha256_hash=frame_hash, enc_path=enc_path,
            status="LOCAL_VERIFIED", party_ids=ids_str,
        )
        st.session_state.last_logged_hash = frame_hash
        st.session_state.last_audit_event = audit_event

        # Async cloud audit sync
        audit_payload = {
            "mode": policy_mode, "verified_parties": parties_str,
            "party_ids": ids_str, "verdict": verdict_str,
            "sha256_hash": frame_hash, "encrypted_path": enc_path,
            "status": "CLOUD_SYNCED",
        }
        threading.Thread(
            target=sync_audit_log_to_cloud, args=(audit_payload,), daemon=True
        ).start()

        # Async evidence upload
        if enc_path and os.path.exists(enc_path):
            def _upload_evidence():
                with open(enc_path, "rb") as fh:
                    raw = fh.read()
                upload_evidence_to_cloud(raw, os.path.basename(enc_path))
            threading.Thread(target=_upload_evidence, daemon=True).start()

        if effective_status == "BREACH" and (now_ts - st.session_state.last_alert_ts > 10.0):
            st.session_state.last_alert_ts = now_ts
            threat_detail = (
                "Anti-spoofing rejection (Laplacian var < 60)"
                if not is_live else policy_msg
            )
            send_sms_alert("AUTOMATED_BREACH_DETECTION", threat_detail, frame_hash)

# ---- Threat Level ----
if policy_status == "BREACH" or not is_live:
    threat_level = "CRITICAL BREACH"
    threat_cls   = "threat-critical"
    threat_icon  = "\U0001f534"
elif policy_status == "WAITING":
    threat_level = "ELEVATED"
    threat_cls   = "threat-elevated"
    threat_icon  = "\U0001f7e1"
else:
    threat_level = "LOW"
    threat_cls   = "threat-low"
    threat_icon  = "\U0001f7e2"

# ---- Solenoid State ----
if vault_unlocked and is_live:
    solenoid_state = "UNLOCKED"
    solenoid_color = "#10B981"
elif policy_status == "BREACH" or not is_live:
    solenoid_state = "LOCKED \u2014 BREACH"
    solenoid_color = "#EF4444"
else:
    solenoid_state = "LOCKED"
    solenoid_color = "#F59E0B"

# ============================================================
# 5. STATE BANNERS
# ============================================================
with banner_slot.container():
    if policy_status == "GRANTED" and is_live:
        st.markdown(
            '<div class="banner-unlocked">\U0001f7e2 VAULT CHAMBER UNLOCKED \u2014 DUAL-CUSTODY SATISFIED \u2714</div>',
            unsafe_allow_html=True,
        )
    elif policy_status == "WAITING" and is_live:
        st.markdown(
            f'<div class="banner-waiting">\U0001f7e1 AWAITING 2ND PARTY \u2014 '
            'FIRST IDENTITY VERIFIED · 5.0s WINDOW ACTIVE</div>',
            unsafe_allow_html=True,
        )
    elif policy_status == "BREACH" or not is_live:
        threat_text = "LIVENESS SPOOF DETECTED" if not is_live else escape(policy_msg.upper())
        evidence_label = "SIMULATION / LOCAL PREVIEW" if simulation_active else "VAULT LOCKED / EVENT RECORDED"
        st.markdown(
            f'<div class="banner-breach">\U0001f534 {evidence_label} \u2014 {threat_text}</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="banner-standby">\U0001f6e1\ufe0f STANDBY \u2014 AUTONOMOUS FIXATION '
            'MONITORING ARMED (SOLENOID ENGAGED)</div>',
            unsafe_allow_html=True,
        )

# ============================================================
# 6. METRIC CARDS ROW
# ============================================================
liveness_pct = (int(100 * st.session_state.liveness_pass_count / st.session_state.liveness_total_count)
                if st.session_state.liveness_total_count else None)
telemetry_sample = (input_token, policy_status)
if telemetry_sample != st.session_state.last_telemetry_sample and (cam_file is not None or simulation_active):
    st.session_state.last_telemetry_sample = telemetry_sample
    st.session_state.telemetry_history = (st.session_state.telemetry_history + [{
        "scans": st.session_state.total_scans_today,
        "liveness": liveness_pct,
        "lock": 1 if vault_unlocked else 0,
        "threat": 2 if policy_status == "BREACH" else 1 if policy_status == "WAITING" else 0,
    }])[-24:]
history = st.session_state.telemetry_history
with metrics_slot:
    metric_columns = st.columns(4, gap="small")
    tiles = [
        ("SNAPSHOTS INGESTED", st.session_state.total_scans_today, "This operator session", "scans", "#00f0ff"),
        ("LIVENESS PASS RATE", f"{liveness_pct}%" if liveness_pct is not None else "—", "Captured face samples only", "liveness", "#10b981"),
        ("VAULT SOLENOID", solenoid_state, "Simulation preview" if simulation_active else "Dual-custody interlock", "lock", solenoid_color),
        ("THREAT LEVEL", threat_level, "Simulation preview" if simulation_active else "Current policy verdict", "threat", hud_color),
    ]
    for index, (column, tile) in enumerate(zip(metric_columns, tiles), 1):
        label, value, note, field, color = tile
        column.markdown(metric_tile(label, value, note, [h[field] for h in history if h[field] is not None], color, f"0{index}"), unsafe_allow_html=True)

# ============================================================
# 7. CAMERA TELEMETRY + VERIFICATION VISUALIZER
# ============================================================
with col_cam:
    # Liveness telemetry card
    liv_pct   = f"{int(liveness_val * 100)}%" if detected_faces else "—"
    liv_color = "#10B981" if is_live else "#EF4444"
    liv_label = ("LIVE — BIOMETRIC PASS" if is_live else "SPOOF DETECTED (Var_Lap < 60)") if detected_faces else "AWAITING A FACE SAMPLE"
    fix_sub   = (
        f"Fixation: {fixation_status} ({int(fixation_ms)}ms)"
        if primary_bbox else "Auto-Fixation: Armed (Standby)"
    )
    st.markdown(f"""
    <div class="glass-card">
      <div class="card-label">Edge-AI Liveness Anti-Spoofing Engine</div>
      <div class="card-value" style="color:{liv_color};">{liv_pct}</div>
      <div class="card-sub">{liv_label} &nbsp;|&nbsp; {fix_sub}</div>
    </div>""", unsafe_allow_html=True)

    # Crypto + Alert card
    sec_conf = load_security_config()
    has_cb   = bool(sec_conf.get("CALLMEBOT_PHONE") and sec_conf.get("CALLMEBOT_API_KEY"))
    chan_str  = "WHATSAPP (CallMeBot)" if has_cb else "TWILIO SMS"
    st.markdown(f"""
    <div class="glass-card">
      <div class="card-label">Evidence Notarization &amp; Alert Dispatch</div>
      <div class="card-value" style="font-size:14px;color:#C084FC;">
        AES-256-GCM &nbsp;|&nbsp; SHA-256 &nbsp;|&nbsp; {chan_str}</div>
      <div class="card-sub">Recipient: {sec_conf.get('ADMIN_ALERT_PHONE','(unconfigured)')}
        &nbsp;|&nbsp; Non-blocking (&le;3.0s)</div>
    </div>""", unsafe_allow_html=True)

with col_verify:
    st.markdown(
        "<div style=\"font-family:'Share Tech Mono',monospace;color:#00F0FF;"
        "font-size:12px;letter-spacing:1.5px;margin-bottom:8px;\">"
        "🔐 TWO-STEP VERIFICATION COMMAND</div>",
        unsafe_allow_html=True,
    )

    # ---- Dual-Slot Personnel Verification Cards ----
    parties = st.session_state.get("ui_verified_parties", {}) if policy_status == "GRANTED" else st.session_state.get("policy_validated_parties", {})
    party_list = list(parties.items())  # [(name, {role, first_seen}), ...]

    def _make_party_card(slot_label: str, name: str = "", role: str = "",
                         validated: bool = False, is_breach: bool = False) -> str:
        if is_breach:
            card_cls  = "party-card-breach"
            check_cls = "check-breach"
            check_sym = "✕"
            avatar    = "⚠️"
        elif validated:
            card_cls  = "party-card-granted"
            check_cls = "check-ok"
            check_sym = "✓"
            avatar    = "👤"
        elif name:
            card_cls  = "party-card-waiting"
            check_cls = "check-ok"
            check_sym = "✓"
            avatar    = "👤"
        else:
            card_cls  = "party-card-empty"
            check_cls = "check-empty"
            check_sym = "○"
            avatar    = "?"
            name      = "Awaiting Personnel"
            role      = "—"

        role_cls = "role-emp" if role == "Employee" else (
            "role-cust" if role == "Customer" else ""
        )
        role_badge = (
            f"<span class='party-role-badge {role_cls}'>{escape(role)}</span>"
            if role and role != "—" else
            "<span style='color:#334155;font-size:11px;'>—</span>"
        )
        return f"""
        <div class="party-card {card_cls}" style="margin-bottom:12px;">
          <div class="party-check {check_cls}">{check_sym}</div>
          <div class="party-slot-label">{slot_label}</div>
          <div class="party-avatar">{avatar}</div>
          <div class="party-name">{escape(name)}</div>
          {role_badge}
        </div>"""

    # Determine card states
    is_breach_mode = (policy_status == "BREACH") or (not is_live and detected_faces)

    if is_breach_mode:
        f0 = detected_faces[0] if detected_faces else {}
        card1 = _make_party_card(
            "PARTY 1 · PRIMARY OFFICER",
            name=f0.get("name", "Unknown"),
            role=f0.get("role", "Unauthorized"),
            validated=False,
            is_breach=True,
        )
        card2 = _make_party_card(
            "PARTY 2 · SECONDARY OFFICER / CUSTOMER",
            name=detected_faces[1].get("name", "Unknown") if len(detected_faces) > 1 else "",
            role=detected_faces[1].get("role", "") if len(detected_faces) > 1 else "",
            validated=False,
            is_breach=len(detected_faces) > 1,
        )
    else:
        p1_name = party_list[0][0] if len(party_list) > 0 else ""
        p1_role = party_list[0][1]["role"] if len(party_list) > 0 else ""
        p2_name = party_list[1][0] if len(party_list) > 1 else ""
        p2_role = party_list[1][1]["role"] if len(party_list) > 1 else ""

        card1 = _make_party_card(
            "PARTY 1 · PRIMARY OFFICER",
            name=p1_name, role=p1_role,
            validated=(policy_status == "GRANTED"),
        )
        card2 = _make_party_card(
            "PARTY 2 · SECONDARY OFFICER / CUSTOMER",
            name=p2_name, role=p2_role,
            validated=(policy_status == "GRANTED"),
        )

    st.markdown(card1 + card2, unsafe_allow_html=True)

    # The client animates smoothly; the server fragment enforces the actual deadline.
    @st.fragment(run_every=0.2 if policy_status == "WAITING" else None)
    def live_countdown():
        result = st.session_state.ui_policy_result or policy_result
        remaining = result.get("remaining", 5.0)
        if result["status"] == "WAITING":
            remaining = max(0.0, 5.0 - (time.time() - st.session_state.policy_timer_start))
            if remaining <= 0:
                # Full rerun uses no new faces, records the timeout once, and updates all HUD states.
                st.rerun(scope="app")
        countdown(result["status"], remaining)
    live_countdown()

    # ---- Threat Level Gauge ----
    st.markdown(f"""
    <div class="threat-gauge" style="border:1px solid rgba(0,240,255,.14);">
      <div class="threat-gauge-title">🔭 Active Security Threat Index</div>
      <div class="threat-level-indicator {threat_cls}" style="padding:10px 16px;
        border-radius:10px;display:inline-block;">{threat_icon} {threat_level}</div>
      <div style="font-family:'Share Tech Mono',monospace;font-size:10px;
        color:#475569;margin-top:8px;letter-spacing:1px;">
        POLICY MODE: {policy_mode.upper()}</div>
    </div>""", unsafe_allow_html=True)

# ============================================================
# 8. LIVE CLOUD AUDIT LEDGER
# ============================================================
st.markdown("<br>", unsafe_allow_html=True)
st.markdown("""
<div class="audit-section-header">
  📜 LIVE CLOUD AUDIT LEDGER &nbsp;—&nbsp; REAL-TIME IMMUTABLE ACCESS LOG
  <span style="float:right;font-size:10px;color:#334155;">
    SHA-256 NOTARIZED · CLICK HASH TO COPY
  </span>
</div>""", unsafe_allow_html=True)

@st.fragment(run_every=3)
def live_audit_ledger():
    logs = get_recent_logs(25)
    filter_col, search_col, refresh_col = st.columns([1, 2, 1])
    with filter_col:
        verdict_filter = st.selectbox("Verdict", ["All events", "GRANTED", "BREACH", "WAITING"], label_visibility="collapsed")
    with search_col:
        audit_search = st.text_input("Search audit ledger", placeholder="Search personnel, digest, or protocol…", label_visibility="collapsed")
    with refresh_col:
        st.button("↻ Refresh ledger", use_container_width=True)

    visible_logs = []
    for row in logs:
        verdict = str(row.get("verdict", ""))
        normalized = "GRANTED" if "GRANTED" in verdict else "BREACH" if ("BREACH" in verdict or "DENIED" in verdict) else "WAITING" if "WAITING" in verdict else verdict
        if verdict_filter != "All events" and normalized != verdict_filter:
            continue
        if audit_search and audit_search.casefold() not in " ".join(str(v) for v in row.values()).casefold():
            continue
        visible_logs.append(dict(row))
    if visible_logs:
        audit_ledger(visible_logs)
        st.caption(f"{len(visible_logs)} of {len(logs)} recent events · Hover a digest to inspect · Click to copy")
    else:
        st.info("No events match this filter." if logs else "Ledger ready. Verified access events will appear here.")

live_audit_ledger()
st.markdown('<div class="hud-foot" style="margin-top:24px;text-align:center">VERITAS-VAULT / EVIDENCE INTEGRITY · DUAL CUSTODY · ZERO TRUST</div>', unsafe_allow_html=True)

# Hands-free autonomous stream loop refresh
if live_feed_active and not is_testing and st.session_state.override_faces is None:
    if policy_status in ("GRANTED", "BREACH"):
        # Pause during verdict confirmation
        time.sleep(1.8)
    else:
        time.sleep(0.04)
    st.rerun()

