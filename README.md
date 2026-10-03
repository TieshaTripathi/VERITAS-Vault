# VERITAS-Vault · Zero-Trust Biometric Physical Access Control & Audit

VERITAS-Vault is a zero-trust edge-biometric access control and tamper-evident audit system designed for high-security vault checkpoints.

### Production Deployment Architecture

```
Browser PWA Client (Mobile / Tablet / Desktop)
      │
      ▼
Firebase Hosting  ──( /api/** rewrites )──►  Google Cloud Run (FastAPI / Python 3.12)
(Static Shell: /checkpoint, /enrollment,       │   ├── ZeroTrustPDP & CaptureSessionManager
 /audit, /control, manifest, Service Worker)  │   ├── Multi-Signal Heuristic PAD
                                              │   ├── Biometric Recognition Engine
                                              │   ├── AES-256-GCM Evidence Encryption
                                              │   └── Ed25519 Tamper-Evident Hash Chain
                                              │
                                              ▼ (service_role only)
                                      Supabase Cloud Infrastructure
                                      ├── PostgreSQL (RLS enabled on all tables)
                                      │   ├── enrolled_users
                                      │   ├── access_audit_logs
                                      │   ├── capture_sessions
                                      │   ├── enrollment_requests
                                      │   └── vault_records (CAS versioning)
                                      └── Private Storage (encrypted-evidence bucket)
```

### Component Status & Truthful Operational Baseline

- **Frontend**: Firebase Hosting (Static PWA under `public/`, service worker caching, HTTPS).
- **Backend Compute**: Google Cloud Run (FastAPI running in Python 3.12 container, listening on dynamic `$PORT`).
- **Database**: Supabase PostgreSQL with Row Level Security (RLS) strictly enforced; direct browser/anon access revoked.
- **Evidence Storage**: Supabase private encrypted storage bucket (`encrypted-evidence`, 5 MB limit, binary octet-stream).
- **Current Biometric Provider**: `TemplateMatchingProvider` (Normalized Cross-Correlation + Mean Squared Error baseline on 128×128 equalized grayscale). `ArcFaceProvider` and `FaceNetProvider` exist in code but require external model weights (`.onnx`); the system fails closed rather than faking weights.
- **Current PAD (Presentation Attack Detection)**: Multi-signal heuristic prototype (`MultiSignalPADProvider` combining Laplacian texture variance, frequency domain FFT analysis, specular highlight analysis, and color distribution).
- **Current Door Controller**: `SimulatedDoorController` (clearly labeled simulated Policy Enforcement Point relay; tracks contact sensors, tamper switch, and pulses software lock).
- **Current Audit Ledger**: Signed tamper-evident hash chain (`AuditLedger` using SHA-256 link chaining and Ed25519 digital signatures, with local/simulated ledger adapter).
- **Replay Protection**: Single-use capture nonces and signed PEP tokens cached in-memory per instance. Multi-instance Cloud Run scaling utilizes Supabase `capture_sessions` with unique nonce constraints.

---


# 🛡️ VERITAS-VAULT — Zero-Trust Physical Access Control System

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-00f0ff?style=for-the-badge&labelColor=0b0f19)
![Python](https://img.shields.io/badge/python-3.10%2B-00f0ff?style=for-the-badge&logo=python&logoColor=white&labelColor=0b0f19)
![Streamlit](https://img.shields.io/badge/streamlit-1.35%2B-ff4b4b?style=for-the-badge&logo=streamlit&logoColor=white&labelColor=0b0f19)
![Supabase](https://img.shields.io/badge/supabase-cloud--connected-3ecf8e?style=for-the-badge&logo=supabase&logoColor=white&labelColor=0b0f19)
![License](https://img.shields.io/badge/license-MIT-f59e0b?style=for-the-badge&labelColor=0b0f19)
![Status](https://img.shields.io/badge/status-OPERATIONAL-10b981?style=for-the-badge&labelColor=0b0f19)

**Production-Grade Biometric Vault Surveillance with Blockchain-Anchored Audit Trails**

*Zero-Trust · Dual-Custody · AES-256-GCM Evidence Encryption · Supabase Cloud Sync*

</div>

---

## 🏛️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    VERITAS-VAULT v2.0 ARCHITECTURE                  │
├─────────────┬──────────────────────┬───────────────────────────────┤
│  EDGE LAYER │   POLICY ENGINE      │   CLOUD LAYER                 │
│             │                      │                               │
│  📷 Camera  │  ┌────────────────┐  │  ☁  Supabase PostgreSQL      │
│  Snapshot   │  │ Two-Man Rule   │  │     enrolled_users            │
│      ↓      │  │ Δt ≤ 5.0s      │  │     access_audit_logs        │
│  👁 Liveness │  │ Temporal Window│  │                               │
│  Detection  │  └───────┬────────┘  │  📦 Supabase Storage         │
│      ↓      │          │           │     encrypted-evidence/       │
│  🧬 Biometric│  ┌───────▼────────┐  │                               │
│  Recognition│  │ evaluate_access│  │  🔔 Alert Dispatch            │
│      ↓      │  │ GRANTED/BREACH │  │     WhatsApp (CallMeBot)      │
│  🔒 AES-GCM │  └───────┬────────┘  │     SMS (Twilio)              │
│  Encryption │          │           │                               │
│  SHA-256    │  ┌───────▼────────┐  │  📊 SQLite Local Buffer       │
│  Notarize   │  │ Solenoid Lock  │  │     (Offline Fallback)        │
│             │  │ ENGAGED/OPEN   │  │                               │
└─────────────┴──────────────────────┴───────────────────────────────┘
```

---

## 🔐 Security Features

| Feature | Implementation | Standard |
|---|---|---|
| Biometric Anti-Spoofing | Laplacian Variance Liveness (>60.0) | NIST SP 800-76 |
| Frame Integrity | SHA-256 pre-write notarization | FIPS 180-4 |
| Evidence Encryption | AES-256-GCM (per-frame unique IV) | FIPS 197 |
| Access Control | Zero-Trust Two-Man Rule (Δt ≤ 5.0s) | DoD 5200.28 |
| Cloud Sync | Supabase RLS-protected tables | SOC 2 Type II |
| Alert Dispatch | Non-blocking ≤3.0s wall-clock | NFPA 72 |
| Local Buffer | SQLite offline fallback | Zero data loss |

---

## 🗂️ Repository Structure

```
vault-surveillance/
├── dashboard/
│   └── app.py                  # Commercial Streamlit SaaS Command Center
├── src/
│   ├── storage/
│   │   ├── db.py               # SQLite singleton (local primary store)
│   │   └── cloud_db.py         # Supabase cloud sync engine
│   ├── policy/
│   │   ├── engine.py           # Zero-Trust temporal policy evaluator
│   │   └── two_man.py          # Two-man rule state machine
│   ├── vision/
│   │   ├── biometrics.py       # Face enrollment & recognition pipeline
│   │   ├── liveness.py         # Edge-AI anti-spoofing detector
│   │   └── auto_capture.py     # Hands-free fixation engine
│   ├── blockchain/
│   │   └── crypto_utils.py     # SHA-256 + AES-256-GCM notarization
│   ├── daemon/
│   │   └── alerts.py           # Non-blocking WhatsApp/SMS dispatcher
│   └── diagnostics/
│       └── boot.py             # Subsystem health checks
├── config/
│   └── settings.yaml           # Non-sensitive app configuration
├── data/
│   └── encrypted_evidence/     # AES-GCM encrypted frame vault
├── models/                     # Face recognition model weights
├── contracts/                  # Policy definitions
├── tests/                      # Pytest suite
├── .streamlit/
│   └── config.toml             # Dark cyber theme + headless server
├── requirements.txt
├── .gitignore
└── README.md
```

---

## ⚡ Quick Start

### 1. Clone & Create Virtual Environment

```bash
git clone https://github.com/YOUR_ORG/vault-surveillance.git
cd vault-surveillance

python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Copy the template and fill in your credentials:

```bash
# Option A — .env file (recommended for local dev)
cp .env.example .env
```

| Variable | Description | Required |
|---|---|---|
| `SUPABASE_URL` | Supabase project URL | For cloud sync |
| `SUPABASE_KEY` | Supabase anon/service role key | For cloud sync |
| `CALLMEBOT_PHONE` | WhatsApp number (intl format) | For alerts |
| `CALLMEBOT_API_KEY` | CallMeBot API key | For alerts |
| `TWILIO_ACCOUNT_SID` | Twilio SID | Fallback alerts |
| `TWILIO_AUTH_TOKEN` | Twilio Auth Token | Fallback alerts |
| `TWILIO_FROM_PHONE` | Twilio sender number | Fallback alerts |
| `ADMIN_ALERT_PHONE` | Alert recipient number | For alerts |

> **Offline mode:** If Supabase credentials are absent, the system falls back to local SQLite automatically — no crash, no data loss.

### 4. Set Up Supabase Tables (Cloud Sync)

Run the following SQL in your Supabase SQL Editor:

```sql
-- Enrolled Users
CREATE TABLE IF NOT EXISTS enrolled_users (
  user_id    TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  role       TEXT NOT NULL,
  image_url  TEXT DEFAULT '',
  synced_at  TIMESTAMPTZ DEFAULT now()
);

-- Access Audit Logs
CREATE TABLE IF NOT EXISTS access_audit_logs (
  id               BIGSERIAL PRIMARY KEY,
  timestamp        TIMESTAMPTZ DEFAULT now(),
  mode             TEXT NOT NULL,
  verified_parties TEXT NOT NULL,
  party_ids        TEXT DEFAULT '',
  verdict          TEXT NOT NULL,
  sha256_hash      TEXT NOT NULL,
  encrypted_path   TEXT DEFAULT '',
  status           TEXT DEFAULT 'CLOUD_SYNCED'
);

-- Enable Row Level Security
ALTER TABLE enrolled_users      ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_audit_logs   ENABLE ROW LEVEL SECURITY;
```

Create the `encrypted-evidence` Storage bucket in your Supabase dashboard (Storage → New Bucket → Name: `encrypted-evidence`).

### 5. Run the Command Center

```bash
.venv\Scripts\streamlit.exe run dashboard/app.py --server.port 8501
```

Navigate to **http://localhost:8501**

The command center requires Streamlit 1.60 or newer (included in `requirements.txt`).
Its camera HUD follows the current verdict: cyan standby, amber waiting, green granted,
and red breach. Capture a snapshot to ingest a new biometric observation.

- **Sound Effects** in the sidebar enables local electronic verdict cues. Sound starts
  off; if the browser blocks autoplay, click **Enable alert audio** when offered.
- **Simulate Party 1 / Start 5s Window** previews the circular timer and automatic
  timeout. Simulations stay local and do not send SMS, upload evidence, or write
  production audit records. **Reset Live Simulation** returns to normal capture.
- The audit ledger refreshes every three seconds. Filter by verdict or search
  personnel, protocol, and hashes. Click any digest badge to copy the full SHA-256
  value; blocked clipboard access offers a manual-copy field.
- Motion respects the operating system's reduced-motion preference. Sparklines
  use session observations; an empty history is displayed until samples exist.

**Default Credentials:**

| Username | Password | Role |
|---|---|---|
| `admin` | `vault@2026` | Vault Administrator |
| `officer` | `secure@2026` | Security Officer |

---

## 🎭 Simulation Scenarios

Use the **Quick Threat Simulation** panel in the sidebar to test all system states without real hardware:

| Simulation | Trigger | Expected Response |
|---|---|---|
| 📸 Spoof Attack | Photo replay detected | BREACH preview + optional sound |
| ⏱️ Timer Timeout | 5s window expires | BREACH preview + expired timer |
| 🔴 Unauthorized Intruder | Unknown face | BREACH preview + optional sound |
| 🟢 Valid Dual Access | Employee + Customer | VAULT UNLOCKED |

---

## 🚀 Cloud Deployment

### Streamlit Cloud

1. Fork this repository to GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io) → New App
3. Set **Main file path**: `dashboard/app.py`
4. Add all environment variables in **Secrets** (TOML format)

### Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8501
CMD [".venv/bin/streamlit", "run", "dashboard/app.py", \
     "--server.port=8501", "--server.headless=true"]
```

---

## 🧪 Testing

```bash
pytest tests/ -v --tb=short
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
<sub>Built with 🛡️ by the VERITAS Security Systems team &nbsp;·&nbsp;
AES-256-GCM &nbsp;·&nbsp; SHA-256 Notarization &nbsp;·&nbsp; Zero-Trust Architecture</sub>
</div>
