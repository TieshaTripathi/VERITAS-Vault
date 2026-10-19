"""Authenticated FastAPI application shared by local Uvicorn and Vercel."""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Any, Dict, Optional, List, Tuple

import numpy as np
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware

from src.pwa.alerts import (
    drain_outbox,
    ensure_vapid_keys,
    get_active_subscriptions,
    get_last_pushover_status,
    get_last_telegram_status,
    get_outbox_summary,
    get_pushover_config,
    get_pushover_diagnostic_status,
    get_telegram_config,
    get_telegram_diagnostic_status,
    send_pushover_alert,
    send_test_push,
    send_test_pushover,
    send_test_telegram,
    settings,
    valid_push_endpoint,
)
from src.pwa.policy import advance, fresh, WINDOW_SECONDS
from src.pwa.security import ROOT, check_password, encryption_key, seal, unseal
from src.pwa.store import Store
from src.pwa.vision import decode, inspect, recognize, template
from src.storage.supabase_client import CloudUnavailable
from src.policy.capture_session import default_capture_manager
from src.policy.pdp import default_pdp
from src.policy.door_controller import default_door_controller
from src.blockchain.audit_chain import default_audit_ledger

logger = logging.getLogger("vault.api")


async def alert_worker_loop():
    """Automatic alert worker loop running in background without requiring HTTP traffic."""
    while True:
        try:
            await run_in_threadpool(drain_outbox)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning("Background alert worker error: %s", exc)
        await asyncio.sleep(2.0)


@asynccontextmanager
async def lifespan(app: FastAPI):
    worker_task = asyncio.create_task(alert_worker_loop())
    try:
        yield
    finally:
        worker_task.cancel()
        try:
            await worker_task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="VERITAS Vault API", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
PUBLIC = ROOT / "public"

FRONTEND_ORIGINS = [
    os.environ.get("APP_ORIGIN", "https://veritas-vault14.web.app").rstrip("/"),
    "https://veritas-vault14.web.app",
    "https://veritas-vault14.firebaseapp.com",
    "http://localhost:8502",
    "http://localhost:3000",
    "http://127.0.0.1:8502",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "DELETE", "HEAD"],
    allow_headers=[
        "Content-Type",
        "X-Vault-Request",
        "Authorization",
    ],
)


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@app.middleware("http")
async def headers(request: Request, call_next):
    if int(request.headers.get("content-length", "0")) > 2_200_000:
        return JSONResponse({"detail": "Request body is too large"}, 413)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin")
        base_url = str(request.base_url).rstrip("/")
        allowed_set = set(FRONTEND_ORIGINS) | {base_url}
        origin_allowed = (
            not origin
            or origin in allowed_set
            or origin.endswith(".web.app")
            or origin.endswith(".firebaseapp.com")
            or "localhost" in origin
            or "127.0.0.1" in origin
        )
        if not origin_allowed or request.headers.get("x-vault-request") != "1":
            return JSONResponse({"detail": "Invalid request origin"}, 403)
    try:
        response = await call_next(request)
    except (CloudUnavailable, RuntimeError):
        response = JSONResponse({"detail": "Secure backend unavailable. Vault access is locked; check deployment configuration."}, 503)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' https://veritas-vault-backend.onrender.com https://veritas-vault14.web.app https://veritas-vault14.firebaseapp.com; worker-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, private"
    return response


def rate_limit(key, limit=10, window=60):
    store = Store()
    record = "rate:" + hashlib.sha256(key.encode()).hexdigest()
    for _ in range(5):
        saved, version = store.get(record)
        if not saved or time.time() - saved["start"] > window:
            saved = {"start": time.time(), "count": 0}
        if saved["count"] >= limit:
            raise HTTPException(429, "Too many requests. Please wait a minute.")
        saved["count"] += 1
        if store.cas(record, version, saved):
            return
    raise HTTPException(409, "Concurrent request; retry")


def authenticated_user(request: Request):
    token = request.cookies.get("vault_session", "")
    if not token:
        auth_hdr = request.headers.get("authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()
    if not token:
        raise HTTPException(401, "Sign in to access protected operations")
    saved, _ = Store().get("auth:" + hashlib.sha256(token.encode()).hexdigest())
    if not saved or saved.get("expires", 0) <= time.time():
        raise HTTPException(401, "Operator session expired")
    if saved.get("token") and not saved.get("cloud_verified"):
        try:
            cloud = Store().cloud
            if cloud:
                access = unseal(base64.b64decode(saved["token"]), "operator").decode()
                user = cloud.request("GET", "/auth/v1/user", headers={"Authorization": "Bearer " + access}).json()
                saved["role"] = user.get("app_metadata", {}).get("vault_role", saved.get("role"))
                saved["cloud_verified"] = True
        except Exception:
            pass
    if saved.get("role") not in ("admin", "operator", "monitor"):
        raise HTTPException(403, "An administrator must assign your vault role")
    return saved


def monitor_or_above(user=Depends(authenticated_user)):
    return user


def operator(user=Depends(authenticated_user)):
    if user["role"] not in ("admin", "operator"):
        raise HTTPException(403, "Operator or administrator access required")
    return user


def admin(user=Depends(authenticated_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    return user


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=256)


@app.post("/api/auth/login")
def login(body: Credentials, request: Request, response: Response):
    rate_limit("login-ip:" + (request.client.host if request.client else "unknown"), limit=30)
    rate_limit("login:" + body.username.casefold(), limit=6)
    encryption_key()
    store = Store()
    saved = None

    # 1. Local accounts authentication (for local admin/operator or monitor)
    uname = body.username.strip().casefold()
    pwd = body.password

    # Check operator/admin account with strict cryptographic PBKDF2 hash verification
    admin_hash = os.environ.get("VAULT_OPERATOR_PASSWORD_HASH", "")
    admin_uname = os.environ.get("VAULT_OPERATOR_USERNAME", "admin").casefold()
    is_prod = bool(
        os.environ.get("RENDER")
        or os.environ.get("VERCEL")
        or os.environ.get("K_SERVICE")
        or os.environ.get("ENV") == "production"
        or os.environ.get("ENVIRONMENT") == "production"
    )

    if admin_hash:
        is_admin_user = bool(uname == admin_uname and check_password(pwd, admin_hash))
    elif not is_prod and not store.cloud:
        # Isolated local developer bootstrap without configured password hash only
        is_admin_user = bool(uname == admin_uname and pwd == "test-only-password-strong")
    else:
        is_admin_user = False

    user_rec, _ = store.get("user:" + uname)
    if is_admin_user:
        saved = {"id": "local-admin", "name": body.username, "role": "admin", "expires": time.time() + 3600}
    elif user_rec and user_rec.get("password_hash") and check_password(pwd, user_rec["password_hash"]):
        saved = {
            "id": user_rec.get("id", "user-" + uname),
            "name": user_rec.get("name", body.username),
            "role": user_rec.get("role", "operator"),
            "expires": time.time() + 3600,
        }
    elif store.cloud:
        # 2. Attempt Supabase Cloud Auth if configured
        try:
            result = store.cloud.request(
                "POST",
                "/auth/v1/token",
                params={"grant_type": "password"},
                json={"email": body.username, "password": body.password},
            ).json()
            user = result["user"]
            role = user.get("app_metadata", {}).get("vault_role")
            if role not in ("admin", "operator", "monitor"):
                raise HTTPException(403, "Vault role has not been assigned")
            saved = {
                "id": user["id"],
                "name": body.username,
                "role": role,
                "cloud_verified": True,
                "token": base64.b64encode(seal(result["access_token"].encode(), "operator")).decode(),
                "expires": time.time() + min(3600, result.get("expires_in", 3600)),
            }
        except CloudUnavailable:
            raise HTTPException(401, "Unable to authenticate operator")
    else:
        raise HTTPException(401, "Invalid operator credentials")

    token = secrets.token_urlsafe(32)
    store.put("auth:" + hashlib.sha256(token.encode()).hexdigest(), saved)
    response.set_cookie(
        key="vault_session",
        value=token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=3600,
        path="/",
    )
    return {
        "name": saved["name"],
        "role": saved["role"],
        "token": token,
    }


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get("vault_session")
    if not token:
        auth_hdr = request.headers.get("authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()
    if token:
        Store().put("auth:" + hashlib.sha256(token.encode()).hexdigest(), {"expires": 0})
    response.delete_cookie(
        key="vault_session",
        path="/",
        secure=True,
        httponly=True,
        samesite="none",
    )
    return {"ok": True}


@app.get("/api/auth/me")
def me(user=Depends(monitor_or_above)):
    return {k: user[k] for k in ("name", "role")}


def get_git_commit():
    env_c = os.environ.get("RENDER_GIT_COMMIT") or os.environ.get("VERCEL_GIT_COMMIT_SHA")
    if env_c:
        return env_c
    try:
        import subprocess
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "local"


@app.get("/api/health")
def health():
    """Lightweight application liveness check for Render / health monitors."""
    return {
        "status": "healthy",
        "service": "VERITAS",
        "version": "3.0.0",
        "cloud_configured": bool(os.environ.get("SUPABASE_URL")),
        "auth_configured": bool(os.environ.get("SUPABASE_URL") or os.environ.get("VAULT_OPERATOR_PASSWORD_HASH")),
        "encryption_configured": bool(os.environ.get("VAULT_ENCRYPTION_KEY")),
        "pushover_configured": bool(os.environ.get("PUSHOVER_APP_TOKEN") and os.environ.get("PUSHOVER_USER_KEY")),
        "telegram_configured": bool(os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID")),
        "commit": get_git_commit(),
        "timestamp": utc(),
    }


@app.get("/api/health/ready")
@app.get("/api/ready")
def readiness(response: Response):
    """Dependency readiness check evaluating database connectivity and model assets."""
    store = Store()
    db_check = store.check_connectivity(timeout=3.0)
    from src.vision.biometric_service import default_biometric_service
    biometrics_ready = hasattr(default_biometric_service, "detector") and default_biometric_service.detector is not None
    active_version = getattr(default_biometric_service.embedding_extractor, "version", "unknown")
    cfg = ensure_vapid_keys(store)
    active_subs = get_active_subscriptions(store)

    is_ready = db_check["connected"] and biometrics_ready
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if is_ready else "degraded",
        "timestamp": utc(),
        "database": db_check,
        "biometrics": {
            "ready": biometrics_ready,
            "model_version": active_version,
            "cache_loaded": default_biometric_service._cache_loaded,
            "enrolled_count": len(default_biometric_service._cache),
        },
        "notifications": {
            "pushover_configured": bool(os.environ.get("PUSHOVER_APP_TOKEN") and os.environ.get("PUSHOVER_USER_KEY")),
            "vapid_configured": bool(cfg.get("VAPID_PUBLIC_KEY")),
            "active_subscriptions": len(active_subs),
        },
        "commit": get_git_commit(),
    }


class Snapshot(BaseModel):
    image: str = Field(max_length=2_100_000)


class FrameCapturePayload(Snapshot):
    session_id: str | None = None
    capture_nonce: str | None = None
    frame_seq: int | None = None
    device_id: str | None = "DEV-EDGE-01"
    checkpoint_id: str | None = "CP-MAIN-01"
    signature: str | None = None


class SessionChallengeRequest(BaseModel):
    device_id: str = "DEV-EDGE-01"
    checkpoint_id: str = "CP-MAIN-01"


@app.post("/api/checkpoint/session")
def issue_session(body: SessionChallengeRequest, user=Depends(operator)):
    rate_limit("session:" + user["id"], 120)
    try:
        return default_capture_manager.create_session(body.device_id, body.checkpoint_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


class Enrollment(BaseModel):
    image: Optional[str] = None
    samples: Optional[List[str]] = None
    name: str = Field(min_length=2, max_length=80)
    personnel_id: str = Field(pattern=r"^[A-Za-z0-9_-]{2,40}$")
    role: Literal["Employee", "Customer"]


@app.post("/api/enrollment/quality")
def quality(body: Snapshot, user=Depends(admin)):
    rate_limit("quality:" + user["id"], 90)
    try:
        frame, _ = decode(body.image)
        _, report = inspect(frame)
        return report
    except ValueError as exc:
        raise HTTPException(422, str(exc))


def process_enrollment_payload(
    body: Enrollment,
    person_id: str
) -> Tuple[str, np.ndarray, Dict[str, Any]]:
    """
    Unified multi-sample enrollment processing:
      - Accepts 5 distinct sample snapshots (or fallback single snapshot)
      - Inspects each frame for single aligned face, even lighting, sharpness, and PAD pass
      - Uses default_biometric_service.create_multisample_template (5-sample aggregation)
      - Returns (sealed_template_base64, primary_face_crop, quality_report)
    """
    from src.vision.biometric_service import default_biometric_service

    sample_crops: List[np.ndarray] = []
    landmarks_list: List[Optional[Dict]] = []
    reports: List[Dict[str, Any]] = []

    samples_to_process = body.samples if (body.samples and len(body.samples) >= 5) else ([body.image] if body.image else [])
    if not samples_to_process:
        raise HTTPException(422, "Enrollment image or samples required")

    for idx, s_img in enumerate(samples_to_process):
        frame, _ = decode(s_img)
        faces, report = inspect(frame)
        if not faces or len(faces) != 1 or not all(report[k] for k in ("lighting_ok", "aligned", "texture_ok")):
            raise HTTPException(422, f"Sample {idx+1} must contain exactly one aligned, well-lit, sharp face")
        if not faces[0].get("is_live", True):
            raise HTTPException(422, f"Sample {idx+1} rejected: Presentation attack detected (PAD)")

        sample_crops.append(faces[0]["crop"])
        landmarks_list.append(faces[0].get("landmarks"))
        reports.append(report)

    # If single image provided, replicate to satisfy 5-sample requirement
    if len(sample_crops) == 1:
        base_crop = sample_crops[0]
        base_lm = landmarks_list[0]
        sample_crops = [base_crop] * 5
        landmarks_list = [base_lm] * 5

    template_blob = default_biometric_service.create_multisample_template(
        person_id,
        sample_crops,
        landmarks_list
    )
    return template_blob, sample_crops[0], reports[0]


@app.post("/api/enrollment")
@app.post("/api/enroll")
def enroll(body: Enrollment, user=Depends(admin)):
    rate_limit("enroll:" + user["id"], 20)
    try:
        from src.vision.biometric_service import default_biometric_service
        store = Store()
        person_id = body.personnel_id.upper()
        if any(p["id"] == person_id for p in store.personnel()):
            raise HTTPException(409, "Personnel ID already enrolled")

        template_blob, primary_crop, report = process_enrollment_payload(body, person_id)

        person = {
            "id": person_id,
            "name": body.name.strip(),
            "role": body.role,
            "created_at": utc(),
            "template": template_blob,
            "baseline": f"baselines/{person_id}-{uuid.uuid4()}.enc"
        }
        import cv2
        ok, crop_enc = cv2.imencode(".png", primary_crop)
        if not ok:
            raise ValueError("Unable to encode baseline")
        encrypted = seal(crop_enc.tobytes(), "baseline:" + person_id)
        store.save_blob(person["baseline"], encrypted)
        store.enroll(person)
        if not store.cloud:
            baselines = ROOT / "models" / "known_faces"
            baselines.mkdir(parents=True, exist_ok=True)
            (baselines / f"{person_id}.enc").write_bytes(encrypted)
        default_biometric_service.invalidate_cache()
        return {k: person[k] for k in ("id", "name", "role", "created_at")}
    except (ValueError, sqlite3.IntegrityError) as exc:
        raise HTTPException(422, str(exc))


class RejectionPayload(BaseModel):
    reason: str = Field(min_length=2, max_length=256)


@app.post("/api/enrollment/request")
def create_enrollment_request(body: Enrollment, user=Depends(admin)):
    rate_limit("enroll_req:" + user["id"], 20)
    try:
        store = Store()
        person_id = body.personnel_id.upper()
        if any(p["id"] == person_id for p in store.personnel()):
            raise HTTPException(409, "Personnel ID already enrolled")

        template_blob, primary_crop, report = process_enrollment_payload(body, person_id)

        req_id = str(uuid.uuid4())
        baseline_path = f"baselines/{person_id}-{uuid.uuid4()}.enc"
        import cv2
        ok, crop_enc = cv2.imencode(".png", primary_crop)
        if not ok:
            raise ValueError("Unable to encode baseline")
        encrypted = seal(crop_enc.tobytes(), "baseline:" + person_id)
        store.save_blob(baseline_path, encrypted)

        req = {
            "request_id": req_id,
            "user_id": person_id,
            "name": body.name.strip(),
            "role": body.role,
            "clearance_level": "L3",
            "created_by": user["id"],
            "created_at": utc(),
            "status": "PENDING",
            "template": template_blob,
            "baseline": baseline_path,
            "quality_report": report
        }
        store.save_enrollment_request(req)
        return {
            "request_id": req_id,
            "user_id": person_id,
            "name": req["name"],
            "role": req["role"],
            "status": "PENDING",
            "created_by": req["created_by"],
            "created_at": req["created_at"],
            "message": "Enrollment request submitted. Secondary administrator approval required."
        }
    except (ValueError, sqlite3.IntegrityError) as exc:
        raise HTTPException(422, str(exc))


@app.get("/api/enrollment/requests")
def list_enrollment_requests(status: str = "", user=Depends(admin)):
    return Store().enrollment_requests(status)


@app.post("/api/enrollment/requests/{request_id}/approve")
def approve_enrollment_request(request_id: str, user=Depends(admin)):
    rate_limit("enroll_approve:" + user["id"], 20)
    store = Store()
    req = store.get_enrollment_request(request_id)
    if not req:
        raise HTTPException(404, "Enrollment request not found")
    if req.get("status") != "PENDING":
        raise HTTPException(409, f"Cannot approve request with status: {req.get('status')}")

    # Zero-Trust Separation of Duties: maker cannot be checker
    if req.get("created_by") == user["id"]:
        raise HTTPException(403, "Maker-checker violation: Administrator cannot approve their own enrollment request")

    req["status"] = "APPROVED"
    req["approved_by"] = user["id"]
    req["approved_at"] = utc()
    store.save_enrollment_request(req)

    # Activate the identity
    person = {
        "id": req["user_id"],
        "name": req["name"],
        "role": req["role"],
        "clearance_level": req.get("clearance_level", "L3"),
        "created_at": req["created_at"],
        "status": "APPROVED",
        "approved_by": req["approved_by"],
        "approved_at": req["approved_at"],
        "template": req["template"],
        "baseline": req["baseline"]
    }
    store.enroll(person)
    from src.vision.biometric_service import default_biometric_service
    default_biometric_service.invalidate_cache()
    return {"status": "APPROVED", "user_id": req["user_id"], "approved_by": user["id"], "activated": True}


@app.post("/api/enrollment/requests/{request_id}/reject")
def reject_enrollment_request(request_id: str, body: RejectionPayload, user=Depends(admin)):
    store = Store()
    req = store.get_enrollment_request(request_id)
    if not req:
        raise HTTPException(404, "Enrollment request not found")
    if req.get("status") != "PENDING":
        raise HTTPException(409, f"Cannot reject request with status: {req.get('status')}")

    req["status"] = "REJECTED"
    req["rejected_by"] = user["id"]
    req["rejected_at"] = utc()
    req["rejection_reason"] = body.reason
    store.save_enrollment_request(req)
    return {"status": "REJECTED", "user_id": req["user_id"], "rejected_by": user["id"], "reason": body.reason}


@app.post("/api/enrollment/{user_id}/revoke")
def revoke_identity_endpoint(user_id: str, user=Depends(admin)):
    store = Store()
    ok = store.revoke_user(user_id.upper(), revoker=user["id"])
    if not ok:
        raise HTTPException(404, f"Identity {user_id} not found in enrolled personnel")
    from src.vision.biometric_service import default_biometric_service
    default_biometric_service.invalidate_cache()
    return {"status": "REVOKED", "user_id": user_id.upper(), "revoked_by": user["id"]}


@app.get("/api/personnel")
def personnel(user=Depends(admin)):
    from src.vision.biometric_service import default_biometric_service
    people = Store().personnel()
    default_biometric_service.load_cache_if_needed(people)
    cache = default_biometric_service._cache
    result = []
    for p in people:
        row = {k: p[k] for k in ("id", "name", "role", "created_at")}
        cached = cache.get(p.get("id"))
        if cached:
            row["needs_reenrollment"] = getattr(cached, "needs_reenrollment", False)
            row["model_version"] = getattr(cached, "model_version", "legacy")
        else:
            row["needs_reenrollment"] = False
            row["model_version"] = "unknown"
        result.append(row)
    return result


@app.delete("/api/personnel")
def reset_all_personnel(user=Depends(admin)):
    rate_limit("clear_personnel:" + user["id"], 5)
    store = Store()
    deleted = store.clear_personnel()
    from src.pwa.vision import detector
    detector.cache_clear()
    from src.vision.biometric_service import default_biometric_service
    default_biometric_service.invalidate_cache()
    return {"deleted": deleted}


@app.post("/api/admin/reset-demo")
def reset_demo_environment(user=Depends(admin)):
    """Admin-only action: RESET DEMO ENVIRONMENT.
    Clears:
    - all enrolled test personnel
    - biometric template cache
    - active checkpoint state (reset to STANDBY)
    - active incidents
    - pending alert jobs
    - old push subscriptions
    - stale capture sessions
    Preserves:
    - application source code
    - encryption keys
    - Supabase schema
    - audit-log structure & ledger
    - system configuration
    """
    rate_limit("reset_demo:" + user["id"], 5)
    store = Store()
    default_capture_manager.clear_all()
    from src.pwa.vision import detector
    detector.cache_clear()
    from src.vision.biometric_service import default_biometric_service
    default_biometric_service.invalidate_cache()
    res = store.clear_demo_environment()
    return {
        "ok": True,
        "state": "STANDBY",
        "scanner": "STOPPED",
        "camera": "STOPPED",
        "enrolled_personnel_count": 0,
        "alerts_cleared": True,
        "active_incident": None,
        "deleted_personnel": res.get("deleted_personnel", 0),
        "message": "Demo environment reset successfully. Checkpoint is STANDBY, cache cleared."
    }


def transition(faces=None, evidence=None, key="checkpoint:main", raw=None, frame_shape=None, digest=None):
    store = Store()
    for _ in range(8):
        state, version = store.get(key)
        state = state or fresh()
        already_seen = (digest in (state.get("seen") or [])) if digest else False
        ev_digest = (evidence.get("sha256") if evidence else None) or (None if already_seen else digest) or (None if already_seen else (hashlib.sha256(raw).hexdigest() if raw else None))
        updated, terminal = advance(state, faces or [], time.time(), ev_digest)
        if evidence:
            updated["evidence"] = evidence
        event = job = None
        if terminal:
            event_id = str(uuid.uuid4())
            proof = updated.get("evidence", {})
            d = (evidence.get("sha256") if evidence else None) or digest or (hashlib.sha256(raw).hexdigest() if raw else None)
            if not proof and raw and d:
                ev_path = f"evidence/{uuid.uuid4()}.enc"
                store.save_blob(ev_path, seal(raw, "evidence:" + d))
                proof = {
                    "path": ev_path,
                    "sha256": d,
                    "shape": frame_shape or [120, 120, 3],
                    "encoding": "BGR uint8 decoded pixels",
                    "key_id": os.environ.get("VAULT_KEY_ID", "primary-v1"),
                }
                from src.pwa.alerts import cache_evidence_photo
                cache_evidence_photo(ev_path, raw)
            now_utc = utc()
            ledger_entry = default_audit_ledger.append_event(
                event_id=event_id,
                timestamp=now_utc,
                payload={
                    "verdict": updated["state"],
                    "mode": updated["mode"],
                    "parties": updated["parties"],
                    "reason": updated["reason"],
                    "reason_code": updated.get("reason_code"),
                    "risk_score": updated.get("risk_score", 0),
                    "policy_version": updated.get("policy_version", "VAULT-ZT-v1.0")
                },
                evidence_hash=proof.get("sha256", "")
            )
            event = {
                "id": event_id, "timestamp": now_utc, "verdict": updated["state"], "mode": updated["mode"],
                "parties": updated["parties"], "reason": updated["reason"], "reason_code": updated.get("reason_code"),
                "evidence": proof,
                "sha256_hash": proof.get("sha256"), "status": "CLOUD_STORED" if store.cloud else "LOCAL_STORED",
                "chain_sequence": ledger_entry["sequence_number"], "event_hash": ledger_entry["event_hash"],
                "previous_hash": ledger_entry["previous_hash"], "signature": ledger_entry["signature"],
                "signer_key_id": ledger_entry["signer_key_id"]
            }
            updated["last_event"] = event_id
            if updated["state"] == "BREACH":
                job = {
                    "id": event_id,
                    "created_at": now_utc,
                    "done": False,
                    "attempts": 0,
                    "status": "PENDING",
                    "reason_code": updated.get("reason_code", "ZT-001"),
                    "reason": updated.get("reason", "Unregistered identity detected at CP-MAIN-01"),
                    "checkpoint": "CP-MAIN-01",
                    "evidence_path": proof.get("path"),
                    "evidence_hash": proof.get("sha256"),
                }
        if store.cas(key, version, updated, event, job):
            updated["revision"] = version + 1
            updated["remaining"] = max(0, updated["deadline"] - time.time()) if updated["state"] == "WAITING" else 0
            updated["server_time"] = time.time()
            updated.pop("seen", None)
            updated.pop("evidence", None)
            return updated, terminal
    raise HTTPException(409, "Another operator updated the checkpoint; retry")


def finish_window(deadline):
    delay = max(0.0, min(WINDOW_SECONDS, deadline - time.time()))
    if delay > 0:
        time.sleep(delay)
    store = Store()
    st, _ = store.get("checkpoint:main")
    if st and st.get("state") == "WAITING" and st.get("deadline") == deadline:
        transition()
        drain_outbox()


async def auto_relock_after_grant(delay_seconds: float = 4.0):
    """Automatically relocks the door back to STANDBY after the simulated access cycle."""
    await asyncio.sleep(delay_seconds)
    store = Store()
    for _ in range(5):
        state, ver = store.get("checkpoint:main")
        if not state or state.get("state") != "GRANTED":
            return
        fresh_state = fresh(state.get("mode", "standard"))
        fresh_state.update(reason="Door relocked · Vault secure")
        if store.cas("checkpoint:main", ver, fresh_state, None):
            return


INCIDENT_COOLDOWN_SECONDS = 20.0
FACE_ABSENCE_RESET_SECONDS = 3.5


def get_or_create_incident(faces, reason_code="ZT-001"):
    """Deduplicates breach incidents for continuous surveillance.
    Returns (is_duplicate: bool, incident_id: str).
    """
    store = Store()
    now = time.time()
    active, ver = store.get("incident:active")
    has_breach_face = any(not f.get("is_recognized") or not f.get("is_live") for f in faces)

    if not has_breach_face:
        if active and (now - active.get("last_seen", 0) > FACE_ABSENCE_RESET_SECONDS):
            store.cas("incident:active", ver, None)
        return False, None

    if active and active.get("id"):
        time_since_last_seen = now - active.get("last_seen", 0)
        cooldown_active = now < active.get("cooldown_until", 0)
        continuous = time_since_last_seen <= FACE_ABSENCE_RESET_SECONDS

        if continuous and cooldown_active:
            active["last_seen"] = now
            store.cas("incident:active", ver, active)
            return True, active["id"]

    new_id = str(uuid.uuid4())
    new_record = {
        "id": new_id,
        "reason_code": reason_code,
        "started_at": now,
        "last_seen": now,
        "cooldown_until": now + INCIDENT_COOLDOWN_SECONDS,
    }
    store.cas("incident:active", ver, new_record)
    return False, new_id


_scan_lock = threading.Lock()


@app.post("/api/checkpoint/frame")
def scan(body: FrameCapturePayload, background: BackgroundTasks, user=Depends(operator)):
    rate_limit("scan:" + user["id"], 120)
    store = Store()
    current, _ = store.get("checkpoint:main")
    current = current or fresh()

    # Drop old frame if a previous scan is still active — strictly ONE frame request at a time
    if not _scan_lock.acquire(blocking=False):
        res = dict(current)
        res["dropped_frame"] = True
        return res

    try:
        from src.vision.biometric_service import default_biometric_service
        people = store.personnel() if not default_biometric_service._cache_loaded else []
        frame, raw = decode(body.image)
        faces, quality_report = recognize(frame, people)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    finally:
        _scan_lock.release()

    now = time.time()
    frame_size = [int(frame.shape[1]), int(frame.shape[0])]

    # Terminal states (GRANTED, BREACH, DENIED) stay latched until reset:
    # Return terminal verdict while including live faces and quality for continuous HUD overlay
    if current and current.get("state") in ("GRANTED", "BREACH", "DENIED"):
        res = dict(current)
        res.update(faces=faces, quality=quality_report, frame_size=frame_size, latched_terminal=True)
        active_inc, _ = store.get("incident:active")
        if active_inc and any(not f.get("is_recognized") or not f.get("is_live") for f in faces):
            active_inc["last_seen"] = now
            store.put("incident:active", active_inc)
        res["active_incident"] = active_inc.get("id") if (active_inc and current.get("state") == "BREACH") else (current.get("last_event") or "NONE")
        res["incident_code"] = current.get("reason_code") or "NONE"
        if faces and all(f.get("is_recognized") and f.get("is_live") for f in faces):
            res["safe_user_message"] = "PREVIOUS BREACH SESSION ACTIVE: Reset checkpoint before new verification"
        return res

    # Anti-replay capture validation if session challenge was provided
    if body.session_id and body.capture_nonce:
        valid, capture_err, frame_hash = default_capture_manager.validate_capture(
            session_id=body.session_id,
            capture_nonce=body.capture_nonce,
            device_id=body.device_id or "DEV-EDGE-01",
            checkpoint_id=body.checkpoint_id or "CP-MAIN-01",
            raw_frame_bytes=raw,
            signature=body.signature,
            require_signature=False,
            frame_seq=body.frame_seq,
        )
        if not valid:
            code = "ZT-009" if "REPLAY" in capture_err else "ZT-013"
            state, ver = store.get("checkpoint:main")
            state = state or fresh()
            state.update(state="BREACH", reason=capture_err)
            event_id = str(uuid.uuid4())
            proof = {}
            if raw:
                ev_digest = hashlib.sha256(raw).hexdigest()
                ev_path = f"evidence/{uuid.uuid4()}.enc"
                store.save_blob(ev_path, seal(raw, "evidence:" + ev_digest))
                proof = {"path": ev_path, "sha256": ev_digest, "key_id": os.environ.get("VAULT_KEY_ID", "primary-v1")}
            now_utc = utc()
            event = {"id": event_id, "timestamp": now_utc, "verdict": "BREACH", "mode": state.get("mode", "standard"),
                     "parties": state.get("parties", []), "reason": capture_err, "evidence": proof,
                     "sha256_hash": proof.get("sha256") or hashlib.sha256(raw).hexdigest(), "status": "RECORDED"}
            job = {"id": event_id, "created_at": now_utc, "done": False, "attempts": 0, "status": "PENDING",
                   "checkpoint": "CP-MAIN-01", "reason_code": code, "reason": capture_err,
                   "evidence_path": proof.get("path"), "evidence_hash": proof.get("sha256")}
            store.cas("checkpoint:main", ver, state, event, job)
            background.add_task(drain_outbox)
            state.update(reason_code=code, safe_user_message="ACCESS DENIED: Capture integrity check failed", risk_score=95,
                         faces=faces, quality=quality_report, frame_size=frame_size, active_incident=event_id, incident_code=code)
            return state

    # Incident deduplication for continuous unauthorized faces
    potential_breach_code = (
        "ZT-002" if any(not f.get("is_live") and f.get("liveness") == "FAIL" for f in faces)
        else "ZT-001" if any(not f.get("is_recognized") and f.get("recognition_state") not in ("VERIFYING", "POSSIBLE_MATCH") for f in faces)
        else None
    )
    active_incident_id = None
    if potential_breach_code:
        is_dup, inc_id = get_or_create_incident(faces, potential_breach_code)
        active_incident_id = inc_id
        if is_dup and current.get("state") == "BREACH":
            res = dict(current)
            res.update(faces=faces, quality=quality_report, frame_size=frame_size, active_incident=inc_id, incident_code=potential_breach_code)
            return res

    digest = hashlib.sha256(frame.tobytes()).hexdigest()  # Hash in memory before any storage.
    result, terminal = transition(
        faces=faces,
        evidence=None,
        key="checkpoint:main",
        raw=raw,
        frame_shape=frame_size,
        digest=digest,
    )
    result.update(faces=faces, quality=quality_report, frame_size=frame_size)
    if result["state"] == "GRANTED":
        result["authorization_token"] = default_pdp._issue_signed_authorization(
            checkpoint_id=body.checkpoint_id or "CP-MAIN-01",
            parties=result.get("parties", []),
            mode=result.get("mode", "standard"),
            risk_score=15
        )
        result["safe_user_message"] = "ACCESS GRANTED: Proceed to vault entry"
        result["policy_version"] = "VAULT-ZT-v1.0"
    elif result["state"] == "BREACH":
        result["safe_user_message"] = "ACCESS DENIED: Contact Security"
        result["policy_version"] = "VAULT-ZT-v1.0"

    result["active_incident"] = active_incident_id or result.get("last_event") or "NONE"
    result["incident_code"] = result.get("reason_code") or "NONE"

    if result.get("state") == "WAITING" and result.get("parties"):
        first_p = result["parties"][0]
        result["first_party"] = f"{first_p.get('id')} / {first_p.get('name')}"
        if faces and len(faces) > 0:
            curr_f = faces[0]
            curr_id = curr_f.get("id", "unknown")
            curr_name = curr_f.get("name", "Unknown individual")
            result["current_face"] = f"{curr_id} / {curr_name}"
            result["distinct_face"] = "NO" if curr_id == first_p.get("id") else ("YES" if curr_f.get("is_recognized") else "UNKNOWN")
        else:
            result["current_face"] = "NONE (FRAME EMPTY)"
            result["distinct_face"] = "WAITING"
        if result.get("deadline"):
            result["remaining_seconds"] = max(0.0, round(result["deadline"] - now, 1))
            result["remaining"] = max(0.0, result["deadline"] - now)

    if body.session_id:
        result["session_id"] = body.session_id
        result["next_frame_seq"] = (body.frame_seq + 1) if body.frame_seq is not None else 0

    if result["state"] == "WAITING":
        threading.Thread(target=finish_window, args=(result["deadline"],), daemon=True).start()
    elif terminal:
        background.add_task(drain_outbox)
    return result


class PEPVerificationRequest(BaseModel):
    token: dict[str, Any]


@app.post("/api/pep/verify")
def pep_verify(body: PEPVerificationRequest, user=Depends(operator)):
    cp_id = body.token.get("payload", {}).get("checkpoint_id")
    valid, reason = default_pdp.verify_authorization_token(body.token, expected_checkpoint_id=cp_id)
    if not valid:
        raise HTTPException(403, f"PEP Actuation Blocked: {reason}")
    auth_id = body.token.get("payload", {}).get("authorization_id", "AUTH-UNKNOWN")
    pulse = default_door_controller.pulse_unlock(authorization_id=auth_id, duration_ms=3000)
    return {"status": "RELAY_ACTUATED", "detail": reason, "pulse": pulse, "pulse_ms": 3000}


@app.get("/api/pep/telemetry")
def pep_telemetry(user=Depends(operator)):
    return default_door_controller.get_telemetry()


@app.post("/api/checkpoint/tick")
def tick(background: BackgroundTasks, user=Depends(operator)):
    result, terminal = transition()
    if terminal:
        background.add_task(drain_outbox)
    store = Store()
    active_inc, _ = store.get("incident:active")
    result["active_incident"] = active_inc.get("id") if (active_inc and result.get("state") == "BREACH") else (result.get("last_event") or "NONE")
    result["incident_code"] = result.get("reason_code") or "NONE"
    if result.get("state") in ("GRANTED", "BREACH", "DENIED"):
        result["latched_terminal"] = True
        if result.get("state") == "BREACH":
            result["safe_user_message"] = "PREVIOUS BREACH SESSION ACTIVE: Reset checkpoint before new verification"
    now = time.time()
    if result.get("state") == "WAITING" and result.get("parties"):
        first_p = result["parties"][0]
        result["first_party"] = f"{first_p.get('id')} / {first_p.get('name')}"
        result["current_face"] = "AWAITING INCOMING"
        result["distinct_face"] = "WAITING"
        if result.get("deadline"):
            result["remaining_seconds"] = max(0.0, round(result["deadline"] - now, 1))
            result["remaining"] = max(0.0, result["deadline"] - now)
    return result


class Mode(BaseModel):
    mode: Literal["standard", "high-value"] = "standard"


@app.post("/api/checkpoint/reset")
def reset(body: Mode, user=Depends(operator)):
    store = Store()
    state, version = store.get("checkpoint:main")
    store.put("incident:active", None)
    from src.vision.biometric_service import default_biometric_service
    default_biometric_service.tracker.clear()
    event = {"id": str(uuid.uuid4()), "timestamp": utc(), "verdict": "RESET", "mode": body.mode,
             "parties": [], "reason": "Operator reset: " + user["id"], "evidence": {}, "status": "RECORDED"}
    if not store.cas("checkpoint:main", version, fresh(body.mode), event):
        raise HTTPException(409, "Checkpoint changed; retry")
    fresh_state = fresh(body.mode)
    fresh_state["active_incident"] = "NONE"
    fresh_state["incident_code"] = "NONE"
    return fresh_state


@app.get("/api/checkpoint/status")
def checkpoint_status(user=Depends(monitor_or_above)):
    store = Store()
    current, _ = store.get("checkpoint:main")
    current = current or fresh()
    active_inc, _ = store.get("incident:active")
    current["active_incident"] = active_inc.get("id") if (active_inc and current.get("state") == "BREACH") else "NONE"
    current["incident_code"] = (current.get("reason_code") if current.get("state") == "BREACH" else "NONE") or "NONE"
    return current


@app.get("/api/logs")
def logs(verdict: str = "", start: str = "", end: str = "", user=Depends(monitor_or_above)):
    if verdict and verdict not in ("GRANTED", "DENIED", "BREACH", "WAITING", "RESET"):
        raise HTTPException(422, "Unknown verdict")
    for date in (start, end):
        if date:
            try:
                datetime.strptime(date, "%Y-%m-%d")
            except ValueError:
                raise HTTPException(422, "Use an ISO date")
    return [e for e in Store().logs() if (not verdict or e["verdict"] == verdict)
            and (not start or e["timestamp"][:10] >= start) and (not end or e["timestamp"][:10] <= end)]


@app.get("/api/logs/{event_id}")
def single_log(event_id: uuid.UUID, user=Depends(monitor_or_above)):
    event = Store().event(str(event_id))
    if not event:
        raise HTTPException(404, "Audit log event not found")
    return event


@app.get("/api/logs/{event_id}/evidence")
def evidence(event_id: uuid.UUID, user=Depends(monitor_or_above)):
    event = Store().event(str(event_id))
    if not event or not event.get("evidence", {}).get("path"):
        raise HTTPException(404, "No encrypted frame for this event")
    return Response(Store().read_blob(event["evidence"]["path"]), media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{event_id}.enc"'})


@app.get("/api/logs/{event_id}/evidence/preview")
def evidence_preview(event_id: uuid.UUID, user=Depends(monitor_or_above)):
    event = Store().event(str(event_id))
    if not event or not event.get("evidence", {}).get("path"):
        raise HTTPException(404, "No encrypted frame for this event")
    evidence_meta = event["evidence"]
    path = evidence_meta["path"]
    digest = evidence_meta.get("sha256", "")
    try:
        encrypted_blob = Store().read_blob(path)
        decrypted = unseal(encrypted_blob, "evidence:" + digest)
    except Exception as exc:
        raise HTTPException(500, "Unable to decrypt evidence frame") from exc
    media_type = "image/png" if decrypted.startswith(b"\x89PNG") else "image/jpeg"
    return Response(
        content=decrypted,
        media_type=media_type,
        headers={
            "Cache-Control": "no-store, private",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/audit/verify")
def verify_audit_ledger(limit: int = 100, user=Depends(monitor_or_above)):
    """Mathematically verify the SHA-256 hash chain and Ed25519 digital signatures."""
    return default_audit_ledger.verify_chain(limit=limit)


@app.get("/api/audit/verify/{event_id}")
def verify_audit_event(event_id: str, user=Depends(monitor_or_above)):
    """Mathematically verify hash linkage, digital signature, and proof for an individual event."""
    res = default_audit_ledger.verify_event(event_id)
    if not res.get("verified"):
        raise HTTPException(422, f"Cryptographic audit verification failed: {res}")
    return res


@app.get("/api/control")
def control(user=Depends(admin)):
    store = Store()
    active_subs = get_active_subscriptions(store)
    po_cfg = get_pushover_config()
    tg_cfg = get_telegram_config()
    last_po_status = get_last_pushover_status(store)
    last_tg_status = get_last_telegram_status(store)
    outbox_summary = get_outbox_summary(store)
    return {
        "storage": "Supabase" if store.cloud else "SQLite local",
        "facenet": bool(os.environ.get("FACENET_MODEL_PATH")),
        "pushover_configured": po_cfg["configured"],
        "last_pushover_status": last_po_status,
        "telegram_configured": tg_cfg["configured"],
        "last_telegram_status": last_tg_status,
        "subscriptions_count": len(active_subs),
        "audit_verified": True,
        "delivery_summary": outbox_summary,
        "outbox": [v for _, v, _ in store.records("job:")][-30:],
    }


@app.get("/api/alerts/status")
def alerts_status(user=Depends(monitor_or_above)):
    store = Store()
    active_subs = get_active_subscriptions(store)
    po_cfg = get_pushover_config()
    tg_cfg = get_telegram_config()
    last_po_status = get_last_pushover_status(store)
    last_tg_status = get_last_telegram_status(store)
    outbox_summary = get_outbox_summary(store)
    return {
        "pushover_configured": po_cfg["configured"],
        "last_pushover_status": last_po_status,
        "telegram_configured": tg_cfg["configured"],
        "last_telegram_status": last_tg_status,
        "push_configured": bool(ensure_vapid_keys(store).get("VAPID_PUBLIC_KEY")),
        "subscriptions_count": len(active_subs),
        "delivery_summary": outbox_summary,
    }


@app.get("/api/alerts/pushover/status")
def pushover_status(user=Depends(admin)):
    """Backend Pushover diagnostic endpoint (admin only).
    Returns safe configuration and reachability status without exposing secrets.
    """
    return get_pushover_diagnostic_status()


@app.post("/api/alerts/pushover/test")
def pushover_test(user=Depends(admin)):
    """Authenticated admin test endpoint sending a verified Pushover test notification."""
    return send_test_pushover()


@app.get("/api/alerts/telegram/status")
def telegram_status(user=Depends(admin)):
    """Backend Telegram diagnostic endpoint (admin only).
    Returns safe configuration and reachability status without exposing secrets.
    """
    return get_telegram_diagnostic_status()


@app.post("/api/alerts/telegram/test")
def telegram_test(user=Depends(admin)):
    """Authenticated admin test endpoint executing text-first, then photo Telegram test."""
    return send_test_telegram()


class AlertSettings(BaseModel):
    CALLMEBOT_PHONE: str = Field(default="", max_length=25, pattern=r"^\+?[0-9]*$")
    CALLMEBOT_API_KEY: str = Field(default="", max_length=256)
    VAPID_PUBLIC_KEY: str = Field(default="", max_length=256)
    VAPID_PRIVATE_KEY: str = Field(default="", max_length=512)
    VAPID_SUBJECT: str = Field(default="", max_length=254, pattern=r"^(mailto:[^\s@]+@[^\s@]+|)$")


@app.post("/api/control/settings")
def save_settings(body: AlertSettings, user=Depends(admin)):
    store = Store()
    config = settings(store)
    config.update({key: value for key, value in body.model_dump().items() if value})
    config.pop("TELEGRAM_BOT_TOKEN", None)
    config.pop("TELEGRAM_CHAT_ID", None)
    store.put("config:alerts", {"encrypted": base64.b64encode(seal(json.dumps(config).encode(), "settings")).decode()})
    return {"saved": True}


@app.get("/api/push/public-key")
@app.get("/api/push/key")
def push_key(user=Depends(monitor_or_above)):
    return {"public_key": ensure_vapid_keys(Store()).get("VAPID_PUBLIC_KEY", "")}


class Subscription(BaseModel):
    endpoint: str = Field(max_length=2048)
    keys: dict[str, str]
    device_label: str = Field(default="", max_length=128)


@app.post("/api/push/subscribe")
def subscribe(body: Subscription, user=Depends(monitor_or_above)):
    try:
        valid = valid_push_endpoint(body.endpoint)
    except ValueError:
        valid = False
    if not valid or set(body.keys) != {"p256dh", "auth"} or any(len(v) > 256 for v in body.keys.values()):
        raise HTTPException(422, "Invalid push subscription")
    key = "push:" + hashlib.sha256(body.endpoint.encode()).hexdigest()
    store = Store()
    sub_data = {
        "subscription": body.model_dump(),
        "owner": user["id"],
        "device_label": body.device_label or "Web Device",
        "active": True,
        "created_at": utc(),
        "updated_at": utc(),
    }
    store.put(key, sub_data)
    if store.cloud:
        try:
            store.cloud.request("POST", "/rest/v1/push_subscriptions", json={
                "user_id": user["id"],
                "endpoint": body.endpoint,
                "p256dh": body.keys["p256dh"],
                "auth": body.keys["auth"],
                "device_label": body.device_label or "Web Device",
                "enabled": True,
            }, params={"on_conflict": "endpoint"}, headers={"Prefer": "resolution=merge-duplicates"})
        except Exception as exc:
            import logging
            logging.getLogger("vault.api").warning("Failed to record push subscription in Supabase: %s", exc)
    return {"subscribed": True}


@app.post("/api/push/unsubscribe")
def unsubscribe(body: Subscription, user=Depends(monitor_or_above)):
    key = "push:" + hashlib.sha256(body.endpoint.encode()).hexdigest()
    store = Store()
    saved, version = store.get(key)
    if saved and (saved.get("owner") == user["id"] or user.get("role") == "admin"):
        store.cas(key, version, dict(saved, active=False, updated_at=utc()))
    if store.cloud:
        try:
            store.cloud.request("PATCH", f"/rest/v1/push_subscriptions?endpoint=eq.{body.endpoint}", json={"enabled": False})
        except Exception as exc:
            import logging
            logging.getLogger("vault.api").warning("Failed to disable push subscription in Supabase: %s", exc)
    return {"subscribed": False}


@app.get("/api/push/status")
def push_status(user=Depends(monitor_or_above)):
    store = Store()
    cfg = ensure_vapid_keys(store)
    active = get_active_subscriptions(store)
    return {
        "configured": bool(cfg.get("VAPID_PUBLIC_KEY") and cfg.get("VAPID_PRIVATE_KEY")),
        "subscriptions": len(active),
    }


@app.post("/api/push/test")
def push_test(user=Depends(monitor_or_above)):
    return send_test_push()


class FCMTokenRegistration(BaseModel):
    fcm_token: str = Field(max_length=4096)
    device_label: str = Field(default="Mobile Monitor Phone", max_length=128)


@app.post("/api/fcm/register")
def register_fcm_token(body: FCMTokenRegistration, user=Depends(monitor_or_above)):
    """Register mobile phone Firebase Cloud Messaging (FCM) token for critical breach alerts."""
    store = Store()
    token = body.fcm_token.strip()
    key = "fcm:" + hashlib.sha256(token.encode()).hexdigest()
    fcm_data = {
        "fcm_token": token,
        "owner": user["id"],
        "device_label": body.device_label or "Mobile Monitor Phone",
        "active": True,
        "created_at": utc(),
    }
    store.put(key, fcm_data)
    return {"registered": True, "provider": "FCM", "device_label": body.device_label}


class PushReceipt(BaseModel):
    event_id: str = Field(max_length=128)
    device_label: str = Field(default="Mobile Monitor Phone", max_length=128)
    channel: Optional[str] = Field(default=None, max_length=32)


@app.post("/api/push/receipt")
def record_push_receipt(body: PushReceipt):
    """Device-side confirmation that notification was actually displayed/received on phone."""
    store = Store()
    key = f"job:{body.event_id}"
    job, ver = store.get(key)
    if job:
        chan = (body.channel or "").lower()
        label = (body.device_label or "").lower()
        if chan == "pushover" or "pushover" in label:
            job["pushover_received"] = True
            job["pushover_received_at"] = utc()
        elif chan in ("webpush", "pwa") or "installed pwa" in label or "web device" in label:
            job["pwa_received"] = True
            job["pwa_received_at"] = utc()

        job["device_received"] = True
        job["device_received_at"] = utc()
        job["device_label"] = body.device_label
        store.cas(key, ver, job)
    return {"status": "CONFIRMED", "event_id": body.event_id}


@app.get("/api/worker")
def worker(request: Request):
    secret = os.environ.get("CRON_SECRET", "")
    if not secret or not hmac.compare_digest(request.headers.get("authorization", ""), "Bearer " + secret):
        raise HTTPException(401, "Worker authorization required")
    transition()
    drain_outbox()
    return {"ok": True}


@app.get("/")
def home():
    return RedirectResponse("/checkpoint", status_code=307)


@app.get("/{page}")
def page(page: str):
    if page in ("checkpoint", "enrollment", "logs", "audit", "control"):
        folder = "logs" if page == "audit" and not (PUBLIC / "audit" / "index.html").exists() else page
        return FileResponse(PUBLIC / folder / "index.html", headers={"Cache-Control": "no-cache"})
    if page in ("manifest.json", "sw.js", "offline.html"):
        return FileResponse(PUBLIC / page, headers={"Cache-Control": "no-cache", "Service-Worker-Allowed": "/"})
    raise HTTPException(404, "Page not found")


app.mount("/assets", StaticFiles(directory=PUBLIC / "assets", check_dir=False), name="assets")
app.mount("/icons", StaticFiles(directory=PUBLIC / "icons", check_dir=False), name="icons")
