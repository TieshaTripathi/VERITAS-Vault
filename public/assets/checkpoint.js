import {
  $,
  escape,
  api,
  post,
  action,
  toast,
  currentUser,
  startCamera,
  snapshot,
  ring,
} from "./common.js";
import {
  initAudio,
  startAlarm,
  stopAlarm,
  acknowledgeAlert,
  isAlarmActive,
  isMuted,
  setMuted,
  evaluateSecurityEvent,
  getActiveAlert,
  clearActiveAlert,
  testSiren,
  testTelegram,
  getAlertsStatus,
  CRITICAL_REASON_CODES,
} from "./alerts.js";

// Scanner runtime constants & state
const SCAN_INTERVAL = 1200; // 1200ms recognition interval for optimal performance
let stopCamera = null;
let loop = null;
let busy = false; // Strict scan lock: only one recognition request at a time
let state = "STANDBY";
let end = 0;
let revision = -1;
let manuallyStopped = false;
let animFrameId = null;
let trackCounter = 1;
let tracks = [];
let cameraStarting = false;

// Anti-replay session caching (Phase 5)
let activeSession = null;
let activeSessionExpiresAt = 0;
let frameSequence = 0;

// Single breach popup tracking (Phase 8: one event ID -> one modal)
const shownEventIds = new Set();
let telegramConfigured = false;

const video = $("#camera");
const canvas = $("#hud-overlay");
const ctx = canvas ? canvas.getContext("2d") : null;
let hudStatusEl = null;

function getHudStatus() {
  if (!hudStatusEl && $("#hud")) {
    hudStatusEl = document.createElement("div");
    hudStatusEl.id = "hud-status";
    hudStatusEl.style.cssText =
      "position:absolute;top:10px;left:14px;right:14px;background:rgba(11,15,25,0.88);backdrop-filter:blur(8px);border-left:3px solid var(--state,#00f0ff);color:var(--state,#00f0ff);font-family:'Share Tech Mono',Consolas,monospace;font-size:12px;letter-spacing:2px;padding:6px 12px;z-index:10;border-radius:4px;pointer-events:none;transition:all .2s;";
    hudStatusEl.textContent = "SCANNING FOR FACE...";
    $("#hud").appendChild(hudStatusEl);
  }
  return hudStatusEl;
}

function setStartupStatus(statusText, isError = false) {
  const hud = getHudStatus();
  if (hud && (state === "STANDBY" || isError)) {
    hud.textContent = statusText;
    hud.style.borderColor = isError ? "var(--red, #ef4444)" : "var(--cyan, #00f0ff)";
    hud.style.color = isError ? "var(--red, #ef4444)" : "var(--cyan, #00f0ff)";
  }
  const feedState = $("#feed-state");
  if (feedState && state === "STANDBY" && !isError) {
    feedState.textContent = statusText;
  }
  updateTelemetry();
}

/* =========================================================
   SESSION LIFECYCLE (PHASE 5: Reusable 45-60s Session)
   ========================================================= */

async function getOrRenewSession() {
  const now = performance.now();
  if (activeSession && now < activeSessionExpiresAt) {
    return activeSession;
  }
  try {
    activeSession = await post("/checkpoint/session", {
      device_id: "DEV-PWA-01",
      checkpoint_id: "CP-MAIN-01",
    });
    frameSequence = 0;
    const ttlMs = Math.max(10, (activeSession.ttl_seconds || 60) - 5) * 1000;
    activeSessionExpiresAt = now + ttlMs;
    return activeSession;
  } catch (e) {
    console.warn("[SESSION] Capture session acquisition failed:", e.message);
    activeSession = null;
    return null;
  }
}

/* =========================================================
   LIGHTWEIGHT BROWSER-SIDE FACE TRACKING & OVERLAY
   ========================================================= */

function bboxIoU(b1, b2) {
  const x1 = Math.max(b1[0], b2[0]);
  const y1 = Math.max(b1[1], b2[1]);
  const x2 = Math.min(b1[0] + b1[2], b2[0] + b2[2]);
  const y2 = Math.min(b1[1] + b1[3], b2[1] + b2[3]);
  const interW = Math.max(0, x2 - x1);
  const interH = Math.max(0, y2 - y1);
  const inter = interW * interH;
  const union = b1[2] * b1[3] + b2[2] * b2[3] - inter;
  return union > 0 ? inter / union : 0;
}

function updateTracks(detectedFaces, frameSize) {
  const now = performance.now();
  const matchedTrackIds = new Set();
  const snapW = frameSize?.[0] || 640;
  const snapH = frameSize?.[1] || 480;

  for (const face of detectedFaces) {
    const bbox = face.bbox;
    let bestTrack = null;
    let bestScore = 0;

    for (const track of tracks) {
      if (matchedTrackIds.has(track.trackId)) continue;
      const iou = bboxIoU(bbox, track.targetBbox);
      if (iou > 0.20 && iou > bestScore) {
        bestScore = iou;
        bestTrack = track;
      }
    }

    if (bestTrack) {
      matchedTrackIds.add(bestTrack.trackId);
      bestTrack.targetBbox = [...bbox];
      bestTrack.name = face.name;
      bestTrack.role = face.role;
      bestTrack.personnelId = face.id;
      bestTrack.is_recognized = face.is_recognized;
      bestTrack.is_live = face.is_live;
      bestTrack.confidence = face.confidence;
      bestTrack.recognition_state = face.recognition_state || (face.is_recognized ? "VERIFIED" : "UNKNOWN");
      bestTrack.candidate_name = face.candidate_name || face.name;
      bestTrack.liveness = face.liveness || (face.is_live ? "PASS" : "FAIL");
      bestTrack.pad_status = face.pad_status;
      bestTrack.missedFrames = 0;
      bestTrack.lastSeen = now;
      bestTrack.snapW = snapW;
      bestTrack.snapH = snapH;
    } else {
      const trackId = face.track_id || ("TRACK " + String(trackCounter++).padStart(2, "0"));
      matchedTrackIds.add(trackId);
      tracks.push({
        trackId,
        currentBbox: [...bbox],
        targetBbox: [...bbox],
        name: face.name,
        role: face.role,
        personnelId: face.id,
        is_recognized: face.is_recognized,
        is_live: face.is_live,
        confidence: face.confidence,
        recognition_state: face.recognition_state || (face.is_recognized ? "VERIFIED" : "UNKNOWN"),
        candidate_name: face.candidate_name || face.name,
        liveness: face.liveness || (face.is_live ? "PASS" : "FAIL"),
        pad_status: face.pad_status,
        missedFrames: 0,
        lastSeen: now,
        snapW,
        snapH,
      });
    }
  }

  tracks = tracks.filter((track) => {
    if (!matchedTrackIds.has(track.trackId)) {
      track.missedFrames += 1;
    }
    return track.missedFrames <= 2 && now - track.lastSeen < 2500;
  });
}

function clearTracks() {
  tracks = [];
  if (ctx && canvas) {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
  }
}

function renderOverlay() {
  if (!canvas || !ctx || !video) return;

  if (canvas.width !== video.clientWidth || canvas.height !== video.clientHeight) {
    canvas.width = video.clientWidth;
    canvas.height = video.clientHeight;
  }

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  if (!stopCamera || tracks.length === 0) {
    animFrameId = requestAnimationFrame(renderOverlay);
    return;
  }

  const cWidth = canvas.width;
  const cHeight = canvas.height;
  const vWidth = video.videoWidth || 640;
  const vHeight = video.videoHeight || 480;

  const videoRatio = vWidth / vHeight;
  const canvasRatio = cWidth / cHeight;
  let renderW, renderH, offsetX, offsetY;
  if (canvasRatio > videoRatio) {
    renderH = cHeight;
    renderW = cHeight * videoRatio;
    offsetX = (cWidth - renderW) / 2;
    offsetY = 0;
  } else {
    renderW = cWidth;
    renderH = cWidth / videoRatio;
    offsetX = 0;
    offsetY = (cHeight - renderH) / 2;
  }

  for (const track of tracks) {
    for (let i = 0; i < 4; i++) {
      track.currentBbox[i] += (track.targetBbox[i] - track.currentBbox[i]) * 0.28;
    }

    const snapW = track.snapW || vWidth;
    const snapH = track.snapH || vHeight;
    const scaleX = renderW / snapW;
    const scaleY = renderH / snapH;

    const [bx, by, bw, bh] = track.currentBbox;
    const x = offsetX + bx * scaleX;
    const y = offsetY + by * scaleY;
    const w = bw * scaleX;
    const h = bh * scaleY;

    let statusColor = "#00f0ff";
    let isWarning = false;
    let isBreach = false;

    const rState = track.recognition_state || (track.is_recognized ? "VERIFIED" : "UNKNOWN");
    const isLiveFailed = (!track.is_live && track.liveness === "FAIL");

    if (isLiveFailed) {
      statusColor = "#ef4444";
      isBreach = true;
    } else if (rState === "VERIFIED") {
      statusColor = "#10b981";
    } else if (rState === "POSSIBLE_MATCH") {
      statusColor = "#f59e0b";
      isWarning = true;
    } else if (rState === "UNKNOWN_CONFIRMED" || (!track.is_recognized && state === "BREACH")) {
      statusColor = "#ef4444";
      isBreach = true;
    } else {
      // VERIFYING
      statusColor = "#00f0ff";
    }

    ctx.save();
    ctx.fillStyle = isBreach
      ? "rgba(239, 68, 68, 0.10)"
      : isWarning
        ? "rgba(245, 158, 11, 0.08)"
        : "rgba(0, 240, 255, 0.08)";
    ctx.fillRect(x, y, w, h);

    ctx.strokeStyle = statusColor;
    ctx.lineWidth = 2;
    const corner = Math.min(22, Math.min(w, h) * 0.3);
    ctx.beginPath();
    ctx.moveTo(x, y + corner); ctx.lineTo(x, y); ctx.lineTo(x + corner, y);
    ctx.moveTo(x + w - corner, y); ctx.lineTo(x + w, y); ctx.lineTo(x + w, y + corner);
    ctx.moveTo(x + w, y + h - corner); ctx.lineTo(x + w, y + h); ctx.lineTo(x + w - corner, y + h);
    ctx.moveTo(x + corner, y + h); ctx.lineTo(x, y + h); ctx.lineTo(x, y + h - corner);
    ctx.stroke();

    ctx.font = "bold 11px 'Share Tech Mono', Consolas, monospace";
    let line1 = "";
    let line2 = "";

    if (isLiveFailed) {
      line1 = `SPOOF DETECTED · ${track.trackId}`;
      line2 = `PAD REJECTED · ACCESS BLOCKED`;
    } else if (rState === "VERIFIED") {
      const matchPct = Math.round((track.confidence || 0.87) * 100);
      line1 = `${(track.name || "OFFICER").toUpperCase()} · ${(track.role || "EMPLOYEE").toUpperCase()}`;
      line2 = `VERIFIED · MATCH ${matchPct}% · LIVENESS PASS`;
    } else if (rState === "POSSIBLE_MATCH") {
      const matchPct = Math.round((track.confidence || 0.71) * 100);
      line1 = `POSSIBLE MATCH · ${(track.candidate_name || track.name || "INDIVIDUAL").toUpperCase()}`;
      line2 = `VERIFYING · MATCH ${matchPct}% · HOLD STILL`;
    } else if (rState === "UNKNOWN_CONFIRMED" || (!track.is_recognized && state === "BREACH")) {
      line1 = `UNKNOWN PERSON · ${track.trackId}`;
      line2 = `ACCESS DENIED · CAPTURED`;
    } else {
      line1 = `IDENTITY VERIFYING · ${track.trackId}`;
      line2 = `HOLD STILL · ANALYZING BIOMETRICS`;
    }

    const textWidth = Math.max(ctx.measureText(line1).width, ctx.measureText(line2).width);
    const tagW = textWidth + 16;
    const tagH = 34;
    const tagX = Math.max(6, Math.min(cWidth - tagW - 6, x));
    const tagY = y > tagH + 8 ? y - tagH - 6 : y + h + 6;

    ctx.fillStyle = "rgba(6, 13, 22, 0.92)";
    ctx.fillRect(tagX, tagY, tagW, tagH);
    ctx.strokeStyle = statusColor;
    ctx.lineWidth = 1;
    ctx.strokeRect(tagX, tagY, tagW, tagH);

    ctx.fillStyle = statusColor;
    ctx.fillRect(tagX, tagY, 3, tagH);
    ctx.fillText(line1, tagX + 8, tagY + 14);

    ctx.font = "10px 'Share Tech Mono', Consolas, monospace";
    ctx.fillStyle = "#eaf1fa";
    ctx.fillText(line2, tagX + 8, tagY + 28);

    ctx.restore();
  }

  animFrameId = requestAnimationFrame(renderOverlay);
}

/* =========================================================
   CHECKPOINT STATE DISPLAY & TELEMETRY
   ========================================================= */

function display(result) {
  const hud = getHudStatus();
  if (hud) {
    if (result.state === "GRANTED") hud.textContent = "ACCESS GRANTED · UNLOCKED";
    else if (result.state === "BREACH") hud.textContent = "SECURITY BREACH · ACCESS DENIED";
    else if (result.state === "WAITING") {
      hud.textContent = result.duplicate_first_party
        ? "ALREADY VERIFIED — PLEASE SCAN DIFFERENT PERSON"
        : "STEP 1 COMPLETE · MOVE OUT OF CAMERA";
    } else if (result.faces && result.faces.length > 0) {
      hud.textContent = "FACE DETECTED · VERIFYING...";
    } else {
      hud.textContent = "MONITORING · SCANNING FOR FACE";
    }
  }

  if (Array.isArray(result.faces)) {
    updateTracks(result.faces, result.frame_size);
  }

  // Security severity and alarm processing (Phase 8: single breach modal)
  evaluateSecurityEvent(result);

  if (result.revision !== undefined && result.revision < revision) return;
  revision = result.revision ?? revision;
  state = result.state;
  end = performance.now() + (result.remaining || 0) * 1000;

  document.documentElement.style.setProperty(
    "--state",
    {
      STANDBY: "#00f0ff",
      WAITING: "#f59e0b",
      GRANTED: "#10b981",
      BREACH: "#ef4444",
    }[state] || "#ef4444",
  );

  const remaining = Math.max(0, (end - performance.now()) / 1000);
  const remText = remaining.toFixed(1) + "s remaining";

  const verdictEl = $("#verdict");
  if (verdictEl) {
    if (state === "GRANTED") {
      verdictEl.textContent = "UNLOCKED · DUAL CUSTODY VERIFIED";
    } else if (state === "WAITING") {
      verdictEl.textContent = result.duplicate_first_party
        ? `ALREADY VERIFIED — PLEASE SCAN DIFFERENT PERSON\n${remText}`
        : `PERSON 1 VERIFIED · MOVE OUT OF CAMERA · SCAN SECOND PERSON\n${remText}`;
    } else if (state === "BREACH") {
      verdictEl.textContent = `BREACH · ${result.reason || "ACCESS DENIED"}`;
    } else {
      verdictEl.textContent = "STANDBY · AUTHENTICATE TO BEGIN VERIFICATION";
    }
  }

  const waitCard = $("#waiting-instruction-card");
  if (waitCard) {
    if (state === "WAITING") {
      waitCard.hidden = false;
      const primary = result.parties?.[0];
      const pName = primary?.name || primary?.id || "Primary Officer";
      const wPrimary = $("#waiting-primary-name");
      if (wPrimary) wPrimary.textContent = `${pName.toUpperCase()} VERIFIED`;
      const wText = $("#waiting-action-text");
      if (wText) {
        wText.textContent = result.duplicate_first_party
          ? "Please step aside so a different authorized person can scan."
          : `Second authorized person must appear within ${remText}.`;
      }
    } else {
      waitCard.hidden = true;
    }
  }

  const feedState = $("#feed-state");
  if (feedState) feedState.textContent = state;

  const modeEl = $("#mode");
  if (modeEl && result.mode) modeEl.value = result.mode;

  const livenessEl = $("#liveness");
  if (livenessEl) {
    if (!result.faces || result.faces.length === 0) {
      livenessEl.textContent = "NO FACE";
    } else if (result.quality && !result.quality.texture_ok) {
      livenessEl.textContent = "REJECTED";
    } else {
      livenessEl.textContent = "PASS";
    }
  }

  // Update verified parties display
  for (let i = 0; i < 2; i++) {
    const p = result.parties?.[i];
    const node = $("#party-" + i);
    if (node) {
      node.classList.toggle("verified", !!p);
      const av = $(".avatar", node);
      if (av) av.textContent = p ? "✓" : String(i + 1);
      const str = $("strong", node);
      if (str) str.textContent = p ? p.name : "Awaiting identity";
      const sm = $("small", node);
      if (sm) {
        sm.textContent = p
          ? p.role
          : i === 0
            ? "Primary officer / customer"
            : "Second distinct party";
      }
    }
  }

  const timerTitle = $("#timer-title");
  if (timerTitle) {
    timerTitle.textContent =
      state === "WAITING"
        ? "PRIMARY VERIFIED"
        : state === "GRANTED"
          ? "Policy satisfied"
          : state === "BREACH"
            ? "Window closed"
            : "Ready to verify";
  }

  const deadlineNote = $("#deadline-note");
  if (deadlineNote) {
    deadlineNote.textContent =
      state === "WAITING"
        ? `Awaiting second authorized party · ${remText}`
        : "The first verified identity starts the 15-second server-enforced clock.";
  }

  updateTelemetry();
}

function updateTelemetry() {
  const camStatusEl = $("#camera-status");
  if (camStatusEl) {
    if (stopCamera) {
      camStatusEl.textContent = "ACTIVE";
      camStatusEl.style.color = "var(--green)";
    } else if (cameraStarting) {
      camStatusEl.textContent = "INITIALIZING";
      camStatusEl.style.color = "var(--cyan)";
    } else if (manuallyStopped) {
      camStatusEl.textContent = "STOPPED";
      camStatusEl.style.color = "var(--amber, #f59e0b)";
    } else {
      camStatusEl.textContent = "STANDBY";
      camStatusEl.style.color = "#91a5bc";
    }
  }

  const scannerStatusEl = $("#scanner-status");
  if (scannerStatusEl) {
    if (stopCamera) {
      scannerStatusEl.textContent = busy ? "SCANNING" : "RUNNING";
      scannerStatusEl.style.color = "var(--green)";
    } else if (manuallyStopped) {
      scannerStatusEl.textContent = "PAUSED";
      scannerStatusEl.style.color = "#91a5bc";
    } else {
      scannerStatusEl.textContent = "STANDBY";
      scannerStatusEl.style.color = "#91a5bc";
    }
  }

  const alarmStatusEl = $("#alarm-status");
  const alert = getActiveAlert();
  if (alarmStatusEl) {
    const alarmText = isAlarmActive()
      ? "SOUNDING"
      : alert?.acknowledged
        ? "ACKNOWLEDGED"
        : isMuted()
          ? "MUTED"
          : "SILENT";
    const alarmColor = isAlarmActive()
      ? "var(--red)"
      : alert?.acknowledged
        ? "var(--amber)"
        : isMuted()
          ? "var(--muted)"
          : "#91a5bc";
    alarmStatusEl.textContent = alarmText;
    alarmStatusEl.style.color = alarmColor;
  }

  const tgStatusEl = $("#telegram-status");
  if (tgStatusEl) {
    const isBreach = alert && state === "BREACH";
    tgStatusEl.textContent = isBreach ? "DISPATCHED" : telegramConfigured ? "READY" : "NOT CONFIGURED";
    tgStatusEl.style.color = isBreach ? "var(--red)" : telegramConfigured ? "var(--green)" : "#91a5bc";
  }

  updateMuteButton();
}

function updateMuteButton() {
  const btn = $("#toggle-mute");
  if (btn) {
    const muted = isMuted();
    btn.textContent = muted ? "SIREN MUTED" : "SIREN ON";
    btn.style.color = muted ? "var(--muted)" : "var(--cyan)";
  }
}

/* =========================================================
   POPUP SYSTEM (PHASE 8: Single modal, deduplicated)
   ========================================================= */

export function showBreachModal(alert) {
  if (!alert || !alert.id) return;
  if (shownEventIds.has(alert.id)) return;
  shownEventIds.add(alert.id);

  const modal = $("#breach-modal");
  if (!modal || typeof modal.showModal !== "function") return;

  const bmSubtitle = $("#bm-subtitle");
  if (bmSubtitle) bmSubtitle.textContent = alert.subtitle || "UNAUTHORIZED PERSON DETECTED";

  const bmCode = $("#bm-code");
  if (bmCode) bmCode.textContent = `${alert.code || "ZT-001"} · ACCESS DENIED`;

  const bmCheckpoint = $("#bm-checkpoint");
  if (bmCheckpoint) bmCheckpoint.textContent = alert.checkpoint || "CP-MAIN-01";

  const bmTime = $("#bm-time");
  if (bmTime) bmTime.textContent = alert.timestamp || "—";

  const bmEvidence = $("#bm-evidence");
  if (bmEvidence) bmEvidence.textContent = alert.evidence || "CAPTURED";

  const bmView = $("#bm-btn-view");
  if (bmView) bmView.href = `/audit?event=${encodeURIComponent(alert.id)}`;

  const bmBtnAck = $("#bm-btn-ack");
  if (bmBtnAck) {
    bmBtnAck.classList.toggle("acknowledged", !!alert.acknowledged);
    bmBtnAck.textContent = alert.acknowledged ? "ACKNOWLEDGED ✓" : "ACKNOWLEDGE ALERT";
  }

  const bmBtnReset = $("#bm-btn-reset");
  if (bmBtnReset) bmBtnReset.hidden = false;

  if (!modal.open) {
    try {
      modal.showModal();
    } catch {}
  }
}

/* =========================================================
   SURVEILLANCE & CAMERA ENGINE (PHASE 4)
   ========================================================= */

export async function beginSurveillance({ manual = false } = {}) {
  if (!currentUser) return;
  if (manual) {
    manuallyStopped = false;
  } else if (manuallyStopped) {
    return;
  }

  if (stopCamera || cameraStarting) return;
  if (!video) return;

  video.autoplay = true;
  video.muted = true;
  video.playsInline = true;

  const fallbackBar = $("#camera-fallback-bar");
  if (navigator.permissions?.query) {
    try {
      const perm = await navigator.permissions.query({ name: "camera" });
      perm.onchange = () => {
        if (perm.state === "granted" && !stopCamera && currentUser) {
          if (fallbackBar) fallbackBar.hidden = true;
          beginSurveillance();
        }
      };
      if (perm.state === "denied") {
        if (fallbackBar) fallbackBar.hidden = false;
        setStartupStatus("CAMERA BLOCKED", true);
        return;
      }
    } catch {}
  }

  cameraStarting = true;
  setStartupStatus("CAMERA INITIALIZING");
  console.log("[VERITAS CAMERA] CAMERA_INIT_START");

  try {
    stopCamera = await startCamera(video, $("#camera-empty"));
    console.log("[VERITAS CAMERA] CAMERA_PERMISSION_GRANTED");
    console.log("[VERITAS CAMERA] CAMERA_STREAM_READY");
    if (fallbackBar) fallbackBar.hidden = true;
    setStartupStatus("CAMERA ACTIVE");

    if ($("#stop-camera")) $("#stop-camera").disabled = false;
    if ($("#start-camera")) $("#start-camera").disabled = true;

    if (!animFrameId) {
      animFrameId = requestAnimationFrame(renderOverlay);
    }

    if (video.readyState < 2 || video.videoWidth === 0) {
      await new Promise((resolve) => {
        const onLoaded = () => {
          video.removeEventListener("loadedmetadata", onLoaded);
          resolve();
        };
        video.addEventListener("loadedmetadata", onLoaded, { once: true });
        setTimeout(resolve, 600);
      });
    }

    console.log("[VERITAS CAMERA] CAMERA_PLAYING");
    setStartupStatus("SCANNER RUNNING");

    // Establish reusable capture session challenge
    await getOrRenewSession();

    clearInterval(loop);
    loop = setInterval(scan, SCAN_INTERVAL);

    // Initial immediate scan
    await scan();
    if (state === "STANDBY") {
      setStartupStatus("MONITORING");
    }
  } catch (err) {
    console.warn("[VERITAS CAMERA] CAMERA_INIT_FAILED", err.message);
    stopCamera = null;
    const isPermission =
      err.name === "NotAllowedError" ||
      err.name === "PermissionDeniedError" ||
      err.name === "SecurityError";

    if (fallbackBar) fallbackBar.hidden = false;
    setStartupStatus(isPermission ? "CAMERA PERMISSION REQUIRED" : "CAMERA BLOCKED", true);
    if (manual) toast(err.message || "Failed to start camera.");
  } finally {
    cameraStarting = false;
  }
}

function onStopCamera() {
  manuallyStopped = true;
  stop();
}

function stop() {
  clearInterval(loop);
  loop = null;
  if (stopCamera) {
    stopCamera();
    stopCamera = null;
  }
  clearTracks();
  if (animFrameId) {
    cancelAnimationFrame(animFrameId);
    animFrameId = null;
  }
  $("#hud")?.classList.remove("ingesting");
  if ($("#start-camera")) $("#start-camera").disabled = false;
  if ($("#stop-camera")) $("#stop-camera").disabled = true;

  updateTelemetry();
  const hud = getHudStatus();
  if (hud && state !== "BREACH" && state !== "GRANTED") {
    hud.textContent = "CAMERA STOPPED · SCANNER PAUSED";
  }
}

/* =========================================================
   SCANNER LOOP (PHASE 4: 1200ms, strict lock, 1 request)
   ========================================================= */

async function scan() {
  if (busy || !stopCamera || !navigator.onLine || !currentUser) return;
  if (!video || video.videoWidth === 0) return;
  busy = true;

  const hud = getHudStatus();
  if (hud && state === "STANDBY") {
    hud.textContent = "SCANNING FOR FACE...";
  }

  try {
    const session = await getOrRenewSession();
    const tSnap0 = performance.now();
    const snapData = snapshot(video);
    const captureMs = Math.round(performance.now() - tSnap0);

    const payload = {
      image: snapData,
      device_id: "DEV-PWA-01",
      checkpoint_id: "CP-MAIN-01",
    };
    if (session && session.session_id) {
      payload.session_id = session.session_id;
      payload.capture_nonce = session.capture_nonce;
      payload.frame_seq = frameSequence++;
    }

    const tApi0 = performance.now();
    const result = await post("/checkpoint/frame", payload);
    const apiMs = Math.round(performance.now() - tApi0);

    const tRender0 = performance.now();
    display(result);
    const renderMs = Math.round(performance.now() - tRender0);

    if (window.VAULT_DEBUG || window.location.search.includes("debug")) {
      console.debug(`[PERF] capture_ms=${captureMs} api_total_ms=${apiMs} render_ms=${renderMs}`);
    }

    // Door PEP Relay unlock on dual custody grant
    if (result.state === "GRANTED" && result.authorization_token) {
      try {
        await post("/pep/verify", { token: result.authorization_token });
        if (hud) hud.textContent = "RELAY ACTUATED · DOOR UNLOCKED (4S)";
      } catch (pepErr) {
        toast("PEP Relay Blocked: " + pepErr.message);
      }
    }
  } catch (error) {
    console.warn("[VERITAS SCAN GLITCH]", error.message);
    if (!navigator.onLine) {
      setStartupStatus("BACKEND OFFLINE", true);
    } else {
      setStartupStatus("SCANNER ERROR", true);
    }
  } finally {
    busy = false;
  }
}

/* =========================================================
   RESET & ACKNOWLEDGE LIFECYCLE
   ========================================================= */

async function resetCheckpoint() {
  shownEventIds.clear();
  clearActiveAlert();
  manuallyStopped = false;

  const modal = $("#breach-modal");
  if (modal && modal.open) {
    try { modal.close(); } catch {}
  }

  const modeVal = $("#mode") ? $("#mode").value : "standard";
  const res = await post("/checkpoint/reset", { mode: modeVal });
  display(res);
  toast("Checkpoint reset to STANDBY");

  if (currentUser && !stopCamera) {
    await beginSurveillance();
  }
}

function onAcknowledgeAlert() {
  acknowledgeAlert();
  const modal = $("#breach-modal");
  if (modal && modal.open) {
    try { modal.close(); } catch {}
  }
  updateTelemetry();
}

/* =========================================================
   EVENT LISTENERS & BINDINGS
   ========================================================= */

$("#start-camera")?.addEventListener("click", () =>
  action($("#start-camera"), async () => {
    await beginSurveillance({ manual: true });
  })
);

$("#stop-camera")?.addEventListener("click", onStopCamera);
$("#reset")?.addEventListener("click", () => action($("#reset"), resetCheckpoint));
$("#btn-checkpoint-reset")?.addEventListener("click", () => action($("#btn-checkpoint-reset"), resetCheckpoint));

$("#bm-btn-ack")?.addEventListener("click", onAcknowledgeAlert);
$("#bm-btn-reset")?.addEventListener("click", () => action($("#bm-btn-reset"), resetCheckpoint));
$("#bm-btn-view")?.addEventListener("click", onAcknowledgeAlert);

$("#btn-test-siren")?.addEventListener("click", () => {
  initAudio();
  testSiren();
  toast("Alarm siren test active (2s).");
  updateTelemetry();
});

$("#btn-test-telegram")?.addEventListener("click", async () => {
  const btn = $("#btn-test-telegram");
  if (btn) btn.disabled = true;
  try {
    const res = await testTelegram();
    if (res.ok) {
      toast("Telegram test alert dispatched successfully (text + photo).");
    } else {
      toast(res.error || "Telegram alert failed. Configure Render environment variables.");
    }
  } catch (err) {
    toast(err.message || "Telegram test failed.");
  } finally {
    if (btn) btn.disabled = false;
    updateTelemetry();
  }
});

$("#toggle-mute")?.addEventListener("click", () => {
  setMuted(!isMuted());
  updateMuteButton();
});

document.addEventListener("vault-alarm-state", () => {
  updateTelemetry();
});

document.addEventListener("vault-critical-alert", (e) => {
  updateTelemetry();
  if (e.detail) {
    showBreachModal(e.detail);
  }
});

document.addEventListener("vault-alert-acknowledged", () => {
  const modal = $("#breach-modal");
  if (modal && modal.open) {
    try { modal.close(); } catch {}
  }
  updateTelemetry();
});

document.addEventListener("vault-alert-cleared", () => {
  const modal = $("#breach-modal");
  if (modal && modal.open) {
    try { modal.close(); } catch {}
  }
  updateTelemetry();
});

// Single countdown timer tick (100ms) for smooth dial ring
setInterval(() => {
  if (state === "WAITING") {
    const remaining = Math.max(0, (end - performance.now()) / 1000);
    const remText = remaining.toFixed(1) + "s remaining";
    const deadlineNote = $("#deadline-note");
    if (deadlineNote) deadlineNote.textContent = `Awaiting second authorized party · ${remText}`;
    const wText = $("#waiting-action-text");
    if (wText) wText.textContent = `Second authorized person must appear within ${remText}.`;

    ring($("#timer"), state, remaining, 15);

    // If temporal window has expired, poll tick once to let backend register ZT-008 breach
    if (remaining <= 0 && !busy) {
      post("/checkpoint/tick").then(display).catch(() => {});
    }
  } else {
    ring($("#timer"), state, state === "STANDBY" ? 15 : 0, 15);
  }
}, 100);

// Load Telegram configured status ONCE on startup
async function loadTelegramStatus() {
  try {
    const res = await getAlertsStatus();
    telegramConfigured = Boolean(res?.telegram_configured);
    updateTelemetry();
  } catch {}
}

document.addEventListener("vault-auth", async () => {
  manuallyStopped = false;
  initAudio();
  setStartupStatus("AUTHENTICATED");
  await loadTelegramStatus();
  try {
    display(await post("/checkpoint/tick"));
  } catch {}
  setTimeout(() => beginSurveillance(), 150);
});

if (currentUser) {
  setStartupStatus("AUTHENTICATED");
  loadTelegramStatus();
  post("/checkpoint/tick").then(display).catch(() => {});
  setTimeout(() => beginSurveillance(), 150);
} else {
  loadTelegramStatus();
  post("/checkpoint/tick").then(display).catch(() => {});
}

addEventListener("pagehide", stop);
addEventListener("offline", () => {
  stop();
  setStartupStatus("BACKEND OFFLINE", true);
  const verdictEl = $("#verdict");
  if (verdictEl) verdictEl.textContent = "OFFLINE · VERIFICATION PAUSED · VAULT LOCKED";
});
addEventListener("online", () => {
  if (currentUser && !manuallyStopped) {
    beginSurveillance();
  }
});
