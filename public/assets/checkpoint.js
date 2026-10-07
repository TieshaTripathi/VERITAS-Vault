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
  areNotificationsEnabled,
  requestNotificationPermission,
  evaluateSecurityEvent,
  getActiveAlert,
  clearActiveAlert,
  subscribePush,
  getPushSubscription,
} from "./alerts.js";

let stopCamera = null;
let loop = null;
let busy = false;
let state = "STANDBY";
let end = 0;
let polling = false;
let revision = -1;
let manuallyStopped = false;
let animFrameId = null;
let trackCounter = 1;
let tracks = [];
// Prevents double-entry while async startCamera() is in flight
let cameraStarting = false;

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
    const bbox = face.bbox; // [x, y, w, h] in snapshot coords
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
      bestTrack.pad_status = face.pad_status;
      bestTrack.missedFrames = 0;
      bestTrack.lastSeen = now;
      bestTrack.snapW = snapW;
      bestTrack.snapH = snapH;
    } else {
      const trackId = "TRACK " + String(trackCounter++).padStart(2, "0");
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
        pad_status: face.pad_status,
        missedFrames: 0,
        lastSeen: now,
        snapW,
        snapH,
      });
    }
  }

  // Prune lost tracks
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
    // Smooth linear interpolation for stable box movement
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

    if (!track.is_live) {
      statusColor = "#ef4444";
      isBreach = true;
    } else if (!track.is_recognized) {
      statusColor = "#ef4444";
      isBreach = true;
    } else if (state === "WAITING") {
      statusColor = "#f59e0b";
      isWarning = true;
    } else if (state === "GRANTED") {
      statusColor = "#10b981";
    }

    ctx.save();

    // Box tint
    ctx.fillStyle = isBreach
      ? "rgba(239, 68, 68, 0.10)"
      : isWarning
        ? "rgba(245, 158, 11, 0.08)"
        : "rgba(0, 240, 255, 0.08)";
    ctx.fillRect(x, y, w, h);

    // Box corner brackets
    ctx.strokeStyle = statusColor;
    ctx.lineWidth = 2;
    const corner = Math.min(22, Math.min(w, h) * 0.3);
    ctx.beginPath();
    ctx.moveTo(x, y + corner); ctx.lineTo(x, y); ctx.lineTo(x + corner, y);
    ctx.moveTo(x + w - corner, y); ctx.lineTo(x + w, y); ctx.lineTo(x + w, y + corner);
    ctx.moveTo(x + w, y + h - corner); ctx.lineTo(x + w, y + h); ctx.lineTo(x + w - corner, y + h);
    ctx.moveTo(x + corner, y + h); ctx.lineTo(x, y + h); ctx.lineTo(x, y + h - corner);
    ctx.stroke();

    // Label construction
    ctx.font = "bold 11px 'Share Tech Mono', Consolas, monospace";
    let line1 = "";
    let line2 = "";

    if (!track.is_live) {
      line1 = `SPOOF SUSPECTED · ${track.trackId}`;
      line2 = `PAD REJECTED · ACCESS BLOCKED`;
    } else if (!track.is_recognized) {
      line1 = `UNKNOWN / INTRUDER · ${track.trackId}`;
      line2 = `ACCESS DENIED · CAPTURED`;
    } else {
      const matchPct = Math.round((track.confidence || 0.88) * 100);
      line1 = `${(track.name || "AUTHORIZED").toUpperCase()} · ${(track.role || "EMPLOYEE").toUpperCase()}`;
      line2 = `LIVE · MATCH ${matchPct}% · ${track.trackId}`;
    }

    const textWidth = Math.max(ctx.measureText(line1).width, ctx.measureText(line2).width);
    const tagW = textWidth + 16;
    const tagH = 34;
    const tagX = Math.max(6, Math.min(cWidth - tagW - 6, x));
    const tagY = y > tagH + 8 ? y - tagH - 6 : y + h + 6;

    // Tag background
    ctx.fillStyle = "rgba(6, 13, 22, 0.92)";
    ctx.fillRect(tagX, tagY, tagW, tagH);
    ctx.strokeStyle = statusColor;
    ctx.lineWidth = 1;
    ctx.strokeRect(tagX, tagY, tagW, tagH);

    // Status indicator stripe
    ctx.fillStyle = statusColor;
    ctx.fillRect(tagX, tagY, 3, tagH);

    // Render lines
    ctx.fillStyle = statusColor;
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
    else if (result.faces && result.faces.length > 0) hud.textContent = "HOLD STILL — FIXATING...";
    else hud.textContent = "SCANNING FOR FACE...";
  }

  // Feed detection updates to face tracking overlay
  if (Array.isArray(result.faces)) {
    updateTracks(result.faces, result.frame_size);
  }

  // Security severity and alarm processing
  evaluateSecurityEvent(result);
  updateAlertCenterUI();

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

  $("#verdict").textContent =
    state === "GRANTED"
      ? "UNLOCKED · DUAL CUSTODY VERIFIED"
      : state === "WAITING"
        ? "WAITING FOR SECOND PARTY"
        : state + " · " + result.reason;

  $("#feed-state").textContent = state;
  $("#mode").value = result.mode;
  $("#lock-state").textContent = state === "GRANTED" ? "UNLOCKED" : "LOCKED";
  $("#face-count").textContent = result.faces?.length ?? result.parties?.length ?? "0";

  // FIX: When face_count is 0, always show NO FACE — never REJECTED
  if (result.quality) {
    const faceCount = result.quality.face_count || 0;
    const livenessEl = $("#liveness");
    if (livenessEl) {
      if (faceCount === 0) {
        livenessEl.textContent = "NO FACE";
      } else if (!result.quality.texture_ok) {
        livenessEl.textContent = "REJECTED";
      } else {
        livenessEl.textContent = "PASS";
      }
    }
  }

  for (let i = 0; i < 2; i++) {
    const p = result.parties?.[i];
    const node = $("#party-" + i);
    if (node) {
      node.classList.toggle("verified", !!p);
      $(".avatar", node).textContent = p ? "✓" : String(i + 1);
      $("strong", node).textContent = p ? p.name : "Awaiting identity";
      $("small", node).textContent = p
        ? p.role
        : i === 0
          ? "Primary officer / customer"
          : "Second distinct party";
    }
  }

  $("#timer-title").textContent =
    state === "WAITING"
      ? "Verify second party"
      : state === "GRANTED"
        ? "Policy satisfied"
        : state === "BREACH"
          ? "Window closed"
          : "Ready to verify";

  $("#deadline-note").textContent =
    state === "WAITING"
      ? "The server enforces this deadline."
      : "A new authorized scan starts the five-second window.";

  if (state === "GRANTED" || state === "BREACH") {
    stop();
  }
}

function updateAlertCenterUI() {
  const alert = getActiveAlert();
  const alertCard = $("#critical-alert-card");
  const alertBadge = $("#alert-center-badge");
  const standbyBox = $("#alert-center-standby");
  const breachBox = $("#alert-center-breach");
  const alarmIndicator = $("#alarm-state-indicator");
  const ackBtn = $("#btn-ack-alert");

  if (alert && state !== "GRANTED" && state !== "STANDBY") {
    if (alertCard) {
      alertCard.hidden = false;
      $("#alert-code").textContent = `${alert.title} · ${alert.code}`;
      $("#alert-time").textContent = alert.timestamp;
      $("#alert-message").textContent = `${alert.reason.toUpperCase()} · EVIDENCE CAPTURED · ACCESS LOCKED`;
      if (ackBtn) {
        ackBtn.classList.toggle("acknowledged", alert.acknowledged);
        ackBtn.textContent = alert.acknowledged ? "ACKNOWLEDGED ✓" : "ACKNOWLEDGE";
      }
    }
    if (standbyBox) standbyBox.hidden = true;
    if (breachBox) {
      breachBox.hidden = false;
      if ($("#ac-breach-title")) $("#ac-breach-title").textContent = `${alert.code} · ${alert.title}`;
      if ($("#ac-breach-time")) $("#ac-breach-time").textContent = alert.timestamp;
      if ($("#ac-breach-alarm")) {
        $("#ac-breach-alarm").textContent = isAlarmActive() ? "SOUNDING" : alert.acknowledged ? "ACKNOWLEDGED" : "SILENT";
      }
      if ($("#ac-breach-push")) $("#ac-breach-push").textContent = "SENT";
    }
    if (alertBadge) {
      alertBadge.textContent = "BREACH";
      alertBadge.className = "badge BREACH";
    }
  } else {
    if (alertCard) alertCard.hidden = true;
    if (standbyBox) standbyBox.hidden = false;
    if (breachBox) breachBox.hidden = true;
    if (alertBadge) {
      alertBadge.textContent = state === "WAITING" ? "STANDBY / WAITING" : "STANDBY";
      alertBadge.className = "badge";
    }
    if (alarmIndicator) {
      alarmIndicator.textContent = "SILENT";
      alarmIndicator.style.color = "#91a5bc";
    }
  }

  updateMuteButton();
  updateNotifButton();
}

function updateMuteButton() {
  const btn = $("#toggle-mute");
  if (btn) {
    const muted = isMuted();
    btn.textContent = muted ? "SIREN MUTED" : "SIREN ON";
    btn.style.color = muted ? "var(--muted)" : "var(--cyan)";
  }
}

function updateNotifButton() {
  const phoneIndicator = $("#phone-push-indicator");
  const phoneBtn = $("#btn-enable-phone");
  getPushSubscription().then((sub) => {
    if (phoneIndicator) {
      phoneIndicator.textContent = sub ? "ACTIVE" : "NOT CONFIGURED";
      phoneIndicator.style.color = sub ? "var(--green)" : "#91a5bc";
    }
    if (phoneBtn) {
      phoneBtn.textContent = sub ? "PHONE ALERTS: ACTIVE" : "ENABLE PHONE ALERTS";
      phoneBtn.style.color = sub ? "var(--green)" : "var(--muted)";
    }
  }).catch(() => {});
}

/* =========================================================
   SURVEILLANCE & CAMERA ENGINE
   ========================================================= */

export async function beginSurveillance({ manual = false } = {}) {
  if (!currentUser) return;
  if (["GRANTED", "BREACH"].includes(state)) {
    if (manual) toast("Reset the checkpoint before beginning surveillance.");
    return;
  }
  // Prevent double-entry: guard both stopCamera (already running) and
  // cameraStarting (async gap while getUserMedia is in flight)
  if (stopCamera || cameraStarting) return;

  if (manual) {
    manuallyStopped = false;
  } else if (manuallyStopped) {
    return;
  }

  if (!video) return;

  video.autoplay = true;
  video.muted = true;
  video.playsInline = true;

  // Check permission state to provide early user feedback without
  // triggering a permission prompt on unsupported browsers
  if (!manual && navigator.permissions?.query) {
    try {
      const perm = await navigator.permissions.query({ name: "camera" });
      if (perm.state === "denied") {
        const notice = $("#notice");
        if (notice) notice.textContent = "CAMERA BLOCKED · Allow camera in browser settings, then click Start Surveillance";
        return;
      }
    } catch { /* permissions API not supported — continue */ }
  }

  cameraStarting = true;
  console.log("[VERITAS CAMERA] CAMERA_INIT_START");

  try {
    stopCamera = await startCamera(video, $("#camera-empty"));
    console.log("[VERITAS CAMERA] CAMERA_PERMISSION_GRANTED");
    console.log("[VERITAS CAMERA] CAMERA_STREAM_READY");

    if ($("#stop-camera")) $("#stop-camera").disabled = false;
    if ($("#start-camera")) $("#start-camera").disabled = true;

    // Clear any previous notice
    const notice = $("#notice");
    if (notice) notice.textContent = "";

    if (!animFrameId) {
      animFrameId = requestAnimationFrame(renderOverlay);
    }

    // Wait until video has dimensions and is playing
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

    clearInterval(loop);
    loop = setInterval(scan, 1000);

    // Initial immediate scan
    await scan();
  } catch (err) {
    console.warn("[VERITAS CAMERA] CAMERA_INIT_FAILED:", err.name, err.message);
    stopCamera = null; // Ensure not left in inconsistent state
    if (manual) {
      toast(err.message || "Failed to start camera.");
    } else {
      const notice = $("#notice");
      if (notice) {
        const isPermission = err.name === "NotAllowedError" || err.name === "PermissionDeniedError";
        notice.textContent = isPermission
          ? "CAMERA PERMISSION REQUIRED · CLICK START SURVEILLANCE"
          : `CAMERA INITIALIZATION FAILED · ${err.message || "CLICK START SURVEILLANCE TO RETRY"}`;
      }
    }
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
}

async function scan() {
  if (busy || !stopCamera || !navigator.onLine) return;
  busy = true;
  const hud = getHudStatus();
  if (hud && !["GRANTED", "BREACH"].includes(state)) {
    hud.textContent = "VERIFYING IDENTITY...";
  }
  $("#hud")?.classList.add("ingesting");
  try {
    // 1. Obtain single-use capture session challenge nonce
    let session = null;
    try {
      session = await post("/checkpoint/session", {
        device_id: "DEV-PWA-01",
        checkpoint_id: "CP-MAIN-01",
      });
    } catch (e) {
      console.warn("Session challenge error, attempting direct frame scan", e);
    }

    const payload = { image: snapshot(video) };
    if (session && session.session_id) {
      payload.session_id = session.session_id;
      payload.capture_nonce = session.capture_nonce;
      payload.device_id = "DEV-PWA-01";
      payload.checkpoint_id = "CP-MAIN-01";
    }

    const result = await post("/checkpoint/frame", payload);
    display(result);

    // 2. If access granted, submit signed authorization token to Edge PEP door relay
    if (result.state === "GRANTED" && result.authorization_token) {
      try {
        await post("/pep/verify", { token: result.authorization_token });
        if (hud) hud.textContent = "RELAY ACTUATED · DOOR UNLOCKED (3S)";
      } catch (pepErr) {
        toast("PEP Relay Blocked: " + pepErr.message);
      }
    }
  } catch (error) {
    stop();
    toast(error.message);
  } finally {
    busy = false;
    $("#hud")?.classList.remove("ingesting");
  }
}

/* =========================================================
   EVENT LISTENERS & LIFECYCLE
   ========================================================= */

$("#start-camera").onclick = () =>
  action($("#start-camera"), async () => {
    await beginSurveillance({ manual: true });
  });

$("#stop-camera").onclick = onStopCamera;

$("#reset").onclick = () =>
  action($("#reset"), async () => {
    clearActiveAlert();
    manuallyStopped = false;
    const res = await post("/checkpoint/reset", { mode: $("#mode").value });
    display(res);
    toast("Checkpoint reset to STANDBY");
    // Automatically begin surveillance after successful reset
    if (currentUser) {
      await beginSurveillance();
    }
  });

$("#btn-ack-alert")?.addEventListener("click", () => {
  acknowledgeAlert();
  updateAlertCenterUI();
});

$("#toggle-mute")?.addEventListener("click", () => {
  setMuted(!isMuted());
  updateMuteButton();
});

$("#btn-enable-notifs")?.addEventListener("click", async () => {
  await requestNotificationPermission();
  updateNotifButton();
});

// Phone push subscription (in alert center panel)
$("#btn-enable-phone")?.addEventListener("click", async () => {
  const btn = $("#btn-enable-phone");
  if (btn) btn.disabled = true;
  try {
    initAudio(); // Prime audio on user gesture
    await subscribePush();
    updateNotifButton();
    toast("This device registered for security push notifications.");
  } catch (err) {
    toast(err.message || "Push registration failed.");
  } finally {
    if (btn) btn.disabled = false;
  }
});

document.addEventListener("vault-alarm-state", () => {
  updateAlertCenterUI();
});

document.addEventListener("vault-critical-alert", () => {
  updateAlertCenterUI();
});

document.addEventListener("vault-alert-cleared", () => {
  updateAlertCenterUI();
});

async function poll() {
  if (!currentUser || polling || !navigator.onLine) return;
  polling = true;
  try {
    display(await post("/checkpoint/tick"));
  } catch (error) {
    $("#verdict").textContent = "VERIFICATION UNAVAILABLE · VAULT LOCKED";
    if (error.status === 401) stop();
  } finally {
    polling = false;
  }
}

setInterval(poll, 1000);

/**
 * KEY FIX: vault-auth fires AFTER initialize() in common.js resolves and
 * confirms a valid operator session. currentUser is populated at this point.
 * This is the ONLY correct place to trigger automatic surveillance startup.
 * The bare beginSurveillance() at module init (old code line 625) was the
 * root cause of the camera not starting — currentUser was still null then.
 */
document.addEventListener("vault-auth", async () => {
  manuallyStopped = false;
  initAudio();
  await poll();
  // Short delay to let the DOM settle before starting camera
  setTimeout(() => beginSurveillance(), 200);
});

// On module load: poll state, and if currentUser is already authenticated, start surveillance
poll();
updateAlertCenterUI();
if (currentUser) {
  setTimeout(() => beginSurveillance(), 200);
}
// Initialize liveness display to neutral state
const _livenessEl = $("#liveness");
if (_livenessEl && (!_livenessEl.textContent || _livenessEl.textContent === "—")) {
  _livenessEl.textContent = "NO FACE";
}

setInterval(
  () =>
    ring(
      $("#timer"),
      state,
      state === "WAITING"
        ? Math.max(0, (end - performance.now()) / 1000)
        : state === "STANDBY"
          ? 5
          : 0,
    ),
  50,
);

addEventListener("pagehide", stop);
addEventListener("offline", () => {
  stop();
  $("#verdict").textContent = "OFFLINE · VERIFICATION PAUSED · VAULT LOCKED";
});
