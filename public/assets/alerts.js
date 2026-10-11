
/**
 * VERITAS-Vault Audio Alarm and PWA Push Remote Alerts Subsystem.
 * Clean baseline: Web Audio siren, PWA Web Push notification lifecycle,
 * and strict breach popup deduplication (one event ID = one popup).
 */

let audioCtx = null;
let sirenOsc = null;
let sirenGain = null;
let sirenTimer = null;
let autoStopTimer = null;
let isAlarmSounding = false;
let currentAlert = null;

export const shownBreachIds = new Set();
// Backward-compatibility alias for test suites
export const notifiedEventIds = shownBreachIds;

export const CRITICAL_REASON_CODES = ["ZT-001", "ZT-002", "ZT-008", "ZT-009", "ZT-013"];
const STORAGE_KEY_MUTED = "vault_alarm_muted";

/* =========================================================
   AUDIO & SIREN ENGINE
   ========================================================= */

export function isMuted() {
  try {
    return localStorage.getItem(STORAGE_KEY_MUTED) === "true";
  } catch {
    return false;
  }
}

export function setMuted(val) {
  const muted = Boolean(val);
  try {
    localStorage.setItem(STORAGE_KEY_MUTED, String(muted));
  } catch {}
  if (muted && isAlarmSounding) {
    stopAlarm();
  }
  dispatchAlertEvent("vault-mute-changed", { muted });
  return muted;
}

export function initAudio() {
  if (!audioCtx) {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (AudioContextClass) {
      audioCtx = new AudioContextClass();
    }
  }
  if (audioCtx && audioCtx.state === "suspended") {
    audioCtx.resume().catch(() => {});
  }
}

export function isAlarmActive() {
  return isAlarmSounding;
}

export function getActiveAlert() {
  return currentAlert;
}

export function clearActiveAlert() {
  stopAlarm();
  currentAlert = null;
  shownBreachIds.clear();
  dispatchAlertEvent("vault-alert-cleared", null);
}

export function startAlarm({ duration = 12000 } = {}) {
  if (isMuted() || isAlarmSounding) {
    return;
  }

  initAudio();
  if (!audioCtx) return;

  try {
    isAlarmSounding = true;
    sirenOsc = audioCtx.createOscillator();
    sirenGain = audioCtx.createGain();

    sirenOsc.type = "sawtooth";
    sirenOsc.frequency.setValueAtTime(880, audioCtx.currentTime);
    sirenGain.gain.setValueAtTime(0.18, audioCtx.currentTime);

    sirenOsc.connect(sirenGain);
    sirenGain.connect(audioCtx.destination);
    sirenOsc.start();

    // High-low alternating siren pulse (880 Hz <-> 660 Hz)
    let high = true;
    sirenTimer = setInterval(() => {
      if (!isAlarmSounding || !audioCtx) return;
      high = !high;
      const targetFreq = high ? 880 : 660;
      sirenOsc.frequency.setValueAtTime(targetFreq, audioCtx.currentTime);
    }, 250);

    clearTimeout(autoStopTimer);
    autoStopTimer = setTimeout(() => {
      stopAlarm();
    }, duration);

    dispatchAlertEvent("vault-alarm-state", { active: true });
  } catch (err) {
    console.warn("[alerts] Audio playback failed:", err);
    isAlarmSounding = false;
  }
}

export function stopAlarm() {
  if (!isAlarmSounding && !sirenOsc) return;

  clearTimeout(autoStopTimer);
  clearInterval(sirenTimer);
  sirenTimer = null;
  autoStopTimer = null;

  if (sirenOsc) {
    try {
      sirenOsc.stop();
      sirenOsc.disconnect();
    } catch {}
    sirenOsc = null;
  }

  if (sirenGain) {
    try {
      sirenGain.disconnect();
    } catch {}
    sirenGain = null;
  }

  isAlarmSounding = false;
  dispatchAlertEvent("vault-alarm-state", { active: false });
}

export function acknowledgeAlert() {
  stopAlarm();
  if (currentAlert) {
    currentAlert.acknowledged = true;
  }
  dispatchAlertEvent("vault-alert-acknowledged", currentAlert);
  return currentAlert;
}

export function getAudioState() {
  if (isMuted()) return "SIREN MUTED";
  if (isAlarmSounding) return "SIREN SOUNDING";
  if (audioCtx && audioCtx.state === "running") return "SIREN READY";
  if (audioCtx && audioCtx.state === "suspended") return "SIREN BLOCKED";
  return "SIREN READY";
}

export function testSiren() {
  initAudio();
  startAlarm({ duration: 2000 });
}

/* =========================================================
   PWA WEB PUSH NOTIFICATION SUBSCRIPTION LIFECYCLE
   ========================================================= */

function urlB64ToUint8Array(base64String) {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

export function isPushSupported() {
  return typeof window !== "undefined" && "serviceWorker" in navigator && "PushManager" in window;
}

export async function getPushSubscription() {
  if (!isPushSupported()) return null;
  try {
    const reg = await navigator.serviceWorker.ready;
    return await reg.pushManager.getSubscription();
  } catch {
    return null;
  }
}

export async function enablePushNotifications() {
  if (!isPushSupported()) {
    throw new Error("Push notifications are not supported in this browser.");
  }
  const perm = await Notification.requestPermission();
  if (perm !== "granted") {
    throw new Error("Push notification permission denied by user.");
  }
  const { api, post } = await import("./common.js");
  const reg = await navigator.serviceWorker.ready;
  const keyRes = await api("/push/public-key");
  const pubKey = keyRes?.public_key;
  if (!pubKey) {
    throw new Error("VAPID public key unavailable from server.");
  }

  const sub = await reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlB64ToUint8Array(pubKey),
  });

  const subJson = sub.toJSON();
  const isMobile = /Mobile|Android|iPhone|iPad/i.test(navigator.userAgent);
  await post("/push/subscribe", {
    endpoint: sub.endpoint,
    keys: {
      p256dh: subJson.keys?.p256dh || "",
      auth: subJson.keys?.auth || "",
    },
    device_label: isMobile ? "Mobile PWA Device" : "Desktop Operations Console",
  });
  dispatchAlertEvent("vault-push-changed", { subscribed: true });
  return sub;
}

export async function disablePushNotifications() {
  if (!isPushSupported()) return true;
  try {
    const { post } = await import("./common.js");
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.getSubscription();
    if (sub) {
      await post("/push/unsubscribe", {
        endpoint: sub.endpoint,
        keys: { p256dh: "", auth: "" },
      }).catch(() => {});
      await sub.unsubscribe();
    }
    dispatchAlertEvent("vault-push-changed", { subscribed: false });
    return true;
  } catch (err) {
    console.warn("Failed to unsubscribe push:", err);
    return false;
  }
}

export async function testPush() {
  const { post } = await import("./common.js");
  return await post("/push/test", {});
}

export const subscribePush = enablePushNotifications;

export async function getAlertsStatus() {
  const { api } = await import("./common.js");
  return await api("/alerts/status");
}

/* =========================================================
   SECURITY BREACH EVALUATION & MODAL DEDUPLICATION
   ========================================================= */

/**
 * Evaluates checkpoint scan result cleanly.
 * Strictly triggers modal and siren for confirmed breach codes only:
 * ZT-001, ZT-002, ZT-008, ZT-009, ZT-013.
 * One event ID = exactly one popup.
 */
export function evaluateSecurityEvent(result) {
  if (!result || typeof result !== "object") return;

  const state = result.state || "";
  const reasonCode = result.reason_code || result.incident_code || "";
  const reason = result.reason || "";
  const isDuplicateFirst = Boolean(result.duplicate_first_party);

  // Never show breach popup for non-breach states
  if (
    state === "STANDBY" ||
    state === "VERIFYING" ||
    state === "WAITING" ||
    state === "GRANTED" ||
    state === "RESET" ||
    isDuplicateFirst ||
    reasonCode === "ZT-007"
  ) {
    if (state === "GRANTED" || state === "RESET") {
      stopAlarm();
    }
    if (state === "RESET" || state === "STANDBY") {
      clearActiveAlert();
    }
    return;
  }

  // If all faces are verified and live: no popup
  if (Array.isArray(result.faces) && result.faces.length > 0) {
    const allValid = result.faces.every((f) => f.is_recognized && f.is_live);
    if (allValid) {
      return;
    }
  }

  // Terminal state guard: latched terminal breach from previous session
  if (result.latched_terminal) {
    if (!result.faces || result.faces.length === 0 || result.faces.every((f) => f.is_recognized && f.is_live)) {
      return;
    }
  }

  const hasSpoof = Array.isArray(result.faces) && result.faces.some((f) => !f.is_live);
  const hasUnrecognized = Array.isArray(result.faces) && result.faces.some((f) => !f.is_recognized);

  let code = reasonCode;
  if (!code || code === "NONE") {
    if (hasSpoof || reason.toLowerCase().includes("spoof")) {
      code = "ZT-002";
    } else if (hasUnrecognized || reason.toLowerCase().includes("unregistered") || reason.toLowerCase().includes("unknown")) {
      code = "ZT-001";
    } else if (reason.toLowerCase().includes("timeout") || reason.toLowerCase().includes("expired")) {
      code = "ZT-008";
    } else if (reason.toLowerCase().includes("replay")) {
      code = "ZT-009";
    } else if (reason.toLowerCase().includes("integrity")) {
      code = "ZT-013";
    } else if (state === "BREACH") {
      code = "ZT-001";
    }
  }

  const isCritical = state === "BREACH" && CRITICAL_REASON_CODES.includes(code);
  if (!isCritical) {
    return;
  }

  // Single breach event ID deduplication: one event ID = one popup
  const eventId =
    result.last_event ||
    result.active_incident ||
    result.id ||
    (code ? `BREACH-${code}` : "BREACH-GENERIC");

  if (shownBreachIds.has(eventId)) {
    if (currentAlert && currentAlert.id === eventId) {
      currentAlert.raw = result;
    }
    return;
  }
  shownBreachIds.add(eventId);

  const subtitle =
    code === "ZT-001"
      ? "UNAUTHORIZED PERSON DETECTED"
      : code === "ZT-002"
        ? "BIOMETRIC SPOOF ATTACK"
        : code === "ZT-008"
          ? "CUSTODY TIMEOUT EXPIRED"
          : code === "ZT-009"
            ? "REPLAY ATTACK DETECTED"
            : code === "ZT-013"
              ? "CAPTURE INTEGRITY VIOLATION"
              : "SECURITY BREACH DETECTED";

  currentAlert = {
    id: eventId,
    code,
    title: "SECURITY BREACH",
    subtitle,
    accessState: "ACCESS DENIED",
    reason: reason || "Unauthorized person detected at vault checkpoint",
    timestamp: new Date().toLocaleTimeString(),
    checkpoint: result.checkpoint_id || "CP-MAIN-01",
    evidence: "CAPTURED",
    acknowledged: false,
    raw: result,
  };

  startAlarm({ duration: 15000 });
  dispatchAlertEvent("vault-critical-alert", currentAlert);
}

function dispatchAlertEvent(name, detail) {
  try {
    document.dispatchEvent(new CustomEvent(name, { detail }));
  } catch {}
}

// Global user interaction listener to prime Web Audio context
if (typeof window !== "undefined") {
  ["click", "keydown", "touchstart"].forEach((evt) => {
    window.addEventListener(evt, initAudio, { once: true, passive: true });
  });
}
