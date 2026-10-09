/**
 * VERITAS-Vault Audio Alarm and Local Security Alert Subsystem.
 * Performance-first, minimal architecture: Local siren, Telegram testing, and breach deduplication.
 */

// Test compatibility stubs (Web Push disabled in production)
export async function getPushSubscription() { return null; }
export async function subscribePush() { return null; }
export async function unsubscribePush() { return true; }
export async function testPush() { return { sent: 0 }; }

let audioCtx = null;
let sirenOsc = null;
let sirenGain = null;
let sirenTimer = null;
let autoStopTimer = null;
let isAlarmSounding = false;
let currentAlert = null;
let lastNotifiedEventId = null;
const notifiedEventIds = new Set();

const STORAGE_KEY_MUTED = "vault_alarm_muted";

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
  lastNotifiedEventId = null;
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

    // Controlled volume — prominent without clipping
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

    // Bounded siren duration (defaults to 12s)
    clearTimeout(autoStopTimer);
    autoStopTimer = setTimeout(() => {
      stopAlarm();
    }, duration);

    dispatchAlertEvent("vault-alarm-state", { active: true });
  } catch (err) {
    console.warn("[alerts] Web Audio playback failed:", err);
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
  if (audioCtx && audioCtx.state === "suspended") return "SIREN BLOCKED BY BROWSER";
  return "SIREN READY";
}

export function testSiren() {
  initAudio();
  startAlarm({ duration: 2000 });
}

export async function testTelegram() {
  return await post("/alerts/telegram/test", {});
}

export async function getAlertsStatus() {
  return await api("/alerts/status");
}

export const CRITICAL_REASON_CODES = ["ZT-001", "ZT-002", "ZT-008", "ZT-009", "ZT-013"];

/**
 * Event Severity Classifier:
 * - Critical only: ZT-001, ZT-002, ZT-008, ZT-009, ZT-013 -> siren, breach modal
 * - Non-alarm states: STANDBY, WAITING, GRANTED, RESET
 */
export function evaluateSecurityEvent(result) {
  if (!result || typeof result !== "object") return;

  const state = result.state || "";
  const reasonCode = result.reason_code || result.incident_code || "";
  const reason = result.reason || "";
  const isDuplicateFirst = Boolean(result.duplicate_first_party);

  // Do NOT show breach popup for:
  // STANDBY, WAITING, GRANTED, recognized duplicate first user, ZT-007, RESET
  if (
    state === "STANDBY" ||
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

  // Biometric recognition check:
  // If all faces are is_recognized == true AND is_live == true: NO popup.
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

  // Critical failure identification
  let code = reasonCode;
  if (!code || code === "NONE") {
    if (hasSpoof || reason.toLowerCase().includes("spoof")) {
      code = "ZT-002";
    } else if (hasUnrecognized || reason.toLowerCase().includes("unregistered") || reason.toLowerCase().includes("unauthorized") || reason.toLowerCase().includes("unknown")) {
      code = "ZT-001";
    } else if (reason.toLowerCase().includes("expired") || reason.toLowerCase().includes("timeout")) {
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

  // Event deduplication using event ID / last_event as unique key
  const eventId =
    result.last_event ||
    result.active_incident ||
    result.id ||
    (code ? `BREACH-${code}` : "BREACH-GENERIC");

  // Rule: If incoming result has the SAME breach event ID as currentAlert.id:
  // - do NOT reopen modal
  // - do NOT restart siren
  // - do NOT reset acknowledged=false
  // - only update current telemetry/raw result
  if (currentAlert && currentAlert.id === eventId) {
    currentAlert.raw = result;
    return;
  }

  // Acknowledged alert must NEVER reopen for same event ID
  if (currentAlert?.acknowledged && currentAlert.id === eventId) {
    currentAlert.raw = result;
    return;
  }

  // Only trigger a new alert when a new unique breach event ID appears
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

  // Play Web Audio siren on new critical breach
  startAlarm({ duration: 15000 });

  dispatchAlertEvent("vault-critical-alert", currentAlert);
}

function dispatchAlertEvent(name, detail) {
  try {
    document.dispatchEvent(new CustomEvent(name, { detail }));
  } catch {}
}

// Global user interaction handler to prime audio context
["click", "keydown", "touchstart"].forEach((evt) => {
  window.addEventListener(evt, initAudio, { once: true, passive: true });
});
