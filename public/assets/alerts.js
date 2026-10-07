/**
 * VERITAS-Vault Audio Alarm, Browser Notifications, and Alert Center Manager
 * Zero-Trust physical security response subsystem.
 */

let audioCtx = null;
let sirenOsc = null;
let sirenGain = null;
let sirenTimer = null;
let autoStopTimer = null;
let isAlarmSounding = false;
let currentAlert = null;
let lastNotifiedEventId = null;

const STORAGE_KEY_MUTED = "vault_alarm_muted";
const STORAGE_KEY_NOTIFS = "vault_notifications_enabled";

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

export function areNotificationsEnabled() {
  try {
    return (
      "Notification" in window &&
      Notification.permission === "granted" &&
      localStorage.getItem(STORAGE_KEY_NOTIFS) === "true"
    );
  } catch {
    return false;
  }
}

export async function requestNotificationPermission() {
  if (!("Notification" in window)) {
    return "unsupported";
  }
  try {
    const perm = await Notification.requestPermission();
    if (perm === "granted") {
      localStorage.setItem(STORAGE_KEY_NOTIFS, "true");
    } else {
      localStorage.setItem(STORAGE_KEY_NOTIFS, "false");
    }
    dispatchAlertEvent("vault-notif-perm-changed", { permission: perm });
    return perm;
  } catch {
    return "denied";
  }
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

export async function sendSecurityNotification({ title, body, eventId }) {
  if (!areNotificationsEnabled()) return;
  if (eventId && lastNotifiedEventId === eventId) return;

  if (eventId) {
    lastNotifiedEventId = eventId;
  }

  try {
    if (navigator.serviceWorker?.controller) {
      const reg = await navigator.serviceWorker.ready;
      if (reg && reg.showNotification) {
        await reg.showNotification(title, {
          body,
          icon: "/icons/icon-192.png",
          badge: "/icons/logo.svg",
          tag: eventId || "vault-security-breach",
          renotify: true,
          requireInteraction: true,
        });
        return;
      }
    }

    new Notification(title, {
      body,
      icon: "/icons/icon-192.png",
      tag: eventId || "vault-security-breach",
    });
  } catch (err) {
    console.warn("[alerts] Browser notification delivery failed:", err);
  }
}

/**
 * Event Severity Classifier:
 * - CRITICAL: BREACH, ZT-001 (intruder), ZT-002 (spoof), ZT-008 (timeout), ZT-009 (replay), ZT-013 (integrity)
 * - WARNING: window expiring, camera degraded
 * - INFO: STANDBY, WAITING, GRANTED, RESET
 */
export function evaluateSecurityEvent(result) {
  if (!result || typeof result !== "object") return;

  const isBreach = result.state === "BREACH";
  const reasonCode = result.reason_code || "";
  const reason = result.reason || "";
  const hasUnrecognized = Array.isArray(result.faces) && result.faces.some((f) => !f.is_recognized);
  const hasSpoof = Array.isArray(result.faces) && result.faces.some((f) => !f.is_live);

  const isCritical =
    isBreach ||
    ["ZT-001", "ZT-002", "ZT-008", "ZT-009", "ZT-013"].includes(reasonCode) ||
    hasUnrecognized ||
    hasSpoof;

  if (isCritical) {
    const eventId =
      result.last_event ||
      reasonCode ||
      `BREACH-${result.state}-${Date.now()}`;

    let code = reasonCode;
    if (!code) {
      if (hasUnrecognized || reason.toLowerCase().includes("unregistered")) {
        code = "ZT-001";
      } else if (hasSpoof || reason.toLowerCase().includes("spoof")) {
        code = "ZT-002";
      } else {
        code = "ZT-BREACH";
      }
    }

    const title =
      code === "ZT-001"
        ? "UNREGISTERED INTRUDER DETECTED"
        : code === "ZT-002"
          ? "BIOMETRIC PRESENTATION ATTACK"
          : "SECURITY ACCESS BREACH";

    currentAlert = {
      id: eventId,
      code,
      title,
      reason: reason || "Unregistered identity detected at vault checkpoint",
      timestamp: new Date().toLocaleTimeString(),
      checkpoint: "CP-MAIN-01",
      acknowledged: false,
      raw: result,
    };

    // Trigger critical alarm sound
    startAlarm({ duration: 12000 });

    // Trigger browser notification
    sendSecurityNotification({
      title: "VERITAS SECURITY ALERT",
      body: `${title}\nReason: ${currentAlert.reason}\nCheckpoint: CP-MAIN-01\nAccess remains locked.`,
      eventId,
    });

    dispatchAlertEvent("vault-critical-alert", currentAlert);
  } else if (result.state === "RESET" || result.state === "STANDBY") {
    clearActiveAlert();
  } else if (result.state === "GRANTED") {
    stopAlarm();
  }
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
