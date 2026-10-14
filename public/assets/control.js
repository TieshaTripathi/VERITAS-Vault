import {
  $,
  escape,
  api,
  post,
  action,
  toast,
  currentUser,
  ring,
} from "./common.js";
import {
  initAudio,
  testSiren,
  enablePushNotifications,
  disablePushNotifications,
  getPushSubscription,
  testPush,
  isPushSupported,
  clearActiveAlert,
  shownBreachIds,
} from "./alerts.js";

let simulationTimer;
document.querySelectorAll("[data-simulate]").forEach(
  (button) =>
    (button.onclick = () => {
      clearInterval(simulationTimer);
      const kind = button.dataset.simulate;
      const display = $("#sim-result");
      display.className = "status-banner";
      display.textContent =
        "SIMULATION / " +
        {
          spoof: "2D PRESENTATION SPOOF · BREACH",
          intruder: "UNKNOWN IDENTITY · BREACH",
          granted: "DUAL CUSTODY SATISFIED · GRANTED",
          timeout: "FIRST PARTY VERIFIED · WAITING",
        }[kind];
      display.style.setProperty(
        "--state",
        kind === "granted"
          ? "#10b981"
          : kind === "timeout"
            ? "#f59e0b"
            : "#ef4444",
      );
      $("#sim-timer").hidden = false;
      const end = performance.now() + 15000;
      const update = () => {
        const remaining = Math.max(0, (end - performance.now()) / 1000);
        ring(
          $("#sim-timer"),
          kind === "timeout"
            ? remaining > 0
              ? "WAITING"
              : "BREACH"
            : kind === "granted"
              ? "GRANTED"
              : "BREACH",
          kind === "timeout" ? remaining : 0,
          15,
        );
        if (kind === "timeout" && remaining <= 0) {
          clearInterval(simulationTimer);
          display.textContent =
            "SIMULATION / WINDOW EXPIRED · SINGLE-CUSTODY BREACH";
          display.style.setProperty("--state", "#ef4444");
        }
      };
      update();
      if (kind === "timeout") simulationTimer = setInterval(update, 50);
    }),
);

async function checkCameraStatus() {
  if (navigator.permissions?.query) {
    try {
      const perm = await navigator.permissions.query({ name: "camera" });
      if (perm.state === "granted") return "READY";
      if (perm.state === "denied") return "BLOCKED";
      return "PERMISSION REQUIRED";
    } catch {}
  }
  return navigator.mediaDevices?.getUserMedia ? "READY" : "UNAVAILABLE";
}

async function load() {
  if (currentUser?.role !== "admin") return;
  try {
    const result = await api("/control");
    if ($("#storage-status")) $("#storage-status").textContent = result.storage === "Supabase" ? "CONNECTED" : result.storage;
    if ($("#camera-status")) $("#camera-status").textContent = await checkCameraStatus();
    if ($("#audio-status")) $("#audio-status").textContent = "READY";
    if ($("#audit-status")) $("#audit-status").textContent = result.audit_verified ? "VERIFIED" : "UNVERIFIED";

    // Query PWA Push status
    try {
      const sub = await getPushSubscription();
      const statusEl = $("#control-push-status");
      const badgeEl = $("#control-push-badge");
      const devicesEl = $("#control-push-devices");
      const permEl = $("#control-push-perm");
      const enableBtn = $("#btn-enable-push");

      const perm = typeof Notification !== "undefined" ? Notification.permission : "unsupported";
      if (permEl) permEl.textContent = perm.toUpperCase();

      const isSubscribed = Boolean(sub);
      if (statusEl) {
        statusEl.textContent = isSubscribed ? "SUBSCRIBED" : "STANDBY";
        statusEl.style.color = isSubscribed ? "var(--green)" : "#91a5bc";
      }
      if (badgeEl) {
        badgeEl.textContent = isSubscribed ? "ACTIVE" : "STANDBY";
        badgeEl.className = isSubscribed ? "badge" : "badge muted";
      }
      if (devicesEl) {
        devicesEl.textContent = String(result.subscriptions_count || (isSubscribed ? 1 : 0));
      }
      if (enableBtn) {
        enableBtn.textContent = isSubscribed
          ? "SECURITY NOTIFICATIONS ACTIVE ✓"
          : "ENABLE SECURITY NOTIFICATIONS";
      }

      // Outbox delivery pipeline tracking
      if (result.delivery_summary) {
        if ($("#track-queued")) $("#track-queued").textContent = String(result.delivery_summary.QUEUED || 0);
        if ($("#track-sent")) $("#track-sent").textContent = String(result.delivery_summary.SENT || 0);
        if ($("#track-retrying")) $("#track-retrying").textContent = String(result.delivery_summary.RETRYING || 0);
        if ($("#track-failed")) $("#track-failed").textContent = String(result.delivery_summary.FAILED || 0);
      }
    } catch (pushErr) {
      console.warn("Failed to retrieve push status:", pushErr);
    }
  } catch (error) {
    toast(error.message);
  }
}

$("#btn-enable-push")?.addEventListener("click", () =>
  action($("#btn-enable-push"), async () => {
    if (!currentUser) throw new Error("Sign in to enable push notifications.");
    const existing = await getPushSubscription();
    if (existing) {
      toast("PWA Push notifications already active on this device.");
      return;
    }
    await enablePushNotifications();
    toast("Security notifications enabled for this PWA!");
    await load();
  }),
);

$("#btn-test-push")?.addEventListener("click", () =>
  action($("#btn-test-push"), async () => {
    if (!currentUser || currentUser.role !== "admin") throw new Error("Administrator sign-in required.");
    const res = await testPush();
    if (res.sent > 0) {
      toast(`Test push delivered to ${res.sent} active device(s).`);
    } else {
      toast(res.error || "No active push subscriptions found. Click 'Enable Security Notifications' first.");
    }
    await load();
  }),
);

$("#btn-reset-demo")?.addEventListener("click", () =>
  action($("#btn-reset-demo"), async () => {
    if (!currentUser || currentUser.role !== "admin") throw new Error("Administrator sign-in required.");
    const ok = window.confirm(
      "RESET DEMO ENVIRONMENT?\n\nThis will clear:\n- All enrolled test personnel\n- Biometric template cache\n- Active checkpoint state (reset to STANDBY)\n- Active incidents\n- Pending alert jobs\n- Old push subscriptions\n\nAudit chain ledger and forensic evidence will be preserved."
    );
    if (!ok) return;

    try {
      // Clear client state
      clearActiveAlert();
      shownBreachIds.clear();
      try {
        localStorage.removeItem("vault_alarm_muted");
        sessionStorage.clear();
      } catch {}

      const res = await post("/admin/reset-demo", {});
      toast("Demo environment reset: Checkpoint is STANDBY, cache cleared.");
      await load();
    } catch (err) {
      toast(err.message || "Failed to reset demo environment.");
    }
  }),
);

$("#btn-test-siren")?.addEventListener("click", () => {
  try {
    initAudio();
    testSiren();
    toast("Test siren sounding for 2 seconds.");
  } catch (e) {
    toast(e.message || "Failed to trigger test siren.");
  }
});

document.addEventListener("vault-auth", load);
document.addEventListener("vault-push-changed", load);
load();
addEventListener("pagehide", () => clearInterval(simulationTimer));
