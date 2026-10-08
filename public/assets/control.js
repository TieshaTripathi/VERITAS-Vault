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
  testTelegram,
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
      const end = performance.now() + 5000;
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

    // Query Telegram diagnostic status
    try {
      const tg = await api("/alerts/telegram/status");
      const isConfigured = Boolean(tg.configured);
      const tgStatusEl = $("#control-telegram-status");
      const tgBadgeEl = $("#control-telegram-badge");
      const botApiEl = $("#control-bot-api");
      const lastTgEl = $("#control-last-telegram");
      const noticeEl = $("#control-tg-notice");
      const errorEl = $("#control-tg-error");

      if (tgStatusEl) {
        tgStatusEl.textContent = isConfigured ? "CONFIGURED" : "NOT CONFIGURED";
        tgStatusEl.style.color = isConfigured ? "var(--green)" : "#ef4444";
      }
      if (tgBadgeEl) {
        tgBadgeEl.textContent = isConfigured ? "CONFIGURED" : "NOT CONFIGURED";
        tgBadgeEl.className = isConfigured ? "badge" : "badge muted";
      }
      if (botApiEl) {
        if (!isConfigured) {
          botApiEl.textContent = "DISCONNECTED";
          botApiEl.style.color = "#91a5bc";
        } else if (tg.bot_reachable) {
          botApiEl.textContent = "CONNECTED";
          botApiEl.style.color = "var(--green)";
        } else {
          botApiEl.textContent = "DISCONNECTED";
          botApiEl.style.color = "#ef4444";
        }
      }
      if (lastTgEl) {
        const lastSt = tg.last_telegram_status || "NEVER";
        lastTgEl.textContent = lastSt;
        lastTgEl.style.color = lastSt === "SENT" ? "var(--green)" : lastSt === "FAILED" ? "#ef4444" : "#91a5bc";
      }
      if (noticeEl) {
        noticeEl.style.display = isConfigured ? "none" : "block";
      }
      if (errorEl) {
        if (isConfigured && tg.description && tg.description !== "CONNECTED") {
          errorEl.textContent = `Telegram: ${tg.description}`;
          errorEl.style.display = "block";
        } else {
          errorEl.style.display = "none";
        }
      }
    } catch (tgErr) {
      console.warn("Failed to retrieve Telegram diagnostic status:", tgErr);
    }
  } catch (error) {
    toast(error.message);
  }
}

$("#btn-test-tg-control")?.addEventListener("click", () =>
  action($("#btn-test-tg-control"), async () => {
    if (!currentUser || currentUser.role !== "admin") throw new Error("Sign in as admin to test Telegram.");
    const res = await testTelegram();
    if (res.ok) {
      toast("Telegram test alert sent successfully (text and photo delivered).");
    } else {
      toast(res.error || "Telegram alert failed. Check Render environment variables.");
    }
    load();
  }),
);

$("#btn-test-siren")?.addEventListener("click", () => {
  try {
    testSiren();
    toast("Test siren sounding for 2 seconds.");
  } catch (e) {
    toast(e.message || "Failed to trigger test siren.");
  }
});

document.addEventListener("vault-auth", load);
load();
addEventListener("pagehide", () => clearInterval(simulationTimer));
