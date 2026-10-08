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
  testPush,
  testTelegram,
  subscribePush,
  unsubscribePush,
  getPushSubscription,
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
    if ($("#backend-status")) $("#backend-status").textContent = "ONLINE";
    if ($("#storage-status")) $("#storage-status").textContent = result.storage === "Supabase" ? "CONNECTED" : result.storage;
    if ($("#camera-status")) $("#camera-status").textContent = await checkCameraStatus();
    if ($("#facenet-status")) $("#facenet-status").textContent = "READY";
    if ($("#audio-status")) $("#audio-status").textContent = "READY";
    if ($("#telegram-status")) $("#telegram-status").textContent = result.telegram_configured ? "READY" : "NOT CONFIGURED";
    if ($("#push-status")) $("#push-status").textContent = result.push_configured ? "CONFIGURED" : "NOT CONFIGURED";
    if ($("#subs-count")) $("#subs-count").textContent = String(result.subscriptions_count ?? 0);
    if ($("#audit-status")) $("#audit-status").textContent = result.audit_verified ? "VERIFIED" : "UNVERIFIED";

    const localSub = await getPushSubscription();
    if ($("#device-sub-status")) {
      $("#device-sub-status").textContent = localSub ? "SUBSCRIBED" : "NOT SUBSCRIBED";
    }
  } catch (error) {
    toast(error.message);
  }
}

$("#settings-form").onsubmit = (event) => {
  event.preventDefault();
  action($("#save-settings"), async () => {
    const data = Object.fromEntries(new FormData(event.target));
    await post("/control/settings", data);
    event.target.reset();
    toast(
      "Encrypted server settings saved. Secrets are never returned to the browser.",
    );
    load();
  });
};

$("#btn-test-tg-control")?.addEventListener("click", () =>
  action($("#btn-test-tg-control"), async () => {
    if (!currentUser) throw new Error("Sign in as admin to test Telegram.");
    const res = await testTelegram();
    if (res.ok) {
      toast(`Telegram test alert sent to chat ${res.recipient || ""}`);
    } else {
      toast(res.error || "Telegram alert failed. Configure token and chat ID.");
    }
    load();
  }),
);

$("#enable-push")?.addEventListener("click", () =>
  action($("#enable-push"), async () => {
    if (!currentUser) throw new Error("Sign in before registering notifications.");
    initAudio();
    await subscribePush();
    toast("Device registered for security notifications.");
    load();
  }),
);

$("#disable-push")?.addEventListener("click", () =>
  action($("#disable-push"), async () => {
    await unsubscribePush();
    toast("Device notifications disabled.");
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

$("#btn-test-phone-push")?.addEventListener("click", () =>
  action($("#btn-test-phone-push"), async () => {
    if (!currentUser) throw new Error("Sign in as admin to test push.");
    const res = await testPush();
    if (res.error) {
      toast("Test push failed: " + res.error);
    } else {
      toast(`VERITAS TEST ALERT dispatched to ${res.sent} active subscription(s).`);
    }
    load();
  }),
);

document.addEventListener("vault-auth", load);
load();
addEventListener("pagehide", () => clearInterval(simulationTimer));
