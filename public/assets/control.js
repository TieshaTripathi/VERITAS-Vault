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
async function load() {
  if (currentUser?.role !== "admin") return;
  try {
    const result = await api("/control");
    $("#storage-status").textContent = result.storage;
    $("#facenet-status").textContent = result.facenet
      ? "MODEL CONFIGURED"
      : "NCC ACTIVE / FACENET NOT CONFIGURED";
    $("#whatsapp-status").textContent = result.configured.CALLMEBOT_API_KEY
      ? "KEY CONFIGURED"
      : "NOT CONFIGURED";
    $("#push-status").textContent = result.configured.VAPID_PRIVATE_KEY
      ? "VAPID CONFIGURED"
      : "NOT CONFIGURED";
    $("#outbox-status").textContent =
      result.outbox.filter((j) => !j.done).length + " ALERTS PENDING";
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
function decodeKey(value) {
  const raw = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}
$("#enable-push").onclick = () =>
  action($("#enable-push"), async () => {
    if (!currentUser)
      throw new Error("Sign in before registering notifications.");
    if (!("PushManager" in window) || !("Notification" in window))
      throw new Error(
        "This browser does not support Web Push. On iPhone install the app first.",
      );
    const { public_key } = await api("/push/key");
    if (!public_key)
      throw new Error("Configure VAPID keys before enabling push.");
    if ((await Notification.requestPermission()) !== "granted")
      throw new Error("Notification permission was not granted.");
    const registration = await navigator.serviceWorker.ready;
    const subscription =
      (await registration.pushManager.getSubscription()) ||
      (await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: decodeKey(public_key),
      }));
    await post("/push/subscribe", subscription.toJSON());
    toast("Device registered for security notifications.");
  });
$("#disable-push").onclick = () =>
  action($("#disable-push"), async () => {
    const registration = await navigator.serviceWorker.ready;
    const subscription = await registration.pushManager.getSubscription();
    if (subscription) {
      await post("/push/unsubscribe", subscription.toJSON());
      await subscription.unsubscribe();
    }
    toast("Device notifications disabled.");
  });
document.addEventListener("vault-auth", load);
load();
addEventListener("pagehide", () => clearInterval(simulationTimer));
