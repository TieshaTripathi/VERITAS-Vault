export const $ = (selector, root = document) => root.querySelector(selector);
export const escape = (value) => {
  const node = document.createElement("span");
  node.textContent = String(value ?? "");
  return node.innerHTML;
};
export function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (node.hidden = true), 5000);
}
export async function api(path, options = {}) {
  if (!navigator.onLine)
    throw new Error("Offline. Protected operations are paused.");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 18000);
  try {
    const response = await fetch("/api" + path, {
      credentials: "same-origin",
      ...options,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        "X-Vault-Request": "1",
        ...options.headers,
      },
      cache: "no-store",
    });
    const result = await response.json();
    if (!response.ok) {
      const error = new Error(
        typeof result.detail === "string"
          ? result.detail
          : "Request validation failed",
      );
      error.status = response.status;
      throw error;
    }
    return result;
  } finally {
    clearTimeout(timeout);
  }
}
export const post = (path, body = {}) =>
  api(path, { method: "POST", body: JSON.stringify(body) });
export async function action(button, work) {
  button.disabled = true;
  try {
    return await work();
  } catch (error) {
    toast(error.message || "Unable to complete operation");
  } finally {
    button.disabled = false;
  }
}
export let currentUser = null;
const names = {
  checkpoint: "Checkpoint",
  enrollment: "Enrollment",
  logs: "Audit Logs",
  control: "Control Room",
};
document.querySelectorAll(".nav a").forEach((link) => {
  if (link.pathname === location.pathname)
    link.setAttribute("aria-current", "page");
});
function connection() {
  const offline = !navigator.onLine;
  $("#offline").hidden = !offline;
  $("#connection").classList.toggle("online", !offline);
  $("#connection").title = offline ? "Offline" : "Network available";
}
addEventListener("online", connection);
addEventListener("offline", connection);
connection();
$("#signin").onclick = () => $("#auth-dialog").showModal();
document
  .querySelectorAll("[data-close]")
  .forEach(
    (button) => (button.onclick = () => button.closest("dialog").close()),
  );
$("#auth-form").onsubmit = async (event) => {
  event.preventDefault();
  $("#auth-error").textContent = "";
  const button = $("button[type=submit]", event.target);
  button.disabled = true;
  try {
    currentUser = await post("/auth/login", {
      username: $("#username").value,
      password: $("#password").value,
    });
    $("#password").value = "";
    $("#auth-dialog").close();
    await initialize();
    document.dispatchEvent(new Event("vault-auth"));
  } catch (error) {
    $("#auth-error").textContent = error.message;
  } finally {
    button.disabled = false;
  }
};
$("#signout").onclick = () =>
  action($("#signout"), async () => {
    await post("/auth/logout");
    location.reload();
  });
export async function initialize() {
  try {
    currentUser = await api("/auth/me");
    $("#signin").hidden = true;
    $("#signout").hidden = false;
    $("#operator").textContent = currentUser.role.toUpperCase();
    $("#notice").textContent = "";
  } catch (error) {
    currentUser = null;
    $("#notice").textContent =
      error.status === 401
        ? "Sign in as an authorized operator to access this station."
        : "Backend setup or connectivity needs attention. Protected operations remain locked.";
  }
  return currentUser;
}
let installPrompt;
addEventListener("beforeinstallprompt", (event) => {
  event.preventDefault();
  installPrompt = event;
  document
    .querySelectorAll("[data-install]")
    .forEach((b) => (b.hidden = false));
});
document.querySelectorAll("[data-install]").forEach(
  (button) =>
    (button.onclick = async () => {
      if (installPrompt) {
        await installPrompt.prompt();
        installPrompt = null;
      } else
        toast(
          "On iPhone: Share → Add to Home Screen. Otherwise use your browser’s Install app menu.",
        );
    }),
);
if ("serviceWorker" in navigator)
  navigator.serviceWorker
    .register("/sw.js")
    .catch(() =>
      toast(
        "Offline shell installation failed. The online app is still available.",
      ),
    );
export async function startCamera(video, empty) {
  if (!navigator.mediaDevices?.getUserMedia)
    throw new Error("Camera access needs HTTPS or localhost.");
  const stream = await navigator.mediaDevices.getUserMedia({
    video: {
      facingMode: "user",
      width: { ideal: 640 },
      height: { ideal: 480 },
    },
    audio: false,
  });
  video.srcObject = stream;
  await video.play();
  if (empty) empty.hidden = true;
  return () => {
    stream.getTracks().forEach((track) => track.stop());
    video.srcObject = null;
    if (empty) empty.hidden = false;
  };
}
export function snapshot(video) {
  if (!video.videoWidth) throw new Error("Start the camera first.");
  const canvas = document.createElement("canvas");
  canvas.width = 640;
  canvas.height = Math.round((video.videoHeight * 640) / video.videoWidth);
  canvas.getContext("2d").drawImage(video, 0, 0, canvas.width, canvas.height);
  return canvas.toDataURL("image/jpeg", 0.85);
}
export function ring(root, state, remaining) {
  const color =
    state === "BREACH"
      ? "#ef4444"
      : state === "GRANTED"
        ? "#10b981"
        : state === "WAITING"
          ? remaining > 3
            ? "#10b981"
            : remaining > 1.5
              ? "#f59e0b"
              : "#ef4444"
          : "#00f0ff";
  $(".arc", root).style.stroke = color;
  $(".arc", root).style.strokeDashoffset =
    314.159 * (1 - (state === "GRANTED" ? 1 : Math.max(0, remaining) / 5));
  $(".dial-value strong", root).textContent =
    state === "GRANTED" ? "PASS" : remaining.toFixed(1) + "s";
  $(".dial-value strong", root).style.color = color;
}
await initialize();
