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
let stopCamera,
  loop,
  busy = false,
  state = "STANDBY",
  end = 0,
  polling = false,
  revision = -1;
const video = $("#camera");
let hudStatusEl = null;
function getHudStatus() {
  if (!hudStatusEl && $("#hud")) {
    hudStatusEl = document.createElement("div");
    hudStatusEl.id = "hud-status";
    hudStatusEl.style.cssText = "position:absolute;top:10px;left:14px;right:14px;background:rgba(11,15,25,0.85);backdrop-filter:blur(8px);border-left:3px solid var(--state,#00f0ff);color:var(--state,#00f0ff);font-family:'Share Tech Mono',monospace;font-size:12px;letter-spacing:2px;padding:6px 12px;z-index:10;border-radius:4px;pointer-events:none;transition:all .2s;";
    hudStatusEl.textContent = "SCANNING FOR FACE...";
    $("#hud").appendChild(hudStatusEl);
  }
  return hudStatusEl;
}
function display(result) {
  const hud = getHudStatus();
  if (hud) {
    if (result.state === "GRANTED") hud.textContent = "ACCESS GRANTED · UNLOCKED";
    else if (result.state === "BREACH") hud.textContent = "SECURITY BREACH · ACCESS DENIED";
    else if (result.faces && result.faces.length > 0) hud.textContent = "HOLD STILL — FIXATING...";
    else hud.textContent = "SCANNING FOR FACE...";
  }
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
  $("#face-count").textContent = result.faces?.length ?? result.parties.length;
  if (result.quality)
    $("#liveness").textContent = result.quality.face_count
      ? result.quality.texture_ok
        ? "PASS"
        : "REJECTED"
      : "NO FACE";
  for (let i = 0; i < 2; i++) {
    const p = result.parties[i],
      node = $("#party-" + i);
    node.classList.toggle("verified", !!p);
    $(".avatar", node).textContent = p ? "✓" : String(i + 1);
    $("strong", node).textContent = p ? p.name : "Awaiting identity";
    $("small", node).textContent = p
      ? p.role
      : i === 0
        ? "Primary officer / customer"
        : "Second distinct party";
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
  if (state === "GRANTED" || state === "BREACH") stop();
}
function stop() {
  clearInterval(loop);
  loop = null;
  stopCamera?.();
  stopCamera = null;
  $("#hud").classList.remove("ingesting");
  $("#start-camera").disabled = false;
  $("#stop-camera").disabled = true;
}
async function scan() {
  if (busy || !stopCamera || !navigator.onLine) return;
  busy = true;
  const hud = getHudStatus();
  if (hud && !["GRANTED", "BREACH"].includes(state)) hud.textContent = "VERIFYING IDENTITY...";
  $("#hud").classList.add("ingesting");
  try {
    // 1. Obtain single-use capture session challenge nonce
    let session = null;
    try {
      session = await post("/checkpoint/session", { device_id: "DEV-PWA-01", checkpoint_id: "CP-MAIN-01" });
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
        const pepResult = await post("/pep/verify", { token: result.authorization_token });
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
    $("#hud").classList.remove("ingesting");
  }
}
$("#start-camera").onclick = () =>
  action($("#start-camera"), async () => {
    if (stopCamera) return;
    if (!currentUser) throw new Error("Sign in before starting surveillance.");
    if (["GRANTED", "BREACH"].includes(state))
      throw new Error("Reset the checkpoint before a new verification.");
    stopCamera = await startCamera(video, $("#camera-empty"));
    $("#stop-camera").disabled = false;
    loop = setInterval(scan, 1000);
    await scan();
  });
$("#stop-camera").onclick = stop;
$("#reset").onclick = () =>
  action($("#reset"), async () =>
    display(await post("/checkpoint/reset", { mode: $("#mode").value })),
  );
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
document.addEventListener("vault-auth", poll);
poll();
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
