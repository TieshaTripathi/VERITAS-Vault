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

/* =========================================================
   VERITAS VAULT — PRODUCTION BACKEND
   Firebase frontend -> Render FastAPI backend
   ========================================================= */

const API_BASE = "https://veritas-vault-backend.onrender.com";

/* =========================================================
   API CLIENT
   ========================================================= */

export async function api(path, options = {}) {
  if (!navigator.onLine) {
    throw new Error("Offline. Protected operations are paused.");
  }

  const controller = new AbortController();

  /*
   * Render free tier can take some time to wake up after inactivity,
   * so we allow a longer timeout than the original local setup.
   */
  const timeout = setTimeout(() => controller.abort(), 30000);

  try {
    const response = await fetch(API_BASE + "/api" + path, {
      credentials: "include",
      ...options,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        "X-Vault-Request": "1",
        ...options.headers,
      },
      cache: "no-store",
    });

    let result;

    try {
      result = await response.json();
    } catch {
      throw new Error(
        "Backend returned an invalid response. Please try again.",
      );
    }

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
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error(
        "Backend is taking too long to respond. The free server may be waking up. Please try again.",
      );
    }

    if (
      error instanceof TypeError &&
      !error.status
    ) {
      throw new Error(
        "Unable to connect to the secure backend.",
      );
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

/* =========================================================
   POST HELPER
   ========================================================= */

export const post = (path, body = {}) =>
  api(path, {
    method: "POST",
    body: JSON.stringify(body),
  });

/* =========================================================
   BUTTON ACTION HELPER
   ========================================================= */

export async function action(button, work) {
  button.disabled = true;

  try {
    return await work();
  } catch (error) {
    toast(
      error.message ||
      "Unable to complete operation",
    );
  } finally {
    button.disabled = false;
  }
}

/* =========================================================
   CURRENT OPERATOR
   ========================================================= */

export let currentUser = null;

const names = {
  checkpoint: "Checkpoint",
  enrollment: "Enrollment",
  logs: "Audit Logs",
  control: "Control Room",
};

/* =========================================================
   ACTIVE NAVIGATION
   ========================================================= */

document.querySelectorAll(".nav a").forEach((link) => {
  if (link.pathname === location.pathname) {
    link.setAttribute("aria-current", "page");
  }
});

/* =========================================================
   CONNECTION STATUS
   ========================================================= */

function connection() {
  const offline = !navigator.onLine;

  const offlineNode = $("#offline");
  const connectionNode = $("#connection");

  if (offlineNode) {
    offlineNode.hidden = !offline;
  }

  if (connectionNode) {
    connectionNode.classList.toggle(
      "online",
      !offline,
    );

    connectionNode.title = offline
      ? "Offline"
      : "Network available";
  }
}

addEventListener("online", connection);
addEventListener("offline", connection);

connection();

/* =========================================================
   LOGIN DIALOG
   ========================================================= */

const signinButton = $("#signin");

if (signinButton) {
  signinButton.onclick = () => {
    const dialog = $("#auth-dialog");

    if (dialog) {
      dialog.showModal();
    }
  };
}

document
  .querySelectorAll("[data-close]")
  .forEach((button) => {
    button.onclick = () => {
      const dialog = button.closest("dialog");

      if (dialog) {
        dialog.close();
      }
    };
  });

/* =========================================================
   LOGIN FORM
   ========================================================= */

const authForm = $("#auth-form");

if (authForm) {
  authForm.onsubmit = async (event) => {
    event.preventDefault();

    const errorNode = $("#auth-error");

    if (errorNode) {
      errorNode.textContent = "";
    }

    const button = $(
      "button[type=submit]",
      event.target,
    );

    if (button) {
      button.disabled = true;
    }

    try {
      currentUser = await post(
        "/auth/login",
        {
          username: $("#username").value,
          password: $("#password").value,
        },
      );

      $("#password").value = "";

      const dialog = $("#auth-dialog");

      if (dialog) {
        dialog.close();
      }

      await initialize();

      document.dispatchEvent(
        new Event("vault-auth"),
      );
    } catch (error) {
      if (errorNode) {
        errorNode.textContent =
          error.message ||
          "Authentication failed.";
      }
    } finally {
      if (button) {
        button.disabled = false;
      }
    }
  };
}

/* =========================================================
   LOGOUT
   ========================================================= */

const signoutButton = $("#signout");

if (signoutButton) {
  signoutButton.onclick = () =>
    action(signoutButton, async () => {
      await post("/auth/logout");

      location.reload();
    });
}

/* =========================================================
   INITIALIZE AUTH STATE
   ========================================================= */

export async function initialize() {
  const notice = $("#notice");

  try {
    currentUser = await api("/auth/me");

    if ($("#signin")) {
      $("#signin").hidden = true;
    }

    if ($("#signout")) {
      $("#signout").hidden = false;
    }

    if ($("#operator")) {
      $("#operator").textContent =
        currentUser.role.toUpperCase();
    }

    if (notice) {
      notice.textContent = "";
    }
  } catch (error) {
    currentUser = null;

    if ($("#signin")) {
      $("#signin").hidden = false;
    }

    if ($("#signout")) {
      $("#signout").hidden = true;
    }

    if ($("#operator")) {
      $("#operator").textContent = "";
    }

    if (notice) {
      notice.textContent =
        error.status === 401
          ? "Sign in as an authorized operator to access this station."
          : "Backend setup or connectivity needs attention. Protected operations remain locked.";
    }
  }

  return currentUser;
}

/* =========================================================
   PWA INSTALL
   ========================================================= */

let installPrompt;

addEventListener(
  "beforeinstallprompt",
  (event) => {
    event.preventDefault();

    installPrompt = event;

    document
      .querySelectorAll("[data-install]")
      .forEach((button) => {
        button.hidden = false;
      });
  },
);

document
  .querySelectorAll("[data-install]")
  .forEach((button) => {
    button.onclick = async () => {
      if (installPrompt) {
        await installPrompt.prompt();

        installPrompt = null;
      } else {
        toast(
          "On iPhone: Share → Add to Home Screen. Otherwise use your browser’s Install app menu.",
        );
      }
    };
  });

/* =========================================================
   SERVICE WORKER
   ========================================================= */

if ("serviceWorker" in navigator) {
  navigator.serviceWorker
    .register("/sw.js")
    .catch(() => {
      toast(
        "Offline shell installation failed. The online app is still available.",
      );
    });
}

/* =========================================================
   CAMERA
   ========================================================= */

export async function startCamera(
  video,
  empty,
) {
  if (!navigator.mediaDevices?.getUserMedia) {
    throw new Error(
      "Camera access needs HTTPS or localhost.",
    );
  }

  const stream =
    await navigator.mediaDevices.getUserMedia({
      video: {
        facingMode: "user",

        width: {
          ideal: 640,
        },

        height: {
          ideal: 480,
        },
      },

      audio: false,
    });

  video.srcObject = stream;

  await video.play();

  if (empty) {
    empty.hidden = true;
  }

  return () => {
    stream
      .getTracks()
      .forEach((track) => {
        track.stop();
      });

    video.srcObject = null;

    if (empty) {
      empty.hidden = false;
    }
  };
}

/* =========================================================
   CAMERA SNAPSHOT
   ========================================================= */

export function snapshot(video) {
  if (!video.videoWidth) {
    throw new Error(
      "Start the camera first.",
    );
  }

  const canvas =
    document.createElement("canvas");

  canvas.width = 640;

  canvas.height = Math.round(
    (video.videoHeight * 640) /
    video.videoWidth,
  );

  const context =
    canvas.getContext("2d");

  context.drawImage(
    video,
    0,
    0,
    canvas.width,
    canvas.height,
  );

  return canvas.toDataURL(
    "image/jpeg",
    0.85,
  );
}

/* =========================================================
   DUAL-CUSTODY TIMER RING
   ========================================================= */

export function ring(
  root,
  state,
  remaining,
) {
  if (!root) {
    return;
  }

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

  const arc = $(".arc", root);

  const value = $(
    ".dial-value strong",
    root,
  );

  if (arc) {
    arc.style.stroke = color;

    arc.style.strokeDashoffset =
      314.159 *
      (
        1 -
        (
          state === "GRANTED"
            ? 1
            : Math.max(
              0,
              remaining,
            ) / 5
        )
      );
  }

  if (value) {
    value.textContent =
      state === "GRANTED"
        ? "PASS"
        : remaining.toFixed(1) + "s";

    value.style.color = color;
  }
}

/* =========================================================
   START APPLICATION
   ========================================================= */

await initialize();