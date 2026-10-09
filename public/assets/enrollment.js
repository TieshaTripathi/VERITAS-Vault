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
} from "./common.js";

const STEPS = [
  "LOOK STRAIGHT",
  "TURN SLIGHTLY LEFT",
  "TURN SLIGHTLY RIGHT",
  "MOVE SLIGHTLY CLOSER",
  "NEUTRAL POSITION",
];

let stopCamera,
  timer,
  busy = false,
  qualityOK = false,
  currentStepIndex = 0;

const collectedSamples = [];
const video = $("#camera");

function stop() {
  stopCamera?.();
  stopCamera = null;
  clearInterval(timer);
  qualityOK = false;
  updateUI();
}

function updateUI() {
  const stepLabel = $("#sample-step-label");
  const countBadge = $("#sample-count-badge");
  const captureBtn = $("#capture-sample-btn");
  const resetBtn = $("#reset-samples-btn");
  const submitBtn = $("#enroll-submit");
  const guidance = $("#sample-guidance-text");

  const total = STEPS.length;
  const count = collectedSamples.length;

  if (countBadge) {
    countBadge.textContent = `${count} / ${total} COLLECTED`;
    countBadge.style.color = count === total ? "var(--green)" : "var(--cyan)";
  }

  if (resetBtn) {
    resetBtn.style.display = count > 0 ? "inline-block" : "none";
  }

  if (count < total) {
    const stepName = STEPS[count];
    if (stepLabel) {
      stepLabel.textContent = `SAMPLE ${count + 1}/${total} · ${stepName}`;
      stepLabel.style.color = "var(--cyan)";
    }
    if (guidance) {
      guidance.textContent = qualityOK
        ? `Ready! Click "Capture Sample" for: ${stepName}`
        : `Please adjust pose: ${stepName}`;
    }
    if (captureBtn) {
      captureBtn.disabled = !qualityOK || !stopCamera;
      captureBtn.textContent = `Capture Sample (${count + 1}/${total})`;
    }
    if (submitBtn) {
      submitBtn.disabled = true;
    }
  } else {
    if (stepLabel) {
      stepLabel.textContent = "5/5 SAMPLES COLLECTED ✓";
      stepLabel.style.color = "var(--green)";
    }
    if (guidance) {
      guidance.textContent = "Multi-sample capture complete! Fill in personnel details and submit enrollment.";
    }
    if (captureBtn) {
      captureBtn.disabled = true;
      captureBtn.textContent = "All Samples Captured ✓";
    }
    if (submitBtn) {
      submitBtn.disabled = false;
    }
  }
}

async function checkQuality() {
  if (busy || !stopCamera) return;
  busy = true;
  try {
    const result = await post("/enrollment/quality", {
      image: snapshot(video),
    });

    for (const [id, key] of [
      ["lighting", "lighting_ok"],
      ["alignment", "aligned"],
      ["texture", "texture_ok"],
    ]) {
      const item = $("#quality-" + id);
      if (item) {
        item.className = "quality-item " + (result[key] ? "pass" : "fail");
        item.textContent = id.toUpperCase() + " / " + (result[key] ? "READY" : "ADJUST");
      }
    }

    const facesEl = $("#quality-faces");
    if (facesEl) {
      facesEl.textContent = "FACES / " + (result.face_count || 0);
    }

    qualityOK =
      result.face_count === 1 &&
      result.lighting_ok &&
      result.aligned &&
      result.texture_ok;

    updateUI();
  } catch (error) {
    stop();
    toast(error.message);
  } finally {
    busy = false;
  }
}

const startCameraBtn = $("#start-camera");
if (startCameraBtn) {
  startCameraBtn.onclick = () =>
    action(startCameraBtn, async () => {
      if (currentUser?.role !== "admin") {
        throw new Error("Administrator sign-in is required for enrollment.");
      }
      stop();
      stopCamera = await startCamera(video, $("#camera-empty"));
      timer = setInterval(checkQuality, 1000);
      await checkQuality();
    });
}

const captureBtn = $("#capture-sample-btn");
if (captureBtn) {
  captureBtn.onclick = () => {
    if (!stopCamera || !qualityOK || collectedSamples.length >= STEPS.length) return;
    const snap = snapshot(video);
    collectedSamples.push(snap);
    const count = collectedSamples.length;
    toast(`Sample ${count}/${STEPS.length} captured ✓`);
    updateUI();
  };
}

const resetBtn = $("#reset-samples-btn");
if (resetBtn) {
  resetBtn.onclick = () => {
    collectedSamples.length = 0;
    toast("Enrollment samples cleared. Restarting sample 1.");
    updateUI();
  };
}

const enrollForm = $("#enroll-form");
if (enrollForm) {
  enrollForm.onsubmit = (event) => {
    event.preventDefault();
    const submitBtn = $("#enroll-submit");
    action(submitBtn, async () => {
      if (collectedSamples.length < STEPS.length) {
        throw new Error(`Collect all ${STEPS.length} samples first.`);
      }

      await post("/enrollment", {
        samples: collectedSamples,
        image: collectedSamples[0],
        name: $("#full-name").value,
        personnel_id: $("#personnel-id").value,
        role: $("#role").value,
      });

      toast("Personnel enrolled! 512-D identity embedding sealed and encrypted.");
      event.target.reset();
      collectedSamples.length = 0;
      updateUI();
      await loadPeople();
    });
  };
}

async function loadPeople() {
  const dangerZone = $("#danger-zone-panel");
  if (currentUser?.role !== "admin") {
    if (dangerZone) dangerZone.hidden = true;
    return;
  }
  if (dangerZone) dangerZone.hidden = false;
  try {
    const people = await api("/personnel");
    const list = $("#personnel-list");
    if (!list) return;
    list.replaceChildren();
    if (!people.length) {
      list.textContent = "No personnel enrolled.";
      return;
    }
    for (const person of people) {
      const line = document.createElement("div");
      line.className = "config-status";
      line.textContent = `${person.id} · ${person.name} / ${person.role}`;
      list.append(line);
    }
  } catch (error) {
    toast(error.message);
  }
}

const btnResetEnrollments = $("#btn-reset-enrollments");
if (btnResetEnrollments) {
  btnResetEnrollments.onclick = async () => {
    if (currentUser?.role !== "admin") return;
    const ok = window.confirm("Delete all enrolled biometric identities and clear cache?");
    if (!ok) return;
    try {
      btnResetEnrollments.disabled = true;
      const res = await api("/personnel", { method: "DELETE" });
      toast(`All enrolled identities reset (${res.deleted || 0} deleted). Biometric cache cleared.`);
      await loadPeople();
      const list = $("#personnel-list");
      if (list) list.textContent = "No personnel enrolled.";
    } catch (err) {
      toast(err.message || "Failed to reset enrollments.");
    } finally {
      btnResetEnrollments.disabled = false;
    }
  };
}

document.addEventListener("vault-auth", loadPeople);
loadPeople();
addEventListener("pagehide", stop);
addEventListener("offline", stop);
