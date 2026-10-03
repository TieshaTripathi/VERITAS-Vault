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
let stopCamera,
  timer,
  busy = false,
  qualityOK = false;
const video = $("#camera");
function stop() {
  stopCamera?.();
  stopCamera = null;
  clearInterval(timer);
  qualityOK = false;
  $("#enroll-submit").disabled = true;
}
async function quality() {
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
      item.className = "quality-item " + (result[key] ? "pass" : "fail");
      item.textContent =
        id.toUpperCase() + " / " + (result[key] ? "READY" : "ADJUST");
    }
    $("#quality-faces").textContent = "FACES / " + result.face_count;
    qualityOK =
      result.face_count === 1 &&
      result.lighting_ok &&
      result.aligned &&
      result.texture_ok;
    $("#enroll-submit").disabled = !qualityOK;
  } catch (error) {
    stop();
    toast(error.message);
  } finally {
    busy = false;
  }
}
$("#start-camera").onclick = () =>
  action($("#start-camera"), async () => {
    if (currentUser?.role !== "admin")
      throw new Error("Administrator sign-in is required for enrollment.");
    stop();
    stopCamera = await startCamera(video, $("#camera-empty"));
    timer = setInterval(quality, 1200);
    await quality();
  });
$("#enroll-form").onsubmit = (event) => {
  event.preventDefault();
  action($("#enroll-submit"), async () => {
    if (!qualityOK)
      throw new Error("Adjust camera lighting and alignment first.");
    await post("/enrollment", {
      image: snapshot(video),
      name: $("#full-name").value,
      personnel_id: $("#personnel-id").value,
      role: $("#role").value,
    });
    toast("Personnel enrolled. Encrypted baseline stored.");
    event.target.reset();
    await loadPeople();
  });
};
async function loadPeople() {
  if (currentUser?.role !== "admin") return;
  try {
    const people = await api("/personnel");
    $("#personnel-list").replaceChildren();
    if (!people.length) {
      $("#personnel-list").textContent = "No personnel enrolled yet.";
      return;
    }
    for (const person of people) {
      const line = document.createElement("div");
      line.className = "config-status";
      line.textContent = person.id + " · " + person.name + " / " + person.role;
      $("#personnel-list").append(line);
    }
  } catch (error) {
    toast(error.message);
  }
}
document.addEventListener("vault-auth", loadPeople);
loadPeople();
addEventListener("pagehide", stop);
addEventListener("offline", stop);
