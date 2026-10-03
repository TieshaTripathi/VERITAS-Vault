import { $, escape, api, action, toast, currentUser } from "./common.js";
let busy = false,
  events = [];
async function load() {
  if (!currentUser || busy || !navigator.onLine) return;
  busy = true;
  try {
    const query = new URLSearchParams({
      verdict: $("#filter-status").value,
      start: $("#date-start").value,
      end: $("#date-end").value,
    });
    events = await api("/logs?" + query);
    const body = $("#audit-body");
    body.replaceChildren();
    $("#logs-empty").hidden = events.length > 0;
    $("#event-count").textContent = events.length + " RECENT RECORDS";
    for (const event of events) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="mono">${escape(event.timestamp.slice(0, 19).replace("T", " "))}</td><td><span class="badge ${escape(event.verdict)}">${escape(event.verdict)}</span></td><td>${escape(event.parties.map((p) => p.name).join(" + ") || "—")}</td><td>${escape(event.mode)}</td><td></td><td><button class="quiet inspect">Inspect ↗</button></td>`;
      const hash = document.createElement("button");
      hash.className = "hash";
      hash.textContent = event.sha256_hash
        ? event.sha256_hash.slice(0, 12) + "… ⧉"
        : "NO FRAME";
      hash.disabled = !event.sha256_hash;
      hash.onclick = async () => {
        try {
          await navigator.clipboard.writeText(event.sha256_hash);
          toast("Copied SHA-256 Digest!");
        } catch {
          inspect(event);
          toast("Select the full digest in the inspector to copy manually.");
        }
      };
      tr.children[4].append(hash);
      $(".inspect", tr).onclick = () => inspect(event);
      body.append(tr);
    }
  } catch (error) {
    toast(error.message);
  } finally {
    busy = false;
  }
}
function inspect(event) {
  $("#inspector-data").replaceChildren();
  const fields = {
    "Event ID": event.id,
    "ISO timestamp": event.timestamp,
    Verdict: event.verdict,
    Policy: event.mode,
    Reason: event.reason,
    "Verified roles":
      event.parties.map((p) => `${p.name} (${p.role}) · ${p.id}`).join("\n") ||
      "None",
    "SHA-256 / decoded frame": event.sha256_hash || "No frame attached",
    Storage: event.status,
    "Encryption key ID": event.evidence?.key_id || "—",
  };
  for (const [label, value] of Object.entries(fields)) {
    const dt = document.createElement("dt"),
      dd = document.createElement("dd");
    dt.textContent = label;
    dd.textContent = value;
    if (label.includes("SHA-256") && event.sha256_hash) {
      const copyBtn = document.createElement("button");
      copyBtn.className = "quiet";
      copyBtn.style.cssText = "margin-left: 8px; padding: 2px 8px; font-size: 11px; vertical-align: middle;";
      copyBtn.textContent = "Copy ⧉";
      copyBtn.onclick = async (e) => {
        e.preventDefault();
        try {
          await navigator.clipboard.writeText(event.sha256_hash);
          toast("Copied SHA-256 Digest!");
        } catch {
          toast("Clipboard permission denied");
        }
      };
      dd.append(" ", copyBtn);
    }
    $("#inspector-data").append(dt, dd);
  }
  const modalCopyBtn = $("#copy-modal-hash");
  if (modalCopyBtn) {
    if (event.sha256_hash) {
      modalCopyBtn.style.display = "inline-flex";
      modalCopyBtn.onclick = async () => {
        try {
          await navigator.clipboard.writeText(event.sha256_hash);
          toast("Copied SHA-256 Digest!");
        } catch {
          toast("Clipboard permission denied");
        }
      };
    } else {
      modalCopyBtn.style.display = "none";
    }
  }
  $("#download-evidence").hidden = !event.evidence?.path;
  $("#download-evidence").href =
    "/api/logs/" + encodeURIComponent(event.id) + "/evidence";
  $("#inspector").showModal();
}
$("#filters").onsubmit = (event) => {
  event.preventDefault();
  load();
};
$("#refresh").onclick = load;
document.addEventListener("vault-auth", load);
load();
setInterval(() => {
  if (!document.hidden) load();
}, 3000);
