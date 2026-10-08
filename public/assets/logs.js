import { $, escape, api, action, toast, currentUser, evidenceUrl } from "./common.js";
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
      tr.innerHTML = `<td class="mono">${escape(event.timestamp.slice(0, 19).replace("T", " "))}</td><td><span class="badge ${escape(event.verdict)}">${escape(event.verdict)}</span></td><td>${escape(event.parties.map((p) => p.name).join(" + ") || "—")}</td><td>${escape(event.mode)}</td><td></td><td><button class="quiet inspect">${event.evidence?.path ? "View Evidence 👁" : "Inspect ↗"}</button></td>`;
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

    // Auto-inspect event if specified in query parameter (?event=<event_id>)
    const targetEventId = new URLSearchParams(window.location.search).get("event");
    if (targetEventId && events.length > 0) {
      const match = events.find((e) => e.id === targetEventId);
      if (match) {
        inspect(match);
      }
    }
  } catch (error) {
    toast(error.message);
  } finally {
    busy = false;
  }
}
function inspect(event) {
  $("#inspector-data").replaceChildren();

  // Intruder Badge on ZT-001 or unrecognized identity breach
  const isIntruder =
    event.verdict === "BREACH" &&
    (event.reason?.toLowerCase().includes("unregistered") ||
      event.reason_code === "ZT-001" ||
      !event.parties?.length);
  const badgeEl = $("#inspector-intruder-badge");
  if (badgeEl) {
    badgeEl.hidden = !isIntruder;
  }

  // Reset preview box
  const previewBox = $("#inspector-preview-box");
  const previewImg = $("#evidence-preview-img");
  const previewSpinner = $("#preview-spinner");
  if (previewBox) previewBox.hidden = true;
  if (previewImg) previewImg.src = "";
  if (previewSpinner) {
    previewSpinner.hidden = false;
    previewSpinner.textContent = "DECRYPTING EVIDENCE...";
  }

  const fields = {
    "Event ID": event.id,
    "ISO timestamp": event.timestamp,
    Verdict: event.verdict,
    Policy: event.mode,
    Reason: event.reason,
    "Reason code": event.reason_code || (isIntruder ? "ZT-001" : "—"),
    "Verified roles":
      event.parties.map((p) => `${p.name} (${p.role}) · ${p.id}`).join("\n") ||
      (isIntruder ? "UNKNOWN / UNAUTHORIZED" : "None"),
    "SHA-256 / decoded frame": event.sha256_hash || "No frame attached",
    Storage: event.status || "ENCRYPTED / SUPABASE",
    "Encryption key ID": event.evidence?.key_id || "primary-v1",
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

  const hasEvidence = Boolean(event.evidence?.path);
  const viewPreviewBtn = $("#btn-view-preview");
  const downloadBtn = $("#download-evidence");

  if (viewPreviewBtn) {
    viewPreviewBtn.style.display = hasEvidence ? "inline-flex" : "none";
    viewPreviewBtn.onclick = async () => {
      if (!hasEvidence) return;
      if (previewBox) previewBox.hidden = false;
      if (previewSpinner) previewSpinner.hidden = false;
      if (previewImg) previewImg.style.display = "none";
      try {
        const res = await fetch(evidenceUrl(event.id, true), {
          credentials: "include",
          headers: { "X-Vault-Request": "1" },
        });
        if (!res.ok) {
          throw new Error(`Failed to decrypt evidence: ${res.statusText}`);
        }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        if (previewImg) {
          previewImg.src = url;
          previewImg.onload = () => {
            if (previewSpinner) previewSpinner.hidden = true;
            previewImg.style.display = "block";
            const dimEl = $("#preview-dim");
            if (dimEl) {
              dimEl.textContent = `${previewImg.naturalWidth} × ${previewImg.naturalHeight} · IN-MEMORY DECRYPTED`;
            }
          };
        }
      } catch (err) {
        if (previewSpinner) {
          previewSpinner.textContent = "DECRYPTION FAILED · SECURE ACCESS ONLY";
        }
        toast(err.message);
      }
    };
  }

  if (downloadBtn) {
    downloadBtn.hidden = !hasEvidence;
    downloadBtn.href = hasEvidence ? evidenceUrl(event.id, false) : "#";
  }

  // If intruder event has evidence, auto-trigger preview decryption
  if (isIntruder && hasEvidence && viewPreviewBtn) {
    viewPreviewBtn.click();
  }

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
