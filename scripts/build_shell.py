"""Generate four static documents with a shared, accessible PWA navigation shell."""
from pathlib import Path
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1] / "public"
ICONS = {
    "checkpoint": '<rect x="3" y="5" width="13" height="14" rx="3"/><path d="m16 10 5-3v10l-5-3"/>',
    "enrollment": '<circle cx="12" cy="8" r="4"/><path d="M4 21v-2a8 8 0 0 1 16 0v2"/>',
    "logs": '<path d="M5 3h10l4 4v14H5zM9 11h6M9 15h6M9 7h2"/>',
    "control": '<path d="M9 3h6M10 3v6L4 19a1 1 0 0 0 1 2h14a1 1 0 0 0 1-2L14 9V3M7 15h10"/>',
}
NAMES = {"checkpoint": "Checkpoint", "enrollment": "Enrollment", "logs": "Audit Logs", "control": "Control Room"}


def icon(page):
    return f'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true">{ICONS[page]}</svg>'


def dial(identifier="timer"):
    return f'''<div class="dial" id="{identifier}" role="timer" aria-label="15-second verification window">
    <svg viewBox="0 0 120 120" aria-hidden="true"><circle class="track" cx="60" cy="60" r="50"/><circle class="arc" cx="60" cy="60" r="50"/></svg>
    <div class="dial-value"><strong>15.0s</strong><small>/ 15.0 SEC</small></div></div>'''


def camera(enrollment=False):
    return f'''<div class="hud" id="hud"><video id="camera" autoplay playsinline muted aria-label="Local camera preview"></video>
    <canvas id="hud-overlay" class="hud-overlay" aria-hidden="true"></canvas>
    <div class="empty" id="camera-empty"><div class="reticle">{icon('checkpoint')}</div><b>{'ENROLLMENT STATION' if enrollment else 'VAULT CHAMBER / CAM 01'}</b><p>Start the camera when you are ready.<br>Your browser will request camera permission.</p></div>
    <i class="hud-corner tl"></i><i class="hud-corner tr"></i><i class="hud-corner bl"></i><i class="hud-corner br"></i><i class="scanline"></i>
    <div class="camera-meta"><span>ENCRYPTED INGESTION</span><span>640 × 480 / LOCAL PREVIEW</span></div></div>'''


CHECKPOINT = f'''
<div class="status-banner" id="verdict" role="status">CHECKPOINT INACTIVE</div>
<div class="grid"><section class="panel"><div class="panel-head"><h2 class="section-label">01 / LIVE BIOMETRIC FEED</h2><span class="badge" id="feed-state">INACTIVE</span></div>
{camera()}
<div class="camera-controls-bar" id="camera-controls-bar">
  <button type="button" class="primary" id="start-camera">START CAMERA</button>
  <button type="button" class="quiet" id="stop-camera" disabled>STOP CAMERA</button>
  <button type="button" class="quiet" id="btn-checkpoint-reset">RESET CHECKPOINT</button>
</div>
<div class="camera-fallback" id="camera-fallback-bar" hidden>
  <span id="camera-prompt-text">CAMERA PERMISSION REQUIRED</span>
</div>
<div class="telemetry">
  <div class="stat"><span class="stat-label">CAMERA</span><strong id="camera-status">STOPPED</strong></div>
  <div class="stat"><span class="stat-label">SCANNER</span><strong id="scanner-status">STOPPED</strong></div>
  <div class="stat"><span class="stat-label">LIVENESS</span><strong id="liveness">NO FACE</strong></div>
  <div class="stat"><span class="stat-label">PUSH</span><strong id="push-status">READY</strong></div>
  <div class="stat"><span class="stat-label">ALARM</span><strong id="alarm-status">SILENT</strong></div>
</div>
<div class="mobile-notifications-card" id="mobile-push-card">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <strong style="color:var(--cyan,#00f0ff);font-size:12px;letter-spacing:1px;">🔔 PWA PUSH ALERTS</strong>
    <span class="badge" id="mobile-push-badge">STANDBY</span>
  </div>
  <p style="font-size:12px;color:#91a5bc;margin:0 0 10px 0;">Receive immediate real-time notifications for confirmed security breaches on this mobile device.</p>
  <div style="display:flex;gap:8px;flex-wrap:wrap;">
    <button type="button" class="primary" id="btn-mobile-enable-push" style="flex:1;">ENABLE SECURITY NOTIFICATIONS</button>
    <button type="button" class="quiet" id="btn-mobile-test-push">TEST PUSH 🔔</button>
  </div>
</div>
<details class="diagnostics-panel" id="diagnostics-panel">
  <summary class="diagnostics-summary">⚙ ADVANCED / DIAGNOSTICS</summary>
  <div class="diagnostics-content">
    <div class="diag-group">
      <span class="diag-label">Diagnostic Alarms & Alerts</span>
      <div class="diag-actions">
        <button type="button" id="btn-test-siren" class="quiet">Test Siren 🔊</button>
        <button type="button" id="toggle-mute" class="quiet">Siren On</button>
      </div>
    </div>
    <div class="diag-group" id="diag-biometrics" style="margin-top:14px;border-top:1px solid var(--line);padding-top:10px;">
      <span class="diag-label">Biometric Pipeline Debug</span>
      <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(130px, 1fr));gap:8px;margin-top:8px;">
        <div class="stat"><span class="stat-label">DETECTOR</span><strong id="diag-detector">OpenCV Haar</strong></div>
        <div class="stat"><span class="stat-label">EMBEDDING MODEL</span><strong id="diag-model">Standard-512D</strong></div>
        <div class="stat"><span class="stat-label">TRACK ID</span><strong id="diag-track">—</strong></div>
        <div class="stat"><span class="stat-label">CANDIDATE</span><strong id="diag-candidate">—</strong></div>
        <div class="stat"><span class="stat-label">SIMILARITY</span><strong id="diag-similarity">—</strong></div>
        <div class="stat"><span class="stat-label">RECOGNITION STATE</span><strong id="diag-rec-state">STANDBY</strong></div>
        <div class="stat"><span class="stat-label">CONSENSUS</span><strong id="diag-consensus">—</strong></div>
        <div class="stat"><span class="stat-label">PAD STATE</span><strong id="diag-pad">—</strong></div>
        <div class="stat"><span class="stat-label">TOTAL BIOMETRIC MS</span><strong id="diag-total-ms">—</strong></div>
      </div>
    </div>
  </div>
</details>
</section>
<div class="stack"><section class="panel"><div class="panel-head"><h2 class="section-label">02 / DUAL-CUSTODY VERIFICATION</h2><span class="badge">Δt ≤ 15.0s</span></div>
<div class="waiting-instruction-card" id="waiting-instruction-card" hidden>
  <div class="waiting-header"><span class="step-badge">STEP 1 COMPLETE</span><strong id="waiting-primary-name" style="color:var(--amber,#f59e0b)">PRIMARY VERIFIED</strong></div>
  <div class="waiting-action">
    <strong>PERSON 1 VERIFIED · MOVE OUT OF CAMERA · SCAN SECOND PERSON</strong>
    <p id="waiting-action-text">Second authorized person must appear within window.</p>
  </div>
</div>
<div class="party" id="party-0"><div class="avatar">1</div><div><strong>Awaiting identity</strong><small>Primary officer / customer</small></div></div>
<div class="party" id="party-1"><div class="avatar">2</div><div><strong>Awaiting identity</strong><small>Second distinct party</small></div></div>
<div class="timer-panel">{dial()}<div><span class="eyebrow">TEMPORAL WINDOW</span><h3 id="timer-title">Ready to verify</h3><p id="deadline-note">The first verified identity starts the 15-second server-enforced clock.</p></div></div>
<div class="rules"><div class="rule"><span>01</span> Two distinct enrolled identities</div><div class="rule"><span>02</span> NCC ≥ 0.82 · Laplacian ≥ 60.0</div><div class="rule"><span>03</span> SHA-256 notarization · AES-256-GCM</div></div>
<div style="margin-top:18px;border-top:1px solid var(--line);padding-top:14px;">
  <label for="mode">Required custody combination</label>
  <div style="display:flex;gap:10px;margin-top:6px;">
    <select id="mode" style="margin-top:0;">
      <option value="standard">Employee + Customer</option>
      <option value="high-value">Two distinct Employees</option>
    </select>
    <button type="button" id="reset" class="quiet" style="white-space:nowrap;">Reset / apply protocol</button>
  </div>
</div>
</section>
</div></div>
<dialog id="breach-modal" class="breach-modal" role="alertdialog" aria-modal="true" aria-labelledby="bm-title">
  <div class="bm-card">
    <div class="bm-header">
      <span class="bm-icon" aria-hidden="true">⚠️</span>
      <h2 id="bm-title" class="bm-title">SECURITY BREACH</h2>
      <p class="bm-subtitle" id="bm-subtitle">UNAUTHORIZED PERSON DETECTED</p>
      <div class="bm-denied-badge" id="bm-code">ZT-001 · ACCESS DENIED</div>
    </div>
    <div class="bm-body">
      <div class="bm-meta-row">
        <span class="bm-meta-label">Checkpoint:</span>
        <strong class="bm-meta-val" id="bm-checkpoint">CP-MAIN-01</strong>
      </div>
      <div class="bm-meta-row">
        <span class="bm-meta-label">Time:</span>
        <strong class="bm-meta-val" id="bm-time">—</strong>
      </div>
      <div class="bm-meta-row">
        <span class="bm-meta-label">Evidence:</span>
        <strong class="bm-meta-val bm-evidence-tag" id="bm-evidence">CAPTURED</strong>
      </div>
    </div>
    <div class="bm-actions">
      <a href="/audit" id="bm-btn-view" class="bm-btn bm-btn-evidence">VIEW EVIDENCE 👁</a>
      <button type="button" id="bm-btn-ack" class="bm-btn bm-btn-ack">ACKNOWLEDGE ALERT</button>
      <button type="button" id="bm-btn-reset" class="bm-btn bm-btn-reset">RESET CHECKPOINT</button>
    </div>
  </div>
</dialog>
'''

ENROLLMENT = f'''
<div class="grid"><section class="panel"><div class="panel-head"><h2 class="section-label">01 / MULTI-SAMPLE IDENTITY CAPTURE</h2><span class="badge">ADMIN ONLY</span></div>{camera(True)}
<div class="camera-controls">
  <button class="primary" id="start-camera">Start enrollment camera</button>
  <button type="button" class="quiet" id="stop-camera" disabled>Stop Camera</button>
  <button type="button" id="capture-sample-btn" class="button" style="background:var(--cyan,#00e5ff);color:#0b0f19;font-weight:700;cursor:pointer" disabled>Capture Sample (1/5)</button>
  <button type="button" id="reset-samples-btn" class="button" style="display:none;cursor:pointer">Reset Samples</button>
</div>
<div class="enrollment-guide" id="enrollment-guide" style="margin:10px 0;padding:12px;background:rgba(18,26,45,0.85);border:1px solid rgba(0,229,255,0.25);border-radius:6px;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
    <span id="sample-step-label" style="font-weight:700;color:var(--cyan,#00e5ff);font-size:13px;letter-spacing:0.05em;">SAMPLE 1/5 · LOOK STRAIGHT</span>
    <span id="sample-count-badge" class="badge" style="border-color:rgba(0,229,255,0.4);color:var(--cyan,#00e5ff)">0 / 5 COLLECTED</span>
  </div>
  <div id="sample-guidance-text" style="font-size:12px;color:#91a5bc;">Align face in camera reticle with even lighting.</div>
</div>
<div class="quality-grid"><div id="quality-lighting" class="quality-item">LIGHTING / WAITING</div><div id="quality-alignment" class="quality-item">ALIGNMENT / WAITING</div><div id="quality-texture" class="quality-item">TEXTURE / WAITING</div><div id="quality-faces" class="quality-item">FACES / —</div></div>
<p class="callout">Multi-sample enrollment captures 5 distinct angles to generate a robust 512-D identity embedding.</p></section>
<div class="stack"><section class="panel"><div class="panel-head"><h2 class="section-label">02 / PERSONNEL DETAILS</h2><span class="badge">AES-256</span></div><form id="enroll-form">
<label>Full name<input id="full-name" required minlength="2" maxlength="80" autocomplete="name" placeholder="e.g. Alex Morgan"></label>
<label>Personnel ID<input id="personnel-id" required pattern="[A-Za-z0-9_-]{{2,40}}" maxlength="40" placeholder="e.g. EMP-1042" autocomplete="off"></label>
<label>Access role<select id="role"><option>Employee</option><option>Customer</option></select></label>
<div class="form-actions"><button class="primary" id="enroll-submit" type="submit" disabled>Enroll Biometric Identity</button></div></form>
<p class="callout">Biometric templates and cropped baselines are encrypted before storage. Duplicate personnel IDs are rejected.</p></section>
<section class="panel"><div class="panel-head"><h2 class="section-label">ENROLLED PERSONNEL</h2></div><div id="personnel-list" class="muted">Sign in as an administrator to view the registry.</div></section>
<section class="panel danger-zone-panel" id="danger-zone-panel" hidden><div class="panel-head"><h2 class="section-label" style="color:var(--red,#ef4444)">ADVANCED / DANGER ZONE</h2><span class="badge" style="background:rgba(239,68,68,0.2);color:#ef4444;border-color:rgba(239,68,68,0.4)">ADMIN ONLY</span></div>
<p style="font-size:13px;color:#91a5bc;margin-bottom:12px;">Irreversible administrative actions for biometric enrollment baselines. Access audit logs and forensic evidence are strictly preserved.</p>
<div class="danger-zone-actions" style="display:flex;gap:10px;flex-wrap:wrap;">
  <button type="button" id="btn-reset-enrollments" class="button" style="background:transparent;color:#ef4444;border-color:#ef4444;font-weight:600">RESET ALL ENROLLMENTS</button>
  <button type="button" id="btn-reset-demo" class="button" style="background:#ef4444;color:#fff;border-color:#ef4444;font-weight:700">RESET DEMO ENVIRONMENT</button>
</div>
</section>
</div></div>'''

LOGS = '''<section class="panel"><div class="panel-head"><h2 class="section-label">FORENSIC EVIDENCE LEDGER</h2><span class="badge" id="event-count">AUTHENTICATION REQUIRED</span></div>
<form class="filters" id="filters"><label>Verdict<select id="filter-status"><option value="">All events</option><option>GRANTED</option><option>DENIED</option><option>BREACH</option><option>RESET</option></select></label><label>From / UTC<input type="date" id="date-start"></label><label>Through / UTC<input type="date" id="date-end"></label><button class="primary" type="submit">Apply filters</button><button type="button" id="refresh">↻ Refresh</button></form>
<div class="table-scroll"><table><thead><tr><th>TIMESTAMP / UTC</th><th>VERDICT</th><th>VERIFIED PARTIES</th><th>PROTOCOL</th><th>SHA-256 DIGEST</th><th>EVIDENCE</th></tr></thead><tbody id="audit-body"></tbody></table><div class="empty-state" id="logs-empty"><b>The evidence trail starts here.</b>Sign in to inspect recent access events, identity roles, and encrypted payloads.</div></div>
<p class="callout">Newest 200 records · Refreshes every 3 seconds · SHA-256 covers the decoded BGR frame bytes · Evidence downloads contain ciphertext only.</p></section>
<dialog id="inspector" aria-labelledby="inspector-title"><button class="close" data-close aria-label="Close inspector">×</button>
<div id="inspector-intruder-badge" class="intruder-badge" hidden>🚨 INTRUDER CAPTURE · UNREGISTERED IDENTITY DETECTED</div>
<h2 id="inspector-title">Evidence inspector</h2>
<div id="inspector-preview-box" class="evidence-preview-box" hidden>
  <div class="preview-box-header">
    <span class="preview-badge">AUTHENTICATED DECRYPTED FRAME</span>
    <span id="preview-dim" class="preview-dim">640 × 480</span>
  </div>
  <div class="preview-img-wrap">
    <img id="evidence-preview-img" alt="Captured Frame Preview" src="" />
    <div id="preview-spinner" class="preview-spinner" hidden>DECRYPTING EVIDENCE...</div>
  </div>
</div>
<dl id="inspector-data"></dl>
<div style="display:flex;gap:10px;align-items:center;margin-top:14px;flex-wrap:wrap">
  <button type="button" id="btn-view-preview" class="primary" style="display:none">View captured frame 👁</button>
  <a id="download-evidence" class="button" href="#" download>Download encrypted payload ↗</a>
  <button type="button" id="copy-modal-hash" class="quiet" style="display:none">Copy SHA-256 Digest ⧉</button>
</div>
<p class="callout">Decrypted server-side in memory for authenticated operators only. Payloads are never placed in the offline cache.</p></dialog>'''

CONTROL = f'''<div class="control-grid"><div class="stack"><section class="panel"><div class="panel-head"><h2 class="section-label">THREAT SIMULATION LAB</h2><span class="badge">ISOLATED PREVIEW</span></div><p>Exercise the visual states without touching the live checkpoint or sending alerts.</p>
<div class="sim-grid"><button data-simulate="spoof"><b>◈ Presentation spoof</b><small>Simulate a printed / replayed face</small></button><button data-simulate="intruder"><b>⌖ Unregistered intruder</b><small>Simulate an unknown identity</small></button><button data-simulate="timeout"><b>◷ Single-custody timeout</b><small>Run the complete 15.0s window</small></button><button data-simulate="granted"><b>✓ Valid dual custody</b><small>Preview the granted state</small></button></div>
<div class="sim-result" id="sim-result" role="status">Select a scenario to begin.</div>{dial('sim-timer')}<p class="callout">All results in this panel are synthetic. No biometric decisions, evidence records, or alerts are created.</p></section>
<section class="panel"><div class="panel-head"><h2 class="section-label">SYSTEM HEALTH & READINESS</h2><span class="badge">ZERO TRUST</span></div><div class="config-grid">
  <div class="config-status">Storage<span id="storage-status">CONNECTED</span></div>
  <div class="config-status">Audit Ledger<span id="audit-status">VERIFIED</span></div>
  <div class="config-status">Local Siren<span id="audio-status">READY</span></div>
  <div class="config-status">Camera<span id="camera-status">READY</span></div>
</div><div class="camera-controls" style="margin-top:14px;"><button type="button" id="btn-test-siren" class="button" style="width:100%;">TEST SIREN 🔊</button></div><p class="callout">Supabase URL and credentials are deployment-managed environment variables in Render. Secrets are never exposed to the browser.</p></section>
<section class="panel" id="blockchain-panel"><div class="panel-head"><h2 class="section-label">HYBRID BLOCKCHAIN AUDIT ANCHORS</h2><span class="badge" id="chain-badge">CHECKING...</span></div>
<p style="font-size:13px;color:#91a5bc;margin-bottom:12px;">Cryptographic Merkle roots of audit events are anchored asynchronously to Ethereum Sepolia and Hyperledger Besu via durable outbox queues.</p>
<div class="config-grid" style="margin-bottom:12px;">
  <div class="config-status">Sepolia (11155111)<span id="chain-status" style="font-size:13px;">CHECKING...</span></div>
  <div class="config-status">Besu QBFT (1337)<span id="besu-status" style="font-size:13px;">CHECKING...</span></div>
  <div class="config-status">Sepolia Anchors<strong id="chain-total-anchors" style="font-size:13px;">0</strong></div>
  <div class="config-status">Besu Anchors<strong id="besu-total-anchors" style="font-size:13px;">0</strong></div>
</div>
<div class="delivery-tracking-grid" style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px;text-align:center;">
  <div style="background:rgba(255,255,255,0.03);padding:6px 4px;border-radius:6px;border:1px solid rgba(255,255,255,0.08);">
    <div style="color:#91a5bc;font-size:10px;font-weight:700;">BATCHES</div>
    <strong id="chain-batches-count" style="font-size:13px;color:#e2e8f0;">0</strong>
  </div>
  <div style="background:rgba(255,255,255,0.03);padding:6px 4px;border-radius:6px;border:1px solid rgba(255,255,255,0.08);">
    <div style="color:#91a5bc;font-size:10px;font-weight:700;">PENDING</div>
    <strong id="chain-pending-count" style="font-size:13px;color:#f59e0b;">0</strong>
  </div>
  <div style="background:rgba(255,255,255,0.03);padding:6px 4px;border-radius:6px;border:1px solid rgba(255,255,255,0.08);">
    <div style="color:#91a5bc;font-size:10px;font-weight:700;">CONFIRMED</div>
    <strong id="chain-confirmed-count" style="font-size:13px;color:#10b981;">0</strong>
  </div>
  <div style="background:rgba(255,255,255,0.03);padding:6px 4px;border-radius:6px;border:1px solid rgba(255,255,255,0.08);">
    <div style="color:#91a5bc;font-size:10px;font-weight:700;">RETRYING</div>
    <strong id="chain-retrying-count" style="font-size:13px;color:#38bdf8;">0</strong>
  </div>
</div>
<div class="form-actions" style="display:flex;gap:10px;flex-direction:column;">
  <button type="button" id="btn-refresh-blockchain" class="quiet" style="width:100%;">REFRESH BLOCKCHAIN STATUS ⟳</button>
</div>
<p class="callout" style="margin-top:14px;">Physical access decisions never wait on blockchain processing. Read-only node verification queries <code>AuditAnchor</code> contract at <code>0x64A6...2995</code>.</p></section></div>
<div class="stack"><section class="panel" id="pushover-panel"><div class="panel-head"><h2 class="section-label">PUSHOVER / LEGACY FALLBACK</h2><span class="badge" id="pushover-badge">CHECKING...</span></div>
<p style="font-size:13px;color:#91a5bc;margin-bottom:12px;">Optional legacy channel used when no native PWA Web Push device is registered. Enable security notifications in the PWA panel below for native alerts.</p>
<div class="config-grid" style="margin-bottom:12px;">
  <div class="config-status">Configuration<strong id="po-config-status" style="font-size:13px;">STANDBY</strong></div>
  <div class="config-status">Connection<span id="po-connect-status" style="font-size:13px;">CHECKING...</span></div>
  <div class="config-status">Last Send Result<strong id="po-last-result" style="font-size:13px;">NEVER</strong></div>
</div>
<div class="delivery-tracking-grid" style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-bottom:14px;text-align:center;">
  <div style="background:rgba(255,255,255,0.03);padding:6px 4px;border-radius:6px;border:1px solid rgba(255,255,255,0.08);">
    <div style="color:#91a5bc;font-size:10px;font-weight:700;">RETRYING ALERTS</div>
    <strong id="po-retrying-count" style="font-size:13px;color:#38bdf8;">0</strong>
  </div>
  <div style="background:rgba(255,255,255,0.03);padding:6px 4px;border-radius:6px;border:1px solid rgba(255,255,255,0.08);">
    <div style="color:#91a5bc;font-size:10px;font-weight:700;">FAILED ALERTS</div>
    <strong id="po-failed-count" style="font-size:13px;color:#ef4444;">0</strong>
  </div>
</div>
<div class="form-actions" style="display:flex;gap:10px;flex-direction:column;">
  <button type="button" id="btn-test-pushover" class="primary" style="width:100%;">TEST PUSHOVER NOTIFICATION 🚨</button>
  <button type="button" id="btn-validate-pushover" class="quiet" style="width:100%;">VALIDATE CONNECTION ⟳</button>
</div>
<p class="callout" style="margin-top:14px;">Credentials are managed securely in Render environment variables (<code>PUSHOVER_APP_TOKEN</code>, <code>PUSHOVER_USER_KEY</code>). Secrets are never exposed to client storage or the browser.</p></section>
<section class="panel" id="push-panel"><div class="panel-head"><h2 class="section-label">PWA REMOTE ALERTS</h2><span class="badge" id="control-push-badge">NOT SUBSCRIBED</span></div>
<div class="config-grid" style="margin-bottom:12px;">
  <div class="config-status">Web Push<strong id="control-push-status" style="font-size:14px;">STANDBY</strong></div>
  <div class="config-status">Active Devices<span id="control-push-devices">0</span></div>
  <div class="config-status">Permission<span id="control-push-perm">DEFAULT</span></div>
</div>
<div class="delivery-tracking-grid" style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px;text-align:center;">
  <div style="background:rgba(255,255,255,0.03);padding:6px 4px;border-radius:6px;border:1px solid rgba(255,255,255,0.08);">
    <div style="color:#91a5bc;font-size:10px;font-weight:700;">QUEUED</div>
    <strong id="track-queued" style="font-size:13px;color:#f59e0b;">0</strong>
  </div>
  <div style="background:rgba(255,255,255,0.03);padding:6px 4px;border-radius:6px;border:1px solid rgba(255,255,255,0.08);">
    <div style="color:#91a5bc;font-size:10px;font-weight:700;">SENT</div>
    <strong id="track-sent" style="font-size:13px;color:#10b981;">0</strong>
  </div>
  <div style="background:rgba(255,255,255,0.03);padding:6px 4px;border-radius:6px;border:1px solid rgba(255,255,255,0.08);">
    <div style="color:#91a5bc;font-size:10px;font-weight:700;">RETRYING</div>
    <strong id="track-retrying" style="font-size:13px;color:#38bdf8;">0</strong>
  </div>
  <div style="background:rgba(255,255,255,0.03);padding:6px 4px;border-radius:6px;border:1px solid rgba(255,255,255,0.08);">
    <div style="color:#91a5bc;font-size:10px;font-weight:700;">FAILED</div>
    <strong id="track-failed" style="font-size:13px;color:#ef4444;">0</strong>
  </div>
</div>
<div class="form-actions" style="display:flex;gap:10px;flex-direction:column;">
  <button type="button" id="btn-enable-push" class="primary" style="width:100%;">ENABLE SECURITY NOTIFICATIONS</button>
  <button type="button" id="btn-test-push" class="quiet" style="width:100%;">TEST PWA PUSH 🔔</button>
</div>
<p class="callout" style="margin-top:14px;">Remote notifications are delivered exclusively via your installed VERITAS PWA. Instant alerts for confirmed breaches (ZT-001, ZT-002, ZT-008, ZT-009, ZT-013).</p></section>
<section class="panel danger-zone-panel"><div class="panel-head"><h2 class="section-label" style="color:var(--red,#ef4444)">ADMINISTRATION / DANGER ZONE</h2><span class="badge" style="background:rgba(239,68,68,0.2);color:#ef4444;border-color:rgba(239,68,68,0.4)">ADMIN ONLY</span></div>
<p style="font-size:13px;color:#91a5bc;margin-bottom:12px;">Completely wipe enrolled test personnel, reset checkpoint state machine to STANDBY, flush template cache, and clear alert queues. Audit chain and forensic evidence are preserved.</p>
<div class="danger-zone-actions">
  <button type="button" id="btn-reset-demo" class="button" style="width:100%;background:#ef4444;color:#fff;border-color:#ef4444;font-weight:700">RESET DEMO ENVIRONMENT</button>
</div>
</section>
</div></div>'''


TITLES = {"checkpoint": ("SECURITY OPERATIONS / VAULT 01", "Live checkpoint", "Verify identities. Enforce dual custody. Seal every evidence trail."),
          "enrollment": ("IDENTITY MANAGEMENT / ONBOARDING", "Face enrollment", "A dedicated station for securely registering officers and customers."),
          "logs": ("FORENSICS / CHAIN OF EVIDENCE", "Audit & evidence", "Trace every verdict to its exact timestamp, verified parties, and encrypted frame."),
          "audit": ("FORENSICS / CHAIN OF EVIDENCE", "Audit ledger", "Trace every verdict to its exact timestamp, verified parties, and encrypted frame."),
          "control": ("ADMINISTRATION / SYSTEM READINESS", "Control room", "Test response states, manage integrations, and connect your security devices.")}


def build():
    (ROOT / "icons").mkdir(parents=True, exist_ok=True)
    (ROOT / "icons" / "logo.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><path d="M32 5 55 14v19c0 13-23 26-23 26S9 46 9 33V14z" fill="#0d2431" stroke="#00f0ff" stroke-width="3"/><path d="m20 25 12 17 13-23" fill="none" stroke="#00f0ff" stroke-width="4"/></svg>', encoding="utf-8")
    for size in (192, 512):
        image = Image.new("RGB", (size, size), "#0b0f19")
        draw = ImageDraw.Draw(image)
        points = [(size*x/64,size*y/64) for x,y in [(32,14),(47,20),(47,34),(43,42),(32,50),(21,42),(17,34),(17,20)]]
        draw.polygon(points, fill="#102c38", outline="#00f0ff", width=max(2,size//64))
        draw.line([(size*24/64,size*29/64),(size*31/64,size*39/64),(size*41/64,size*24/64)], fill="#00f0ff", width=max(3,size//28))
        image.save(ROOT / "icons" / f"icon-{size}.png")
    pages = {"checkpoint": CHECKPOINT, "enrollment": ENROLLMENT, "logs": LOGS, "audit": LOGS, "control": CONTROL}
    for page, content in pages.items():
        eyebrow, title, subtitle = TITLES[page]
        script_name = "logs" if page == "audit" else page
        nav = ''.join(f'<a href="/{key}" class="nav-{key}" {"aria-current=page" if key==page or (page=="audit" and key=="logs") else ""}>{icon(key)}<span>{label}</span></a>' for key,label in NAMES.items())
        html = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><meta name="theme-color" content="#0b0f19"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="description" content="VERITAS-Vault authenticated security operations"><title>{title} · VERITAS-Vault</title><link rel="manifest" href="/manifest.json"><link rel="icon" href="/icons/logo.svg" type="image/svg+xml"><link rel="apple-touch-icon" href="/icons/icon-192.png"><link rel="stylesheet" href="/assets/styles.css"><script type="module" src="/assets/{script_name}.js"></script></head>
<body><a class="skip" href="#main">Skip to content</a><div class="offline-bar" id="offline" hidden role="status">Offline shell · verification and evidence access paused</div><header class="topbar"><a class="brand" href="/checkpoint"><img src="/icons/logo.svg" alt=""><span>VERITAS<small>VAULT SECURITY SYSTEMS</small></span></a><nav class="nav" aria-label="Primary navigation">{nav}</nav><div class="top-actions"><span id="connection" class="connection" aria-label="Network status"></span><span id="operator" class="eyebrow"></span><button class="install quiet" data-install hidden>Install ↗</button><button id="signin">Operator sign-in</button><button id="signout" hidden>Sign out</button></div></header>
<main id="main"><section class="hero compact-hero"><div><div class="eyebrow">{eyebrow}</div><h1>{title}<em>.</em></h1><p>{subtitle}</p></div></section><div id="notice" class="notice" role="status"></div>{content}</main>
<footer class="footer"><span>VERITAS VAULT OPERATING CONSOLE</span><span>DUAL CUSTODY · ENCRYPTED EVIDENCE · AUDIT CHAIN</span></footer><div id="toast" class="toast" hidden role="status"></div>
<dialog id="auth-dialog" aria-labelledby="auth-title"><button class="close" data-close aria-label="Close sign-in">&times;</button><p class="eyebrow">AUTHORIZED PERSONNEL ONLY</p><h2 id="auth-title">Operator authentication</h2><p>Use your Supabase operator email or the locally configured administrator account.</p><form id="auth-form"><label>Operator email / username<input id="username" required autocomplete="username"></label><label>Password<input id="password" required type="password" autocomplete="current-password"></label><p id="auth-error" role="alert"></p><div class="form-actions"><button class="primary" type="submit">Authenticate</button></div></form><p class="callout">Local first run: execute <code>python scripts/setup_local.py</code>. No default password is enabled.</p></dialog><noscript><div class="notice">JavaScript is required for camera capture and protected operations.</div></noscript></body></html>'''
        directory=ROOT/page
        directory.mkdir(parents=True,exist_ok=True)
        (directory/'index.html').write_text(html,encoding='utf-8')


if __name__ == '__main__':
    build()
