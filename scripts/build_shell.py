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
    return f'''<div class="dial" id="{identifier}" role="timer" aria-label="Five-second verification window">
    <svg viewBox="0 0 120 120" aria-hidden="true"><circle class="track" cx="60" cy="60" r="50"/><circle class="arc" cx="60" cy="60" r="50"/></svg>
    <div class="dial-value"><strong>5.0s</strong><small>/ 5.0 SEC</small></div></div>'''


def camera(enrollment=False):
    return f'''<div class="hud" id="hud"><video id="camera" autoplay playsinline muted aria-label="Local camera preview"></video>
    <canvas id="hud-overlay" class="hud-overlay" aria-hidden="true"></canvas>
    <div class="empty" id="camera-empty"><div class="reticle">{icon('checkpoint')}</div><b>{'ENROLLMENT STATION' if enrollment else 'VAULT CHAMBER / CAM 01'}</b><p>Start the camera when you are ready.<br>Your browser will request camera permission.</p></div>
    <i class="hud-corner tl"></i><i class="hud-corner tr"></i><i class="hud-corner bl"></i><i class="hud-corner br"></i><i class="scanline"></i>
    <div class="camera-meta"><span>ENCRYPTED INGESTION</span><span>640 × 480 / LOCAL PREVIEW</span></div></div>'''


CHECKPOINT = f'''
<div class="critical-alert-card" id="critical-alert-card" hidden role="alert">
  <div class="critical-alert-content">
    <div class="alert-icon">⚠️</div>
    <div class="alert-details">
      <div class="alert-header">
        <strong id="alert-code">SECURITY BREACH · ACCESS DENIED</strong>
        <span id="alert-time" class="alert-time"></span>
      </div>
      <p id="alert-message">UNREGISTERED IDENTITY DETECTED · EVIDENCE CAPTURED · ACCESS LOCKED</p>
    </div>
  </div>
  <div class="alert-actions">
    <button type="button" id="btn-ack-alert" class="ack-btn">ACKNOWLEDGE ALERT</button>
  </div>
</div>
<div class="status-banner" id="verdict" role="status">LOCKED · AUTHENTICATE TO BEGIN VERIFICATION</div>
<div class="grid"><section class="panel"><div class="panel-head"><h2 class="section-label">01 / LIVE BIOMETRIC FEED</h2><span class="badge" id="feed-state">STANDBY</span></div>
{camera()}<div class="camera-controls"><button class="primary" id="start-camera">Start surveillance</button><button id="stop-camera" disabled>Stop camera</button><small>VIDEO STAYS LOCAL · SAMPLED FRAMES VERIFIED SERVER-SIDE</small></div>
<div class="telemetry"><div class="stat"><span class="stat-label">DETECTED</span><strong id="face-count">—</strong></div><div class="stat"><span class="stat-label">LIVENESS</span><strong id="liveness">—</strong></div><div class="stat"><span class="stat-label">ACCESS STATE</span><strong id="lock-state">LOCKED</strong></div></div></section>
<div class="stack"><section class="panel"><div class="panel-head"><h2 class="section-label">02 / DUAL-CUSTODY VERIFICATION</h2><span class="badge">Δt ≤ 5.0s</span></div>
<div class="party" id="party-0"><div class="avatar">1</div><div><strong>Awaiting identity</strong><small>Primary officer / customer</small></div></div>
<div class="party" id="party-1"><div class="avatar">2</div><div><strong>Awaiting identity</strong><small>Second distinct party</small></div></div>
<div class="timer-panel">{dial()}<div><span class="eyebrow">TEMPORAL WINDOW</span><h3 id="timer-title">Ready to verify</h3><p id="deadline-note">The first verified identity starts the server-enforced clock.</p></div></div>
<div class="rules"><div class="rule"><span>01</span> Two distinct enrolled identities</div><div class="rule"><span>02</span> NCC ≥ 0.82 · Laplacian ≥ 60.0</div><div class="rule"><span>03</span> SHA-256 notarization · AES-256-GCM</div></div></section>
<section class="panel" id="alert-center-panel"><div class="panel-head"><h2 class="section-label">03 / ALERT CENTER</h2><span class="badge" id="alert-center-badge">STANDBY</span></div>
<div class="alert-center-box" id="alert-center-standby">
  <div class="alert-center-row">
    <div class="alert-field"><span class="field-label">Alarm sound</span><strong id="alarm-state-indicator" class="field-val">SILENT</strong></div>
    <button type="button" id="toggle-mute" class="ac-btn">SIREN ON</button>
  </div>
  <div class="alert-center-row">
    <div class="alert-field"><span class="field-label">Phone alerts</span><strong id="phone-push-indicator" class="field-val">NOT CONFIGURED</strong></div>
    <button type="button" id="btn-enable-phone" class="ac-btn">ENABLE PHONE ALERTS</button>
  </div>
</div>
<div class="alert-center-box breach-box" id="alert-center-breach" hidden>
  <div class="alert-breach-header">
    <strong id="ac-breach-title">ZT-001 · UNKNOWN IDENTITY</strong>
    <span id="ac-breach-time" class="field-time"></span>
  </div>
  <div class="alert-center-row">
    <div class="alert-field"><span class="field-label">Alarm</span><strong id="ac-breach-alarm" class="field-val alarm-sounding">SOUNDING</strong></div>
    <div class="alert-field"><span class="field-label">Phone push</span><strong id="ac-breach-push" class="field-val">SENT</strong></div>
  </div>
  <div class="alert-center-actions">
    <button type="button" id="btn-ack-alert" class="ack-btn">ACKNOWLEDGE</button>
  </div>
</div></section>
<section class="panel"><div class="panel-head"><h2>Access protocol</h2><span class="badge">ZERO TRUST</span></div><label for="mode">Required custody combination</label><select id="mode"><option value="standard">Employee + Customer</option><option value="high-value">Two distinct Employees</option></select><div class="form-actions"><button id="reset">Reset / apply protocol</button></div><p class="callout">A terminal verdict stays latched until reset. This console reports a policy decision; it does not directly actuate a door lock.</p></section></div></div>'''

ENROLLMENT = f'''
<div class="grid"><section class="panel"><div class="panel-head"><h2 class="section-label">01 / IDENTITY CAPTURE</h2><span class="badge">ADMIN ONLY</span></div>{camera(True)}
<div class="camera-controls"><button class="primary" id="start-camera">Start enrollment camera</button><small>ONE FACE · EVEN LIGHTING · LOOK FORWARD</small></div>
<div class="quality-grid"><div id="quality-lighting" class="quality-item">LIGHTING / WAITING</div><div id="quality-alignment" class="quality-item">ALIGNMENT / WAITING</div><div id="quality-texture" class="quality-item">TEXTURE / WAITING</div><div id="quality-faces" class="quality-item">FACES / —</div></div>
<p class="callout">Quality checks run on fresh snapshots. Enrollment requires exactly one aligned, well-lit face that meets the texture threshold.</p></section>
<div class="stack"><section class="panel"><div class="panel-head"><h2 class="section-label">02 / PERSONNEL DETAILS</h2><span class="badge">AES-256</span></div><form id="enroll-form">
<label>Full name<input id="full-name" required minlength="2" maxlength="80" autocomplete="name" placeholder="e.g. Alex Morgan"></label>
<label>Personnel ID<input id="personnel-id" required pattern="[A-Za-z0-9_-]{{2,40}}" maxlength="40" placeholder="e.g. EMP-1042" autocomplete="off"></label>
<label>Access role<select id="role"><option>Employee</option><option>Customer</option></select></label>
<div class="form-actions"><button class="primary" id="enroll-submit" type="submit" disabled>Capture & enroll identity</button></div></form>
<p class="callout">Biometric templates and cropped baselines are encrypted before storage. Duplicate personnel IDs are rejected.</p></section>
<section class="panel"><div class="panel-head"><h2 class="section-label">ENROLLED PERSONNEL</h2></div><div id="personnel-list" class="muted">Sign in as an administrator to view the registry.</div></section></div></div>'''

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
<div class="sim-grid"><button data-simulate="spoof"><b>◈ Presentation spoof</b><small>Simulate a printed / replayed face</small></button><button data-simulate="intruder"><b>⌖ Unregistered intruder</b><small>Simulate an unknown identity</small></button><button data-simulate="timeout"><b>◷ Single-custody timeout</b><small>Run the complete 5.0s window</small></button><button data-simulate="granted"><b>✓ Valid dual custody</b><small>Preview the granted state</small></button></div>
<div class="sim-result" id="sim-result" role="status">Select a scenario to begin.</div>{dial('sim-timer')}<p class="callout">All results in this panel are synthetic. No biometric decisions, evidence records, push notifications, or WhatsApp messages are created.</p></section>
<section class="panel"><div class="panel-head"><h2 class="section-label">DEVICE & NOTIFICATIONS</h2><span class="badge">PWA</span></div><p>Install the app, then register this device for generic security alerts. Biometric details never appear on the lock screen.</p><div class="camera-controls"><button class="primary" id="enable-push">ENABLE PHONE ALERTS</button><button id="disable-push">Disable on this device</button><button data-install>Install app ↗</button></div>
<div class="camera-controls" style="margin-top: 12px; gap: 8px;">
  <button type="button" id="btn-test-siren" class="button" style="flex:1;">TEST SIREN 🔊</button>
  <button type="button" id="btn-test-phone-push" class="primary" style="flex:1;">TEST PHONE ALERT 📱</button>
</div>
<p class="callout">On iPhone, use Share → Add to Home Screen, then enable alerts from the installed app. Delivery depends on browser/OS permissions and configured VAPID keys.</p></section></div>
<div class="stack"><section class="panel"><div class="panel-head"><h2 class="section-label">INTEGRATION STATUS</h2><span class="badge">ADMIN ONLY</span></div><div class="config-grid">
  <div class="config-status">Backend<span id="backend-status">ONLINE</span></div>
  <div class="config-status">Supabase<span id="storage-status">SIGN IN</span></div>
  <div class="config-status">Camera<span id="camera-status">READY</span></div>
  <div class="config-status">Biometric scanner<span id="facenet-status">READY</span></div>
  <div class="config-status">Alarm audio<span id="audio-status">READY</span></div>
  <div class="config-status">Phone Push<span id="push-status">NOT CHECKED</span></div>
  <div class="config-status">This device<span id="device-sub-status">NOT CHECKED</span></div>
  <div class="config-status">Active push subscriptions<span id="subs-count">0</span></div>
  <div class="config-status">Audit chain<span id="audit-status">VERIFIED</span></div>
</div><p class="callout">Supabase URL and server key are deployment-managed environment variables. Change them in Render and redeploy; the browser never receives privileged keys.</p></section>
<section class="panel"><div class="panel-head"><h2 class="section-label">ALERT CREDENTIAL MANAGER</h2></div><form id="settings-form"><label>CallMeBot phone<input name="CALLMEBOT_PHONE" type="tel" placeholder="+ country code and number" autocomplete="off"></label><label>CallMeBot API key<input name="CALLMEBOT_API_KEY" type="password" placeholder="Leave blank to preserve existing key" autocomplete="new-password"></label><label>VAPID public key<input name="VAPID_PUBLIC_KEY" placeholder="Base64url public key" autocomplete="off"></label><label>VAPID private key<input name="VAPID_PRIVATE_KEY" type="password" placeholder="Never shared with the browser" autocomplete="new-password"></label><label>VAPID contact subject<input name="VAPID_SUBJECT" placeholder="mailto:security@example.com" autocomplete="off"></label><div class="form-actions"><button id="save-settings" class="primary" type="submit">Save encrypted settings</button></div></form></section></div></div>'''

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
        nav = ''.join(f'<a href="/{key}" {"aria-current=page" if key==page or (page=="audit" and key=="logs") else ""}>{icon(key)}<span>{label}</span></a>' for key,label in NAMES.items())
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
