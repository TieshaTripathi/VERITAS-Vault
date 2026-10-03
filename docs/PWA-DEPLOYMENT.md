# VERITAS-Vault v3: browser PWA deployment

## Run locally

Use Python 3.12–3.14. The Python dependencies are pinned in `pyproject.toml`,
`requirements.txt`, and the resolved `uv.lock`.

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe scripts/setup_local.py
.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8502
```

Open http://localhost:8502/checkpoint. The setup script asks you to choose a local
administrator password. It generates a stable encryption key in the ignored `.env`.
There is no hardcoded PWA password. Keep that encryption key securely backed up;
losing it makes existing templates and evidence unrecoverable.

The four pages are real documents at `/checkpoint`, `/enrollment`, `/logs`, and
`/control`. They share a navigation shell; navigation becomes bottom tabs on mobile.
`scripts/build_shell.py` regenerates those documents and the two PNG icons.
The existing Streamlit dashboard remains available with `requirements-legacy.txt`.
It is excluded from the Vercel function bundle and is not the cloud entrypoint.

## Supabase bootstrap

Create/select a dedicated Supabase project and configure:

| Variable | Scope | Purpose |
|---|---|---|
| `SUPABASE_URL` | Server | Project HTTPS API URL |
| `SUPABASE_KEY` | Server | Secret/service-role key, never anon/publishable |
| `DATABASE_URL` | Provisioning only | PostgreSQL connection string with DDL permission |
| `VAULT_ENCRYPTION_KEY` | Server | Base64 encoding of exactly 32 random bytes |
| `VAULT_KEY_ID` | Server | Evidence encryption key version, initially `primary-v1` |
| `APP_ORIGIN` | Server | Exact application origin, e.g. `https://vault.example.com` |
| `CRON_SECRET` | Server | Random worker authorization secret |

Run `python scripts/provision_cloud.py` from a trusted terminal with the environment
configured. It creates/upgrades the tables, enables RLS, restricts browser grants,
installs the atomic `vault_commit` RPC, and provisions the **private**
`encrypted-evidence` bucket. It then verifies database RLS, API access, and bucket
privacy. `supabase/schema.sql` is the idempotent bootstrap source, not a fabricated
CLI migration history entry. Review it before applying to a project that serves
other applications; its table grants intentionally make the vault server-only.

An API key alone cannot create arbitrary SQL tables. `DATABASE_URL` is needed only
for the provisioning command; do not install DDL privileges in the browser.

Cloud-mode authentication uses Supabase Auth. Create your operators in Supabase
and assign trusted **app metadata**, not user metadata:

```json
{"vault_role": "admin"}
```

Use `operator` for checkpoint and audit access; `admin` additionally allows
enrollment, integration configuration, and personnel listing. Public sign-up
does not grant access. The server revalidates cloud user identity and app role on
protected requests. Local and cloud operator sessions expire in one hour; logout
revokes the application's opaque, HttpOnly, SameSite=Strict session cookie.

## Vercel

The root `app.py` exports FastAPI. Vercel's FastAPI preset routes the same paths
used locally and serves the public shell. `vercel.json` supplies function limits,
cache headers, the service-worker scope, and the durable-worker cron schedule.
The Python lockfile prevents deployment from resolving different package versions.

1. Authenticate with Vercel CLI: `npx vercel login`. The CLI is separate deployment
   tooling and is not an application dependency. Alternatively import the GitHub
   repository in Vercel's dashboard and use its Git deployment integration.
2. Link the intended project: `npx vercel link`.
3. Set the server environment variables above for the intended environment.
   Use `npx vercel env add NAME production`; paste each value into the CLI prompt.
   Add `CALLMEBOT_PHONE`, `CALLMEBOT_API_KEY`, `VAPID_PUBLIC_KEY`,
   `VAPID_PRIVATE_KEY`, and `VAPID_SUBJECT` if these integrations are used.
4. Provision Supabase before sending checkpoint traffic.
5. Deploy: `npx vercel --prod`.
6. Verify `/api/health`, operator login, enrollment, custody timeout, evidence
   download, and alert delivery against that deployment.

Environment variables are read server-side by name; secrets are intentionally
not embedded in `vercel.json` or committed as legacy `@secret` bindings.
The Control Room can update alert credentials encrypted at rest, but cannot
replace the root Supabase connection or master encryption key through an HTTP form.

The one-minute recovery cron requires a Vercel plan that permits that frequency.
For a plan without it, use a trusted external scheduler to call `/api/worker`
with `Authorization: Bearer <CRON_SECRET>`, or run `python scripts/worker.py`
on an always-on edge host. Do not weaken cron authentication or fall back to
ephemeral serverless SQLite. When Supabase is configured but unreachable, the
API fails closed; SQLite is used only in local mode when both cloud keys are absent.

## Verification and alert semantics

Camera video stays in the browser via `getUserMedia` (WebRTC media capture).
At most one frame request is active per capture loop. Still frames are processed
in FastAPI's worker pool so the native video preview remains responsive; this is
not a peer-to-peer remote video transport or continuous server-side stream.

The first verified distinct personnel ID anchors a five-second deadline.
PostgreSQL CAS/RPC or SQLite transactions preserve that state across requests.
Duplicate frames do not refresh the deadline; liveness failure of **any** detected
face rejects the attempt. GRANTED/BREACH stays latched until explicit reset.
Pending custody windows cannot be silently reset. The server owns time; the
animated browser timer is presentation only. No hardware lock actuator is wired.

When a window starts, an awaited ASGI background task wakes at its deadline.
Browser ticks also advance the state. The recovery worker covers function
interruption or closed browsers. Serverless suspension can delay notification,
but a later request cannot grant access past an expired deadline.

Terminal verdict, audit record, and alert job are committed in one database
transaction. Alerts use durable jobs, leases, bounded concurrency, per-channel
completion markers, and retry backoff. Delivery is **at least once**, not exactly
once: providers without an idempotency API can receive a duplicate after a worker
crash between sending and committing delivery status. Client UI never waits for
provider delivery. CallMeBot and Web Push require valid credentials and recipient
permission; provider delivery cannot be certified in an unconfigured local build.

The ledger polls every three seconds, newest 200 records, with status/UTC-date
filters. It shows ciphertext downloads through an authenticated same-origin API,
not public storage URLs. Timeout events without an available image say no frame;
they do not invent hashes. Ingested frames are hashed as decoded BGR uint8 bytes
before storage, then original encoded bytes are AES-256-GCM encrypted with a fresh
nonce, key version, and context binding. Recompute the digest by decoding the
decrypted JPEG/PNG and hashing its BGR bytes. Baselines and templates are also
encrypted. Local baselines are saved under `models/known_faces/*.enc`.

The PWA API reads records marked with `pwa_data`; pre-v3 plaintext/NCC records are
not silently trusted or imported. Re-enroll identities through the new admin flow
or perform a separately reviewed encrypted data migration. Preserve legacy audit
data in its original ledger. Do not mix independent local and cloud live sessions.

To move this PWA's encrypted local registry and historical events to a provisioned
cloud project, configure the cloud credentials and run `python scripts/sync_local.py`.
The script verifies that the current encryption key can decrypt each payload before
upload, skips existing IDs, and does not copy active sessions or resend old alerts.

## FaceNet and anti-spoofing limits

The original repository supplies Haar detection, normalized 128×128 grayscale
NCC matching (`>= 0.82`, pixel error `<= 0.18`) and Laplacian variance (`>= 60`).
These rules are retained. Laplacian texture is a heuristic, not a validated
presentation-attack detector; textured prints/screens can pass it. This software
must not be represented as certified physical-access biometrics without validation
against the intended cameras, users, attack classes, and deployment environment.

No FaceNet weights were supplied. `FACENET_MODEL_PATH` optionally activates a
compatible 160×160 NCHW, prewhitened, RGB ONNX FaceNet model. If configured, both
NCC and embedding cosine `>= 0.70` must pass; incompatible/missing model files
fail closed. Confirm the model's license, preprocessing, output shape, and
calibrate that threshold before deployment. Enroll again after selecting a model;
templates created without embeddings cannot pass the embedding gate. The UI
honestly shows when FaceNet is not configured.

## PWA / push behavior

HTTPS is required outside localhost. `manifest.json` includes 192/512 icons, a
standalone display, start URL and full scope. The service worker caches only
allowlisted public documents/assets. API responses, photos, session information,
audit data, and evidence are never cached. Offline mode pauses protected actions.
Push notifications reveal only a generic incident message; tapping opens `/logs`.
Notification permission is requested only after the operator clicks Enable.
On iOS, install via Share → Add to Home Screen before enabling supported Web Push.

Generate and securely retain a VAPID pair with the `py-vapid` CLI (`vapid --help`).
Set its public/private keys and a `mailto:` contact subject. The push endpoint
allowlist prevents arbitrary subscription URLs from becoming an SSRF target.
Expired (404/410) subscriptions are disabled during delivery. On deprovisioning
an operator, also revoke their device subscriptions in `vault_records`.

## Validation

```powershell
.venv\Scripts\python.exe -m pytest tests/test_pwa.py -q -p no:cacheprovider
.venv\Scripts\python.exe scripts/build_shell.py
node --check public/sw.js
```

Tests use temporary SQLite, generated images, test-only passwords, and mocked
recognition at the API boundary. They cover routing, authentication, CSRF, roles,
deadline boundaries, duplicate IDs/frames, CAS contention, encryption tampering,
evidence/hash round trips, audit deduplication, enrollment, push URL validation,
secret redaction, cloud fail-closed behavior, and manifest/cache privacy. They do
not substitute for live Supabase/RLS, Vercel runtime, real camera, FaceNet, or
external notification delivery acceptance tests.

## Sources used for runtime decisions

- [Vercel Python runtime](https://vercel.com/docs/functions/runtimes/python)
- [FastAPI on Vercel](https://vercel.com/docs/frameworks/backend/fastapi)
- [Supabase server-side authentication](https://supabase.com/docs/guides/auth/passwords)
- [Supabase storage buckets](https://supabase.com/docs/guides/storage/buckets/creating-buckets)
- [Web Push API](https://developer.mozilla.org/en-US/docs/Web/API/Push_API)
