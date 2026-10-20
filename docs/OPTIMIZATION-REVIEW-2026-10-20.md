# VERITAS-Vault optimization review — 20 October 2026

Reviewed branch: `refactor/codebase-cleanup-and-optimization`, starting at `1376219`.
No deployment, cloud configuration changes, or reset/deletion of existing enrollment or evidence data was performed. Regression tests used disposable fixtures.

## Confirmed fixes

- Translate detector landmarks from full-frame coordinates into face-crop coordinates before recognition alignment. Keep image coordinates for quality checks and overlays.
- Use the same subject-eye naming convention in Haar and YuNet detectors.
- MobileFaceNet no longer returns handcrafted features under the `mbf_onnx_v2` version when its runtime is unavailable. Reject non-finite, zero, or incorrectly sized outputs and serialize shared OpenCV network inference.
- Preserve legacy normalized-image templates as requiring re-enrollment instead of silently relabeling them as current-model captures. Existing enrollment data is retained.
- Withhold a verified output for a poor-quality current crop or pending identity conflict. Current uncertain PAD cannot inherit a previously passing liveness result for authorization.
- Cloud revocation updates the existing enrollment rather than attempting a duplicate primary-key insert.
- Check subscription ownership before cloud unsubscribe; parameterize its endpoint filter.
- Restrict request origins to the explicit trusted list instead of accepting every Firebase site or any hostname containing `localhost`.
- Prefer native Web Push when a registered PWA and VAPID configuration are available. Retain Pushover/Telegram/CallMeBot compatibility when native push is unavailable; do not send parallel legacy notifications when native push is selected.
- Route service-worker receipts from Firebase Hosting to the Render backend with the required request header. Require an authenticated session or an event-scoped HMAC proof delivered inside encrypted Web Push. Report receipt only after notification display succeeds.
- Remove audit-page code that falsely attributed every deep link to Pushover delivery.
- Preserve delivery progress if a concurrent device receipt changes the outbox record during a send.
- Update the service-worker cache version and generated Control Room fallback description. CI now checks the real `/audit` directory, runs JavaScript regression tests, and explicitly propagates failures through its `tee` pipeline.
- Isolate legacy notification credentials in tests and mock the intentional Telegram failure instead of making an external request with a fake token.

## Validation

Final full regression run: **184 passed, 1 warning in 303.41 seconds**. This includes the original **170 tests** and **14 new security/biometric/notification regressions**, with no failures or skips. The warning is the existing Starlette TestClient `httpx` deprecation.

JavaScript: **3 passed, 0 failed**, covering the existing repeated-alert suite plus installed-PWA receipt routing and rejection of false receipt confirmation after failed notification display.

Commands used:

```powershell
.\.venv\Scripts\python.exe -m pytest tests -vv -o addopts= -o faulthandler_timeout=60 --basetemp=artifacts/review-verified -p no:cacheprovider --durations=10
node --test tests/test_alerts_dedup.mjs tests/test_service_worker.mjs
```

The initial sandboxed run stalled in Windows asyncio loopback socket creation. Final results came from the authorized run with local socket access. An intermediate full run exposed four stale test expectations for the cache version, native-push precedence, and authenticated receipts; the corrected expectations passed in the final complete run.

- Original test inventory: **170 Python tests**.
- `python -m pip check`: no broken installed requirements.
- Python compilation and JavaScript syntax checks: passed.
- Frontend generator: completed; generated Control Room matches its source template.
- npm audit: **0 reported vulnerabilities** in the npm dependency tree. This is not a Python vulnerability audit.
- Exact AST function-body comparison found no identical multi-statement function bodies across `src`. This does not establish that there is no conceptual duplication.

## Live checks and performance

- Read-only public Render health check returned HTTP 200, `healthy`, version `3.0.0`, commit `7bf6b98b006f3dde09df6ee4e488ba8dfa32d449`. That deployment is separate from these branch changes. A health response does not verify camera recognition or database readiness.
- Read-only Supabase queries using the existing local server configuration failed. The diagnostic query to `vault_records` returned **HTTP 401**. Queries to enrolled users, audit logs, enrollment requests, and push subscriptions also failed. Live authentication, RLS enforcement, storage access, and cloud writes are therefore **not certified**. No cloud configuration was altered to resolve this.
- Local Windows CPU, OpenCV 4.14.0, synthetic input, 2 warm-ups followed by 10 measured samples: MobileFaceNet embedding median **17.04 ms**, p95 **21.25 ms**, output **512 dimensions**. Blank-frame YuNet detection including orientation fallback median **104.62 ms**, p95 **119.85 ms**. Model construction took **27.27 ms**. Process working set after these measurements was **146.17 MiB**.
- These measurements are not face-detection accuracy, real-person recognition latency, peak production memory, or Render memory usage. Raw measurement scope and local file hashes are in `artifacts/optimization-inference.json`.
- Real-camera recognition with two enrolled people and an unknown person, genuine/impostor calibration, and actual phone delivery were **not tested in this review**.

## Blockchain and Solidity status

- **No Solidity contract exists in the tracked project.** `contracts/` contains only `.gitkeep`; there is no tracked `.sol` file, compiled contract artifact, or active EVM deployment integration.
- The working audit implementation is a local SHA-256 hash chain with Ed25519 signatures and Merkle support. `LocalLedgerAdapter` explicitly simulates anchoring in RAM. Fabric and Quorum adapters raise `NotImplementedError`.
- `src/blockchain/api_controller.py` is a separate forensic prototype, not mounted into the main PWA. Its heuristics/AI are simulated, Firebase initialization is a stub, and its optional `firebase_admin` import is unavailable in this environment. Its default HMAC secret and open controller must not be treated as a production security boundary. It was retained because it has its own internal references and integration documentation.

## Remaining limitations and readiness

**Not ready to approve for production deployment.** Automated regressions alone do not establish biometric or operational acceptance.

1. Resolve the Supabase HTTP 401 through the deployment owner, then verify actual database permissions, private evidence storage, encrypted enrollment updates, and durable outbox behavior. No secret values are included in this report.
2. Verify the complete recognition flow on the real camera, with two enrolled people and an unknown person. Measure genuine/impostor score distributions and tune thresholds from that evidence; current defaults are not a measured production calibration.
3. Model weights exist locally but are ignored by Git. A fresh checkout has no ONNX assets or automated, license-reviewed, checksum-pinned provisioning. Registry metadata does not enforce a trusted MobileFaceNet checksum. The default factory still supports the legacy standard descriptor when no model exists; production must verify the actual loaded provider rather than infer it from the repository's model-version default.
4. Enrollment inspection still uses the legacy Haar path, and single-image compatibility repeats a sample five times. This is not five independent captures. Enrollment consistency/duplicate identity calibration and a controlled re-enrollment workflow remain separate acceptance work; no existing enrollment was reset to conceal this.
5. YuNet orientation fallback returns coordinates from a rotated image. Recognition crop alignment is corrected here, but overlays from orientation fallback still need explicit inverse-coordinate tests before claiming tilted-camera support.
6. Real-device PWA delivery, permission/session persistence, background display, and audit deep-link behavior require phone testing. Native provider acceptance and device-side display confirmation remain distinct from a human seeing a notification. Exactly-once transport delivery cannot be guaranteed after a provider timeout.
7. Legacy Telegram/Pushover test and diagnostic endpoints, Control Room fallback controls, CallMeBot fallback, and raw FCM registration remain for compatibility. Raw FCM tokens are stored separately and are not native Web Push subscriptions; registration alone does not establish delivery. Complete removal should follow an explicit migration of configured recipients and consumers. Telegram fallback can transmit an evidence photograph.
8. Cache invalidation and capture/tracking state are process-local. Review cross-process revocation, custody timer recovery after restarts, and distributed concurrency before scaling beyond the current single-worker deployment. Record enumeration is limited to 1,000 rows and requires pagination/queue filtering for sustained growth.
9. The older Streamlit dashboard and PWA have overlapping vision, policy, storage, and notification stacks; legacy files are still referenced by the dashboard/tests/tools. The legacy benchmark measures `TemplateMatchingProvider`, not the active MobileFaceNet pipeline. Synthetic scripts named `live_*` are not proof of a real-camera test. No consumer was found for the local ignored `face_recognition_sface_2021dec.onnx` weight; it was retained. No such files were deleted on the basis of naming or import absence alone.
10. The existing viva/deployment narrative contains historical test counts, Cloud Run rewrite assumptions, and memory/latency claims that this review does not substantiate. Use this dated review for current verification status. One Starlette TestClient dependency deprecation warning remains; no framework upgrade was introduced merely to silence it.

Only reviewed source, tests, documentation, generated shell changes, and the scoped inference measurement should be committed. Temporary test databases, credentials, evidence, and model binaries are excluded.
