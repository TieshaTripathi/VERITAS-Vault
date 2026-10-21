const CACHE = "veritas-shell-v4.2.1";
const API_BASE = ["veritas-vault14.web.app", "veritas-vault14.firebaseapp.com"].includes(self.location.hostname)
  ? "https://veritas-vault-backend.onrender.com" : "";
const SHELL = [
  "/checkpoint",
  "/enrollment",
  "/logs",
  "/audit",
  "/control",
  "/offline.html",
  "/manifest.json",
  "/assets/styles.css",
  "/assets/fonts.css",
  "/assets/common.js",
  "/assets/checkpoint.js",
  "/assets/enrollment.js",
  "/assets/logs.js",
  "/assets/control.js",
  "/assets/alerts.js",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  "/icons/logo.svg",
];

self.addEventListener("install", (event) =>
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL))),
);

self.addEventListener("activate", (event) =>
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key !== CACHE)
            .map((key) => caches.delete(key)),
        ),
      )
      .then(() => self.clients.claim()),
  ),
);

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  // Explicit allowlist: never cache auth, API, evidence, photos, or external requests.
  if (
    event.request.method !== "GET" ||
    url.origin !== self.location.origin ||
    !SHELL.includes(url.pathname)
  )
    return;
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response.ok) {
          const copy = response.clone();
          event.waitUntil(
            caches.open(CACHE).then((cache) => cache.put(event.request, copy)),
          );
        }
        return response;
      })
      .catch(
        async () =>
          (await caches.match(event.request)) ||
          (await caches.match("/offline.html")),
      ),
  );
});

self.addEventListener("push", (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch (_) {
    payload = { body: event.data ? event.data.text() : "Security update" };
  }
  const event_id = payload.event_id || payload.eventId || "";
  const title = payload.title || "🚨 VERITAS SECURITY BREACH";
  const body =
    payload.body ||
    "Unauthorized identity detected\nCheckpoint: CP-MAIN-01\nAccess: DENIED";
  const targetUrl =
    payload.url ||
    (event_id ? `/audit?event=${encodeURIComponent(event_id)}` : "/audit");

  // Base options supported by all standards-compliant browsers including WebKit on iOS
  const baseOptions = {
    body: body,
    icon: payload.icon || "/icons/icon-192.png",
    tag: event_id || "vault-breach",
    data: {
      event_id: event_id,
      url: targetUrl,
      received_at: Date.now(),
      ...payload,
    },
  };

  // Extended options (badge, renotify, requireInteraction)
  const fullOptions = {
    ...baseOptions,
    badge: payload.badge || "/icons/icon-192.png",
    renotify: true,
    requireInteraction: true,
  };

  // WebKit on iOS Safari throws/rejects if unsupported options (like requireInteraction) are passed.
  // Fallback to baseOptions ensures notification is always rendered on iPhone.
  // If the fallback display also fails, the promise rejects so no false receipt is recorded.
  const showNotificationWithFallback = async () => {
    if (!self.registration || !self.registration.showNotification) return;
    try {
      return await self.registration.showNotification(title, fullOptions);
    } catch (err) {
      console.warn("showNotification fullOptions failed, falling back for WebKit/iOS:", err);
      return await self.registration.showNotification(title, baseOptions);
    }
  };

  // Device-side delivery confirmation back to backend
  const sendReceipt = () => event_id && payload.receipt_token
    ? fetch(API_BASE + "/api/push/receipt", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Vault-Request": "1" },
        body: JSON.stringify({
          event_id: event_id,
          channel: "webpush",
          receipt_token: payload.receipt_token,
          device_label: /Mobile|Android|iPhone|iPad/i.test(navigator.userAgent)
            ? "Mobile Monitor Phone"
            : "Installed PWA Device",
        }),
      }).catch(() => {})
    : Promise.resolve();

  event.waitUntil(showNotificationWithFallback().then(sendReceipt));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const event_id = event.notification.data && event.notification.data.event_id;
  const targetUrl =
    (event.notification.data && event.notification.data.url) ||
    (event_id ? `/audit?event=${encodeURIComponent(event_id)}` : "/audit");

  event.waitUntil(
    clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then((clientList) => {
        for (const client of clientList) {
          if ("focus" in client) {
            client.focus();
            if ("navigate" in client && targetUrl) {
              return client.navigate(targetUrl);
            }
            return client;
          }
        }
        if (clients.openWindow) {
          return clients.openWindow(targetUrl);
        }
      }),
  );
});


