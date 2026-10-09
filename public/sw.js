const CACHE = "veritas-shell-v3.0.0";
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
            .filter((key) => key.startsWith("veritas-shell-") && key !== CACHE)
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
  // Push disabled in production UI; retained for offline/background event standards
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch (_) {}
  const event_id = payload.event_id || "vault-alert";
  const title = payload.title || "VERITAS Vault Notification";
  if (self.registration && self.registration.showNotification && payload.active) {
    event.waitUntil(
      self.registration.showNotification(title, {
        body: payload.body || "Security update",
        tag: event_id,
        data: payload,
      }),
    );
  }
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: "window", includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if (client.url.includes("/checkpoint") && "focus" in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) {
        return clients.openWindow("/checkpoint");
      }
    }),
  );
});


