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
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch {
    payload = { body: event.data ? event.data.text() : "Security breach detected." };
  }

  event.waitUntil(
    self.registration.showNotification(
      payload.title || "VERITAS SECURITY ALERT",
      {
        body: payload.body || "Security breach detected.",
        icon: "/icons/icon-192.png",
        badge: "/icons/icon-192.png",
        tag: payload.event_id || payload.tag || "vault-security-alert",
        requireInteraction: true,
        data: {
          url: payload.url || "/logs",
          event_id: payload.event_id || payload.tag,
        },
      },
    ),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const targetUrl = event.notification.data?.url || "/logs";
  event.waitUntil(
    self.clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then(async (clients) => {
        for (const client of clients) {
          if (new URL(client.url).origin === self.location.origin) {
            await client.navigate(targetUrl);
            return client.focus();
          }
        }
        return self.clients.openWindow(targetUrl);
      }),
  );
});
