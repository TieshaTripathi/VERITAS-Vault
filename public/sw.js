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

  const title = payload.title || "VERITAS SECURITY ALERT";
  const body = payload.body || "Security breach detected. Access locked.";
  const eventId = payload.event_id || payload.tag || "vault-security-alert";
  const targetUrl = payload.url || (eventId ? `/audit?event=${encodeURIComponent(eventId)}` : "/audit");

  // Post message to open client windows so in-app breach popup/modal reacts immediately
  event.waitUntil(
    self.clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then((clients) => {
        clients.forEach((client) => {
          client.postMessage({
            type: "SECURITY_BREACH_PUSH",
            payload: {
              ...payload,
              event_id: eventId,
              url: targetUrl,
            },
          });
        });
      })
      .catch(() => {}),
  );

  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon: "/icons/icon-192.png",
      badge: "/icons/logo.svg",
      tag: eventId,
      renotify: true,
      requireInteraction: true,
      data: {
        url: targetUrl,
        event_id: eventId,
        reason_code: payload.reason_code,
      },
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const targetUrl = event.notification.data?.url || "/audit";
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
