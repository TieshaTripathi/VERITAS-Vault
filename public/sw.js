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
    payload = event.data?.json() || {};
  } catch {}
  event.waitUntil(
    self.registration.showNotification("VERITAS security alert", {
      body: "A breach requires operator review. Open the secure audit ledger.",
      icon: "/icons/icon-192.png",
      badge: "/icons/icon-192.png",
      tag: String(payload.tag || "vault-breach"),
      data: { url: "/logs" },
      requireInteraction: true,
    }),
  );
});
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then(async (clients) => {
        for (const client of clients) {
          if (new URL(client.url).origin === self.location.origin) {
            await client.navigate("/logs");
            return client.focus();
          }
        }
        return self.clients.openWindow("/logs");
      }),
  );
});
