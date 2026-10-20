import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../public/sw.js", import.meta.url), "utf8");

function worker(showNotification = async () => {}) {
  const handlers = {};
  const requests = [];
  vm.runInNewContext(source, {
    self: {
      location: { hostname: "veritas-vault14.web.app" },
      addEventListener: (name, handler) => { handlers[name] = handler; },
      registration: { showNotification },
    },
    navigator: { userAgent: "Android" },
    fetch: async (url, options) => { requests.push({ url, options }); },
    URL, console,
  });
  return { handlers, requests };
}

test("installed Firebase PWA sends authenticated receipt to Render after displaying notification", async () => {
  let displayed = false;
  const { handlers, requests } = worker(async () => { displayed = true; });
  let pending;
  handlers.push({
    data: { json: () => ({ event_id: "event-1", receipt_token: "proof-1" }) },
    waitUntil: (promise) => { pending = promise; },
  });
  await pending;
  assert.equal(displayed, true);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, "https://veritas-vault-backend.onrender.com/api/push/receipt");
  assert.equal(requests[0].options.headers["X-Vault-Request"], "1");
  assert.equal(JSON.parse(requests[0].options.body).receipt_token, "proof-1");
});

test("failed notification display never claims device receipt", async () => {
  const { handlers, requests } = worker(async () => { throw new Error("permission denied"); });
  let pending;
  handlers.push({
    data: { json: () => ({ event_id: "event-1", receipt_token: "proof-1" }) },
    waitUntil: (promise) => { pending = promise; },
  });
  await assert.rejects(pending, /permission denied/);
  assert.equal(requests.length, 0);
});
