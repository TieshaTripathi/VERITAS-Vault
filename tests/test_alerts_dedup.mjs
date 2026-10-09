// JS Test Suite for Parts 5, 6, 7 (Alert deduplication, popup conditions, and acknowledge)
import assert from "node:assert";

// Setup browser globals mock
let dispatchedEvents = [];
globalThis.document = {
  dispatchEvent: (event) => {
    dispatchedEvents.push(event);
  },
  querySelectorAll: () => [],
  querySelector: () => null,
  addEventListener: () => {},
  documentElement: { style: { setProperty: () => {} } },
  location: { pathname: "/" },
};
globalThis.window = {
  addEventListener: () => {},
  location: { pathname: "/" },
};
globalThis.addEventListener = () => {};

try {
  Object.defineProperty(globalThis, "navigator", {
    value: { serviceWorker: { register: () => Promise.resolve(), addEventListener: () => {} }, onLine: true },
    configurable: true,
  });
} catch {}



globalThis.localStorage = {
  getItem: () => null,
  setItem: () => {},
};
globalThis.CustomEvent = class CustomEvent {
  constructor(name, opts = {}) {
    this.type = name;
    this.detail = opts.detail;
  }
};


// Import evaluateSecurityEvent, getActiveAlert, acknowledgeAlert, clearActiveAlert dynamically
const {
  evaluateSecurityEvent,
  getActiveAlert,
  acknowledgeAlert,
  clearActiveAlert,
} = await import("../public/assets/alerts.js");


console.log("Running Alerts Deduplication & Conditions Test Suite...");

// Reset state
clearActiveAlert();
dispatchedEvents = [];

function getCriticalEvents() {
  return dispatchedEvents.filter((e) => e.type === "vault-critical-alert");
}

// PART 6: Popup conditions: NO popup for STANDBY, WAITING, GRANTED
evaluateSecurityEvent({ state: "STANDBY" });
assert.strictEqual(getActiveAlert(), null, "STANDBY should not create alert");
assert.strictEqual(getCriticalEvents().length, 0);

evaluateSecurityEvent({ state: "WAITING", reason: "First verified" });
assert.strictEqual(getActiveAlert(), null, "WAITING should not create alert");
assert.strictEqual(getCriticalEvents().length, 0);

evaluateSecurityEvent({ state: "GRANTED", reason: "Dual verified" });
assert.strictEqual(getActiveAlert(), null, "GRANTED should not create alert");
assert.strictEqual(getCriticalEvents().length, 0);

// Recognized duplicate first user: NO popup
evaluateSecurityEvent({
  state: "WAITING",
  duplicate_first_party: true,
  faces: [{ is_recognized: true, is_live: true, id: "EMP-01" }],
});
assert.strictEqual(getActiveAlert(), null, "Duplicate first user should not create alert");
assert.strictEqual(getCriticalEvents().length, 0);

// Normal scan with recognized + live face: NO popup
evaluateSecurityEvent({
  state: "STANDBY",
  faces: [{ is_recognized: true, is_live: true, id: "EMP-01" }],
});
assert.strictEqual(getActiveAlert(), null, "Recognized and live face should not create alert");
assert.strictEqual(getCriticalEvents().length, 0);

// Part B & F: ZT-007 must NEVER trigger alert
evaluateSecurityEvent({ state: "WAITING", reason_code: "ZT-007", reason: "Primary identity verified" });
assert.strictEqual(getActiveAlert(), null, "ZT-007 should not create alert");
assert.strictEqual(getCriticalEvents().length, 0);

// Part C & F: latched_terminal must NEVER trigger alert popup
evaluateSecurityEvent({ state: "BREACH", latched_terminal: true, reason: "Previous breach session active" });
assert.strictEqual(getActiveAlert(), null, "latched_terminal should not create alert");
assert.strictEqual(getCriticalEvents().length, 0);

console.log("✓ Part 6 non-alarm conditions passed (including ZT-007 and latched_terminal)");


// PART 5 & Item 11: Same breach result scanned 20 times -> exactly ONE modal/event
const breachPayload = {
  state: "BREACH",
  reason_code: "ZT-001",
  reason: "Unregistered identity detected at CP-MAIN-01",
  last_event: "EVENT-BREACH-UUID-001",
  faces: [{ is_recognized: false, is_live: true, id: "unknown" }],
};

for (let i = 0; i < 20; i++) {
  evaluateSecurityEvent(breachPayload);
}

const criticalEvents = dispatchedEvents.filter(e => e.type === "vault-critical-alert");
assert.strictEqual(criticalEvents.length, 1, `Expected 1 critical alert event, got ${criticalEvents.length}`);
const alert = getActiveAlert();
assert.ok(alert, "Active alert should exist");
assert.strictEqual(alert.id, "EVENT-BREACH-UUID-001");
assert.strictEqual(alert.acknowledged, false);

console.log("✓ Item 11: 20 repeated breach scans produced exactly 1 modal/event");

// PART 7 & Item 12: Acknowledged alert does not reopen
acknowledgeAlert();
assert.strictEqual(getActiveAlert().acknowledged, true, "Alert should be acknowledged");

const ackEventsCount = dispatchedEvents.length;

// Now scan 10 more times with the exact same breach
for (let i = 0; i < 10; i++) {
  evaluateSecurityEvent(breachPayload);
}

// No new vault-critical-alert events should have been dispatched
const criticalEventsAfter = dispatchedEvents.filter(e => e.type === "vault-critical-alert");
assert.strictEqual(criticalEventsAfter.length, 1, "Acknowledged alert must NEVER reopen for same event");
assert.strictEqual(getActiveAlert().acknowledged, true, "Acknowledged flag must remain true");

console.log("✓ Item 12: Acknowledged alert does not reopen on repeated scans");

// Item 13: New unique breach -> one new popup
const newBreachPayload = {
  state: "BREACH",
  reason_code: "ZT-002",
  reason: "Presentation spoof rejected",
  last_event: "EVENT-BREACH-UUID-002",
  faces: [{ is_recognized: true, is_live: false, id: "EMP-01" }],
};

evaluateSecurityEvent(newBreachPayload);
const criticalEventsNew = dispatchedEvents.filter(e => e.type === "vault-critical-alert");
assert.strictEqual(criticalEventsNew.length, 2, "New unique breach ID must trigger exactly one new popup");
const newAlert = getActiveAlert();
assert.strictEqual(newAlert.id, "EVENT-BREACH-UUID-002");
assert.strictEqual(newAlert.code, "ZT-002");
assert.strictEqual(newAlert.acknowledged, false);

console.log("✓ Item 13: New unique breach triggers one new popup");

console.log("\nALL ALERTS DEDUPLICATION TESTS PASSED!");
