// Unit tests with fake browser/network boundaries. These are NOT live Gmail tests.
const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
function harness(overrides = {}) {
  const storage = {
    automatic: true,
    account: "demo@example.com",
    pairToken: "unit-test-only",
    ...overrides,
  };
  let listener;
  const calls = [];
  const chrome = {
    storage: {
      local: {
        setAccessLevel: async () => {},
        get: async () => ({ ...storage }),
        set: async (x) => Object.assign(storage, x),
        remove: async (keys) => keys.forEach((k) => delete storage[k]),
      },
    },
    runtime: {
      getManifest: () => ({ oauth2: { client_id: "test-client" } }),
      getURL: (p) => "chrome-extension://" + "a".repeat(32) + "/" + p,
      onInstalled: { addListener() {} },
      onMessage: {
        addListener(fn) {
          listener = fn;
        },
      },
      openOptionsPage: async () => {},
    },
    identity: {
      getAuthToken: async () => ({ token: "unit-test-token" }),
      removeCachedAuthToken: async () => {},
      clearAllCachedAuthTokens: async () => {
        storage.cleared = true;
      },
    },
  };
  const fetch = async (url, opts) => {
    calls.push(url);
    let data = { status: "ok" };
    if (url.endsWith("/profile")) data = { emailAddress: "demo@example.com" };
    if (url.includes("?format=raw"))
      data = {
        id: overrides.returnedId || "abcdef12345678",
        raw: Buffer.from("From: a@example.com\n\nhello").toString("base64url"),
      };
    if (url.endsWith("/api/analyze"))
      data = {
        analysis_id: "analysis-1",
        gmail_message_id: overrides.analysisId || "abcdef12345678",
      };
    return { ok: true, status: 200, json: async () => data };
  };
  vm.runInNewContext(
    fs.readFileSync(__dirname + "/local-background.js", "utf8"),
    { chrome, fetch, AbortSignal, Map, Error, encodeURIComponent, console },
  );
  const send = (
    request,
    sender = { tab: { id: 1 }, url: "https://mail.google.com/mail/u/0/" },
  ) => new Promise((resolve) => listener(request, sender, resolve));
  return { send, calls, storage };
}
test("mismatched Gmail raw message never reaches analysis", async () => {
  const h = harness({ returnedId: "bbbbbbbbbbbbbb" });
  const r = await h.send({
    action: "analyze",
    messageId: "abcdef12345678",
    account: "demo@example.com",
  });
  assert.equal(r.ok, false);
  assert.match(r.error, /different message/);
  assert.equal(
    h.calls.some((x) => x.endsWith("/api/analyze")),
    false,
  );
});
test("account mismatch is rejected before raw retrieval", async () => {
  const h = harness();
  const r = await h.send({
    action: "analyze",
    messageId: "abcdef12345678",
    account: "other@example.com",
  });
  assert.equal(r.ok, false);
  assert.equal(h.calls.length, 0);
});
test("automatic disabled prevents automatic requests", async () => {
  const h = harness({ automatic: false });
  const r = await h.send({
    action: "analyze",
    automatic: true,
    messageId: "abcdef12345678",
    account: "demo@example.com",
  });
  assert.equal(r.ok, false);
  assert.equal(h.calls.length, 0);
});
test("backend correlation mismatch is rejected", async () => {
  const h = harness({ analysisId: "bbbbbbbbbbbbbb" });
  const r = await h.send({
    action: "analyze",
    messageId: "abcdef12345678",
    account: "demo@example.com",
  });
  assert.equal(r.ok, false);
  assert.match(r.error, /mismatch/);
});
test("untrusted page cannot invoke extension operations", async () => {
  const h = harness();
  const r = await h.send(
    { action: "connect" },
    { tab: { id: 1 }, url: "https://evil.example/" },
  );
  assert.equal(r.ok, false);
  assert.equal(h.calls.length, 0);
});
