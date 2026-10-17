// OAuth tokens remain in Chrome's identity cache, never in content scripts or logs.
const LOCAL = "http://127.0.0.1:5000";
const cache = new Map();
chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
chrome.runtime.onInstalled.addListener(async () => {
  const s = await chrome.storage.local.get("automatic");
  if (s.automatic === undefined)
    await chrome.storage.local.set({ automatic: true });
});
async function local(path, body) {
  const { pairToken } = await chrome.storage.local.get("pairToken");
  let r;
  try {
    r = await fetch(LOCAL + path, {
      method: body ? "POST" : "GET",
      headers: {
        "Content-Type": "application/json",
        ...(pairToken ? { Authorization: "Bearer " + pairToken } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30000),
    });
  } catch {
    throw new Error("Protection is off — start the PhishGuard local app.");
  }
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || "Local analysis failed.");
  return d;
}
async function token(interactive = false) {
  if (chrome.runtime.getManifest().oauth2.client_id.startsWith("REPLACE_"))
    throw new Error(
      "Gmail setup is incomplete. Configure the Google OAuth client ID.",
    );
  try {
    const result = await chrome.identity.getAuthToken({
      interactive,
      scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    });
    return typeof result === "string" ? result : result.token;
  } catch {
    throw new Error(
      "Gmail authorization is missing or expired. Open PhishGuard settings and connect Gmail.",
    );
  }
}
async function google(path, access) {
  const r = await fetch(
    "https://gmail.googleapis.com/gmail/v1/users/me/" + path,
    {
      headers: { Authorization: "Bearer " + access },
      signal: AbortSignal.timeout(20000),
    },
  );
  if (r.status === 401) {
    await chrome.identity.removeCachedAuthToken({ token: access });
    throw new Error(
      "Gmail authorization expired. Reconnect in PhishGuard settings.",
    );
  }
  if (!r.ok)
    throw new Error(
      "Gmail could not return this message. Reconnect or use an EML file.",
    );
  return r.json();
}
async function dispatch(request, sender) {
  const isOptions = sender.url?.startsWith(
    chrome.runtime.getURL("options.html"),
  );
  const isGmail =
    sender.tab && sender.url?.startsWith("https://mail.google.com/");
  if (!isOptions && !isGmail) throw new Error("Untrusted caller.");
  if (request.action === "status") {
    const { automatic = true, account } = await chrome.storage.local.get([
      "automatic",
      "account",
    ]);
    try {
      await local("/health");
      return { online: true, automatic, account };
    } catch (error) {
      return { online: false, automatic, account, error: error.message };
    }
  }
  if (request.action === "settings") {
    await chrome.runtime.openOptionsPage();
    return {};
  }
  if (isOptions && request.action === "pair") {
    const result = await local("/api/pair", {
      code: String(request.code || ""),
    });
    await chrome.storage.local.set({ pairToken: result.token });
    cache.clear();
    return { message: "Paired with this computer." };
  }
  if (isOptions && request.action === "automatic") {
    await chrome.storage.local.set({ automatic: request.enabled === true });
    return {};
  }
  if (isOptions && request.action === "connect") {
    const access = await token(true);
    const profile = await google("profile", access);
    await chrome.storage.local.set({ account: profile.emailAddress });
    cache.clear();
    return { message: "Connected as " + profile.emailAddress };
  }
  if (isOptions && request.action === "signout") {
    let revoked = false;
    try {
      const access = await token(false);
      const response = await fetch("https://oauth2.googleapis.com/revoke", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "token=" + encodeURIComponent(access),
        signal: AbortSignal.timeout(10000),
      });
      revoked = response.ok;
    } catch {}
    await chrome.identity.clearAllCachedAuthTokens();
    await chrome.storage.local.remove(["account"]);
    cache.clear();
    return {
      message: revoked
        ? "Signed out and Google access revoked."
        : "Local tokens deleted. To revoke the Google grant, remove PhishGuard from your Google Account connections.",
    };
  }
  if (request.action === "analyze" && isGmail) {
    const id = request.messageId;
    if (!/^[a-f0-9]{8,32}$/i.test(id || ""))
      throw new Error(
        "Cannot identify this exact Gmail message. Use an EML export instead.",
      );
    const { automatic = true, account } = await chrome.storage.local.get([
      "automatic",
      "account",
    ]);
    if (request.automatic && !automatic)
      throw new Error("Automatic checks are off. Use Check this email.");
    if (
      !account ||
      !request.account ||
      account.toLowerCase() !== request.account.toLowerCase()
    )
      throw new Error(
        "Cannot confirm this Gmail account matches the connected account. Open settings or use EML upload.",
      );
    await local("/health");
    const key = account + ":" + id;
    if (cache.has(key)) {
      const saved = await local("/api/analyses/" + cache.get(key));
      if (saved.gmail_message_id !== id)
        throw new Error("Cached message mismatch.");
      return { report: saved, messageId: id };
    }
    const access = await token(false);
    const profile = await google("profile", access);
    if (profile.emailAddress.toLowerCase() !== account.toLowerCase())
      throw new Error("Google account changed. Connect Gmail again.");
    const message = await google(
      "messages/" + encodeURIComponent(id) + "?format=raw",
      access,
    );
    if (message.id !== id || !message.raw)
      throw new Error(
        "Gmail returned a different message. No result was displayed.",
      );
    if (message.raw.length > 14 * 1024 * 1024)
      throw new Error("Email exceeds the 10 MiB limit.");
    const raw = message.raw.replace(/-/g, "+").replace(/_/g, "/");
    const report = await local("/api/analyze", {
      input_type: "email",
      filename: "gmail.eml",
      raw_base64: raw + "=".repeat((4 - (raw.length % 4)) % 4),
      gmail_message_id: id,
    });
    if (report.gmail_message_id !== id)
      throw new Error("Analysis message mismatch.");
    cache.set(key, report.analysis_id);
    if (cache.size > 100) cache.delete(cache.keys().next().value);
    return { report, messageId: id };
  }
  throw new Error("Unsupported request.");
}
chrome.runtime.onMessage.addListener((request, sender, reply) => {
  dispatch(request, sender)
    .then((data) => reply({ ok: true, ...data }))
    .catch((error) => reply({ ok: false, error: error.message }));
  return true;
});
