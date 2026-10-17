const status = document.getElementById("status");
async function send(action, data = {}) {
  const r = await chrome.runtime.sendMessage({ action, ...data });
  if (!r.ok) throw new Error(r.error);
  return r;
}
async function run(action, data) {
  status.textContent = "Working…";
  try {
    const r = await send(action, data);
    status.textContent = r.message || "Setting saved.";
  } catch (e) {
    status.textContent = "! " + e.message;
  }
}
document.getElementById("pair").onclick = () => {
  run("pair", { code: document.getElementById("code").value });
  document.getElementById("code").value = "";
};
document.getElementById("connect").onclick = () => run("connect");
document.getElementById("signout").onclick = () => run("signout");
document.getElementById("automatic").onchange = (e) =>
  run("automatic", { enabled: e.target.checked });
send("status")
  .then((r) => {
    document.getElementById("automatic").checked = r.automatic;
    status.textContent =
      (r.online
        ? "✓ Local app is running."
        : "! Protection is off — start PhishGuard.") +
      (r.account ? " Gmail: " + r.account : " Gmail is not connected.");
  })
  .catch((e) => (status.textContent = e.message));
