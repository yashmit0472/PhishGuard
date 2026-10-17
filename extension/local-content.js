// Gmail DOM is used only to locate the exact message ID, never to reconstruct MIME.
// Fail closed if Gmail changes its locator attributes or the account is ambiguous.
(() => {
  const panels = new Map();
  let generation = 0,
    lastRoute = location.href;
  function el(tag, text, attrs = {}) {
    const n = document.createElement(tag);
    if (text) n.textContent = text;
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    return n;
  }
  async function send(action, data = {}) {
    const r = await chrome.runtime.sendMessage({ action, ...data });
    if (!r.ok) throw new Error(r.error);
    return r;
  }
  function account() {
    const labels = [
      ...document.querySelectorAll(
        'a[aria-label*="@"],button[aria-label*="@"]',
      ),
    ].map((n) => n.getAttribute("aria-label"));
    const emails = [
      ...new Set(
        labels.flatMap((s) => s.match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi) || []),
      ),
    ];
    return emails.length === 1 ? emails[0] : null;
  }
  const css = `:host{display:block!important;margin:12px 0!important;font:16px/1.6 system-ui!important;color:#172d36!important}*{box-sizing:border-box}.box{border:2px solid #657973;border-radius:10px;background:#f4f8f6;padding:14px;color:#172d36}button,select,a{font:inherit;min-height:44px;padding:8px 12px;border:1px solid #526d72;border-radius:6px;background:white;color:#174c42;display:inline-block;margin:4px;cursor:pointer}h2{font-size:22px}p{margin:8px 0}label{display:inline-block;margin:4px}button:disabled{opacity:.65;cursor:not-allowed}:focus-visible{outline:3px solid #833900;outline-offset:3px}[hidden]{display:none!important}.danger{border-color:#a02525}.warning{border-color:#8c480b}@media(forced-colors:active){.box,button,select,a{border:2px solid CanvasText}}@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}`;
  function mount(container, id) {
    const host = el("div");
    host.className = "phishguard-local-host";
    container.prepend(host);
    const root = host.attachShadow({ mode: "closed" });
    root.append(el("style", css));
    const box = el("section", null, {
        class: "box",
        "aria-label": "PhishGuard email check",
      }),
      live = el("p", "PhishGuard: checking connection…", {
        role: "status",
        "aria-live": "polite",
        "aria-atomic": "true",
      }),
      check = el("button", "Check this email", { type: "button" }),
      toggle = el("button", "Show explanation", {
        "aria-expanded": "false",
        "aria-controls": "pg-panel",
        type: "button",
      }),
      settings = el("button", "Settings", { type: "button" }),
      panel = el("section", null, {
        id: "pg-panel",
        "aria-label": "Email explanation",
        hidden: "",
      });
    const langLabel = el("label", "Language "),
      lang = el("select", null, { "aria-label": "Language" });
    lang.append(
      el("option", "English", { value: "en" }),
      el("option", "हिन्दी", { value: "hi" }),
    );
    langLabel.append(lang);
    const title = el("h2"),
      reasons = el("ul"),
      action = el("p"),
      coverage = el("p"),
      speechState = el("p", "", { role: "status" }),
      play = el("button", "▶ Read aloud"),
      pause = el("button", "Ⅱ Pause"),
      stop = el("button", "■ Stop"),
      rateLabel = el("label", "Speed "),
      rate = el("select", null, { "aria-label": "Read-aloud speed" }),
      full = el("a", "Full technical report", {
        target: "_blank",
        rel: "noopener",
      }),
      close = el("button", "Close explanation");
    [0.75, 1, 1.25, 1.5].forEach((n) =>
      rate.append(el("option", n + "×", { value: String(n) })),
    );
    rate.value = "1";
    rateLabel.append(rate);
    panel.append(
      langLabel,
      title,
      reasons,
      action,
      coverage,
      play,
      pause,
      stop,
      rateLabel,
      speechState,
      full,
      close,
    );
    box.append(live, check, toggle, settings, panel);
    root.append(box);
    let report = null,
      active = false,
      seq = 0,
      state = "stopped";
    const birth = generation;
    const current = () =>
      host.isConnected &&
      birth === generation &&
      container.getAttribute("data-legacy-message-id") === id;
    function endSpeech() {
      window.speechSynthesis?.cancel();
      state = "stopped";
      voiceStatus();
    }
    function voice() {
      return window.speechSynthesis
        ?.getVoices()
        .find(
          (v) =>
            v.localService === true &&
            v.lang.toLowerCase().startsWith(lang.value),
        );
    }
    function voiceStatus() {
      const hi = lang.value === "hi";
      play.disabled = !voice() || !report || state === "playing";
      pause.disabled = state !== "playing";
      stop.disabled = state === "stopped";
      speechState.textContent = voice()
        ? hi
          ? "केवल डिवाइस की आवाज़ इस्तेमाल होगी।"
          : "Uses an on-device voice only."
        : hi
          ? "स्थानीय हिंदी आवाज़ नहीं मिली। आप पाठ पढ़ सकते हैं।"
          : "No matching on-device voice is available. You can still read the text.";
    }
    function render() {
      const hi = lang.value === "hi";
      panel.lang = lang.value;
      play.textContent = hi ? "▶ सुनें" : "▶ Read aloud";
      pause.textContent = hi ? "Ⅱ रोकें" : "Ⅱ Pause";
      stop.textContent = hi ? "■ बंद करें" : "■ Stop";
      if (report) {
        title.textContent =
          report.verdict_icon + " " + report.verdict_label[lang.value];
        live.textContent = "PhishGuard: " + title.textContent;
        reasons.replaceChildren(
          ...report.reasons.map((r) => el("li", r.text[lang.value])),
        );
        action.textContent = report.action[lang.value];
        coverage.textContent =
          report.completion === "complete"
            ? ""
            : hi
              ? "कुछ जाँचें नहीं हो सकीं। यह संदेश असली है, इसकी पुष्टि नहीं हुई।"
              : "Some checks could not run. This does not confirm the message is genuine.";
        full.href =
          "http://127.0.0.1:5000/?mode=technical&analysis=" +
          encodeURIComponent(report.analysis_id);
        full.hidden = false;
        box.className =
          "box " +
          (report.verdict === "Dangerous"
            ? "danger"
            : report.verdict === "Suspicious"
              ? "warning"
              : "");
      } else {
        full.hidden = true;
      }
      voiceStatus();
    }
    function setOpen(value) {
      panel.hidden = !value;
      toggle.setAttribute("aria-expanded", String(value));
      toggle.textContent = value ? "Hide explanation" : "Show explanation";
      if (value) lang.focus();
      else {
        endSpeech();
        toggle.focus();
      }
    }
    toggle.onclick = () => setOpen(panel.hidden);
    close.onclick = () => setOpen(false);
    panel.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        setOpen(false);
      }
    });
    settings.onclick = () => send("settings");
    lang.onchange = () => {
      endSpeech();
      render();
    };
    rate.onchange = endSpeech;
    play.onclick = () => {
      const v = voice();
      if (!v || !report) return;
      if (state === "paused") {
        speechSynthesis.resume();
        state = "playing";
        voiceStatus();
        return;
      }
      speechSynthesis.cancel();
      const u = new SpeechSynthesisUtterance(
        [
          title.textContent,
          ...report.reasons.map((r) => r.text[lang.value]),
          action.textContent,
          coverage.textContent,
        ].join(". "),
      );
      u.voice = v;
      u.lang = v.lang;
      u.rate = Number(rate.value);
      u.onend = () => {
        state = "stopped";
        voiceStatus();
      };
      u.onerror = () => {
        state = "stopped";
        voiceStatus();
      };
      state = "playing";
      speechSynthesis.speak(u);
      voiceStatus();
    };
    pause.onclick = () => {
      speechSynthesis.pause();
      state = "paused";
      voiceStatus();
    };
    stop.onclick = endSpeech;
    window.speechSynthesis?.addEventListener("voiceschanged", voiceStatus);
    async function scan(automatic = false) {
      if (active) return;
      active = true;
      check.disabled = true;
      report = null;
      render();
      const mine = ++seq;
      live.textContent = "PhishGuard: checking this email locally…";
      try {
        const r = await send("analyze", {
          messageId: id,
          account: account(),
          automatic,
        });
        if (
          !current() ||
          mine !== seq ||
          r.messageId !== id ||
          r.report.gmail_message_id !== id
        )
          return;
        report = r.report;
        render();
      } catch (e) {
        if (current()) {
          live.textContent = "! Analysis unavailable — " + e.message;
          title.textContent = "! Analysis unavailable";
          reasons.replaceChildren();
          action.textContent =
            "Use the local app to upload an EML file if this message cannot be identified.";
        }
      } finally {
        active = false;
        check.disabled = false;
      }
    }
    check.onclick = () => scan(false);
    render();
    send("status")
      .then((s) => {
        if (!current()) return;
        if (!s.online)
          live.textContent =
            "! " + (s.error || "Protection is off — start the PhishGuard local app.");
        else if (s.automatic) scan(true);
        else
          live.textContent =
            "PhishGuard: automatic checks are off. Use Check this email.";
      })
      .catch(
        () =>
          (live.textContent =
            "! Analysis unavailable — reload Gmail after enabling the extension."),
      );
    panels.set(container, {
      host,
      id,
      dispose() {
        seq++;
        endSpeech();
        window.speechSynthesis?.removeEventListener(
          "voiceschanged",
          voiceStatus,
        );
        host.remove();
      },
      offline() {
        live.textContent =
          "! Protection is off — start the PhishGuard local app. The previous result may be out of date.";
      },
    });
  }
  function sync() {
    if (location.href !== lastRoute) {
      generation++;
      lastRoute = location.href;
      for (const p of panels.values()) p.dispose();
      panels.clear();
    }
    for (const [node, p] of panels) {
      if (
        !node.isConnected ||
        node.getAttribute("data-legacy-message-id") !== p.id
      ) {
        p.dispose();
        panels.delete(node);
      }
    }
    for (const node of document.querySelectorAll("[data-legacy-message-id]")) {
      const id = node.getAttribute("data-legacy-message-id");
      if (
        !/^[a-f0-9]{8,32}$/i.test(id || "") ||
        panels.has(node) ||
        !node.querySelector(".ii.gt")?.getClientRects().length ||
        !node.getClientRects().length
      )
        continue;
      mount(node, id);
    }
  }
  const fallbackHost = el("div");
  document.body.append(fallbackHost);
  const fallback = fallbackHost.attachShadow({ mode: "closed" });
  fallback.append(
    el(
      "style",
      css +
        ":host{position:fixed!important;bottom:12px!important;right:12px!important;max-width:360px!important;z-index:2147483647!important}",
    ),
  );
  const fallbackBox = el("section", null, {
      class: "box",
      "aria-label": "PhishGuard protection",
    }),
    fallbackStatus = el("p", "PhishGuard local protection", { role: "status" }),
    manual = el("button", "Check this email"),
    setup = el("button", "Settings");
  manual.onclick = () => {
    sync();
    fallbackStatus.textContent = panels.size
      ? "Use Check this email in the panel above the message you want to check."
      : "Open an email and expand its message, then try again. If no PhishGuard panel appears above the message, use EML upload in the local app.";
  };
  setup.onclick = () => send("settings");
  fallbackBox.append(fallbackStatus, manual, setup);
  fallback.append(fallbackBox);
  setInterval(sync, 1500);
  setInterval(
    () =>
      send("status")
        .then((s) => {
          fallbackStatus.textContent = s.online
            ? "✓ Local app is running. Open a message to check it."
            : "! " + (s.error || "Protection is off — start the PhishGuard local app.");
          if (!s.online) for (const p of panels.values()) p.offline();
        })
        .catch(() => {}),
    10000,
  );
  sync();
})();
