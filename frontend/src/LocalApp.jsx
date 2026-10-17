import React, { useEffect, useRef, useState } from "react";
import "./styles/local.css";
async function api(path, body, method) {
  const r = await fetch("/api/" + path, {
    method: method || (body ? "POST" : "GET"),
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30000),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || "The check could not finish.");
  return d;
}
const words = {
  en: {
    title: "Understand the risk. Know what to do.",
    intro:
      "Check a message, link, or file name on this computer. Nothing is opened or visited.",
    simple: "Simple Mode",
    technical: "Technical Mode",
    check: "Check now",
    checking: "Checking on this computer…",
    unavailable: "Analysis unavailable",
    reasons: "What we found",
    action: "What to do next",
    partial:
      "Some checks could not run. This result cannot confirm that the message is genuine.",
    message: "Paste message",
    link: "Paste link",
    filename: "Check filename",
    email: "Upload email",
    file: "Check saved file",
    input: "Message, link, or filename",
  },
  hi: {
    title: "खतरा समझें। सही कदम उठाएँ।",
    intro:
      "इस कंप्यूटर पर संदेश, लिंक या फ़ाइल का नाम जाँचें। कोई लिंक या फ़ाइल नहीं खोली जाएगी।",
    simple: "सरल मोड",
    technical: "तकनीकी मोड",
    check: "अभी जाँचें",
    checking: "इस कंप्यूटर पर जाँच हो रही है…",
    unavailable: "जाँच उपलब्ध नहीं",
    reasons: "क्या मिला",
    action: "अब क्या करें",
    partial:
      "कुछ जाँचें नहीं हो सकीं। यह नतीजा संदेश के असली होने की पुष्टि नहीं करता।",
    message: "संदेश पेस्ट करें",
    link: "लिंक पेस्ट करें",
    filename: "फ़ाइल का नाम जाँचें",
    email: "ईमेल अपलोड करें",
    file: "सहेजी हुई फ़ाइल जाँचें",
    input: "संदेश, लिंक या फ़ाइल का नाम",
  },
};
function Speech({ text, language }) {
  const [voices, V] = useState([]),
    [speed, S] = useState(1),
    [state, T] = useState("stopped");
  useEffect(() => {
    if (!window.speechSynthesis) return;
    const load = () =>
      V(speechSynthesis.getVoices().filter((v) => v.localService === true));
    load();
    speechSynthesis.addEventListener("voiceschanged", load);
    return () => {
      speechSynthesis.removeEventListener("voiceschanged", load);
      speechSynthesis.cancel();
    };
  }, []);
  useEffect(() => {
    window.speechSynthesis?.cancel();
    T("stopped");
  }, [text, language]);
  const voice = voices.find((v) => v.lang.toLowerCase().startsWith(language)),
    hi = language === "hi";
  function play() {
    if (!voice) return;
    if (state === "paused") {
      speechSynthesis.resume();
      T("playing");
      return;
    }
    speechSynthesis.cancel();
    const u = new SpeechSynthesisUtterance(text);
    u.voice = voice;
    u.lang = voice.lang;
    u.rate = Number(speed);
    u.onend = () => T("stopped");
    u.onerror = () => T("stopped");
    speechSynthesis.speak(u);
    T("playing");
  }
  return (
    <section aria-label={hi ? "पढ़कर सुनाएँ" : "Read aloud"} className="speech">
      <button disabled={!voice || state === "playing"} onClick={play}>
        {hi ? "▶ सुनें" : "▶ Read aloud"}
      </button>
      <button
        disabled={state !== "playing"}
        onClick={() => {
          speechSynthesis.pause();
          T("paused");
        }}
      >
        {hi ? "Ⅱ रोकें" : "Ⅱ Pause"}
      </button>
      <button
        disabled={state === "stopped"}
        onClick={() => {
          speechSynthesis.cancel();
          T("stopped");
        }}
      >
        {hi ? "■ बंद करें" : "■ Stop"}
      </button>
      <label>
        {hi ? "गति" : "Speed"}{" "}
        <select
          value={speed}
          onChange={(e) => {
            S(e.target.value);
            window.speechSynthesis?.cancel();
            T("stopped");
          }}
        >
          {[0.75, 1, 1.25, 1.5].map((n) => (
            <option key={n} value={n}>
              {n}×
            </option>
          ))}
        </select>
      </label>
      <p role="status">
        {!voice
          ? hi
            ? "इस डिवाइस पर स्थानीय हिंदी आवाज़ नहीं मिली। आप पाठ पढ़ सकते हैं।"
            : "No matching on-device voice is available. You can still read the text."
          : hi
            ? "केवल डिवाइस की आवाज़ इस्तेमाल होगी।"
            : "Uses an on-device voice only."}
      </p>
    </section>
  );
}
function Technical({ r }) {
  return (
    <div className="technical" lang="en">
      <h3>Technical evidence</h3>
      <p>
        Score: {r.risk_score ?? "Unavailable"} / 100. This is a rule score, not
        a probability.
      </p>
      <p>
        Analysis ID: <code>{r.analysis_id}</code> · Schema {r.schema_version} ·{" "}
        {r.completion}
      </p>
      <h4>Checks and coverage</h4>
      <ul>
        {r.checks.map((c, i) => (
          <li key={i}>
            <strong>
              {c.id}: {c.status}
            </strong>{" "}
            — {c.detail}
          </li>
        ))}
      </ul>
      <h4>Rule contributions</h4>
      <ul>
        {r.technical.rules.map((x) => (
          <li key={x.rule_id}>
            <code>{x.rule_id}</code> +{x.weight}; evidence:{" "}
            {x.evidence_ids.join(", ")}
          </li>
        ))}
      </ul>
      <h4>Indicators (not clickable)</h4>
      <ul>
        {r.technical.indicators.map((i) => (
          <li key={i.id}>
            <code>{i.display}</code> — {i.type}; source: {i.sources.join(", ")}
          </li>
        ))}
      </ul>
      <h4>Authentication provenance</h4>
      <p>
        Authentication does not prove that a message is harmless. No
        sender-device location is inferred.
      </p>
      <ul>
        {r.technical.authentication.map((a, i) => (
          <li key={i}>
            {a.mechanism}: {a.result} — {a.trust}; header {a.header_index},{" "}
            {a.authserv_id}
          </li>
        ))}
      </ul>
      <details>
        <summary>Headers and receiving chain (original order)</summary>
        <pre>
          {JSON.stringify(
            { headers: r.technical.headers, received: r.technical.received },
            null,
            2,
          )}
        </pre>
      </details>
      <details>
        <summary>Static file findings</summary>
        <pre>{JSON.stringify(r.technical.files, null, 2)}</pre>
      </details>
      <h4>Offline intelligence</h4>
      <p>
        {r.feeds.name || "No dataset installed"} · {r.feeds.status} · Published:{" "}
        {r.feeds.published_at || "Unavailable"}
      </p>
      <p>{r.feeds.meaning}</p>
      <p>
        External services contacted during analysis:{" "}
        {r.external_services_contacted.join(", ") || "None"}
      </p>
      <p>
        Rules: {r.versions.rules}; text model: {r.versions.classifier}
      </p>
      <button
        onClick={() => {
          const u = URL.createObjectURL(
            new Blob([JSON.stringify(r, null, 2)], {
              type: "application/json",
            }),
          );
          const a = document.createElement("a");
          a.href = u;
          a.download = "phishguard-" + r.analysis_id + ".json";
          a.click();
          setTimeout(() => URL.revokeObjectURL(u), 1000);
        }}
      >
        Export redacted report
      </button>
    </div>
  );
}
export default function LocalApp() {
  const [language, L] = useState("en"),
    [mode, M] = useState(
      new URLSearchParams(location.search).get("mode") === "technical"
        ? "technical"
        : "simple",
    ),
    [kind, K] = useState("message"),
    [content, C] = useState(""),
    [file, F] = useState(null),
    [result, R] = useState(null),
    [busy, B] = useState(false),
    [notice, N] = useState(""),
    [error, E] = useState(""),
    [unlocked, U] = useState(false),
    [code, Q] = useState(""),
    [history, H] = useState([]),
    [settings, G] = useState(null),
    [online, O] = useState(true);
  const heading = useRef(null),
    fileInput = useRef(null),
    request = useRef(0),
    t = words[language];
  useEffect(() => {
    document.documentElement.lang = language;
    if (result) N(result.verdict_label[language]);
  }, [language, result]);
  useEffect(() => {
    let active = true;
    const ping = () =>
      fetch("/health", { signal: AbortSignal.timeout(2000) })
        .then((r) => {
          if (active) O(r.ok);
        })
        .catch(() => {
          if (active) O(false);
        });
    ping();
    const timer = setInterval(ping, 10000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);
  async function refresh() {
    H(await api("history"));
    G(await api("settings"));
  }
  async function openSaved(id) {
    const seq = ++request.current;
    B(true);
    E("");
    R(null);
    N("Loading saved result…");
    try {
      const data = await api("analyses/" + encodeURIComponent(id));
      if (seq === request.current) {
        R(data);
        N(data.verdict_label[language]);
        setTimeout(() => heading.current?.focus(), 0);
      }
    } catch (e) {
      E(e.message);
      N(t.unavailable);
    } finally {
      if (seq === request.current) B(false);
    }
  }
  useEffect(() => {
    api("settings")
      .then(async (data) => {
        G(data);
        U(true);
        H(await api("history"));
        const id = new URLSearchParams(location.search).get("analysis");
        if (id) openSaved(id);
      })
      .catch(() => {});
  }, []);
  async function unlock(e) {
    e.preventDefault();
    E("");
    try {
      await api("unlock", { code });
      Q("");
      U(true);
      await refresh();
      const id = new URLSearchParams(location.search).get("analysis");
      if (id) openSaved(id);
    } catch (e) {
      E(e.message);
    }
  }
  async function submit(e) {
    e.preventDefault();
    const seq = ++request.current;
    B(true);
    E("");
    R(null);
    N(t.checking);
    try {
      const p = { input_type: kind };
      if (kind === "email" || kind === "file") {
        if (!file) throw new Error("Choose an already-saved file first.");
        if (file.size > 10 * 1024 * 1024)
          throw new Error("File exceeds 10 MiB.");
        const bytes = new Uint8Array(await file.arrayBuffer());
        let binary = "";
        for (let i = 0; i < bytes.length; i += 32768)
          binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
        p.raw_base64 = btoa(binary);
        p.filename = file.name;
      } else if (kind === "filename") p.filename = content;
      else p.content = content;
      const data = await api("analyze", p);
      if (seq !== request.current) return;
      R(data);
      N(data.verdict_label[language]);
      C("");
      F(null);
      if (fileInput.current) fileInput.current.value = "";
      await refresh();
      setTimeout(() => heading.current?.focus(), 0);
    } catch (e) {
      E(e.message);
      N(t.unavailable);
    } finally {
      if (seq === request.current) B(false);
    }
  }
  const speech = result
    ? [
        result.verdict_label[language],
        ...result.reasons.map((r) => r.text[language]),
        result.action[language],
        result.completion !== "complete" ? t.partial : "",
      ].join(". ")
    : "";
  return (
    <div className="local-app">
      <a href="#main" className="skip">
        Skip to main content
      </a>
      <header>
        <a href="/" className="brand" aria-label="PhishGuard home">
          ◈ PhishGuard
        </a>
        <span className="privacy">Local analysis · No cloud AI</span>
        <label>
          {language === "hi" ? "भाषा" : "Language"}{" "}
          <select value={language} onChange={(e) => L(e.target.value)}>
            <option value="en">English</option>
            <option value="hi">हिन्दी</option>
          </select>
        </label>
      </header>
      <main id="main">
        <div className="hero">
          <p className="eyebrow">A SECOND LOOK BEFORE YOU CLICK</p>
          <h1>{t.title}</h1>
          <p>{t.intro}</p>
        </div>
        <p
          role="status"
          aria-live="polite"
          aria-atomic="true"
          className="status"
        >
          {!online ? "! Protection is off — start the PhishGuard app." : notice}
        </p>
        {error && (
          <div role="alert" className="error">
            <strong>! {t.unavailable}</strong>
            <p>{error}</p>
          </div>
        )}
        {!unlocked ? (
          <section className="card">
            <h2>Unlock this local app</h2>
            <p>
              Enter the 8-character code shown in the PhishGuard window. It
              expires after 10 minutes. Your messages stay on this computer
              during analysis.
            </p>
            <form onSubmit={unlock}>
              <label>
                Local unlock code
                <input
                  autoComplete="off"
                  value={code}
                  onChange={(e) => Q(e.target.value)}
                  maxLength={8}
                  required
                />
              </label>
              <button type="submit">Unlock</button>
            </form>
          </section>
        ) : (
          <>
            <nav aria-label="Report mode" className="modes">
              {["simple", "technical"].map((m) => (
                <button key={m} aria-pressed={mode === m} onClick={() => M(m)}>
                  {t[m]}
                </button>
              ))}
            </nav>
            <section className="card">
              <h2>
                {language === "hi"
                  ? "क्या जाँचना चाहते हैं?"
                  : "What would you like to check?"}
              </h2>
              <form onSubmit={submit}>
                <fieldset disabled={busy}>
                  <legend>
                    {language === "hi" ? "जाँच का प्रकार" : "Choose a check"}
                  </legend>
                  <div className="types">
                    {["message", "link", "filename", "email", "file"].map(
                      (k) => (
                        <label key={k}>
                          <input
                            type="radio"
                            name="kind"
                            value={k}
                            checked={kind === k}
                            onChange={() => {
                              K(k);
                              C("");
                              F(null);
                            }}
                          />
                          {t[k]}
                        </label>
                      ),
                    )}
                  </div>
                  {kind === "email" || kind === "file" ? (
                    <label>
                      {kind === "email"
                        ? "Email (.eml)"
                        : "Already-saved file (10 MiB maximum)"}
                      <input
                        key={kind}
                        ref={fileInput}
                        type="file"
                        accept={kind === "email" ? ".eml" : undefined}
                        onChange={(e) => F(e.target.files[0])}
                      />
                    </label>
                  ) : (
                    <label>
                      {t.input}
                      <textarea
                        value={content}
                        maxLength={100000}
                        rows={kind === "message" ? 6 : 2}
                        onChange={(e) => C(e.target.value)}
                        required
                        placeholder={
                          kind === "message"
                            ? language === "hi"
                              ? "WhatsApp या SMS से संदेश कॉपी करके यहाँ पेस्ट करें।"
                              : "Copy a WhatsApp or SMS message and paste it here."
                            : kind === "link"
                              ? "https://example.com"
                              : "invoice.pdf.apk"
                        }
                      />
                    </label>
                  )}
                  <p className="muted">
                    {language === "hi"
                      ? "संदिग्ध फ़ाइल डाउनलोड न करें। पहले केवल उसका नाम जाँचें।"
                      : "Do not download a suspicious file. Check its name first. No WhatsApp sign-in needed."}
                  </p>
                  <button type="submit" className="primary" disabled={!online}>
                    {busy ? t.checking : t.check}
                  </button>
                </fieldset>
              </form>
            </section>
            {result && (
              <section
                className={
                  "card result verdict-" +
                  result.verdict.toLowerCase().replaceAll(" ", "-")
                }
                aria-labelledby="verdict"
              >
                <h2 id="verdict" ref={heading} tabIndex={-1}>
                  {result.verdict_icon} {result.verdict_label[language]}
                </h2>
                {result.completion !== "complete" && (
                  <p className="coverage">{t.partial}</p>
                )}
                <h3>{t.reasons}</h3>
                {result.reasons.length ? (
                  <ul>
                    {result.reasons.map((r) => (
                      <li key={r.rule_id}>{r.text[language]}</li>
                    ))}
                  </ul>
                ) : (
                  <p>
                    {result.verdict === "No red flags found"
                      ? language === "hi"
                        ? "इन जाँचों में कोई चेतावनी संकेत नहीं मिला। यह असली होने की गारंटी नहीं है।"
                        : "These checks found no warning signs. This is not a guarantee that it is genuine."
                      : language === "hi"
                        ? "पूरी जाँच के लिए पर्याप्त जानकारी नहीं है।"
                        : "We do not have enough evidence for a clear answer."}
                  </p>
                )}
                <div className="action">
                  <h3>{t.action}</h3>
                  <p>{result.action[language]}</p>
                </div>
                <Speech text={speech} language={language} />
                {mode === "technical" && <Technical r={result} />}
              </section>
            )}
            <details className="card">
              <summary>
                {language === "hi" ? "पिछली जाँचें" : "Recent checks"} (
                {history.length})
              </summary>
              <p>
                Only redacted findings are saved. Original messages are not
                retained.
              </p>
              <ul className="history">
                {history.map((r) => (
                  <li key={r.analysis_id}>
                    <button onClick={() => openSaved(r.analysis_id)}>
                      {r.verdict} · {r.input_type} ·{" "}
                      {new Date(r.created_at).toLocaleString()}
                    </button>
                    <button
                      aria-label={"Delete check from " + r.created_at}
                      onClick={async () => {
                        try {
                          await api(
                            "analyses/" + r.analysis_id,
                            null,
                            "DELETE",
                          );
                          if (result?.analysis_id === r.analysis_id) R(null);
                          await refresh();
                        } catch (e) {
                          E(e.message);
                        }
                      }}
                    >
                      Delete
                    </button>
                  </li>
                ))}
              </ul>
            </details>
            <details className="card">
              <summary>Settings and privacy</summary>
              <p>
                Core checks make no network requests. Gmail retrieval contacts
                Google. No reputation API, cloud AI, remote font or map is
                enabled.
              </p>
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={settings?.autostart || false}
                  disabled={!settings?.packaged}
                  onChange={async (e) => {
                    try {
                      await api("settings", { autostart: e.target.checked });
                      await refresh();
                    } catch (err) {
                      E(err.message);
                    }
                  }}
                />
                Start PhishGuard when I sign in to Windows
              </label>
              {!settings?.packaged && (
                <p>Windows login startup is available in the packaged app.</p>
              )}
              <p>
                Extension:{" "}
                {settings?.extension_paired ? "Paired" : "Not paired"}. Open
                extension settings and enter the local code to pair.
              </p>
              <button
                onClick={async () => {
                  try {
                    await api("unpair", {});
                    await refresh();
                  } catch (e) {
                    E(e.message);
                  }
                }}
              >
                Disconnect extension
              </button>
              <h3>Offline threat dataset</h3>
              <p>
                {settings?.feeds.status}. Import only datasets you have
                permission to use. No feed is downloaded automatically.
              </p>
              <label>
                Import feed JSON
                <input
                  type="file"
                  accept=".json"
                  onChange={async (e) => {
                    try {
                      const f = e.target.files[0];
                      if (!f) return;
                      if (f.size > 10 * 1024 * 1024)
                        throw new Error("Feed exceeds 10 MiB.");
                      await api("feeds/import", JSON.parse(await f.text()));
                      await refresh();
                      N("Dataset imported.");
                    } catch (err) {
                      E(err.message);
                    }
                  }}
                />
              </label>
              <button
                onClick={async () => {
                  try {
                    await api("shutdown", {});
                    O(false);
                  } catch (e) {
                    E(e.message);
                  }
                }}
              >
                Stop local protection
              </button>
            </details>
          </>
        )}
        <footer>
          PhishGuard helps you spot warning signs. It cannot prove a message or
          file is genuine.
        </footer>
      </main>
    </div>
  );
}
