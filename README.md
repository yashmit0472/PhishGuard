# PhishGuard — local scam and phishing checks

PhishGuard bridges the gap between cybersecurity evidence and everyday decisions:
**one verdict, up to three understandable reasons, and one practical next step.**
English/Hindi explanations, optional on-device read-aloud, a simple default view,
and an evidence-focused Technical Mode share the same cached analysis.

This is a local-first MVP, not a claim of production-grade detection or complete
accessibility certification. No Gemini, MongoDB, Docker, Ollama, API key or network
connection is needed for core analysis after installation.

## Run the Windows package

The built portable application is at `dist/PhishGuard/PhishGuard.exe`.
Keep the entire `PhishGuard` folder, including `_internal`, together.

1. Open `PhishGuard.exe`. It starts a server on **127.0.0.1:5000** and opens the app.
2. Enter the 8-character local unlock code displayed in the PhishGuard console.
   It expires after 10 minutes. Leave the console running while using protection.
3. Paste a message/link, check a filename, upload an EML, or inspect an already-saved file.
4. Settings includes **Start PhishGuard when I sign in to Windows**. This is opt-in,
   writes only the current user's Run entry, and can be disabled in the same place.
5. Stop using Settings → Stop local protection, or Ctrl+C in the console. If a code
   expires before pairing, stop and reopen the app for a new one.

The package is an unsigned developer build. It includes Python and local web assets;
users do not install Python separately. An earlier build passed startup, shutdown and
restart tests on this development machine. **Windows Application Control blocked the
final rebuilt executable (WinError 4551), so final-binary runtime validation is blocked.**
No security protection was bypassed. Release signing/approval, a clean Windows test and
Windows login-cycle validation remain outstanding. A port conflict is reported rather
than killing another application. Closing the app turns protection off.

## Implemented workflows

- Paste WhatsApp/SMS text without signing into WhatsApp or reading chat history.
- Inspect a copied HTTP(S) link without visiting it or following redirects.
- Check a filename first, including disguised APKs such as `Invitation.pdf.apk`.
- Upload an already-saved file for bounded signature/hash checks. Never execute it.
- Parse raw EML/MIME in memory; inspect sender/reply differences, brand resemblance,
  links and static attachments. HTML is converted to text, never rendered or fetched.
- Preserve separate authentication claims and Received order. Uploaded headers are
  unverified unless an independently validated receiving boundary exists. No invented
  sender-device IP, VPN bypass claim or DNS-based guessed authentication.
- Deterministic weighted rules, grouped to avoid counting the same signal repeatedly.
- SQLite history, cached Technical Mode reports, explicit JSON export and deletion.
- User-supplied offline URL/domain/hash dataset import with freshness/error reporting
  and atomic replacement. Failed imports preserve the previous valid dataset.
- English/Hindi explanations, labelled keyboard controls, live announcements, visible
  focus, responsive wrapping, forced-colors/reduced-motion styles and 44px controls.
- Read aloud / Pause / Stop / speed using only voices with `localService === true`.
  No matching local voice means unavailable speech, never silent cloud fallback.

The new Technical Mode preserves useful technical evidence. Legacy PDF, graph, map,
RAG and campaign sources remain in the repository but are not active dependencies.
Outlook MSG support is not enabled in the minimal local build; use EML export instead.

## Verdict contract

All surfaces use backend-owned verdicts:

| Verdict | Meaning |
|---|---|
| Dangerous | Score 70–100: strong warning evidence |
| Suspicious | Score 30–69: warning evidence |
| No red flags found | Score 0–29 with completed coverage; not a legitimacy guarantee |
| Inconclusive | Score below 30 with incomplete coverage |
| Analysis unavailable | No usable assessment; score is null |

Risk is a capped rule score, **not a probability or confidence percentage**. Every
verdict includes icon and text as well as color. Threats can be identified in partial
analyses. Missing model/feed checks commonly make benign-looking inputs Inconclusive
in the minimal build; missing evidence is never silently treated as reassurance.

See [architecture and contract](docs/LOCAL_ARCHITECTURE.md), [rule weights](docs/RULES.md),
[privacy and feeds](docs/FEEDS_AND_PRIVACY.md), and [existing-data export](docs/PRIVACY_MIGRATION.md).

## Gmail: setup needed before live use

The extension uses Google OAuth and Gmail API **format=raw**, then sends the selected
message only to the authenticated local backend. No hosted backend or reconstructed
DOM-body email is used. It has default-on automatic checking, manual checking, an
expandable explanation, English/Hindi and local-voice controls, and a cached full-report
link. Origin/Host checks, per-install pairing, payload limits and rate limits protect
loopback access. OAuth tokens stay in Chrome's identity cache.

**No API key is required.** The account owner must create a Google Cloud project,
enable Gmail API, configure test-user consent, and create a **Chrome Extension OAuth
client** tied to the extension ID. The only values the developer needs are the public
OAuth client ID and extension ID. Never share passwords, client secrets or access tokens.

The supplied public OAuth client ID is now configured in `extension/manifest.json`,
for the supplied development extension ID `pdkjgddobebepkfbejdmdpmiggcjgmgp`.
Reload the existing extension, refresh Gmail, pair the local app and choose
**Connect Gmail**. Confirm the Google Cloud client's Item ID matches the installed
extension ID; live authorization has not yet been tested. Follow [Gmail setup](docs/GMAIL_SETUP.md).
`gmail.readonly` grants mailbox-wide read permission;
requesting only an open message does not narrow Google's actual consent scope.

**Live Gmail integration is not yet verified.** Gmail's web UI does not expose a
supported selected-message API, so the locator uses a fail-closed DOM adapter. Missing
or ambiguous message/account identifiers require EML upload. Threaded-message mapping,
OAuth renewal, live focus behavior and account switching need testing with your configured
account. Unit tests with fake Google responses do not substitute for that verification.

## Developer setup

Use Python **3.12** and Node **22.12+**. The local core itself uses the Python standard
library; do not install the legacy cloud requirements for this workflow.

```powershell
cd frontend
npm ci
npm run build
cd ..
python backend/local_app.py
```

Open the exact loopback URL printed by the app. `npm run dev` rebuilds the frontend in
watch mode; the Python server continues to serve the build. Do not expose the server
on Wi-Fi or change its bind address to 0.0.0.0. The old FastAPI service is now explicitly
named `backend/legacy_cloud_app.py`; it is not the local application entry point.

Data: `%LOCALAPPDATA%/PhishGuard/phishguard.sqlite3`. Tests can override this with
`PHISHGUARD_DATA_DIR`. Original MIME, message bodies and file bytes are not retained.
Redacted findings are stored; redaction is not a guarantee that every sensitive string
is recognized. Storage inherits the Windows user's protection; it is not encrypted.

### Optional local file tools

The existing OCR/QR and macro modules are retained behind a disposable worker. In a
source installation with their dependencies available, set `PHISHGUARD_DEEP_INSPECTION=1`.
The batch has an 8-second timeout, 4-megapixel image limit, and Office archive metadata
limits (200 entries, 20 MiB expanded size, 100:1 ratio). No recursive archive extraction
or execution occurs. Missing tools, partial OCR/QR coverage and timeouts remain visible.
The minimal Windows package deliberately omits these optional binaries. Their full
real-file behavior is not claimed as verified in this build.

Core limits: 10 MiB file, 100 MIME parts, MIME depth 20, 20 attachments, 100,000 analyzed
text characters. Text beyond the limit produces an explicit incomplete check.

### Build Windows

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements-build.txt
.\scripts\build-windows.ps1 -Python .\.venv\Scripts\python.exe
```

The script creates a portable folder. Bundle no provider datasets or shared secrets.
Google credentials are public client configuration; runtime pairing tokens are generated
locally. Automated provider feed downloads are not implemented pending provider/access
and redistribution decisions. Offline user-managed import works without them.

## Classifier evaluation — no inflated accuracy claim

The old XGBoost converter generated domain-age/SPF inputs from the target label. That
makes the previous 99.92% claim unsuitable as real-world evidence. XGBoost is excluded
from the local scoring path and its benign early exit has been disabled in legacy code.

A TF-IDF (character 3–5 grams) + Logistic Regression training/evaluation workflow now
exports numeric JSON for dependency-free local inference. The classifier is one capped
15-point signal. It cannot skip checks or override a rule verdict.

```powershell
.\.venv\Scripts\python.exe backend/train_text_model.py docs/fixtures/classifier-demo.jsonl docs/evaluation/demo-model.json --demo
```

Measured **smoke-test only**: 32 authored samples, 21 training / 11 held-out, normalized
deduplication and disjoint campaign/source groups, seed 42. Precision 0.875, recall 1.0,
F1 0.9333; confusion matrix `[[3,1],[0,7]]` (rows actual benign/scam). One false positive,
zero false negatives. Language slices: English n=5, Hindi n=3, Hinglish n=3 — far too
small for detection-quality claims. See [full evaluation](docs/evaluation/demo-model.evaluation.json).

The demo model is marked evaluation-only and the app refuses to load it. A representative,
properly licensed corpus, source/campaign split, external holdout and calibration review
remain needed before deploying a model. A reviewed non-demo export can be placed at
`%LOCALAPPDATA%/PhishGuard/text-model.json`, then restart the app. No model downloads occur.

## Verification and demo

```powershell
python -m unittest discover -s backend/tests -p test_local_core.py -v
.\.venv\Scripts\python.exe -m unittest discover -s backend/tests -p test_classifier_portable.py -v
node --test extension/test-background.cjs
.\.venv\Scripts\python.exe scripts/package-smoke.py
```

- 14 local/API regression tests passed, including 12 labelled demo cases, forged headers,
  unsafe HTML, unavailable scores, malformed MIME, oversized files, stale feeds,
  unauthorized requests, optional-tool failure, and network-blocked analysis.
- 2 classifier tests passed (portable inference parity and refusing demo deployment).
- 5 extension unit tests passed (wrong message/account, automatic-off, result mismatch,
  untrusted caller). These use mocked browser/network boundaries, not a live mailbox.
- Production frontend build passed. Latest npm audit reported zero vulnerabilities.
- An earlier Windows build passed local startup, static analysis, access control,
  shutdown/restart and SQLite persistence checks. The final rebuilt binary was blocked
  by Windows Application Control (4551); its runtime and missing-assets tests remain
  unverified. See [package evidence](docs/evaluation/package-smoke.json).
- Keyboard submission/focus and Hindi rendering were exercised in the browser.
  **NVDA was not available; no screen-reader pass is claimed.** Confirmed 200% zoom,
  Windows high contrast, a complete WCAG AA audit and Gmail keyboard testing remain
  outstanding. See [accessibility test record](docs/ACCESSIBILITY_TESTS.md).

Use the [scripted 60-second demo](docs/DEMO.md). Its Gmail segment requires the real OAuth
setup; before that, demonstrate EML upload honestly as the fallback. No mock Gmail success
is included in the product.

Deferred: Outlook integration, mailbox-wide scans, cloud/local LLM chat, expanded campaign
clustering, new PDF work, Android sharing, Wi-Fi phone access, and renaming.
