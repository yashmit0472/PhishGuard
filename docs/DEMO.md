# A rehearsable 60-second demo

Prerequisites: configure Google OAuth and test account; pair the extension; unlock the
local app; have a synthetic test email already in the demo inbox; check that Windows
has a local Hindi speech voice. Do not use an actual victim's private email. Fixtures in
`docs/fixtures/demo.json` are authored regression cases, not malware or accuracy data.

1. **0–10 s:** Open the synthetic password-expiry email in Gmail. Show the PhishGuard
   badge and explain: Google retrieves this message; analysis runs on this computer.
2. **10–20 s:** Expand the explanation. Show the verdict, reasons and recommended action.
3. **20–30 s:** Select हिन्दी, press Read aloud, then Pause/Stop. If no local Hindi voice
   is available, show the honest unavailable message; do not substitute cloud speech.
4. **30–40 s:** Open Full technical report. It loads the cached analysis ID without
   rescanning the message. Show partial coverage and unverified header provenance.
5. **40–55 s:** Return to Simple Mode and paste:
   `आपने लॉटरी जीती है। तुरंत ₹500 जमा करें और ओटीपी भेजें।`
   Show the Dangerous result and Hindi action.
6. **55–60 s:** Check `Wedding Invitation.pdf.apk`. Explain why a filename-only warning
   avoids asking a user to download a suspicious attachment.

The Gmail portion cannot be honestly demonstrated until OAuth and the live locator are
verified. Before then, use the equivalent EML upload from the fixture generator and
explicitly describe it as the fallback. Do not stage fake successful Gmail panels.

Generate EML demo files (synthetic, `.example` destinations only):
`python scripts/export-demo-emails.py`

Keyboard rehearsal: Tab/Shift+Tab through modes and inputs; arrow keys choose radio
options; Enter submits; result heading receives focus. In Gmail, expand moves focus to
Language; Escape or Close returns focus to the explanation toggle. Verify focus remains
visible at 200% zoom and in Windows high-contrast mode. Run an NVDA pass separately.
