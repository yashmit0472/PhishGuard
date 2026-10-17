# Accessibility verification, 2026-10-17

Implemented in the local UI and Gmail panel:
- Verdict icon + text + border color, including unknown/error states.
- Native labelled controls, headings, lists, keyboard activation and visible focus.
- Live status/error announcements; app results move focus to the verdict heading.
- Gmail explanation open focuses Language; Escape/Close returns focus to its toggle.
- English/Hindi explanations; local-only voices, play/pause/stop and rate selection.
- Responsive wrapping, 44px controls, reduced-motion and forced-colors CSS.

Actually exercised in the in-app browser:
- Keyboard unlock, tabbing through Simple/Technical modes, radio group and text input.
- Keyboard submission of an authored scam message; Dangerous result appeared and focus
  moved to its heading. The same score/reasons were shown in Technical Mode.
- Hindi language selection changed verdict, reasons and recommended action.
- A matching local Hindi voice was reported available by the browser. Actual NVDA
  output and speech audio intelligibility were not verified.
- Zoom shortcut/reflow inspected visually: controls wrapped without horizontal overflow
  in the narrow observed viewport. The browser did not expose a confirmed zoom percentage;
  this is not a claimed 200% zoom certification.

Outstanding manual acceptance tests:
- NVDA is not installed in either standard Program Files location and was not running.
  No NVDA pass is claimed. Test loading/error announcements, Hindi pronunciation,
  headings and tab order on a machine with NVDA before calling this accessible-ready.
- Real Gmail keyboard/focus testing requires configured OAuth and a test mailbox.
- Confirm actual 200% browser zoom, Windows forced-colors/high-contrast mode, and a full
  WCAG AA contrast audit including focus, disabled controls and extension/Gmail context.
- Verify missing-Hindi-voice behavior on a machine without that voice, and voice pause/
  resume/stop timing with assistive technology. Code filters localService strictly.

The chosen main text/background colors have generous contrast, but this document does
not assert a complete WCAG conformance audit. Accessibility implementation and a tested
screen-reader experience are different deliverables; the latter remains outstanding.
