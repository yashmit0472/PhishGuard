# Local architecture and v1 contract

The shipped entry point is `backend/local_app.py`. It uses a loopback-only HTTP server,
SQLite and deterministic rules. The previous cloud pipeline remains source-only for
legacy export/reference; it is not imported or exposed by the local application.
React and the extension consume the same cached v1 analysis. No classifier can skip checks.

## Contract: schema_version 1.0

`analysis_id` (UUID), `input_type`, `created_at` (UTC), `verdict`, `risk_score`
(integer 0–100 or null), `completion` (complete/partial/unavailable), `reasons`
(rule ID, weight, evidence IDs, English/Hindi text), `action` (localized),
`technical` (findings, headers, authentication provenance, indicators), `checks`
(ID, status, detail), `feeds`, `versions`, `limitations`, `external_services_contacted`.
The server returns at most three reasons; technical rule contributions retain all matches.

Score is capped sum of independent rule groups (maximum weight per group). 70–100
Dangerous; 30–69 Suspicious; below 30 Inconclusive when coverage is partial, otherwise
No red flags found. Unavailable analyses have null score and Analysis unavailable.
Risk is not probability or confidence. Coverage is represented separately by checks.
An isolated filename is always partial. Missing intelligence never establishes safety.

## Privacy and trust

Original input exists in memory during analysis only. SQLite stores redacted, defanged
findings, not raw MIME, message bodies, credentials or full query strings. Indicator
matching precedes masking. Export is explicit. Existing MongoDB and browser history
are not deleted. No remote fonts, maps, telemetry, DNS, WHOIS or AI calls are made.
Optional local feed import does not contact the provider. Gmail API retrieval contacts
Google from the extension and requires mailbox-wide readonly consent.

The server binds 127.0.0.1:5000, checks Host/Origin and authenticates API requests.
A per-install random secret lives in the user's private app directory. Pairing requires
a short-lived code printed by the local launcher and generates a separate extension
token restricted to the approved extension ID. Tokens never appear in URLs or logs.
The UI uses a short-lived HttpOnly SameSite cookie obtained using the pairing code.
No remote webpage is allowed CORS access. Chrome extension storage is restricted to
trusted extension contexts. The local OS account remains a trusted boundary.

Uploaded headers are unverified claims. A hostname inside a header is not a trust anchor.
The current Gmail connector also reports authentication as unverified: raw API retrieval
does not independently prove which Authentication-Results header Google inserted.
Only an explicitly validated receiving boundary can promote observations to trusted.
Received order is preserved; relay addresses never identify a person's device.

File analysis is bounded to 10 MiB, 100 MIME parts, depth 20, 20 attachments; archive
decompression depth is zero. Files are never run. Optional OCR/macro tools are not
silently counted as successful checks. No third-party intelligence is bundled without
verified redistribution permission.
