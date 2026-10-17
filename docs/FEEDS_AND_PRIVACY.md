# Offline intelligence and outbound paths

Checked against provider documentation on 2026-10-17. No provider data or keys are
bundled. No provider account is required by the local app. A user-supplied JSON dataset
can be imported under Settings; analysis does not download it or call its provider.

| Source | Access/format observed | Decision |
|---|---|---|
| [URLhaus](https://urlhaus.abuse.ch/api/) | Auth-Key; API/export datasets | Do not bundle without confirming applicable use/redistribution terms. URL/hash adapter input is supported through the local import format. |
| [OpenPhish](https://openphish.com/phishing_feeds.html) | Community text feed, limited entries, 12-hour updates; [terms](https://www.openphish.com/terms.html) apply | Do not assume free access permits redistribution. User obtains permitted data separately. |
| [PhishTank](https://phishtank.org/developer_info.php) | Downloadable JSON/CSV; app-key paths documented | No automatic download or bundled data. Review account access and terms before deploying an updater. |
| [MalwareBazaar](https://bazaar.abuse.ch/api/) | Auth-Key required; hash metadata/API | Never download malware samples. No bundled hash dataset pending terms review. |
| [Tor exits](https://blog.torproject.org/changes-tor-exit-list-service/) | Public bulk exit list | Not used for risk scoring. Shared relays do not establish maliciousness. |
| [GeoLite/ASN](https://www.maxmind.com/en/geolite/eula) | EULA, attribution and database update/deletion duties | No redistribution assumed; no map or country-based risk scoring in this build. |

Access documentation is not a redistribution grant. Automated provider-specific updates
remain unimplemented until the selected provider's terms and account setup are settled.
Import preserves the last valid dataset on error and reports the error. Data older than
seven days is labelled stale; stale positive matches remain evidence but expose age.
No match means only "not found in this dataset". Missing feeds reduce coverage.

## Import format

```json
{
  "name": "Your permitted dataset",
  "published_at": "2026-10-17T00:00:00+00:00",
  "license_accepted": true,
  "indicators": [
    {"type": "url", "value": "https://example.invalid/phish"},
    {"type": "domain", "value": "example.invalid"}
  ]
}
```

Allowed types: url, domain, sha256. Exact matches are used. Domains must be lowercase;
URL spelling and query strings must match exactly. Up to 100,000 entries and 10 MiB in
the UI. Import stores indicator digests rather than full sensitive URLs. An import is
atomic; invalid rows reject the whole replacement. No archives are decompressed.

## Network inventory

- Core analysis: no HTTP clients, DNS, WHOIS, cloud AI, model downloads or telemetry.
- App UI: loopback only; system fonts, local JS/CSS, no map tiles or analytics.
- Gmail extension: Google OAuth, profile verification and raw selected-message retrieval;
  full MIME is sent only to authenticated loopback. Google mailbox consent is broad.
- Sign-out: attempts Google's revocation endpoint, then deletes local cached tokens.
- Speech: selects only `SpeechSynthesisVoice.localService === true`. No matching local
  voice means read-aloud is disabled and text remains available. OS voice installation
  can require a separate download, outside this application.
- Dataset updates: user-managed import; no automatic updater or external lookup switch.
- Build/install: npm and pip download developer dependencies. Packaged runtime needs no
  Python, MongoDB, Docker or Ollama installation.
- Legacy modules: previous online analysis remains in the repository for reference, but
  is not called by the local app. Do not deploy the legacy FastAPI entry point as this app.

Raw message/file bytes are transient. SQLite retains redacted findings and metadata.
Regex redaction is not a guarantee that every sensitive string has been recognized.
Per-user storage inherits Windows account protection; it is not encrypted at rest.
Users with access to the same Windows account can access local data/secrets. Reports
can be deleted from History or explicitly exported; export files remain user-managed.
