# Existing data and legacy features

No existing MongoDB collection, browser localStorage history, sample file or `.env` is
deleted. The local app uses a new SQLite store at `%LOCALAPPDATA%/PhishGuard` and never
loads old API credentials automatically. `PHISHGUARD_DATA_DIR` overrides this location
for isolated tests. Keep that directory private to the current Windows account.

To preserve old results, use MongoDB's own JSON export or export the browser's
`phishguard_investigations_history_v1` localStorage array from the old app origin.
Export only data you own. Then run:

```powershell
python scripts/export-legacy-history.py old-history.json archived-summaries.json
```

The converter never connects to a cloud database. It writes a new redacted archival
summary file, refuses to overwrite a file, and does not silently convert legacy scores
to the new verdict scale. Keep the original export separately if full evidence is needed.
Reanalyze original EML files for current v1 results. Full legacy-record import into the
new dashboard is intentionally not provided because those scores have different semantics.

Old dashboard, PDF, campaign and RAG sources remain for reference. Their frontend
dependencies are no longer part of the local bundle. The current Technical Mode exposes
the local result's checks, headers, authentication claims, indicators, files, scoring
contributions and feed state. Cloud chat, online maps and campaign correlation are not
active runtime features. Old FastAPI deployment instructions do not describe this build.
