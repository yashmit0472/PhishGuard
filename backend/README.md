# Backend

The default backend is `local_app.py` (also available through `python app.py`). It uses
Python 3.12 standard-library HTTP/SQLite and `local_core`, with no mandatory third-party
runtime dependency. See the root README for setup, testing, packaging and known limits.

The previous FastAPI/MongoDB/Gemini server has been retained as `legacy_cloud_app.py`
for reference. Legacy cloud requirements/tests are not the local runtime or its regression
suite. Do not deploy that server as the new privacy-preserving local application.

Contract: ../docs/LOCAL_ARCHITECTURE.md
Privacy: ../docs/FEEDS_AND_PRIVACY.md
Rules: ../docs/RULES.md
