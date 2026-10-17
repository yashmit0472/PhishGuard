# Local Windows distribution

Build with `scripts/build-windows.ps1` and distribute the entire `dist/PhishGuard` folder.
The app binds only to 127.0.0.1:5000. It is not a hosted web service and must not be exposed
to a network interface. See [README](README.md) for exact commands and limitations.

Before public release: configure/verify Google OAuth, sign the Windows build, validate
on a clean machine, run an actual Windows login cycle, complete the NVDA and accessibility
acceptance checks, and evaluate detection on representative independent data.
