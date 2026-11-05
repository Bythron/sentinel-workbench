# Phase 2 validation, 2026-11-05

- Python 3.13: editable install with `.[test]` succeeded in a clean virtual environment.
- `python -m pytest -q`: 16 tests passed, 11 subtests passed; one upstream TestClient deprecation warning.
- FastAPI TestClient: health, authentication, scope refusal, input validation and mock authorized route passed. No live network service was started.
- Both trusted built-ins executed in child processes in tests. Cancellation, disabling and exact capability scope were checked.
- `ruff check src tests`: passed after formatting/import corrections.
- `pip-audit`: first run found a vulnerability in pip 26.1.2 in the test environment; pip was upgraded to 26.3 and the final run reported no known vulnerabilities. The editable Sentinel package itself is excluded by pip-audit.
- A `0.2.0` wheel built successfully; it contains both built-in manifests.
- A brief loopback smoke check on port 18765 returned `{"status":"ok"}` and listed two plugins. The server was stopped afterward. The default port 8765 was already occupied by another process, so it was not used for this check.
- The HTTPS check was tested with mocked responses and TLS errors. No real target was contacted.
- The first public GitHub CI run passed tests and lint but failed dependency audit on a preinstalled vulnerable `setuptools` in Python 3.11. The workflow now upgrades `setuptools` before the audit. [CI run #3](https://github.com/Bythron/sentinel-workbench/actions/runs/42118460154) completed successfully on Python 3.11, 3.12 and 3.13.

Tests use temporary databases. No live HTTP/TLS target was contacted.
