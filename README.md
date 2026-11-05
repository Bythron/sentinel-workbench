# Sentinel Workbench v0.2 (phase 2)

Free, open source foundation for authorized security work. This release performs two read-only checks on the operator's own computer, saves evidence in SQLite, exports JSON reports, compares runs and exposes the same service through a CLI and a loopback FastAPI adapter.

## Quick start

Python 3.11+:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/sentinel plugins
.venv/bin/sentinel --db evidence.sqlite3 audit-local --confirm-own-device --operator "Your name"
.venv/bin/sentinel --db evidence.sqlite3 audit-local --confirm-own-device --operator "Your name" --plugin network-interfaces
.venv/bin/sentinel --db evidence.sqlite3 report
.venv/bin/sentinel --db evidence.sqlite3 verify
.venv/bin/sentinel --db evidence.sqlite3 compare 1 2
.venv/bin/sentinel --db evidence.sqlite3 check-https --url https://your-authorized-origin.example --confirm-authorized --operator "Your name"
```

The inventory includes hostname, OS, architecture, Python version and the current process ID. The interface check lists names only. Neither local check scans ports, connects to hosts, reads files or modifies settings. The optional HTTPS check sends one `HEAD /` request to the exact origin asserted by the operator; it does not follow redirects or read response bodies. The report contains host and target data: keep the database private. The digest chain detects accidental changes; it is not a cryptographic signature or protection against an attacker who can rewrite the database.

## Optional local API

Install `.[api]`, set `SENTINEL_API_TOKEN` to a random value of at least 24 characters, and run `python -m sentinel_workbench.api`. It binds to `127.0.0.1:8765` by default; set `SENTINEL_API_PORT` if that port is occupied. Authenticated routes are `GET /v1/plugins`, `POST /v1/audits/local`, `GET /v1/report` and `GET /v1/compare/{first}/{second}`; `GET /health` is public. Send `Authorization: Bearer <token>` and a JSON body such as `{"confirm_own_device":true,"operator":"Your name","plugin":"local-inventory"}`. Do not expose this adapter to a network; it has no user accounts, rate limits, TLS, or deployment hardening.

## Layout

- `src/sentinel_workbench/policy.py`: narrow authorization object
- `core.py`, `inventory.py`, `plugins.py`, `worker.py`: shared service and two allowlisted built-in checks
- `store.py`: SQLite evidence and integrity check
- `cli.py`, `api.py`: interfaces
- `tests/`: authorization and evidence tests
- `docs/ARCHITECTURE.md`, `docs/PLUGIN_API.md`, `docs/ROADMAP.md`: architecture, plugin contract and future interfaces

No third-party plugin execution is enabled. Stronger OS isolation, signing, a permission broker and review process are prerequisites before loading external code. The desktop prototype in a separate local project is not part of this release.

## Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests
.venv/bin/pip-audit --skip-editable
```

This release is a foundation for Blue, Red and Purple team workflows on assets with explicit written authorization. The HTTPS check is limited to one asserted origin and has not been tested against a live target. Broader configuration audits, external tools, AI and distributed agents remain future work. It does not include exploitation, counterattack, credential collection, ransomware, remote access or firewall management.

