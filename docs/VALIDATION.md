# Local validation, 2026-11-05

- `PYTHONPATH=src python3 -m unittest discover -s tests -v`: 2 tests passed on Python 3.15.0/macOS.
- `PYTHONPATH=src python3 -m sentinel_workbench.cli ... audit-local`: produced a local inventory and evidence row in a temporary database; subsequent `verify` returned `evidence_chain_valid: true`. This smoke run used the CLI confirmation flag; ownership of the accessible Mac was not independently verified. The temporary database was deleted after the check.
- CLI without `--confirm-own-device`: refused before creating the database.
- `python3 -m compileall -q src`: passed.
- The suite corrupts one saved payload and confirms that verification fails.

Phase 2 follow-up: Python 3.13 editable installation with `.[test]` succeeded. The expanded test suite, FastAPI TestClient, lint and dependency audit results are recorded in the phase 2 validation note. CI is configured for Python 3.11–3.13 but has not run on GitHub. No public repository has been created.
