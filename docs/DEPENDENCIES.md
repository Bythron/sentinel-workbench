# Dependency review

The core and CLI use Python's standard library. Optional API dependencies are FastAPI and Uvicorn. Test and quality tools are pytest, httpx, Ruff and pip-audit. For the versions installed during local validation, package metadata reported FastAPI and pytest as MIT, Uvicorn and httpx as BSD-3-Clause, Ruff as MIT, and pip-audit with an Apache Software License classifier. This is a preliminary inventory of top-level packages. Transitive packages, license texts and future version changes still need review before a release package is published.

The test environment's dependency audit reported no known vulnerabilities after upgrading pip to 26.3. This is a point-in-time check, not a guarantee about future advisories or all dependency configurations.
