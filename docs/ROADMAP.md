# Roadmap

## Implemented in v0.2

- Python package with core, CLI, optional FastAPI adapter and SQLite evidence
- Explicit own-device confirmation and exact local scope check
- Read-only host and interface inventory, JSON report, chained digest verification and audit comparison
- Validated built-in manifests, process execution, timeout, cancellation hook and tests
- Versioned API routes and community contribution templates
- CLI-only, single-origin HTTPS HEAD check with TLS validation and classified header findings

## Proposed, not implemented

1. Signed scope documents with expiry, asset identifiers and reviewer approval for any nonlocal target.
2. A capability broker and OS-level isolation for externally contributed plugins; manifest schema, signing, review and revocation.
3. Desktop and web views backed by the same service contracts, with authentication and privacy controls.
4. Provider-neutral AI interface limited to proposing actions for human approval, with tool-level policy checks.
5. Blue team inventory and incident notes; Red team lab-only tests; Purple team evidence and remediation tracking.
6. Agent scheduling, persistent jobs, immutable audit export and multi-user roles.
7. Stronger HTTP/TLS target policy with DNS controls and API integration; local configuration audit and a fuller findings taxonomy.

No item above is a current security guarantee. Real target testing requires explicit permission, a defined scope and separate validation.

