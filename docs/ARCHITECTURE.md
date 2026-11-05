# Architecture

The core service is shared by the CLI and the optional FastAPI adapter. A policy object contains a single exact target and action. The built-in registry reads versioned JSON manifests packaged with the application and maps them to two fixed Python functions. It never imports a plugin from a discovered path. Each approved built-in runs in a child Python process with a deadline, output cap and cancellation hook. A SQLite store records the authorization assertion, plugin name and result; chained hashes detect casual edits. JSON reports and comparisons read the same store.

The process boundary limits crashes and hangs but is **not** a sandbox. Child code retains the user's operating-system permissions. The API uses one bearer token and binds to loopback. Its token is not a user identity system. A separate CLI-only HTTPS check accepts one exact origin after an operator authorization assertion; it sends a single `HEAD /`, validates TLS and does not follow redirects. It has no DNS pinning or independent proof of target ownership.

Future adapters for Nuclei, OWASP ZAP, osquery, Wazuh and OpenVAS are only design candidates. Each would need scoped target policy, output normalization, safe resource limits and tests before activation. Desktop, web, TUI, agent and provider-neutral AI frontends should call the same service after adding proper authentication and authorization.

## Decision record: plugin execution

For phase 2 we chose a closed registry of trusted built-ins. Manifests describe capability, compatibility and timeout; they do not grant execution of third-party Python. This keeps local checks useful while signature verification, review, permissions and stronger isolation are designed. State toggles are process-local and reset on restart. Persistent activation requires an authenticated settings store in a later phase.
