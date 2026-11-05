# Built-in plugin API v1

Each packaged manifest has exactly: `api_version` (1), `name`, semantic `version`, `capability`, `target` (`local-host`), empty `permissions`, `platforms` and `timeout_seconds` (1–30). Unknown fields, names, capabilities and permissions fail validation. Only names compiled into the trusted registry can run.

`local-inventory` reports basic host/runtime metadata. `network-interfaces` reports interface names and availability. Neither opens a socket to another host or captures packets. Execution uses a child process, five-second deadline and 64 KiB output cap. Cancellation terminates that child. These controls do not confine malicious code; external plugin execution remains disabled.

Proposals for new built-ins should include an exact action, platform behavior, failure behavior, privacy impact, manifest update and tests. A future external plugin format will need review and a real isolation design before becoming executable.
