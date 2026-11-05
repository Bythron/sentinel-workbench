# Security policy

Version 0.2 is a local development release. Please report vulnerabilities privately to the repository maintainers through GitHub private vulnerability reporting once the repository exists. Until then, do not publish exploit details against this project. Avoid attaching secrets or raw host inventories to reports.

The authorization flag is an operator assertion, not independent proof of ownership. The API bearer token is a single shared secret and only intended for loopback development. The SQLite digest chain is tamper-evident against casual edits, not an authenticated audit ledger. Built-in checks are trusted code; arbitrary plugin Python is disabled. Built-ins run in separate processes for timeout and cancellation, but there is no OS sandbox, firewall, malware remediation or prevention guarantee.

The optional CLI HTTPS check sends one request to the exact origin asserted by the operator. It does not follow redirects or read the response body. It does not independently verify target ownership or pin DNS resolutions; do not use it against targets outside your written scope.

