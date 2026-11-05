# Contributing

Issues and pull requests are welcome after a public repository exists. Describe the authorized use case, expected result, tests and privacy impact. Keep checks read-only by default. New target types must require a verifiable scope policy and fail closed when the target or action does not match. New dependencies need a reason and license review. Run `python -m pytest -q` and `ruff check src tests` before submitting. See [the plugin contract](docs/PLUGIN_API.md). Do not submit exploit chains, credential theft, persistence, counterattack, or scans of third-party targets without a scoped authorization design and review. Suggested starter labels are `good first issue` for tests/docs and `help wanted` for reviewed platform compatibility work.

