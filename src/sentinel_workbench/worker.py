"""Process entry point for fixed trusted plugins."""
import json
import sys

from .plugins import RUNNERS


def main() -> None:
    name = sys.argv[2]
    if name not in RUNNERS:
        raise SystemExit(2)
    print(json.dumps(RUNNERS[name](), separators=(",", ":"), ensure_ascii=False))
