"""Local command line entry point."""

import argparse
import json
import sys
from pathlib import Path

from .core import audit_https_origin, audit_own_device, compare, report
from .plugins import CAPABILITIES, PluginError, list_plugins
from .policy import Authorization, AuthorizationError
from .store import EvidenceStore


def _run(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel")
    parser.add_argument("--db", default=str(Path.home() / ".local/share/sentinel-workbench/evidence.sqlite3"))
    commands = parser.add_subparsers(dest="command", required=True)
    audit = commands.add_parser("audit-local", help="Collect minimal inventory of your own device")
    audit.add_argument("--confirm-own-device", action="store_true", required=True)
    audit.add_argument("--operator", required=True)
    audit.add_argument("--plugin", choices=sorted(CAPABILITIES), default="local-inventory")
    https = commands.add_parser("check-https", help="HEAD / on one expressly authorized HTTPS origin")
    https.add_argument("--url", required=True)
    https.add_argument("--confirm-authorized", action="store_true", required=True)
    https.add_argument("--operator", required=True)
    commands.add_parser("plugins")
    commands.add_parser("report")
    commands.add_parser("verify")
    comparison = commands.add_parser("compare")
    comparison.add_argument("first", type=int)
    comparison.add_argument("second", type=int)
    args = parser.parse_args(argv)
    if args.command == "plugins":
        print(json.dumps(list_plugins(), indent=2))
        return 0
    if args.command in {"audit-local", "check-https"}:
        if args.command == "audit-local":
            auth = Authorization.for_own_device(confirmed=args.confirm_own_device, asserted_by=args.operator,
                                                action=CAPABILITIES[args.plugin])
        else:
            auth = Authorization.for_https_origin(args.url, confirmed=args.confirm_authorized,
                                                  asserted_by=args.operator)
        with_store = EvidenceStore(args.db)
        try:
            output = (audit_own_device(with_store, auth, args.plugin) if args.command == "audit-local"
                      else audit_https_origin(with_store, auth))
        finally:
            with_store.close()
    else:
        with_store = EvidenceStore(args.db)
        try:
            if args.command == "report":
                output = report(with_store)
            elif args.command == "compare":
                output = compare(with_store, args.first, args.second)
            else:
                output = {"evidence_chain_valid": with_store.verify()}
        finally:
            with_store.close()
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0 if args.command != "verify" or output["evidence_chain_valid"] else 1


def main(argv=None) -> int:
    try:
        return _run(argv)
    except (AuthorizationError, PluginError, ValueError) as error:
        print(json.dumps({"error": type(error).__name__, "message": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

