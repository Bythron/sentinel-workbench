"""Application service shared by CLI and HTTP adapter."""

from .https_check import check_https_origin
from .plugins import run_builtin
from .store import EvidenceStore


def audit_own_device(store: EvidenceStore, authorization, plugin: str = "local-inventory") -> dict:
    result = run_builtin(plugin, authorization)
    event = {"authorization": vars(authorization), "plugin": plugin, "result": result}
    evidence_id = store.append(event)
    return {"evidence_id": evidence_id, "result": result}


def audit_https_origin(store: EvidenceStore, authorization) -> dict:
    result = check_https_origin(authorization.target, authorization)
    event = {"authorization": vars(authorization), "plugin": "https-origin", "result": result}
    return {"evidence_id": store.append(event), "result": result}


def compare(store: EvidenceStore, first: int, second: int) -> dict:
    records = {item["id"]: item["payload"] for item in store.records()}
    if first not in records or second not in records:
        raise ValueError("Evidence ID not found")
    a, b = records[first], records[second]
    if a["plugin"] != b["plugin"]:
        raise ValueError("Audits must use the same plugin")
    ignored = {"collected_at", "process_id"}
    left = {k: v for k, v in a["result"].items() if k not in ignored}
    right = {k: v for k, v in b["result"].items() if k not in ignored}
    return {"first": first, "second": second, "plugin": a["plugin"],
            "changed": {k: {"before": left.get(k), "after": right.get(k)}
                        for k in sorted(left.keys() | right.keys()) if left.get(k) != right.get(k)}}


def report(store: EvidenceStore) -> dict:
    records = store.records()
    return {"format": "sentinel-report-v0.1", "evidence_chain_valid": store.verify(),
            "record_count": len(records), "records": records}
