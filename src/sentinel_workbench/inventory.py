"""Read-only, minimal inventory of the current host; no subprocesses or network."""

import os
import platform
import socket
from datetime import UTC, datetime


def collect_local_inventory() -> dict:
    return {
        "collected_at": datetime.now(UTC).isoformat(),
        "target": "local-host",
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "process_id": os.getpid(),
        "checks": {
            "host_identified": bool(socket.gethostname()),
            "runtime_identified": bool(platform.python_version()),
        },
    }


def collect_network_interfaces() -> dict:
    """List interface names only; no packets, addresses or remote traffic."""
    try:
        names = sorted({name for _, name in socket.if_nameindex()})
        availability = "available"
    except (OSError, AttributeError):
        names = []
        availability = "unavailable"
    return {"collected_at": datetime.now(UTC).isoformat(),
            "target": "local-host", "availability": availability,
            "interfaces": names, "count": len(names) if availability == "available" else None}

