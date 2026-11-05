"""Versioned manifests for two trusted built-ins; external code stays disabled."""

import json
import re
import subprocess
import sys
import threading
import time
from importlib import resources
from pathlib import Path

from .inventory import collect_local_inventory, collect_network_interfaces


class PluginError(ValueError):
    pass


class PluginTimeout(PluginError):
    pass


class PluginCancelled(PluginError):
    pass


RUNNERS = {"local-inventory": collect_local_inventory,
           "network-interfaces": collect_network_interfaces}
CAPABILITIES = {"local-inventory": "inventory.read",
                "network-interfaces": "network.interfaces.read"}


def validate_manifest(value: dict) -> dict:
    fields = {"api_version", "name", "version", "capability", "target", "permissions", "platforms", "timeout_seconds"}
    if not isinstance(value, dict) or set(value) != fields:
        raise PluginError("Invalid manifest fields")
    name = value["name"]
    if type(value["api_version"]) is not int or value["api_version"] != 1:
        raise PluginError("Unsupported plugin API")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{2,63}", name):
        raise PluginError("Invalid name")
    if name not in RUNNERS or value["capability"] != CAPABILITIES[name] or value["target"] != "local-host":
        raise PluginError("Untrusted or mismatched plugin")
    if not isinstance(value["version"], str) or not re.fullmatch(r"\d+\.\d+\.\d+", value["version"]):
        raise PluginError("Invalid version")
    if value["permissions"] != []:
        raise PluginError("Unexpected permission")
    if not isinstance(value["platforms"], list) or not value["platforms"] or not set(value["platforms"]) <= {"Darwin", "Linux", "Windows"}:
        raise PluginError("Invalid platforms")
    if type(value["timeout_seconds"]) is not int or not 1 <= value["timeout_seconds"] <= 30:
        raise PluginError("Invalid timeout")
    return value


class PluginManager:
    def __init__(self):
        self._manifests = {}
        self._disabled = set()
        folder = resources.files("sentinel_workbench").joinpath("manifests")
        for file in folder.iterdir():
            if file.name.endswith(".json"):
                manifest = validate_manifest(json.loads(file.read_text(encoding="utf-8")))
                if manifest["name"] in self._manifests:
                    raise PluginError("Duplicate plugin")
                self._manifests[manifest["name"]] = manifest
        if set(self._manifests) != set(RUNNERS):
            raise PluginError("Missing built-in manifest")

    def list(self) -> list[dict]:
        return [{**m, "enabled": name not in self._disabled} for name, m in sorted(self._manifests.items())]

    def set_enabled(self, name: str, enabled: bool) -> None:
        if name not in self._manifests:
            raise PluginError("Unknown plugin")
        (self._disabled.discard if enabled else self._disabled.add)(name)

    def execute(self, name: str, authorization, *, target: str = "local-host",
                cancel: threading.Event | None = None) -> dict:
        manifest = self._manifests.get(name)
        if manifest is None or name in self._disabled:
            raise PluginError("Unknown or disabled plugin")
        authorization.require(target, manifest["capability"])
        current_platform = "Darwin" if sys.platform == "darwin" else "Linux" if sys.platform.startswith("linux") else "Windows"
        if current_platform not in manifest["platforms"]:
            raise PluginError("Incompatible platform")
        package_root = str(Path(__file__).resolve().parent.parent)
        cmd = [sys.executable, "-I", "-c", "import sys; sys.path.insert(0,sys.argv[1]); from sentinel_workbench.worker import main; main()",
               package_root, name]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   stdin=subprocess.DEVNULL, close_fds=True)
        try:
            deadline = time.monotonic() + manifest["timeout_seconds"]
            while process.poll() is None:
                if cancel is not None and cancel.is_set():
                    raise PluginCancelled("Plugin cancelled")
                if time.monotonic() >= deadline:
                    raise PluginTimeout("Plugin timed out")
                time.sleep(0.01)
            output, _ = process.communicate(timeout=1)
            if process.returncode or len(output) > 65536:
                raise PluginError("Plugin failed or output too large")
            result = json.loads(output)
            if not isinstance(result, dict):
                raise PluginError("Invalid plugin output")
            return result
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()


MANAGER = PluginManager()


def run_builtin(name: str, authorization, *, target: str = "local-host") -> dict:
    return MANAGER.execute(name, authorization, target=target)


def list_plugins() -> list[dict]:
    return MANAGER.list()
