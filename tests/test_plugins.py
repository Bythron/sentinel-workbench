import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sentinel_workbench.core import audit_own_device, compare
from sentinel_workbench.plugins import (
    MANAGER,
    PluginCancelled,
    PluginError,
    PluginManager,
    validate_manifest,
)
from sentinel_workbench.policy import Authorization, AuthorizationError
from sentinel_workbench.store import EvidenceStore


class PluginTests(unittest.TestCase):
    def test_both_builtins_discovered(self):
        self.assertEqual({x["name"] for x in MANAGER.list()}, {"local-inventory", "network-interfaces"})

    def test_manifest_validation_rejects_unsafe_changes(self):
        valid = MANAGER.list()[0].copy()
        del valid["enabled"]
        for change in ({"api_version": 2}, {"permissions": ["network"]},
                       {"name": "external"}, {"timeout_seconds": 100},
                       {"capability": "inventory.write"}):
            altered = {**valid, **change}
            with self.subTest(change=change), self.assertRaises(PluginError):
                validate_manifest(altered)

    def test_disable_and_reenable(self):
        manager = PluginManager()
        auth = Authorization.for_own_device(confirmed=True, asserted_by="tester")
        manager.set_enabled("local-inventory", False)
        with self.assertRaises(PluginError):
            manager.execute("local-inventory", auth)
        manager.set_enabled("local-inventory", True)
        self.assertEqual(manager.execute("local-inventory", auth)["target"], "local-host")

    def test_local_interfaces_scope_and_result(self):
        manager = PluginManager()
        inventory = Authorization.for_own_device(confirmed=True, asserted_by="tester")
        with self.assertRaises(AuthorizationError):
            manager.execute("network-interfaces", inventory)
        authorized = Authorization.for_own_device(confirmed=True, asserted_by="tester",
                                                  action="network.interfaces.read")
        result = manager.execute("network-interfaces", authorized)
        self.assertIn(result["availability"], {"available", "unavailable"})
        self.assertIsInstance(result["interfaces"], list)

    def test_cancel_before_result(self):
        manager = PluginManager()
        auth = Authorization.for_own_device(confirmed=True, asserted_by="tester")
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(PluginCancelled):
            manager.execute("local-inventory", auth, cancel=cancel)

    def test_compare_same_plugin(self):
        with TemporaryDirectory() as directory:
            store = EvidenceStore(Path(directory) / "evidence.db")
            auth = Authorization.for_own_device(confirmed=True, asserted_by="tester")
            first = audit_own_device(store, auth)["evidence_id"]
            second = audit_own_device(store, auth)["evidence_id"]
            self.assertEqual(compare(store, first, second)["changed"], {})
            with self.assertRaises(ValueError):
                compare(store, first, 999)
            store.close()
