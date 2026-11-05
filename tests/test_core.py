import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sentinel_workbench.core import audit_own_device, report
from sentinel_workbench.plugins import run_builtin
from sentinel_workbench.policy import Authorization, AuthorizationError
from sentinel_workbench.store import EvidenceStore


class CoreTests(unittest.TestCase):
    def test_authorization_required_and_scope_enforced(self):
        with self.assertRaises(AuthorizationError):
            Authorization.for_own_device(confirmed=False, asserted_by="tester")
        auth = Authorization.for_own_device(confirmed=True, asserted_by="tester")
        with self.assertRaises(AuthorizationError):
            run_builtin("local-inventory", auth, target="example.org")
        with self.assertRaises(ValueError):
            run_builtin("arbitrary-python", auth)

    def test_audit_report_and_tamper_detection(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.sqlite3"
            store = EvidenceStore(path)
            auth = Authorization.for_own_device(confirmed=True, asserted_by="tester")
            item = audit_own_device(store, auth)
            self.assertEqual(item["result"]["target"], "local-host")
            self.assertEqual(report(store)["record_count"], 1)
            self.assertTrue(store.verify())
            store.close()
            db = sqlite3.connect(path)
            db.execute("UPDATE evidence SET payload='{}' WHERE id=1")
            db.commit()
            db.close()
            store = EvidenceStore(path)
            self.assertFalse(store.verify())
            store.close()


if __name__ == "__main__":
    unittest.main()
