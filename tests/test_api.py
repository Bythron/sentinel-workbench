import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient

from sentinel_workbench.api import create_app


class APITests(unittest.TestCase):
    def test_auth_scope_and_report(self):
        with TemporaryDirectory() as directory:
            app = create_app(db_path=str(Path(directory) / "evidence.db"), token="a" * 32)
            client = TestClient(app)
            self.assertEqual(client.get("/health").status_code, 200)
            self.assertEqual(client.get("/v1/plugins").status_code, 401)
            headers = {"Authorization": "Bearer " + "a" * 32}
            self.assertEqual(len(client.get("/v1/plugins", headers=headers).json()), 2)
            refused = client.post("/v1/audits/local", headers=headers,
                                  json={"confirm_own_device": False, "operator": "tester"})
            self.assertEqual(refused.status_code, 403)
            self.assertEqual(client.get("/v1/report", headers=headers).json()["record_count"], 0)
            invalid = client.post("/v1/audits/local", headers=headers,
                                  json={"confirm_own_device": True, "operator": "tester", "plugin": "external"})
            self.assertEqual(invalid.status_code, 422)
            with patch("sentinel_workbench.api.audit_own_device", return_value={"evidence_id": 7, "result": {"fixture": True}}):
                accepted = client.post("/v1/audits/local", headers=headers,
                                       json={"confirm_own_device": True, "operator": "tester",
                                             "plugin": "network-interfaces"})
            self.assertEqual(accepted.status_code, 200)
            self.assertEqual(accepted.json()["evidence_id"], 7)

    def test_short_token_rejected(self):
        with self.assertRaises(ValueError):
            create_app(db_path="unused.db", token="short")
