import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


class CLITests(unittest.TestCase):
    def call(self, db, *args):
        env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
        return subprocess.run([sys.executable, "-m", "sentinel_workbench.cli", "--db", str(db), *args],
                              check=False, capture_output=True, text=True, env=env)

    def test_missing_confirmation_creates_no_database(self):
        with TemporaryDirectory() as directory:
            db = Path(directory) / "evidence.db"
            result = self.call(db, "audit-local", "--operator", "tester")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(db.exists())

    def test_plugins_and_verify_empty_store(self):
        with TemporaryDirectory() as directory:
            db = Path(directory) / "evidence.db"
            plugins = self.call(db, "plugins")
            self.assertEqual(plugins.returncode, 0)
            self.assertEqual(len(json.loads(plugins.stdout)), 2)
            verify = self.call(db, "verify")
            self.assertEqual(verify.returncode, 0)
            self.assertTrue(json.loads(verify.stdout)["evidence_chain_valid"])
