import ssl
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from sentinel_workbench.core import audit_https_origin
from sentinel_workbench.https_check import check_https_origin, normalize_origin
from sentinel_workbench.policy import Authorization, AuthorizationError
from sentinel_workbench.store import EvidenceStore


class FakeResponse:
    status = 200

    def getheaders(self):
        return [("Content-Security-Policy", "default-src 'self'")]


class FakeConnection:
    def __init__(self, *args, **kwargs):
        self.calls = []

    def request(self, method, path):
        self.calls.append((method, path))

    def getresponse(self):
        return FakeResponse()

    def close(self):
        pass


class HTTPSCheckTests(unittest.TestCase):
    def test_origin_input_is_narrow(self):
        for url in ("http://example.test", "https://user:pw@example.test", "https://example.test/path",
                    "https://example.test/?q=1", "https://example.test/#x", "https://example.test:99999"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                normalize_origin(url)
        self.assertEqual(normalize_origin("https://example.test/")[2], "https://example.test")

    def test_requires_exact_authorized_origin(self):
        with self.assertRaises(AuthorizationError):
            Authorization.for_https_origin("https://example.test", confirmed=False, asserted_by="tester")
        auth = Authorization.for_https_origin("https://example.test", confirmed=True, asserted_by="tester")
        with self.assertRaises(AuthorizationError):
            check_https_origin("https://other.test", auth)

    def test_single_head_no_redirect_and_findings_stored(self):
        auth = Authorization.for_https_origin("https://example.test", confirmed=True, asserted_by="tester")
        connection = FakeConnection()
        with TemporaryDirectory() as directory:
            store = EvidenceStore(Path(directory) / "evidence.db")
            with patch("sentinel_workbench.https_check.http.client.HTTPSConnection", return_value=connection):
                result = audit_https_origin(store, auth)
            self.assertEqual(connection.calls, [("HEAD", "/")])
            self.assertEqual(result["result"]["findings"][0]["id"], "missing-hsts")
            self.assertTrue(store.verify())
            store.close()

    def test_tls_failure_becomes_finding(self):
        auth = Authorization.for_https_origin("https://example.test", confirmed=True, asserted_by="tester")
        connection = FakeConnection()
        connection.request = lambda method, path: (_ for _ in ()).throw(ssl.SSLError("fixture"))
        with patch("sentinel_workbench.https_check.http.client.HTTPSConnection", return_value=connection):
            result = check_https_origin(auth.target, auth)
        self.assertEqual(result["findings"][0]["id"], "tls-error")
