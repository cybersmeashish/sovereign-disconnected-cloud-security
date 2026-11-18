import json
import unittest

from lab.fixtures import DEMO_PASSWORD, make_authority
from lab.run import request
from lab.service import running_service


class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority = make_authority()
        cls.context = running_service(cls.authority)
        cls.address = cls.context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.context.__exit__(None, None, None)

    def token(self):
        status, result = request(self.address, "POST", "/login", {
            "principal_id": "government-viewer", "password": DEMO_PASSWORD,
        })
        self.assertEqual(status, 200)
        return result["token"]

    def test_loopback_binding(self):
        self.assertEqual(self.address[0], "127.0.0.1")

    def test_missing_bearer_is_denied(self):
        status, _ = request(self.address, "GET", "/records/government-record-a")
        self.assertEqual(status, 403)

    def test_own_record_and_cross_tenant_over_http(self):
        token = self.token()
        status, body = request(self.address, "GET", "/records/government-record-a", token=token)
        self.assertEqual(status, 200)
        self.assertTrue(body["record"]["synthetic"])
        status, _ = request(self.address, "GET", "/records/government-record-b", token=token)
        self.assertEqual(status, 403)

    def test_caller_tenant_claim_cannot_expand_access(self):
        token = self.token()
        status, _ = request(self.address, "GET", "/records/government-record-b?tenant_id=tenant-a", token=token)
        self.assertEqual(status, 403)

    def test_login_rejects_extra_claims_and_malformed_body(self):
        status, _ = request(self.address, "POST", "/login", {
            "principal_id": "government-viewer", "password": DEMO_PASSWORD, "tenant_id": "tenant-b",
        })
        self.assertEqual(status, 400)
        status, _ = request(self.address, "POST", "/login", [])
        self.assertEqual(status, 400)

    def test_wrong_password_and_unknown_endpoint(self):
        status, _ = request(self.address, "POST", "/login", {
            "principal_id": "government-viewer", "password": "wrong",
        })
        self.assertEqual(status, 403)
        status, _ = request(self.address, "GET", "/admin")
        self.assertEqual(status, 404)
