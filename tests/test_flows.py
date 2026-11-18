from copy import deepcopy
import json
from pathlib import Path
import unittest

from tools.flow_validator import validate

ROOT = Path(__file__).parents[1]


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.register = json.loads((ROOT / "architecture/flow-register.json").read_text())

    def codes(self):
        return {issue["code"] for issue in validate(self.register)}

    def test_three_site_contracts(self):
        self.assertEqual(validate(self.register), [])
        self.assertEqual(len(self.register["flows"]), 8)

    def test_missing_owner_is_rejected(self):
        del self.register["flows"][0]["owner"]
        self.assertIn("required_field", self.codes())

    def test_duplicate_flow_is_rejected(self):
        self.register["flows"].append(deepcopy(self.register["flows"][0]))
        self.assertIn("duplicate_id", self.codes())

    def test_strict_gap_external_network_is_rejected(self):
        self.register["flows"][0]["direction"] = "outbound"
        self.assertIn("air_gap_network", self.codes())

    def test_one_way_inbound_network_is_rejected(self):
        self.register["flows"][4]["direction"] = "inbound"
        self.assertIn("one_way_inbound", self.codes())

    def test_export_without_review_is_rejected(self):
        self.register["flows"][2]["disclosure_review_required"] = False
        self.assertIn("disclosure_review", self.codes())

    def test_import_without_prior_quarantine_is_rejected(self):
        for stages in ([], ["local_repository", "quarantine"]):
            with self.subTest(stages=stages):
                self.register["flows"][3]["stages"] = stages
                self.assertIn("quarantine_order", self.codes())

    def test_duplicate_approval_role_is_rejected(self):
        self.register["flows"][3]["approval_roles"] = ["owner", "owner"]
        self.assertIn("approval_roles", self.codes())

    def test_intermediate_connectivity_requires_connection(self):
        self.register["flows"][1]["allowed_when"] = "always"
        self.assertIn("connectivity_condition", self.codes())

    def test_malformed_shapes_return_issues(self):
        self.assertTrue(validate([]))
        for field in ("direction", "kind", "failure_behavior", "site_id"):
            for bad in (None, True, [], {}):
                with self.subTest(field=field, bad=bad):
                    self.register = json.loads((ROOT / "architecture/flow-register.json").read_text())
                    self.register["flows"][0][field] = bad
                    self.assertTrue(validate(self.register))

    def test_unknown_site_and_negative_retention_are_rejected(self):
        self.register["flows"][0]["site_id"] = "unregistered-site"
        self.register["flows"][0]["retention"]["days"] = -1
        self.assertTrue({"unknown_site", "retention_days"} <= self.codes())
