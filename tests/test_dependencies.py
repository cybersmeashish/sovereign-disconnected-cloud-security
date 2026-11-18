from copy import deepcopy
import json
from pathlib import Path
import unittest

from tools.dependency_analyzer import analyze

ROOT = Path(__file__).parents[1]


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.registry = json.loads((ROOT / "examples/dependencies.json").read_text())

    def statuses(self, **kwargs):
        return {item["id"]: item for item in analyze(self.registry, **kwargs)["capabilities"]}

    def test_connected_baseline(self):
        self.assertTrue(all(item["available"] for item in self.statuses().values()))

    def test_disconnection_preserves_declared_local_services(self):
        result = self.statuses(disconnected=True)
        for key, value in result.items():
            self.assertEqual(value["available"], key.startswith("local-"))
        self.assertEqual(result["enterprise-visibility"]["blocked_by"], ["external-hub"])

    def test_local_clock_failure_propagates(self):
        result = self.statuses(disconnected=True, failed=["local-time"])
        self.assertFalse(result["local-login"]["available"])
        self.assertFalse(result["local-read-record"]["available"])
        self.assertTrue(result["local-rebuild"]["available"])

    def test_rebuild_fails_without_package_cache(self):
        result = self.statuses(failed=["local-package-cache"])
        self.assertFalse(result["local-rebuild"]["available"])
        self.assertTrue(result["local-read-record"]["available"])

    def test_external_only_alternatives_fail_disconnected(self):
        registry = json.loads((ROOT / "examples/dependencies-external-only.json").read_text())
        self.assertTrue(all(not item["available"] for item in analyze(registry, True)["capabilities"]))

    def test_unknown_link_is_rejected(self):
        self.registry["dependencies"][0]["depends_on"] = ["missing"]
        with self.assertRaises(ValueError):
            analyze(self.registry)

    def test_cycles_are_rejected(self):
        self.registry["dependencies"][0]["depends_on"] = ["local-identity"]
        with self.assertRaises(ValueError):
            analyze(self.registry)

    def test_duplicate_dependency_is_rejected(self):
        self.registry["dependencies"].append(deepcopy(self.registry["dependencies"][0]))
        with self.assertRaises(ValueError):
            analyze(self.registry)

    def test_unknown_failed_id_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze(self.registry, failed=["typo"])

    def test_malformed_availability_is_rejected(self):
        for bad in ("false", 0, None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.registry["dependencies"][0]["available"] = bad
                analyze(self.registry)
