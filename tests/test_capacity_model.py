import importlib.util
import pathlib
import unittest

MODEL = pathlib.Path(__file__).parents[1] / "tools" / "capacity_model.py"
SPEC = importlib.util.spec_from_file_location("capacity_model", MODEL)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
capacity = module.capacity


class CapacityModelTests(unittest.TestCase):
    def test_illustrative_model(self):
        result = capacity()
        self.assertAlmostEqual(result["average_eps"], 11574.074074074)
        self.assertAlmostEqual(result["peak_eps"], 34722.222222222)
        self.assertAlmostEqual(result["queue_tb"], 11.7)
        self.assertAlmostEqual(result["search_tb"], 93.6)
        self.assertAlmostEqual(result["archive_tb"], 332.15)

    def test_volume_scaling(self):
        baseline = capacity(ingest_gb_day=1000)
        doubled = capacity(ingest_gb_day=2000)
        for key in baseline:
            self.assertAlmostEqual(doubled[key], 2 * baseline[key])

    def test_zero_retention(self):
        result = capacity(queue_hours=0, search_days=0, archive_days=0)
        for key in ("queue_tb", "search_tb", "archive_tb"):
            self.assertEqual(result[key], 0)
        self.assertGreater(result["average_eps"], 0)
        self.assertTrue(all(value == 0 for value in capacity(ingest_gb_day=0).values()))

    def test_invalid_event_size(self):
        for value in (0, -1, "1000", True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                capacity(event_bytes=value)

    def test_negative_volume(self):
        with self.assertRaises(ValueError):
            capacity(ingest_gb_day=-0.01)

    def test_invalid_peak(self):
        for value in (0, 0.9, -1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                capacity(peak=value)

    def test_nonfinite_input_and_overflow(self):
        for parameter in (
            "ingest_gb_day", "event_bytes", "peak", "queue_hours",
            "search_days", "search_expansion", "archive_days",
            "archive_compression", "queue_multiplier", "headroom",
            "queue_replicas", "search_replicas", "archive_replicas",
        ):
            for value in (float("nan"), float("inf"), float("-inf")):
                with self.subTest(parameter=parameter, value=value):
                    with self.assertRaises(ValueError):
                        capacity(**{parameter: value})
        with self.assertRaises(ValueError):
            capacity(ingest_gb_day=1e308)

    def test_negative_retention_and_multipliers(self):
        for parameter in (
            "queue_hours", "search_days", "archive_days",
            "search_expansion", "archive_compression", "queue_multiplier",
        ):
            with self.subTest(parameter=parameter), self.assertRaises(ValueError):
                capacity(**{parameter: -1})
        with self.assertRaises(ValueError):
            capacity(headroom=0.99)

    def test_invalid_replica_count(self):
        for parameter in ("queue_replicas", "search_replicas", "archive_replicas"):
            for value in (0, -1, 1.5, True):
                with self.subTest(parameter=parameter, value=value):
                    with self.assertRaises(ValueError):
                        capacity(**{parameter: value})


if __name__ == "__main__":
    unittest.main()
