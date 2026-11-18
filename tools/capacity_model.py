"""Illustrative storage arithmetic, with explicit decimal GB/TB assumptions.

This model does not measure throughput, compute, availability, or sovereignty.
"""
import argparse
import json
import math


def _number(name, value, minimum=0):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite or value < minimum:
        raise ValueError(f"{name} must be finite and at least {minimum}")
    return value


def _replicas(name, value):
    _number(name, value, 1)
    if int(value) != value:
        raise ValueError(f"{name} must be a positive integer")
    return value


def capacity(
    ingest_gb_day=1000,
    event_bytes=1000,
    peak=3,
    queue_hours=24,
    search_days=30,
    search_expansion=1.2,
    archive_days=365,
    archive_compression=0.35,
    queue_multiplier=1,
    queue_replicas=3,
    search_replicas=2,
    archive_replicas=2,
    headroom=1.3,
):
    """Return estimated event rates and replicated storage in decimal TB.

    Compression and expansion are caller-supplied nonnegative multipliers.
    Peak is relative to average ingest. Headroom is a multiplicative factor.
    """
    values = locals().copy()
    for name, value in values.items():
        if name.endswith("_replicas"):
            _replicas(name, value)
        elif name in ("peak", "headroom"):
            _number(name, value, 1)
        else:
            _number(name, value)
    if event_bytes == 0:
        raise ValueError("event_bytes must be greater than zero")

    average_eps = ingest_gb_day * 1e9 / (86400 * event_bytes)
    result = {
        "average_eps": average_eps,
        "peak_eps": average_eps * peak,
        "queue_tb": ingest_gb_day * (queue_hours / 24) * peak
        * queue_multiplier * queue_replicas * headroom / 1000,
        "search_tb": ingest_gb_day * search_days * search_expansion
        * search_replicas * headroom / 1000,
        "archive_tb": ingest_gb_day * archive_days * archive_compression
        * archive_replicas * headroom / 1000,
    }
    if not all(math.isfinite(value) for value in result.values()):
        raise ValueError("model result exceeds finite arithmetic range")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    defaults = {
        "ingest-gb-day": 1000, "event-bytes": 1000, "peak": 3,
        "queue-hours": 24, "search-days": 30, "search-expansion": 1.2,
        "archive-days": 365, "archive-compression": 0.35,
        "queue-multiplier": 1, "headroom": 1.3,
    }
    for option, default in defaults.items():
        parser.add_argument(f"--{option}", type=float, default=default)
    for option, default in (
        ("queue-replicas", 3), ("search-replicas", 2), ("archive-replicas", 2),
    ):
        parser.add_argument(f"--{option}", type=int, default=default)
    args = parser.parse_args()
    try:
        result = capacity(**vars(args))
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps({
        "stage": "illustrative arithmetic; no product benchmark",
        "units": "decimal GB/TB",
        "assumptions": vars(args),
        "estimates": result,
    }, indent=2))


if __name__ == "__main__":
    main()
