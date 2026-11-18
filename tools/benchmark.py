"""Measured SQLite/deque fixture; no product or production capacity claim."""
import argparse
from collections import deque
import json
import os
from pathlib import Path
import platform
import sqlite3
import statistics
import tempfile
import time


def summary(values):
    ordered = sorted(values)
    return {"samples": len(values), "min": min(values), "median": statistics.median(values),
            "p95_nearest_rank": ordered[max(0, __import__("math").ceil(.95 * len(values)) - 1)],
            "max": max(values)}


def benchmark(directory, events=3000, trials=5):
    if type(events) is not int or not 100 <= events <= 10000 or type(trials) is not int or not 3 <= trials <= 10:
        raise ValueError("bounded workload: 100–10000 events, 3–10 trials")
    rows = [(i, i % 3, i % 5, "x" * 256) for i in range(events)]
    measurements = []
    for _ in range(trials):
        with tempfile.TemporaryDirectory(dir=directory) as trial:
            database = Path(trial) / "events.sqlite"
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, tenant INTEGER, severity INTEGER, payload TEXT)")
            connection.execute("CREATE INDEX scope ON events(tenant,severity)")
            started = time.perf_counter()
            with connection:
                connection.executemany("INSERT INTO events VALUES (?,?,?,?)", rows)
            ingest = time.perf_counter() - started
            assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == events
            timings = []
            for query in range(30):
                started = time.perf_counter()
                count = connection.execute("SELECT count(*) FROM events WHERE tenant=? AND severity=?",
                                           (query % 3, query % 5)).fetchone()[0]
                timings.append(time.perf_counter() - started)
                assert count == sum(1 for row in rows if row[1:3] == (query % 3, query % 5))
            queue = deque()
            started = time.perf_counter()
            queue.extend(rows)
            for expected in rows:
                assert queue.popleft() == expected
            queue_time = time.perf_counter() - started
            backup = sqlite3.connect(Path(trial) / "backup.sqlite")
            started = time.perf_counter()
            connection.backup(backup)
            backup_time = time.perf_counter() - started
            assert backup.execute("SELECT * FROM events ORDER BY id").fetchall() == rows
            size = database.stat().st_size
            backup.close()
            connection.close()
            started = time.perf_counter()
            restored = sqlite3.connect(Path(trial) / "backup.sqlite")
            assert restored.execute("SELECT count(*) FROM events").fetchone()[0] == events
            recovery_time = time.perf_counter() - started
            restored.close()
            measurements.append({
                "ingest_events_per_second": events / ingest,
                "queue_round_trip_events_per_second": events / queue_time,
                "search_seconds": timings, "storage_bytes": size,
                "sqlite_backup_seconds": backup_time, "reopen_and_count_seconds": recovery_time,
            })
    return {
        "environment": {"system": platform.system(), "machine": platform.machine(),
                        "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                        "logical_cpus_visible": os.cpu_count()},
        "workload": {"events": events, "trials": trials, "queries_per_trial": 30,
                     "payload_bytes": 256, "tenants": 3, "severity_values": 5,
                     "distribution": "deterministic round-robin, fixed-size payload, one synchronous writer",
                     "storage": "temporary filesystem selected by caller; container run uses tmpfs",
                     "durability": "SQLite defaults; no forced power-loss or stable-media guarantee"},
        "raw_trials": measurements,
        "summary": {
            key: summary([trial[key] for trial in measurements])
            for key in ("ingest_events_per_second", "queue_round_trip_events_per_second",
                        "storage_bytes", "sqlite_backup_seconds", "reopen_and_count_seconds")
        } | {"search_seconds": summary([v for trial in measurements for v in trial["search_seconds"]])},
        "limits": "Toy single-process SQLite/deque measurements, tmpfs in the isolated run, small samples, no vendor platform or production sizing inference.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--state", type=Path, default=Path("/tmp"))
    args = parser.parse_args()
    args.state.mkdir(parents=True, exist_ok=True)
    result = benchmark(args.state)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()
