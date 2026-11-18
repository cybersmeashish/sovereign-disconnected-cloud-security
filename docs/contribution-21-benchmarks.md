# 21 — Measured capacity benchmarks

[Benchmark](../tools/benchmark.py) measures synchronous SQLite ingest, indexed searches, deque round trips, database storage, backup and reopen/count recovery. Five trials use 3,000 fixed-payload events with three tenants and five severity values, plus thirty queries per trial. Row/queue/restore correctness is checked.

The published report contains raw trials, median/min/max and nearest-rank p95, runtime versions, visible CPUs and enforced container CPU/memory limits. Storage is tmpfs; the workload is small and deterministic. It is not a vendor platform benchmark or production capacity estimate. The [arithmetic model](../tools/capacity_model.py) remains a separate planning aid; no product throughput is inferred from these measurements.

[Completion and measured evidence](contributions-08-28.md) · [Expanded verification](expanded-verification.md) · [Primary references](expanded-references.md)
