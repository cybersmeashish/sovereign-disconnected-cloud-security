# Verification — contributions 08–28

Observed **18 November 2026**. These reference experiments extend contributions 01–07.

| Check | Actual result |
| --- | --- |
| Host regression suite | 101 tests passed, 6.75 seconds |
| Same suite, isolated Linux container | 101 passed, 8.089 seconds |
| Expanded integration/scenario expectations | 78 passed; includes 30 earlier scenarios |
| Post-quantum/interop experiments | Six checks passed with OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026) on Darwin arm64 |
| Runtime source matching | 52 selected code/test/data/recipe/lock hashes matched |
| Network isolation | Only loopback; no default IPv4 route; external probe `ENETUNREACH` |
| Runtime restrictions | Non-root, read-only root, network none, all capabilities dropped, no-new-privileges, 1 CPU, 256 MiB and 64 processes |
| Storage fault | Actual `ENOSPC` on a dedicated 64 KiB tmpfs; host disk untouched |
| Benchmark | Five trials, 3,000 synthetic records, 150 indexed queries; raw timings retained |
| Clean restoration | Five runs restored config/data/software keys; one post-snapshot record intentionally absent |
| Dependency failures | All 12 declared dependency failures evaluated as models |

[Unit results](../evidence/2026-11-18/expanded-unit-results.json) · [Full run](../evidence/2026-11-18/expanded-isolation-report.json) · [PQ report](../evidence/2026-11-18/pq-compatibility-report.json) · [Benchmark](../evidence/2026-11-18/capacity-benchmark.json) · [Restoration](../evidence/2026-11-18/restoration-measurements.json)

**Passed means the observation matched the expectation.** Explicit unsafe gaps include restartable in-memory replay state and a missing rule for an unknown event type. Placement declarations remain unverified. These outcomes are reported, not treated as production-safe controls.

## Reproduce

Python 3.12 and Docker are the observed path. Prepare dependencies while connected:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --no-cache-dir --require-hashes -r requirements.lock
python -m unittest discover -s tests -v
python -m tools.prepare_dependencies
docker pull python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
docker build --network=none --pull=false -t ashish-sovereign-lab:contributions-01-28 .
python -m tools.run_isolated_lab --expanded --image ashish-sovereign-lab:contributions-01-28 --output evidence/local/expanded-report.json
```

For the separate PQ experiment, supply an OpenSSL implementation supporting ML-KEM/ML-DSA:

```bash
python -m tools.pq_compatibility --openssl openssl --output evidence/local/pq-report.json
```

The source manifest rejects an outdated image. Rebuild after code, lock or JSON fixture changes. Connected preparation and isolated execution are distinct stages. The [workflow](../.github/workflows/verify.yml) installs hash-locked inputs, tests the suite and repeats both isolated runs.

## Limits

One disposable container hosts synthetic logical sites. Key custody, approval signers and replay state are in memory. No HSM, durable anti-rollback anchor, real learned model, provider environment, remote attestation, physical air gap, production TLS/MFA, FIPS validation or national accreditation was demonstrated.

Policy and dependency models are distinct from deployed enforcement and service outages. Timed backup/SQLite/deque observations use tiny tmpfs fixtures, not stable storage or whole-site recovery. PQ compatibility was measured on the host only. Signatures authenticate pinned-key statements; they do not independently establish builder trust, placement or recipient receipt.
