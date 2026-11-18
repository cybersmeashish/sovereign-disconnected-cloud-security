# Verification — contributions 01–07

Observed **18 November 2026**.

## Recorded results

| Check | Actual observation |
| --- | --- |
| Standard-library regression suite, host | 56 passed; Python 3.12.14; macOS arm64 |
| Same regression suite, isolated container | 56 passed; Python 3.12.16; Linux aarch64 |
| Local authorization and dependency scenarios inside isolated runtime | 30 of 30 passed across three logical industry fixtures |
| Network interface observation | Only `lo` |
| Default IPv4 routes | None |
| External probe | `192.0.2.1:443` returned kernel `ENETUNREACH` (errno 101) |
| Actual container configuration | Network none, read-only root, non-root user, capabilities dropped, no-new-privileges, bounded memory/processes/CPU |
| Runtime source matching | All 24 selected code/test/data/image-recipe hashes matched the current checkout |

[Unit observations](../evidence/2026-11-18/unit-results.json) · [Full isolation/scenario report](../evidence/2026-11-18/isolation-report.json) · [Source manifest](../evidence/2026-11-18/source-manifest.json)

The suite contains 47 new tests and the existing nine capacity-model tests. Running the same suite twice demonstrates two execution environments; it does not create 112 distinct test cases.

## Reproduce

```bash
python3 -m unittest discover -s tests -v
python3 -m tools.flow_validator architecture/flow-register.json
python3 -m tools.dependency_analyzer examples/dependencies.json --disconnect
docker build --network=none --pull=false -t ashish-sovereign-lab:contributions-01-07 .
python3 -m tools.run_isolated_lab --output evidence/local/isolation-report.json
```

Prefetch the exact base image as described in [isolated-lab preparation](isolated-lab.md). A source-manifest mismatch fails verification, so rebuild after source or fixture changes. The [GitHub workflow](../.github/workflows/verify.yml) repeats the tests and isolated run on future relevant changes and retains its own output artifact.

## Practical limits

The container is a Linux network namespace within the local engine. This does not establish a physical air gap, data diode, host/hypervisor integrity, provider placement, legal sovereignty, cryptographic certification or national accreditation.

Identity, sessions, role state, clock floor and audit are in memory; the local HTTP service is loopback only and lacks production TLS, MFA, rate controls and persistent identity/time protection. The dependency graph is a declared model. Flow rules validate contracts rather than enforcing network traffic or actual approvals. Release signatures, imported package admission, DNS/registry/PKI services, monitoring platforms, backup/key recovery and customer environments were not exercised.

The capacity reference remains arithmetic and input validation, without a product throughput benchmark. Every credential and record in the lab is an explicitly synthetic public fixture.
