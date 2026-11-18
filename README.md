# Sovereign & Disconnected Cloud Security

[![Verify reference lab](https://github.com/cybersmeashish/sovereign-disconnected-cloud-security/actions/workflows/verify.yml/badge.svg)](https://github.com/cybersmeashish/sovereign-disconnected-cloud-security/actions/workflows/verify.yml)

**Ashish Srivastava** — reference research connecting sovereignty decisions, local operational authority, identity, dependency failure, controlled flows and inspectable evidence.

## Contributions 01–07

| # | Contribution | Inspect the artifact |
| --- | --- | --- |
| 01 | Sovereignty boundary register | [Template and Government/BFSI/Oil & Gas records](docs/contribution-01-sovereignty-boundaries.md) |
| 02 | Connectivity architecture patterns | [Four diagrams, assumptions and permitted directions](architecture/connectivity-patterns.md) |
| 03 | Threat model | [Assets, trust boundaries, attack tree and evidence gaps](docs/threat-model.md) |
| 04 | Dependency inventory | [Graph analyzer, outage scenarios and external-only counterexamples](docs/dependency-inventory.md) |
| 05 | Flow-register validator | [Eight contracts and boundary/negative cases](docs/flow-validation.md) |
| 06 | Isolated-site reference lab | [Digest-pinned container, isolation checks and source matching](docs/isolated-lab.md) |
| 07 | Offline identity and authorization | [Scoped resources, expiry, revocation, service identities and emergency approval](docs/offline-identity.md) |

[Completion and evidence map](docs/contributions-01-07.md) · [Observed verification](docs/verification.md) · [Primary sources](docs/references.md) · [Research roadmap](ROADMAP.md)

## Contributions 08–28

| # | Contribution | Inspect the artifact |
| --- | --- | --- |
| 08 | Key custody and recovery | [Inspect](docs/contribution-08-key-custody.md) |
| 09 | Offline package admission | [Inspect](docs/contribution-09-package-admission.md) |
| 10 | Signature and provenance verification | [Inspect](docs/contribution-10-provenance.md) |
| 11 | Offline software inventory and vulnerability review | [Inspect](docs/contribution-11-offline-inventory.md) |
| 12 | Controlled updates and rollback | [Inspect](docs/contribution-12-updates.md) |
| 13 | Workload and tenant isolation | [Inspect](docs/contribution-13-isolation.md) |
| 14 | Local security monitoring | [Inspect](docs/contribution-14-monitoring.md) |
| 15 | Visibility freshness model | [Inspect](docs/contribution-15-freshness.md) |
| 16 | Controlled evidence export | [Inspect](docs/contribution-16-evidence-export.md) |
| 17 | Audit integrity and time uncertainty | [Inspect](docs/contribution-17-audit-time.md) |
| 18 | Disconnected incident-response playbooks | [Inspect](docs/contribution-18-incident-response.md) |
| 19 | Backup and restoration evidence | [Inspect](docs/contribution-19-restoration.md) |
| 20 | Failure-injection experiments | [Inspect](docs/contribution-20-failure-injection.md) |
| 21 | Measured capacity benchmarks | [Inspect](docs/contribution-21-benchmarks.md) |
| 22 | Control-to-evidence mapping | [Inspect](docs/contribution-22-control-evidence.md) |
| 23 | Placement and residency assurance | [Inspect](docs/contribution-23-placement.md) |
| 24 | Provider capability comparisons | [Inspect](docs/contribution-24-provider-comparison.md) |
| 25 | Post-quantum transition inventory | [Inspect](docs/contribution-25-post-quantum.md) |
| 26 | Sovereign AI integration case | [Inspect](docs/contribution-26-sovereign-ai.md) |
| 27 | Three industry case studies | [Inspect](docs/contribution-27-industry-cases.md) |
| 28 | Research results and executive decision briefs | [Inspect](docs/contribution-28-research-briefs.md) |

[Completion map](docs/contributions-08-28.md) · [Original results](research/2026-11-18-results.md) · [Executive decision brief](briefs/ciso-decision-brief.md) · [Measured verification](docs/expanded-verification.md)

**Recorded local verification — 18 November 2026:** 101 unique regression tests, 78 scenario checks and six host post-quantum/interop checks passed. Expected unsafe gaps are also recorded. [Inspect the results and practical limits](docs/expanded-verification.md).

## Reproduce

Python 3.12 is the verified path. Create a local environment and install hash-locked dependencies before running the expanded suite.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --no-cache-dir --require-hashes -r requirements.lock
python3 -m unittest discover -s tests -v
python3 -m tools.flow_validator architecture/flow-register.json
python3 -m tools.dependency_analyzer examples/dependencies.json --disconnect
```

Follow the [isolated-lab preparation and execution steps](docs/isolated-lab.md) for measured network isolation. The three logical site fixtures share one disposable container.

## Design and evidence

Sovereignty requirements concern data, operators, keys, suppliers, disclosure, placement and recovery. Connectivity is a separate decision. Each claim should identify its accountable owner, enforcement point, observed evidence and remaining uncertainty.

The reference demonstrates scoped local authorization, signed synthetic release admission, staged updates, filtering, audit checkpoints and clean software-key/config/data restoration. Identity/signing/replay state is ephemeral. Physical transfer enforcement, durable authority/freshness, provider placement, production TLS/MFA and real-model integration remain deployment work. Provider comparisons are documentation-only.

[Architecture decisions](docs/architecture-decisions.md) · [Acceptance gates](docs/acceptance-gates.md) · [Capacity model](tools/capacity_model.py) · [Capacity tests](tests/test_capacity_model.py)

The capacity model uses decimal GB/TB and explicit assumptions. Arithmetic tests do not establish throughput, resilience, legal applicability or sovereignty. This repository asserts no classified access, customer deployment, official government role or national accreditation.

## Connected work

[Sovereign landing zone](https://github.com/cybersmeashish/sovereign-landing-zone) · [Sovereign AI & Security](https://github.com/cybersmeashish/sovereign-AI) · [Government](https://github.com/cybersmeashish/government-security) · [BFSI](https://github.com/cybersmeashish/bfsi-security) · [Oil & Gas](https://github.com/cybersmeashish/oil-gas-security)

[Research portfolio](https://github.com/cybersmeashish) · [Contribute](CONTRIBUTING.md)
