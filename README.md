# Sovereign & Disconnected Cloud Security

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

[Completion and evidence map](docs/contributions-01-07.md) · [Observed verification](docs/verification.md) · [Primary sources](docs/references.md) · [Future contribution map](ROADMAP.md)

## Reproduce

Python 3.10+ for host-side reference tools; the observed container is pinned to the official Python 3.12 image digest.

```bash
python3 -m unittest discover -s tests -v
python3 -m tools.flow_validator architecture/flow-register.json
python3 -m tools.dependency_analyzer examples/dependencies.json --disconnect
```

Follow the [isolated-lab preparation and execution steps](docs/isolated-lab.md) for measured network isolation. The three logical site fixtures share one disposable container.

## Design and evidence

Sovereignty requirements concern data, operators, keys, suppliers, disclosure, placement and recovery. Connectivity is a separate decision. Each claim should identify its accountable owner, enforcement point, observed evidence and remaining uncertainty.

The new reference code demonstrates local synthetic authorization and contract/dependency checks. Identity state and audit events are ephemeral; the loopback demonstration has no production TLS, MFA or durable time/state protection. Declared transfers, signatures, platform placement and recovery gates remain design work.

[Architecture decisions](docs/architecture-decisions.md) · [Acceptance gates](docs/acceptance-gates.md) · [Capacity model](tools/capacity_model.py) · [Capacity tests](tests/test_capacity_model.py)

The capacity model uses decimal GB/TB and explicit assumptions. Arithmetic tests do not establish throughput, resilience, legal applicability or sovereignty. This repository asserts no classified access, customer deployment, official government role or national accreditation.

## Connected work

[Sovereign landing zone](https://github.com/cybersmeashish/sovereign-landing-zone) · [Sovereign AI & Security](https://github.com/cybersmeashish/sovereign-AI) · [Government](https://github.com/cybersmeashish/government-security) · [BFSI](https://github.com/cybersmeashish/bfsi-security) · [Oil & Gas](https://github.com/cybersmeashish/oil-gas-security)

[Research portfolio](https://github.com/cybersmeashish) · [Contribute](CONTRIBUTING.md)
