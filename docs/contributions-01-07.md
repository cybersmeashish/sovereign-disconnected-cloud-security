# Contributions 01–07 — delivered reference work

18 November 2026 · Ashish Srivastava

| # | Delivered contribution | Artifact | Evidence stage |
| --- | --- | --- | --- |
| 01 | Sovereignty boundary register | [Template and three industry records](contribution-01-sovereignty-boundaries.md) | Original reference decisions |
| 02 | Four connectivity architecture patterns | [Diagrams, permitted paths and assumptions](../architecture/connectivity-patterns.md) | Reference design |
| 03 | Threat model | [Assets, boundaries, threats, attack tree and gaps](threat-model.md) | Design linked to actual reference tests |
| 04 | External dependency inventory | [Graph analyzer and outage/counterexample registries](dependency-inventory.md) | Tested declared model |
| 05 | Flow-register validator | [Eight contracts and negative cases](flow-validation.md) | Tested contract validation |
| 06 | Reproducible isolated-site lab | [Pinned runtime and actual isolation checks](isolated-lab.md) | Observed Linux container run |
| 07 | Offline identity and authorization | [Expiry, revocation, site/tenant scope, service identities and emergency approvals](offline-identity.md) | Tested in-memory reference and loopback HTTP |

**Result:** 56 unique regression tests passed on the host and in the isolated container. All 30 integration/scenario checks passed. Source inputs were matched against the image. The environment retained local login and permitted actions while an external connection was unavailable.

[Recorded evidence and commands](verification.md) · [Primary sources](references.md) · [Next contributions](../ROADMAP.md)

The Government, BFSI and Oil & Gas cases are synthetic logical fixtures in one container. Completion refers to these inspectable reference contributions; operational deployment, durable identity, signed update admission, physical air-gap assurance, regulatory applicability and organizational adoption remain separate work.

**Leadership decision:** require each workload to identify local action authority and the dependencies that must survive disconnection. Treat missing central evidence as an information gap, and fund environment-specific verification of the unresolved dependencies before operational acceptance.

**Next research question:** which current claims survive when ephemeral fixtures are replaced with the selected identity, package, trust, evidence and recovery services?
