# Sovereignty and disconnected operation: decision record

Sovereignty requirements concern authority, data, operators, suppliers, keys, and recovery. Connectivity is a separate design choice. For each workload, record the requirement, accountable owner, enforcement point, permitted exception, and evidence gate.

| Boundary | Required design decision | Proposed evidence |
| --- | --- | --- |
| Data and disclosure | What remains local, and what derived information may leave? | Synthetic field-level export and query-result tests |
| Operator authority | Who may administer, approve, investigate, and restore? | Locally enforced roles and separation-of-duty cases |
| Identity and keys | Which authentication, revocation, issuance, custody, and recovery services remain local? | Outage and key-recovery exercises |
| Runtime and recovery | Which dependencies are required after external services disappear? | Complete dependency register and isolated rebuild test |
| Transfers | Which approved mechanism moves updates or reports? | Custody record, provenance, integrity, destination and compatibility results |
| Enterprise visibility | What can the hub conclude from delayed or missing information? | Reporting freshness, loss, and overdue-report scenarios |

A strict air gap has no external network path. A one-way connection has an explicit direction; it cannot supply the opposite-direction update path. Record the actual boundary model and test it with the responsible operators.

Local containment authority must remain distinct from query access. A centrally published rule catalog becomes an implemented control only after local compatibility, deployment, and operational evidence exist.

The design asks for signature validation with approved local trust material. No signature verifier or automatic release-promotion service is implemented in this public lab.

[Landing-zone decisions](https://github.com/cybersmeashish/sovereign-landing-zone) · [Industry adaptation](https://github.com/cybersmeashish/cybersmeashish/blob/main/docs/industries.md)
