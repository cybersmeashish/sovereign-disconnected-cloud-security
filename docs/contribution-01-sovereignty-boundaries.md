# 01 — Sovereignty boundary register

**Delivered:** a reusable [boundary template](../templates/sovereignty-boundary.md) and three machine-readable synthetic records.

| Scenario | Boundary record | Process |
| --- | --- | --- |
| Government | [government.json](../examples/boundaries/government.json) | Local citizen-service status review |
| BFSI | [bfsi.json](../examples/boundaries/bfsi.json) | Financial transaction-review status |
| Oil & Gas | [oil-gas.json](../examples/boundaries/oil-gas.json) | Remote maintenance review |

Each record identifies process, security, platform, identity, key, disclosure and recovery owners; workload/evidence/recovery placement; operator and supplier assumptions; permitted flows; exceptions; implemented reference evidence; and planned work.

**Decision:** a workload placement statement needs separate operator, key, supplier, disclosure and recovery decisions. The local lab tests scoped action authority. Provider placement, key custody, legal applicability and organizational acceptance remain separate evaluations.

**Open question:** which actual product or supplier dependencies would invalidate the local-autonomy assumptions?
