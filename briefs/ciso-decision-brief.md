# Decision brief — fund durable local authority before deployment acceptance

**Decision:** require a named local authority owner, protected freshness/replay state, independently controlled recovery material and verified local dependency completeness before accepting an operational disconnected workload.

**Operational consequence:** central disconnection can preserve legitimate local action while degrading enterprise visibility. Missing central evidence cannot justify broader local privileges. Conversely, valid package signatures alone cannot show that a release is fresh after local state is lost.

**Measured reference evidence:** 102 regression cases passed in host/container execution, 78 scenario expectations matched, and six maintained-implementation PQ/interop checks passed. The network namespace had only loopback; denied cross-scope access, signed import rejection and clean software-key/config/data restoration were exercised. Actual storage exhaustion produced `ENOSPC` on a disposable 64 KiB tmpfs.

**Unsafe findings:** restarting the in-memory admission gate loses replay history; an unknown event type has no detector; signed or matching location claims do not independently establish placement. Retention loss and delayed central reports require explicit decision treatment.

**Uncertainty:** synthetic sites share one container. Key custody and approvals are software fixtures. AI is deterministic routing. Small tmpfs timings establish fixture observations, not whole-site RTO/RPO, vendor capacity, physical air-gap assurance or compliance.

**Next investment:** select the real local identity/time/package/key/recovery services; appoint owners; protect durable anti-rollback/checkpoint state; verify deployment/backup/recovery placement; then repeat negative and recovery tests in an authorized representative environment. Establish stop criteria when local authority or required dependencies cannot be validated.

**Industry application:** Government retains bounded service-review authority; BFSI preserves transaction-review/customer boundaries; Oil & Gas separates alert/maintenance review from equipment-control authority.

[Methods and original results](../research/2026-11-18-results.md) · [Evidence map](../docs/contributions-08-28.md)
