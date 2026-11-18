# Government — synthetic disconnected authority case

**Decision:** retain scoped local public-service review during central disconnection, with a locally appointed decision owner and evidence of two independent review approvals.

**Boundary:** site `government`, tenant A records, explicit review actions, approved package inputs and filtered evidence recipients. Tenant B and other sites are denied. Imports remain quarantined until signer/digest/builder/compatibility/approval checks pass.

**Observed reference:** scoped local reads and review acknowledgment succeed; cross-site/cross-tenant access is denied. Key recovery, signed updates, evidence filtering and clean restoration use the shared bounded lab. A central reporting gap must not silently grant new local decision authority.

**Local ownership:** service/identity owner for authority; security and operations for imports/recovery; appointed recipient owner for disclosures. These are synthetic roles, not claimed appointments in a customer organization.

**Open acceptance questions:** which local identity/time/package/key services actually remain available, who appoints emergency approvers, where backups and recovery run, and which disclosure/sector obligations apply? The shared fixture has ephemeral identities, replay state and software custody.

No real public-service determination, customer transaction or industrial command was performed. Shared lab benchmarks cannot establish sector throughput or whole-site recovery performance.

[Industry workspace](https://github.com/cybersmeashish/government-security) · [Actual shared results](../../research/2026-11-18-results.md) · [Contribution 27](../contribution-27-industry-cases.md)
