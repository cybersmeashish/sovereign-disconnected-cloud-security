# 13 — Workload and tenant isolation

[Endpoint policy](../assurance/policy.py) defaults to denial, pins site/tenant/traffic-plane context and admits only named service or management bindings. Tests deny cross-tenant, cross-site and workload-to-management access. Existing [local identity](offline-identity.md) resolves resource scope from the trusted store rather than caller-provided tenant claims.

[Kubernetes NetworkPolicy example](../examples/tenant-network-policy.yaml) shows a default-deny namespace plus explicit API-to-records ingress and egress. It is a design example; no Kubernetes cluster or packet enforcement was deployed. Management, workload and evidence planes require independent environment verification. The Python endpoint model evaluates declared trusted identities rather than authenticating packets.

[Completion and measured evidence](contributions-08-28.md) · [Expanded verification](expanded-verification.md) · [Primary references](expanded-references.md)
