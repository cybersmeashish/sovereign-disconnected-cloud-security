# 02 — Connectivity architecture patterns

These four diagrams are reference designs. Sovereignty boundaries and network connectivity are separate decisions. The runnable lab verifies a container with no external network interface; it does not deploy these four architectures.

## Connected Sovereign

```mermaid
flowchart LR
  H[Enterprise hub] --> Q[Approved local query endpoint]
  Q --> A[Local authorization]
  A --> W[Local workload]
  W --> R[Reviewed result disclosure]
  R --> H
  K[Local identity and key custody] --> A
  W --> E[Local evidence and recovery]
```

## Intermittent

```mermaid
flowchart LR
  H[Enterprise hub] -. Connected window only .-> G[Local boundary gate]
  G --> A[Local identity and authorization]
  A --> W[Local workload]
  W --> B[Local evidence buffer]
  B -. Approved reconnection disclosure .-> H
  W --> R[Local response and recovery]
```

## Strict Air Gap

```mermaid
flowchart LR
  X[External preparation] --> M[Approved physical transfer]
  M --> Q[Local quarantine and review]
  Q --> P[Local package repository]
  P --> W[Local workload]
  I[Local identity and time] --> W
  W --> E[Local evidence and recovery]
  E --> D[Separate approved physical disclosure]
```

## One Way Export

```mermaid
flowchart LR
  W[Local workload] --> F[Disclosure review and filtering]
  F --> O[One-way export boundary]
  O --> H[Enterprise intake]
  X[External updates] --> M[Separate approved physical transfer]
  M --> Q[Local quarantine and admission]
  Q --> W
  I[Local identity and operational authority] --> W
```

| Pattern | Permitted network direction | Updates and evidence | Interruption behavior |
| --- | --- | --- | --- |
| Connected sovereign | Explicitly authorized ingress and egress | Locally reviewed, registered paths | Specify dependency and disclosure failure behavior |
| Intermittent | External paths only while connected | Local buffering and reviewed reconnection | Preserve declared local actions; mark central evidence unavailable or stale |
| Strict air gap | Local network only; no external network path | Separately approved physical transfers | Local identity, time, packages, evidence and response are required design decisions |
| One-way export | Local-to-external network direction only | Updates require a separate permitted mechanism | Export failure must not grant an opposite-direction path |

**Assumptions:** operator eligibility, trust material, local time, package completeness, supplier support, transfer custody and recovery still need environment-specific evidence. One-way arrows are not proof of a deployed data diode. Import quarantine and release-signature verification are future implementation work.

[Flow contracts](flow-register.json) · [Threat model](../docs/threat-model.md) · [Isolation evidence](../docs/verification.md)
