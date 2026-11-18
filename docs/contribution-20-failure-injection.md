# 20 — Failure-injection experiments

[Expanded experiment](../assurance/run.py) fills only a verified disposable tmpfs of at most 128 KiB and requires actual `ENOSPC`; it never fills a host disk. It also injects an unavailable resolver, non-finite authorization clock and update interruption, evaluates an expired signed certificate, and observes telemetry retention loss.

The [dependency fault matrix](../evidence/2026-11-18/dependency-fault-matrix.json) records declared effects of every unavailable dependency. Report categories distinguish actual resource faults, injected adapters, modeled dependencies and unsafe gaps. Certificate testing validates lifecycle timing, not a TLS handshake/CA chain. Restarted replay state and missing detection rules are recorded as unsafe observations rather than successful security controls.

[Completion and measured evidence](contributions-08-28.md) · [Expanded verification](expanded-verification.md) · [Primary references](expanded-references.md)
