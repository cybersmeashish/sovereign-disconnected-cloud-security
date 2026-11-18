# 17 — Audit integrity and time uncertainty

[Audit mechanism](../assurance/audit.py) chains canonical records and verifies an independently trusted signed checkpoint containing count and head. Altered, reordered, truncated and wholly rehashed records fail against that checkpoint. A hash chain without a retained trusted checkpoint can be rewritten.

Time intervals expose uncertainty explicitly. Overlapping intervals yield `indeterminate`; they do not invent a total event ordering. Tests reject negative uncertainty. Checkpoint custody, secure clocks, durable append-only storage and protection against replacement of the trusted checkpoint are outside the current lab. The reference proves consistency against the supplied checkpoint and local signing root.

[Completion and measured evidence](contributions-08-28.md) · [Expanded verification](expanded-verification.md) · [Primary references](expanded-references.md)
