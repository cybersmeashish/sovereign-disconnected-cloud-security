# 15 — Visibility freshness model

[Freshness functions](../assurance/observability.py) distinguish current (up to sixty seconds), delayed (up to fifteen minutes), missing and unverified evidence. Future timestamps and unsigned or unverified-clock records are unverified. A central conclusion requires every declared site to be current.

The experiment holds report content constant and advances evaluation time from 100 to 161: the all-sites-current conclusion becomes false. These are synthetic timestamps and caller-supplied verification flags. The production collector must perform signature/time verification itself; the flags are not remote attestations. [Research results](../research/2026-11-18-results.md) explain the decision consequence.

[Completion and measured evidence](contributions-08-28.md) · [Expanded verification](expanded-verification.md) · [Primary references](expanded-references.md)
