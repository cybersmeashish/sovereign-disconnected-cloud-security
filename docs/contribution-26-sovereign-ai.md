# 26 — Sovereign AI integration case

[Local AI fixture](../assurance/policy.py) consumes admitted model-data, resolves retrieval access through the existing local authority and permits only explicitly mapped tools. Tests allow scoped reads and deny cross-site/cross-tenant reads, shell execution and viewer write actions. A hostile prompt grants no additional tool permission.

The fixture is a deterministic router with **no learned model or downloaded weights**; this establishes authorization boundaries, not prompt-injection detection accuracy. Local model/runtime dependencies, signed model updates, retrieval scope, permitted tool actions and filtered evidence export are documented in the [integration contract](sovereign-ai-integration.md), linked to the Sovereign AI repository.

[Completion and measured evidence](contributions-08-28.md) · [Expanded verification](expanded-verification.md) · [Primary references](expanded-references.md)
