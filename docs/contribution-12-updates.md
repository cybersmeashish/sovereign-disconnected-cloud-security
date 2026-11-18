# 12 — Controlled updates and rollback

[Update store](../assurance/updates.py) stages data, verifies the staged digest and changes an active-version pointer with `os.replace`. Injected pre-activation interruption preserves v1. A completed v2 deployment can return to the previously recorded v1 only after independently signed security/operations rollback approvals bound to the exact digest.

[Regression tests](../tests/test_assurance_crypto.py) exercise corruption, interruption and missing rollback approval. Admission's normal downgrade gate remains separate from authorized recovery. This is a disposable filesystem reference: no executable deployment, power-loss test, transactional multi-service rollout, durable anti-rollback counter or authenticated long-term release journal was established.

[Completion and measured evidence](contributions-08-28.md) · [Expanded verification](expanded-verification.md) · [Primary references](expanded-references.md)
