# 09 — Offline package admission

[Admission gate](../assurance/admission.py) quarantines each attempt, validates the signed manifest and payload digest, checks destination/site/architecture/builder expectations, requires two distinct approval duties, and rejects replay and normal version downgrade.

```bash
python -m tools.admit_fixture examples/packages/valid.json --trust examples/packages/trust-policy.json
python -m tools.admit_fixture examples/packages/altered-artifact.json --trust examples/packages/trust-policy.json
```

The first admits; the second exits one. [Package fixtures](../examples/packages/) include six negative cases. The trusted policy must be installed separately from an import. These packages contain synthetic data and are never executed. Quarantine/replay state is in memory; the expanded experiment records the unsafe acceptance possible after restarting that state.

[Completion and measured evidence](contributions-08-28.md) · [Expanded verification](expanded-verification.md) · [Primary references](expanded-references.md)
