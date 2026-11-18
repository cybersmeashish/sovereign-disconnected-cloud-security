# 10 — Signature and provenance verification

[Verifier](../assurance/crypto.py) uses maintained Ed25519 primitives and pinned public keys. [Admission](../assurance/admission.py) checks signed provenance subject digest, expected builder ID, build type and the exact external-parameter map. Tests reject altered bytes, unexpected signers, signed-but-wrong builder claims and mismatched subjects.

[SLSA v1.0 verification baseline](https://slsa.dev/spec/v1.0/verifying-artifacts) informs the checks. This is a custom signed manifest containing an in-toto-shaped statement, **not DSSE or an independently issued SLSA-level attestation**. A publisher signature authenticates that publisher's statement; it cannot independently establish that the builder behaved correctly. Root distribution, signer revocation and durable approval freshness remain deployment work.

[Completion and measured evidence](contributions-08-28.md) · [Expanded verification](expanded-verification.md) · [Primary references](expanded-references.md)
