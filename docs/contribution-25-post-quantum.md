# 25 — Post-quantum transition inventory

[Transition inventory](../research/post-quantum-inventory.csv) distinguishes key establishment, artifact/approval signatures, identities, audit checkpoints and backup encryption. [Compatibility tool](../tools/pq_compatibility.py) ran actual OpenSSL ML-KEM-768 establishment, ML-DSA-65 signing, altered-input/wrong-key checks and cross-implementation Ed25519 verification.

[NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) cover distinct purposes. The host report records six passed checks and the observed OpenSSL version. ML-KEM tampering may produce implicit rejection with a different secret; a successful decapsulation exit status alone is insufficient validation. This is no hybrid TLS, certificate migration, SLH-DSA test, production transition or FIPS-module validation.

[Completion and measured evidence](contributions-08-28.md) · [Expanded verification](expanded-verification.md) · [Primary references](expanded-references.md)
