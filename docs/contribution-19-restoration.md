# 19 — Backup and restoration evidence

[Encrypted snapshot/restore](../assurance/recovery.py) transfers configuration, synthetic records and an encrypted software-key backup into an empty directory. The experiment restores and verifies keys and old ciphertext in five independent clean directories. Wrong wrapping material, corruption and nonempty destinations are denied.

The backup captures three records; one subsequent record is intentionally absent after recovery. The report publishes actual restoration durations, one-record fixture loss and remaining wrapping-key/approval-root/runtime/storage dependencies. These are bounded config/data/key-fixture observations, not whole-site RTO/RPO or production recovery assurance. Identity database recovery, isolated recovery infrastructure and durable key custodians remain explicit gaps.

[Completion and measured evidence](contributions-08-28.md) · [Expanded verification](expanded-verification.md) · [Primary references](expanded-references.md)
