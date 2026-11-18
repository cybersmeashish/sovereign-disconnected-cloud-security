# Key custody and recovery register

| Field | Deployment decision and evidence |
| --- | --- |
| Key purpose and scope | Establishment/signature/data protection; site, tenant, asset |
| Accountable owner | Named authorized operator; evidence of appointment |
| Custody implementation | Software or HSM/provider; distinguish simulation |
| Creation and version | Trusted ceremony, algorithm, validity, current version |
| Rotation | Trigger, security approval, operations approval, old-key retention |
| Backup wrapping | Separate wrapping material, storage, approved access |
| Recovery | Clean target, exact backup, independent approvals, validation |
| Revocation | Affected roots, sessions, artifacts and rollback handling |
| Durable freshness | Anti-rollback anchor and accepted-release/approval state |
| Lost material | Stop criterion, escalation and irrecoverability decision |

The reference uses software AES-GCM keys and Ed25519 approval signatures; no hardware ceremony or threshold custody was performed.
