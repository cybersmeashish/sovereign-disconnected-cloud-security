# 07 — Offline identity and authorization reference

The [authority](../lab/identity.py) operates without an external IdP. Resources are registered in a trusted local store. A request identifies a record; supplied tenant claims cannot change its site or tenant.

| Role | Permitted reference actions |
| --- | --- |
| Viewer | Read own-scope synthetic records |
| Analyst | Read own-scope records and acknowledge synthetic alerts |
| Service reader | Read own-scope records |
| Identity administrator | Revoke local identities/roles and delegate unprivileged roles to another principal |
| Emergency approver | Approve a resource-scoped emergency request |

The trusted bootstrap sets the privileged administrator/approver roles. The delegation API cannot grant those privileged roles or grant a role to the acting administrator itself.

Login uses salted PBKDF2-HMAC-SHA256 with 600,000 iterations and opaque random session credentials. Ordinary sessions last at most 900 seconds; delegated roles last at most 3,600 seconds. Role grants are evaluated on every action. Local user revocation invalidates sessions immediately. The lab's public fixture passphrase is `synthetic-only-passphrase`; it is intentionally unsuitable as a real credential.

Emergency access requires a valid human requester and two distinct authenticated, active human approvers in the same site/tenant. Self-approval, duplicated or fabricated approval, and wrong-scope approval are denied. The grant is bound to one resource, limited to read/acknowledge actions, lasts at most 300 seconds, and cannot administer identities. Revoked/expired approver authority invalidates the emergency action.

Clock rollback, invalid time or unavailable time fails closed. The observed clock floor is in memory and does not protect against restart, host compromise or malicious time manipulation. Expiry tests use a controlled synthetic clock; the report's generation timestamp is separately recorded.

The HTTP service binds only to loopback, accepts bounded JSON login bodies, rejects extra identity claims, and exposes no administration endpoint. Responses do not log passwords or bearer tokens. Synthetic audit events contain action outcomes, not a durable or tamper-proof audit trail.

**Limitations:** no production TLS, MFA, lockout/rate controls, persistent identity state, federation, trusted time, certificates, password reset workflow, HSM or accreditation. PBKDF2 parameter choice and this reference protocol do not constitute a reviewed production identity design.

[Identity regression tests](../tests/test_identity.py) · [HTTP regression tests](../tests/test_service.py) · [Threat model](threat-model.md) · [Primary sources](references.md)
