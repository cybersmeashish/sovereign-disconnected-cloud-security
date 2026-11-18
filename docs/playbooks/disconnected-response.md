# Disconnected response exercises

| Trigger | Local owner | Action and evidence | Stop criterion | Reference scope |
| --- | --- | --- | --- | --- |
| Compromised account | Appointed identity owner | Revoke local identity; retry old session; retain denial | Any old session remains usable | Actual synthetic revocation exercise |
| Suspicious import | Security + release operator | Keep quarantine; verify signer/digest/provenance; retain rejection | Unknown signer, altered artifact or insufficient approval | Actual signed-package exercise |
| Identity dependency unavailable | Local service owner | Deny actions dependent on unavailable local IdP; inspect fault matrix | No validated authority path | Declared dependency exercise; no IdP crash |
| Local time unusable | Identity owner | Fail authorization closed; preserve clock fault and review emergency procedure | Time cannot be trusted | Actual injected non-finite clock |
| Central connection lost | Local incident commander | Continue only scoped local authority; mark central reports stale/missing | Required dependency or local authority unavailable | Actual network-disabled container |

Do not broaden local privileges to restore central visibility. Roles are synthetic exercise assignments. Manual operational authority, legal triggers and customer escalation contacts require environment-specific approval.
