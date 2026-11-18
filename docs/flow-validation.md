# 05 — Flow-register validator

The canonical executable register is [flow-register.json](../architecture/flow-register.json). The earlier YAML file retains the original planning catalogue.

```bash
python3 -m tools.flow_validator architecture/flow-register.json
```

Valid input prints `{"valid": true, "issues": []}` and exits zero. Contract problems produce issue code, path and explanation, then exit one. Unreadable or invalid JSON is a command-input error.

Eight synthetic flows cover Government local telemetry and physical update admission; BFSI connected query, reviewed results and local records; and Oil & Gas one-way reporting, local recovery and separate physical update imports.

The checker rejects missing owners/destinations/authorization/integrity/retention/failure behavior, duplicate flow IDs, unknown sites, malformed values, negative retention, external network paths for strict-gap models, inbound network paths for one-way export, unconditional intermittent external paths, non-distinct approval roles, missing disclosure review, and import stages that bypass prior quarantine.

Approval-role names and review requirements are declared contracts. The tool does not authenticate approvers, admit packages, scan destinations, install firewall rules, or establish a physical air gap. The identity lab separately demonstrates authenticated emergency approvals.

[Regression cases](../tests/test_flows.py) · [Connectivity patterns](../architecture/connectivity-patterns.md)
