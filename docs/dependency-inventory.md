# 04 — External dependency inventory and failure analysis

[Analyzer](../tools/dependency_analyzer.py) · [Local-first registry](../examples/dependencies.json) · [External-only counterexamples](../examples/dependencies-external-only.json)

The tool reads declared JSON dependencies and owners, rejects cycles and unknown references, and computes transitive blockers for each capability. It performs no host discovery, network probe or product availability measurement.

```bash
python3 -m tools.dependency_analyzer examples/dependencies.json
python3 -m tools.dependency_analyzer examples/dependencies.json --disconnect
python3 -m tools.dependency_analyzer examples/dependencies.json --disconnect --fail local-time
python3 -m tools.dependency_analyzer examples/dependencies.json --disconnect --fail local-package-cache
python3 -m tools.dependency_analyzer examples/dependencies-external-only.json --disconnect
```

| Declared interruption | Expected model outcome |
| --- | --- |
| External connectivity removed | Local login, read, monitoring, rebuild and named-service capabilities remain available; enterprise visibility becomes unavailable |
| Local time unavailable | Local identity, read and monitoring capabilities become unavailable |
| Local package cache unavailable | Local rebuild becomes unavailable; existing local read capability remains available |
| External-only identity, registry or license service | The corresponding capability becomes unavailable during disconnection |

For an actual environment, review identity renewal/revocation, DNS, time, certificate issuance/status, container/package registries, signatures and trust material, entitlement/licensing, monitoring, support access, backup and recovery. Record the exact implementation, owner, outage behavior, tested alternative and evidence freshness. The model's synthetic local-DNS and rebuild entries are not running DNS or registry services in the lab.

**Decision:** a regional placement decision alone does not settle dependencies. AWS's documented Outposts regional-disconnection considerations provide a product-specific example to examine; this repository does not test Outposts.

[Primary sources](references.md) · [Observed lab results](verification.md)
