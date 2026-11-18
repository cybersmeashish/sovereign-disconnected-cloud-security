"""Exact-version offline advisory query snapshots with explicit age/coverage."""
import math
from .crypto import Rejected


def review(sbom, snapshot, now, maximum_age=7 * 86400):
    collected = snapshot.get("collected_at_epoch")
    if (isinstance(collected, bool) or not isinstance(collected, (float, int))
            or not math.isfinite(collected) or not math.isfinite(now)):
        raise Rejected("snapshot time unavailable")
    age = now - collected
    freshness = "unverified" if age < 0 else "stale" if age > maximum_age else "current"
    queries = {(q["name"], q["version"]): q for q in snapshot["queries"]}
    findings = []
    for component in sbom["components"]:
        query = queries.get((component["name"], component["version"]))
        if query is None or query.get("query_succeeded") is not True:
            status, identifiers = "unreviewed", []
        else:
            identifiers = query["advisory_ids"]
            status = "known-finding" if identifiers else "no-match-in-query-snapshot"
        findings.append({"name": component["name"], "version": component["version"],
                         "status": status, "advisory_ids": identifiers})
    return {"snapshot_age_seconds": age, "freshness": freshness, "findings": findings,
            "scope": "Exact-version catalog queries; no absence-of-vulnerability conclusion."}


def placement(declarations, observations):
    results = []
    for item in declarations:
        observation = observations.get(item["component"])
        if observation is None:
            status = "declared-only"
        elif observation.get("region") != item["region"]:
            status = "conflict"
        else:
            status = "matching-claim-needs-independent-placement-evidence"
        results.append({"component": item["component"], "declared_region": item["region"],
                        "status": status})
    return results
