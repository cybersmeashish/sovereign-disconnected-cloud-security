"""Validate declared flow contracts; does not configure network enforcement."""
import argparse
import json
from pathlib import Path

MODELS = {"connected_sovereign", "intermittent", "strict_air_gap", "one_way_export"}
DIRECTIONS = {"local", "inbound", "outbound"}
KINDS = {"network", "removable_media"}
REQUIRED_TEXT = (
    "id", "site_id", "name", "source", "destination", "owner",
    "classification", "authorization", "integrity",
)


def validate(register):
    """Return stable, inspectable issue records, including malformed inputs."""
    issues = []

    def issue(code, path, message):
        issues.append({"code": code, "path": path, "message": message})

    if not isinstance(register, dict):
        issue("root_type", "$", "Register must be an object.")
        return issues
    if type(register.get("schema_version")) is not int or register["schema_version"] != 1:
        issue("schema_version", "schema_version", "Expected schema_version 1.")
    sites = register.get("sites")
    if not isinstance(sites, dict) or not sites:
        issue("sites", "sites", "Declare at least one site and boundary model.")
        sites = {}
    for site_id, site in sites.items():
        if not isinstance(site_id, str) or not site_id.strip() or not isinstance(site, dict):
            issue("site_type", f"sites.{site_id}", "Site ID and record are required.")
        elif not isinstance(site.get("boundary_model"), str) or site["boundary_model"] not in MODELS:
            issue("boundary_model", f"sites.{site_id}.boundary_model", "Unknown boundary model.")
    flows = register.get("flows")
    if not isinstance(flows, list) or not flows:
        issue("flows", "flows", "Declare a nonempty flow list.")
        return issues
    seen = set()
    for index, flow in enumerate(flows):
        path = f"flows[{index}]"
        if not isinstance(flow, dict):
            issue("flow_type", path, "Flow must be an object.")
            continue
        for field in REQUIRED_TEXT:
            value = flow.get(field)
            if not isinstance(value, str) or not value.strip():
                issue("required_field", f"{path}.{field}", "Nonempty string required.")
        flow_id = flow.get("id")
        if isinstance(flow_id, str):
            if flow_id in seen:
                issue("duplicate_id", f"{path}.id", "Flow IDs must be unique.")
            seen.add(flow_id)
        site_id = flow.get("site_id")
        site = sites.get(site_id) if isinstance(site_id, str) else None
        if not isinstance(site, dict):
            issue("unknown_site", f"{path}.site_id", "Flow must reference a declared site.")
            model = None
        else:
            model = site.get("boundary_model")
        direction, kind = flow.get("direction"), flow.get("kind")
        if not isinstance(direction, str) or direction not in DIRECTIONS:
            issue("direction", f"{path}.direction", "Use local, inbound, or outbound.")
        if not isinstance(kind, str) or kind not in KINDS:
            issue("kind", f"{path}.kind", "Use network or removable_media.")
        if (not isinstance(flow.get("failure_behavior"), str)
                or flow["failure_behavior"] not in {"deny", "queue_locally", "stop_and_review"}):
            issue("failure_behavior", f"{path}.failure_behavior", "Explicit safe failure behavior required.")
        retention = flow.get("retention")
        if not isinstance(retention, dict):
            issue("retention", f"{path}.retention", "Retention record required.")
        else:
            days = retention.get("days")
            if type(days) is not int or days < 0:
                issue("retention_days", f"{path}.retention.days", "Nonnegative integer days required.")
            for field in ("owner", "reason"):
                if not isinstance(retention.get(field), str) or not retention[field].strip():
                    issue("retention_field", f"{path}.retention.{field}", "Owner and rationale required.")
        if kind == "network":
            if model == "strict_air_gap" and isinstance(direction, str) and direction in {"inbound", "outbound"}:
                issue("air_gap_network", path, "Strict air-gap model forbids external network flows.")
            if model == "one_way_export" and direction == "inbound":
                issue("one_way_inbound", path, "One-way export model forbids inbound network flows.")
            if model == "intermittent" and isinstance(direction, str) and direction in {"inbound", "outbound"}:
                if flow.get("allowed_when") != "connected":
                    issue("connectivity_condition", f"{path}.allowed_when", "External network flow requires connected state.")
        if isinstance(direction, str) and direction in {"inbound", "outbound"}:
            roles = flow.get("approval_roles")
            if (not isinstance(roles, list) or len(roles) < 2
                    or any(not isinstance(role, str) or not role.strip() for role in roles)
                    or len(set(role for role in roles if isinstance(role, str))) != len(roles)):
                issue("approval_roles", f"{path}.approval_roles", "At least two distinct approval roles required.")
        if direction == "outbound":
            if flow.get("disclosure_review_required") is not True:
                issue("disclosure_review", path, "Outbound flows require an explicit disclosure review.")
        if kind == "removable_media" and direction == "inbound":
            stages = flow.get("stages")
            if (not isinstance(stages, list) or "quarantine" not in stages
                    or "local_repository" not in stages
                    or stages.index("quarantine") >= stages.index("local_repository")):
                issue("quarantine_order", f"{path}.stages", "Quarantine must precede local repository admission.")
            if flow.get("allowed_when") != "approved_transfer_window":
                issue("transfer_condition", f"{path}.allowed_when", "Imported media needs an approved transfer window.")
    return issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("register", type=Path)
    args = parser.parse_args()
    try:
        issues = validate(json.loads(args.register.read_text()))
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({"valid": not issues, "issues": issues}, indent=2))
    raise SystemExit(1 if issues else 0)


if __name__ == "__main__":
    main()
