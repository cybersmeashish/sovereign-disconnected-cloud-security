"""Read-only analysis of a declared dependency graph, not host discovery."""
import argparse
import json
from pathlib import Path


def _named_items(value, name):
    if not isinstance(value, list) or not value:
        raise ValueError(f"{name} must be a nonempty list")
    items = {}
    for item in value:
        if not isinstance(item, dict):
            raise ValueError(f"{name} entries must be objects")
        key = item.get("id")
        if not isinstance(key, str) or not key.strip() or key in items:
            raise ValueError(f"{name} IDs must be nonempty and unique")
        if not isinstance(item.get("owner"), str) or not item["owner"].strip():
            raise ValueError(f"{key}: owner required")
        links = item.get("depends_on")
        if (not isinstance(links, list)
                or any(not isinstance(link, str) or not link.strip() for link in links)
                or len(set(links)) != len(links)):
            raise ValueError(f"{key}: depends_on must contain unique dependency IDs")
        items[key] = item
    return items


def analyze(registry, disconnected=False, failed=()):
    if not isinstance(registry, dict):
        raise ValueError("registry must be an object")
    if type(registry.get("schema_version")) is not int or registry["schema_version"] != 1:
        raise ValueError("schema_version must be 1")
    dependencies = _named_items(registry.get("dependencies"), "dependencies")
    capabilities = _named_items(registry.get("capabilities"), "capabilities")
    if dependencies.keys() & capabilities.keys():
        raise ValueError("dependency and capability IDs must be distinct")
    for key, item in dependencies.items():
        if not isinstance(item.get("location"), str) or item["location"] not in {"local", "external"}:
            raise ValueError(f"{key}: location must be local or external")
        if type(item.get("available")) is not bool:
            raise ValueError(f"{key}: available must be boolean")
    for key, item in {**dependencies, **capabilities}.items():
        missing = set(item["depends_on"]) - dependencies.keys()
        if missing:
            raise ValueError(f"{key}: unknown dependencies: {sorted(missing)}")
    failed = set(failed)
    if failed - dependencies.keys():
        raise ValueError(f"unknown failed dependencies: {sorted(failed - dependencies.keys())}")
    visiting, checked = set(), set()

    def check_cycle(key):
        if key in visiting:
            raise ValueError(f"dependency cycle at {key}")
        if key in checked:
            return
        visiting.add(key)
        for child in dependencies[key]["depends_on"]:
            check_cycle(child)
        visiting.remove(key)
        checked.add(key)

    for key in dependencies:
        check_cycle(key)
    memo = {}

    def blockers(key):
        if key not in memo:
            item = dependencies[key]
            blocked = set()
            if key in failed or not item["available"] or (
                disconnected and item["location"] == "external"
            ):
                blocked.add(key)
            for child in item["depends_on"]:
                blocked.update(blockers(child))
            memo[key] = blocked
        return memo[key]

    return {
        "schema_version": 1,
        "stage": "declared dependency model; no environment discovery or availability probe",
        "disconnected": bool(disconnected),
        "failed_dependencies": sorted(failed),
        "capabilities": [
            {
                "id": key, "owner": item["owner"],
                "available": not blocked,
                "blocked_by": sorted(blocked),
            }
            for key, item in capabilities.items()
            for blocked in [set().union(*(blockers(child) for child in item["depends_on"]))]
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("registry", type=Path)
    parser.add_argument("--disconnect", action="store_true")
    parser.add_argument("--fail", action="append", default=[])
    args = parser.parse_args()
    try:
        result = analyze(json.loads(args.registry.read_text()), args.disconnect, args.fail)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
