"""Exercise site controls and report explicit, bounded isolation evidence."""
import argparse
from datetime import datetime, timezone
import errno
import http.client
import json
import platform
from pathlib import Path
import socket
import sys

from tools.dependency_analyzer import analyze
from tools.flow_validator import validate
from tools.source_manifest import source_manifest
from .fixtures import DEMO_PASSWORD, SITES, ScenarioClock, make_authority
from .identity import Denied
from .service import running_service

ROOT = Path(__file__).resolve().parents[1]


def isolation_probe():
    """Timeout or refusal alone is insufficient isolation evidence.

    Require Linux loopback-only interfaces, no default IPv4 route, and an
    explicit kernel 'network unreachable' result for a TEST-NET address.
    """
    interface_dir = Path("/sys/class/net")
    interfaces = sorted(path.name for path in interface_dir.iterdir()) if interface_dir.exists() else []
    route_file = Path("/proc/net/route")
    default_routes = []
    if route_file.exists():
        for line in route_file.read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 1:
                default_routes.append(fields[0])
    outcome, error_number = "unexpected_connection", None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        try:
            connection.connect(("192.0.2.1", 443))
        except OSError as error:
            error_number = error.errno
            outcome = "network_unreachable" if error.errno == errno.ENETUNREACH else type(error).__name__
    passed = (
        platform.system() == "Linux" and interfaces == ["lo"]
        and route_file.exists() and not default_routes and outcome == "network_unreachable"
    )
    return {
        "passed": passed, "interfaces": interfaces,
        "default_ipv4_routes": default_routes,
        "external_probe": {"target": "192.0.2.1:443 (documentation-only address)",
                           "outcome": outcome, "errno": error_number},
        "boundary": "container network namespace; no physical air-gap or hypervisor assurance",
    }


def request(address, method, path, payload=None, token=None):
    client = http.client.HTTPConnection(*address, timeout=3)
    try:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        client.request(method, path, json.dumps(payload) if payload is not None else None, headers)
        response = client.getresponse()
        return response.status, json.loads(response.read())
    finally:
        client.close()


def exercise():
    clock = ScenarioClock()
    authority = make_authority(clock)
    cases = []

    def record(case_id, passed, observation):
        cases.append({"id": case_id, "passed": bool(passed), "observation": observation})

    register = json.loads((ROOT / "architecture/flow-register.json").read_text())
    issues = validate(register)
    record("flow_contracts", not issues, {"issues": issues})
    dependencies = json.loads((ROOT / "examples/dependencies.json").read_text())
    disconnected = analyze(dependencies, disconnected=True)
    local = [item for item in disconnected["capabilities"] if item["id"].startswith("local-")]
    central = [item for item in disconnected["capabilities"] if item["id"].startswith("enterprise-")]
    record("declared_local_dependencies", bool(local) and all(item["available"] for item in local),
           {"available_local_capabilities": [item["id"] for item in local if item["available"]]})
    record("central_visibility_unavailable", bool(central) and all(not item["available"] for item in central),
           {"unavailable_capabilities": [item["id"] for item in central if not item["available"]]})
    failed_clock = analyze(dependencies, True, ["local-time"])
    record("clock_dependency_failure",
           not next(item for item in failed_clock["capabilities"] if item["id"] == "local-read-record")["available"],
           {"model_blocker": "local-time"})

    with running_service(authority) as address:
        for index, site in enumerate(SITES):
            viewer_id, record_id = f"{site}-viewer", f"{site}-record-a"
            status, response = request(address, "POST", "/login",
                                       {"principal_id": viewer_id, "password": DEMO_PASSWORD})
            record(f"{site}_local_login", status == 200, {"http_status": status})
            if status != 200:
                continue
            token = response["token"]
            status, _ = request(address, "GET", f"/records/{record_id}", token=token)
            record(f"{site}_read_own_scope", status == 200, {"http_status": status})
            other = SITES[(index + 1) % len(SITES)]
            status, _ = request(address, "GET", f"/records/{other}-record-a", token=token)
            record(f"{site}_cross_site_denied", status == 403, {"http_status": status})
            status, _ = request(address, "GET", f"/records/{site}-record-b", token=token)
            record(f"{site}_cross_tenant_denied", status == 403, {"http_status": status})
            status, _ = request(address, "POST", f"/alerts/{record_id}/ack", token=token)
            record(f"{site}_viewer_action_denied", status == 403, {"http_status": status})
            service_token = authority.login(f"{site}-service", DEMO_PASSWORD)
            status, _ = request(address, "GET", f"/records/{record_id}", token=service_token)
            record(f"{site}_service_identity", status == 200, {"http_status": status})
            approvers = [authority.login(f"{site}-approver-{suffix}", DEMO_PASSWORD)
                         for suffix in ("a", "b")]
            emergency = authority.emergency_session(
                token, approvers, record_id, "Synthetic maintenance review", ttl=60,
            )
            status, _ = request(address, "POST", f"/alerts/{record_id}/ack", token=emergency)
            record(f"{site}_approved_emergency_action", status == 200, {"http_status": status})
            admin = authority.login(f"{site}-admin", DEMO_PASSWORD)
            authority.revoke_identity(admin, f"{site}-viewer")
            status, _ = request(address, "GET", f"/records/{record_id}", token=token)
            record(f"{site}_revocation_effective", status == 403, {"http_status": status})

        analyst = authority.login("government-analyst", DEMO_PASSWORD, ttl=100)
        admin = authority.login("government-admin", DEMO_PASSWORD)
        authority.grant_role(admin, "government-analyst", "analyst", ttl=5)
        clock.value += 5
        status, _ = request(address, "POST", "/alerts/government-record-a/ack", token=analyst)
        record("role_expiry_denied", status == 403, {"http_status": status})
        clock.value -= 1
        try:
            authority.authorize(analyst, "read_record", "government-record-a")
            rollback_denied = False
        except Denied:
            rollback_denied = True
        record("clock_rollback_denied", rollback_denied, {"observed_behavior": "fail closed"})
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-isolation", action="store_true")
    args = parser.parse_args()
    isolation = isolation_probe()
    cases = exercise()
    result = {
        "schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
        "synthetic": True,
        "environment": {"python": platform.python_version(), "system": platform.system(),
                        "machine": platform.machine()},
        "network_isolation": isolation,
        "source_manifest": source_manifest(ROOT),
        "cases": cases,
        "passed": all(case["passed"] for case in cases)
        and (isolation["passed"] or not args.require_isolation),
        "limitations": [
            "Three logical site fixtures in one disposable container, not three deployed sites.",
            "Authority, sessions, role state, and audit events are in memory.",
            "Local HTTP is loopback only; production TLS, MFA, rate limiting, durable state and trusted time are absent.",
            "Dependency availability is a declared graph model, not infrastructure measurement.",
            "Flow validation checks contracts; it does not install firewall rules or approve transfers.",
            "No sovereignty, legal, accreditation, HSM, physical air-gap or diode assurance.",
        ],
    }
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
