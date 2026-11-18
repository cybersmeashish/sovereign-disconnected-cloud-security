"""Run and inspect a disposable network-disabled Docker/Podman container."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import uuid

from .source_manifest import source_manifest

ROOT = Path(__file__).resolve().parents[1]


def command(runtime, *args, timeout=120):
    result = subprocess.run(
        [runtime, *args], capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode:
        raise RuntimeError(f"{runtime} {args[0]} failed: {result.stderr.strip()}")
    return result.stdout


def run(runtime, image):
    container_id = None
    name = "ashish-sovereign-lab-" + uuid.uuid4().hex[:12]
    try:
        container_id = command(
            runtime, "create", "--name", name, "--network", "none",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "64", "--memory", "256m", "--cpus", "1",
            image, "python", "-m", "lab.run", "--require-isolation",
        ).strip()
        config = json.loads(command(runtime, "inspect", container_id))[0]
        lab_result = json.loads(command(runtime, "start", "-a", container_id))
        after = json.loads(command(runtime, "inspect", container_id))[0]
        host = config["HostConfig"]
        security = host.get("SecurityOpt") or []
        constraints = {
            "network_mode": host["NetworkMode"],
            "read_only_root": host["ReadonlyRootfs"],
            "dropped_capabilities": host.get("CapDrop", []),
            "no_new_privileges": any(option.split("=")[0] == "no-new-privileges" for option in security),
            "user": config["Config"]["User"],
            "memory_bytes": host.get("Memory"),
            "pids_limit": host.get("PidsLimit"),
            "image_id": config["Image"],
            "exit_code": after["State"]["ExitCode"],
        }
        expected = source_manifest(ROOT)
        match = lab_result.get("source_manifest") == expected
        passed = (
            lab_result["passed"] and constraints["network_mode"] == "none"
            and constraints["read_only_root"] and constraints["no_new_privileges"]
            and "ALL" in constraints["dropped_capabilities"]
            and constraints["user"] == "65532:65532"
            and constraints["exit_code"] == 0 and match
        )
        return {
            "schema_version": 1,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "scope": "Synthetic reference lab, Docker/Podman network namespace",
            "runtime": runtime, "constraints": constraints,
            "source_matches_image": match,
            "source_manifest": expected,
            "lab": lab_result,
            "passed": passed,
        }
    finally:
        if container_id:
            # Remove only the uniquely named container created by this run.
            subprocess.run([runtime, "rm", "-f", container_id], capture_output=True, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", choices=("docker", "podman"), default="docker")
    parser.add_argument("--image", default="ashish-sovereign-lab:contributions-01-07")
    parser.add_argument("--output", type=Path, default=ROOT / "evidence/local/isolation-report.json")
    args = parser.parse_args()
    try:
        report = run(args.runtime, args.image)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Lab verification failed: {error}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({
        "passed": report["passed"], "source_matches_image": report["source_matches_image"],
        "scenario_cases": len(report["lab"]["cases"]), "report": str(args.output),
    }, indent=2))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
