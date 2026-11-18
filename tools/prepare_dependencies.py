"""Connected preparation; download hash-locked wheels for the container CPU."""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", choices=("docker", "podman"), default="docker")
    parser.add_argument("--architecture", choices=("arm64", "amd64"))
    args = parser.parse_args()
    architecture = args.architecture
    if architecture is None:
        observed = subprocess.check_output(
            [args.runtime, "info", "--format", "{{.Architecture}}"], text=True).strip()
        architecture = {"aarch64": "arm64", "arm64": "arm64",
                        "x86_64": "amd64", "amd64": "amd64"}.get(observed)
    if architecture is None:
        parser.error("unsupported engine architecture; provide --architecture")
    machine = "aarch64" if architecture == "arm64" else "x86_64"
    destination = ROOT / "vendor/wheels"
    destination.mkdir(parents=True, exist_ok=True)
    # One wheelhouse is for one image architecture. Refuse stale mixed caches.
    marker = destination / "architecture.txt"
    if marker.exists() and marker.read_text().strip() != architecture:
        parser.error("wheelhouse architecture differs; remove this task-owned wheelhouse first")
    command = [
        sys.executable, "-m", "pip", "download", "--no-cache-dir",
        "--only-binary=:all:", "--require-hashes", "--implementation", "cp",
        "--python-version", "312", "--abi", "cp312", "--abi", "abi3",
        "--dest", str(destination), "-r", str(ROOT / "requirements.lock"),
    ]
    for platform in (f"manylinux_2_28_{machine}", f"manylinux_2_17_{machine}", f"manylinux2014_{machine}"):
        command += ["--platform", platform]
    subprocess.run(command, check=True)
    marker.write_text(architecture + "\n")


if __name__ == "__main__":
    main()
