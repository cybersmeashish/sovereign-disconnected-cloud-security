"""Verify a fixture against a separately selected, trusted local policy."""
import argparse
import json
from pathlib import Path
from assurance.admission import Admission
from assurance.crypto import Rejected, unb64


def admit(fixture, policy):
    release = {name: unb64(value) for name, value in policy["release_keys"].items()}
    approvals = {name: {"public": unb64(item["public"]), "duty": item["duty"]}
                 for name, item in policy["approval_policy"].items()}
    gate = Admission(release, approvals, policy["site"], policy["architecture"], policy["builder"])
    accepted = gate.inspect(fixture["candidate"], fixture["approvals"])
    return {"admitted": True, "version": accepted.version, "sha256": accepted.sha256,
            "release_id": accepted.release_id}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--trust", type=Path, required=True,
                        help="trusted policy installed separately from the imported package")
    args = parser.parse_args()
    try:
        result = admit(json.loads(args.fixture.read_text()), json.loads(args.trust.read_text()))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"admitted": False, "reason": str(error)}))
        raise SystemExit(1)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
