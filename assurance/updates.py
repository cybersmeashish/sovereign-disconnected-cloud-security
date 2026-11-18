"""Disposable atomic update slots and explicit operator-approved rollback."""
import json
import os
from pathlib import Path
from .crypto import Rejected, approvals, canonical, digest


class UpdateStore:
    def __init__(self, directory, policy):
        self.root = Path(directory)
        self.root.mkdir(parents=True, exist_ok=True)
        self.policy = policy
        self.history = {}

    def active(self):
        pointer = self.root / "active.json"
        if not pointer.exists():
            return None
        record = json.loads(pointer.read_text())
        path = self.root / f"v{record['version']}.bin"
        if digest(path.read_bytes()) != record["sha256"]:
            raise Rejected("active payload integrity failed")
        return record

    def _point(self, record):
        temporary = self.root / "next-pointer.json"
        with temporary.open("wb") as stream:
            stream.write(canonical(record))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.root / "active.json")

    def deploy(self, accepted, fault=None):
        current = self.active()
        if current and accepted.version <= current["version"]:
            raise Rejected("normal deployment cannot downgrade")
        if digest(accepted.payload) != accepted.sha256:
            raise Rejected("accepted artifact changed")
        staged = self.root / f"v{accepted.version}.staged"
        with staged.open("wb") as stream:
            stream.write(accepted.payload)
            stream.flush()
            os.fsync(stream.fileno())
        if fault == "after_stage":
            raise Rejected("injected interruption after staging")
        if fault == "corrupt_stage":
            staged.write_bytes(b"synthetic-corruption")
        if digest(staged.read_bytes()) != accepted.sha256:
            raise Rejected("staged bytes failed integrity")
        os.replace(staged, self.root / f"v{accepted.version}.bin")
        if fault == "before_activate":
            raise Rejected("injected interruption before activation")
        record = {"version": accepted.version, "sha256": accepted.sha256,
                  "release_id": accepted.release_id}
        self.history[accepted.version] = record
        self._point(record)
        if fault == "after_activate":
            raise Rejected("activation completed; injected post-activation fault")
        return record

    def rollback(self, version, evidence):
        current = self.active()
        if type(version) is not int or version not in self.history or not current or version >= current["version"]:
            raise Rejected("known earlier release required")
        record = self.history[version]
        body = canonical({"from": current["version"], "to": version, "sha256": record["sha256"]})
        approvals(body, "rollback-release", evidence, self.policy)
        if digest((self.root / f"v{version}.bin").read_bytes()) != record["sha256"]:
            raise Rejected("rollback target changed")
        self._point(record)
        return record
