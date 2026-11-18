"""Quarantine, signed provenance and duty-separated release admission."""
from dataclasses import dataclass
from .crypto import Rejected, approvals, b64, canonical, digest, unb64, verify


def bundle(payload, signer, release_id, version, site="government", architecture="portable",
           builder="synthetic-local-builder", kind="application"):
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": kind, "digest": {"sha256": digest(payload)}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {"buildType": "synthetic-fixture-v1",
                                "externalParameters": {"site": site, "architecture": architecture}},
            "runDetails": {"builder": {"id": builder}},
        },
    }
    manifest = {"schema_version": 1, "release_id": release_id, "version": version,
                "site": site, "architecture": architecture, "kind": kind,
                "payload_sha256": digest(payload), "provenance": statement}
    return {"manifest": manifest, "payload": b64(payload),
            "signature": signer.sign(canonical(manifest))}


@dataclass(frozen=True)
class Accepted:
    release_id: str
    version: int
    site: str
    kind: str
    payload: bytes
    sha256: str


class Admission:
    """Trusted configuration is separate from package-supplied claims."""
    def __init__(self, release_keys, approval_policy, site="government",
                 architecture="portable", builder="synthetic-local-builder"):
        self.release_keys, self.policy = dict(release_keys), approval_policy
        self.site, self.architecture, self.builder = site, architecture, builder
        self.seen = set()
        self.floor = 0
        self.quarantine = []

    def inspect(self, candidate, evidence):
        # Store only a bounded observation, never promote unverified bytes.
        self.quarantine.append({"state": "quarantined"})
        try:
            if not isinstance(candidate, dict) or set(candidate) != {"manifest", "payload", "signature"}:
                raise Rejected("bundle schema denied")
            manifest = candidate["manifest"]
            required = {"schema_version", "release_id", "version", "site", "architecture",
                        "kind", "payload_sha256", "provenance"}
            if not isinstance(manifest, dict) or set(manifest) != required or manifest["schema_version"] != 1:
                raise Rejected("manifest schema denied")
            verify(canonical(manifest), candidate["signature"], self.release_keys)
            payload = unb64(candidate["payload"])
            if len(payload) > 1_048_576 or digest(payload) != manifest["payload_sha256"]:
                raise Rejected("payload digest or size denied")
            if (manifest["site"] != self.site or manifest["architecture"] != self.architecture
                    or manifest["kind"] not in {"application", "model-data"}):
                raise Rejected("destination or compatibility denied")
            version, release_id = manifest["version"], manifest["release_id"]
            if (type(version) is not int or version <= self.floor or
                    not isinstance(release_id, str) or not release_id or release_id in self.seen):
                raise Rejected("replay or version rollback denied")
            statement = manifest["provenance"]
            expected_subject = [{"name": manifest["kind"], "digest": {"sha256": digest(payload)}}]
            if (statement.get("_type") != "https://in-toto.io/Statement/v1"
                    or statement.get("predicateType") != "https://slsa.dev/provenance/v1"
                    or statement.get("subject") != expected_subject
                    or statement["predicate"]["runDetails"]["builder"]["id"] != self.builder
                    or statement["predicate"]["buildDefinition"]["buildType"] != "synthetic-fixture-v1"
                    or statement["predicate"]["buildDefinition"]["externalParameters"] !=
                    {"site": self.site, "architecture": self.architecture}):
                raise Rejected("provenance expectations denied")
            approvals(canonical(manifest), "admit-release", evidence, self.policy)
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            self.quarantine[-1]["state"] = "rejected"
            raise Rejected(str(error)) from error
        self.quarantine[-1]["state"] = "accepted"
        self.seen.add(release_id)
        self.floor = version
        return Accepted(release_id, version, self.site, manifest["kind"], payload, digest(payload))
