import copy
import tempfile
import unittest
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from assurance.admission import Admission, bundle
from assurance.crypto import Rejected, Vault, approve, b64, canonical, demo_signers
from assurance.recovery import restore, snapshot
from assurance.updates import UpdateStore
from tools.admit_fixture import admit


class CryptoAndAdmission(unittest.TestCase):
    def setUp(self):
        self.release, self.security, self.operations, self.policy = demo_signers()
        self.gate = Admission({self.release.key_id: self.release.public}, self.policy)
        self.package = bundle(b"synthetic application data", self.release, "release-1", 1)

    def evidence(self, body, purpose):
        return [approve(s, purpose, body) for s in (self.security, self.operations)]

    def inspect(self, package=None):
        package = self.package if package is None else package
        return self.gate.inspect(package, self.evidence(canonical(package["manifest"]), "admit-release"))

    def test_valid_package_is_admitted(self):
        self.assertEqual(self.inspect().payload, b"synthetic application data")
        self.assertEqual(self.gate.quarantine[-1]["state"], "accepted")

    def test_altered_payload_remains_rejected(self):
        candidate = copy.deepcopy(self.package); candidate["payload"] = b64(b"altered")
        with self.assertRaises(Rejected): self.inspect(candidate)
        self.assertEqual(self.gate.quarantine[-1]["state"], "rejected")

    def test_unexpected_signer(self):
        candidate = copy.deepcopy(self.package); candidate["signature"]["key_id"] = "unexpected"
        with self.assertRaises(Rejected): self.inspect(candidate)

    def test_altered_signed_manifest(self):
        candidate = copy.deepcopy(self.package); candidate["manifest"]["site"] = "bfsi"
        with self.assertRaises(Rejected): self.inspect(candidate)

    def test_valid_signature_wrong_destination(self):
        candidate = bundle(b"data", self.release, "r", 1, site="bfsi")
        with self.assertRaises(Rejected): self.inspect(candidate)

    def test_valid_signature_wrong_architecture(self):
        candidate = bundle(b"data", self.release, "r", 1, architecture="unsupported")
        with self.assertRaises(Rejected): self.inspect(candidate)

    def test_valid_signature_unexpected_builder(self):
        candidate = bundle(b"data", self.release, "r", 1, builder="unexpected-builder")
        with self.assertRaises(Rejected): self.inspect(candidate)

    def test_provenance_subject_digest_mismatch(self):
        candidate = copy.deepcopy(self.package)
        candidate["manifest"]["provenance"]["subject"][0]["digest"]["sha256"] = "0" * 64
        candidate["signature"] = self.release.sign(canonical(candidate["manifest"]))
        with self.assertRaises(Rejected): self.inspect(candidate)

    def test_unknown_provenance_parameters(self):
        candidate = copy.deepcopy(self.package)
        candidate["manifest"]["provenance"]["predicate"]["buildDefinition"]["externalParameters"]["bypass"] = True
        candidate["signature"] = self.release.sign(canonical(candidate["manifest"]))
        with self.assertRaises(Rejected): self.inspect(candidate)

    def test_replay_is_rejected(self):
        self.inspect()
        with self.assertRaises(Rejected): self.inspect()

    def test_version_rollback_is_rejected(self):
        self.inspect(bundle(b"v2", self.release, "r2", 2))
        with self.assertRaises(Rejected): self.inspect()

    def test_duplicate_approval_is_rejected(self):
        approval = approve(self.security, "admit-release", canonical(self.package["manifest"]))
        with self.assertRaises(Rejected): self.gate.inspect(self.package, [approval, approval])

    def test_approval_for_another_purpose_is_rejected(self):
        with self.assertRaises(Rejected):
            self.gate.inspect(self.package, self.evidence(canonical(self.package["manifest"]), "rollback-release"))

    def test_rotated_old_and_new_data_decrypt(self):
        vault = Vault("government/tenant-a", self.policy)
        first = vault.encrypt(b"old")
        vault.rotate(self.evidence(canonical({"scope": vault.scope, "next_version": 2}), "rotate-key"))
        second = vault.encrypt(b"new")
        self.assertEqual(vault.decrypt(first), b"old")
        self.assertEqual(vault.decrypt(second), b"new")
        self.assertNotEqual(first["version"], second["version"])

    def test_key_record_scope_denied(self):
        vault = Vault("government/tenant-a", self.policy)
        record = vault.encrypt(b"data"); record["scope"] = "bfsi/tenant-a"
        with self.assertRaises(Rejected): vault.decrypt(record)

    def test_key_backup_recovery(self):
        vault = Vault("government/tenant-a", self.policy)
        encrypted = vault.encrypt(b"synthetic-data")
        wrapping = AESGCM.generate_key(bit_length=256)
        backup = vault.backup(wrapping)
        recovered = Vault.recover(backup, wrapping, self.evidence(canonical(backup), "recover-key"),
                                  self.policy, vault.scope)
        self.assertEqual(recovered.decrypt(encrypted), b"synthetic-data")

    def test_wrong_wrapping_key_denied(self):
        vault = Vault("government/tenant-a", self.policy)
        backup = vault.backup(AESGCM.generate_key(bit_length=256))
        with self.assertRaises(Rejected):
            Vault.recover(backup, AESGCM.generate_key(bit_length=256),
                          self.evidence(canonical(backup), "recover-key"), self.policy, vault.scope)

    def test_interrupted_update_preserves_active_version(self):
        with tempfile.TemporaryDirectory() as directory:
            store = UpdateStore(directory, self.policy)
            store.deploy(self.inspect())
            second = self.inspect(bundle(b"v2", self.release, "r2", 2))
            with self.assertRaises(Rejected): store.deploy(second, "before_activate")
            self.assertEqual(store.active()["version"], 1)

    def test_corrupt_stage_cannot_activate(self):
        with tempfile.TemporaryDirectory() as directory:
            store = UpdateStore(directory, self.policy)
            with self.assertRaises(Rejected): store.deploy(self.inspect(), "corrupt_stage")
            self.assertIsNone(store.active())

    def test_approved_rollback_and_denied_missing_approvals(self):
        with tempfile.TemporaryDirectory() as directory:
            store = UpdateStore(directory, self.policy)
            store.deploy(self.inspect())
            store.deploy(self.inspect(bundle(b"v2", self.release, "r2", 2)))
            with self.assertRaises(Rejected): store.rollback(1, [])
            body = canonical({"from": 2, "to": 1, "sha256": store.history[1]["sha256"]})
            store.rollback(1, self.evidence(body, "rollback-release"))
            self.assertEqual(store.active()["version"], 1)

    def test_restore_configuration_data_and_key_backup(self):
        wrapping = AESGCM.generate_key(bit_length=256)
        backup = snapshot({"site": "government"}, [{"id": 1}], {"simulated": True}, wrapping)
        with tempfile.TemporaryDirectory() as directory:
            result = restore(backup, wrapping, self.evidence(canonical(backup), "restore-site"), self.policy, directory)
            self.assertEqual(result["records"], [{"id": 1}])
            with self.assertRaises(Rejected):
                restore(backup, wrapping, self.evidence(canonical(backup), "restore-site"), self.policy, directory)

    def test_altered_backup_and_wrong_key_denied(self):
        wrapping = AESGCM.generate_key(bit_length=256)
        backup = snapshot({}, [], {}, wrapping)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(Rejected):
                restore(backup, AESGCM.generate_key(bit_length=256),
                        self.evidence(canonical(backup), "restore-site"), self.policy, directory)
            altered = copy.deepcopy(backup); altered["ciphertext"] = b64(b"altered")
            with self.assertRaises(Rejected):
                restore(altered, wrapping, self.evidence(canonical(altered), "restore-site"), self.policy, directory)

    def test_snapshot_preserves_actual_point_in_time(self):
        wrapping = AESGCM.generate_key(bit_length=256)
        live = [{"id": "before-snapshot"}]
        backup = snapshot({"site": "government"}, live, {"simulated": True}, wrapping)
        live.append({"id": "after-snapshot"})
        with tempfile.TemporaryDirectory() as directory:
            restored = restore(backup, wrapping, self.evidence(canonical(backup), "restore-site"),
                               self.policy, directory)
        missing = {item["id"] for item in live} - {item["id"] for item in restored["records"]}
        self.assertEqual(missing, {"after-snapshot"})

    def test_published_positive_package_fixture(self):
        root = Path(__file__).resolve().parents[1] / "examples/packages"
        policy = json.loads((root / "trust-policy.json").read_text())
        self.assertTrue(admit(json.loads((root / "valid.json").read_text()), policy)["admitted"])

    def test_published_negative_package_fixtures(self):
        root = Path(__file__).resolve().parents[1] / "examples/packages"
        policy = json.loads((root / "trust-policy.json").read_text())
        for path in root.glob("*.json"):
            if path.name in {"trust-policy.json", "valid.json"}:
                continue
            with self.subTest(fixture=path.name):
                with self.assertRaises(Rejected): admit(json.loads(path.read_text()), policy)
