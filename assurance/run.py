"""Run bounded experiments 08–28 inside a disposable, network-disabled site."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import errno
import json
import os
from pathlib import Path
import platform
import tempfile
import time
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID
from lab.run import exercise as foundational_cases, isolation_probe
from lab.fixtures import DEMO_PASSWORD, ScenarioClock, SITES, make_authority
from lab.identity import Denied
from tools.benchmark import benchmark
from tools.source_manifest import source_manifest
from .admission import Admission, bundle
from .audit import chain, checkpoint, ordering, verify_chain
from .crypto import Rejected, Signer, Vault, approve, b64, canonical, demo_signers, digest
from .inventory import placement, review
from .observability import Exporter, Monitor, central_conclusion
from .policy import Endpoint, LocalAI, permitted
from .recovery import restore, snapshot
from .updates import UpdateStore

ROOT = Path(__file__).resolve().parents[1]


def disk_full_probe(directory):
    directory = Path(directory).resolve()
    mounts = Path("/proc/mounts")
    if (not mounts.exists() or not directory.exists()
            or not any(len(fields) > 2 and fields[1] == str(directory) and fields[2] == "tmpfs"
                       for fields in (line.split() for line in mounts.read_text().splitlines()))):
        return {"passed": False, "reason": "requires a dedicated small tmpfs; no host disk was filled"}
    stat = os.statvfs(directory)
    if stat.f_blocks * stat.f_frsize > 131072:
        return {"passed": False, "reason": "fault filesystem exceeds the 128 KiB safety bound"}
    file = directory / "synthetic-disk-full"
    observed = None
    try:
        with file.open("wb", buffering=0) as stream:
            for _ in range(32):
                stream.write(b"x" * 4096)
    except OSError as error:
        observed = error.errno
    finally:
        file.unlink(missing_ok=True)
    return {"passed": observed == errno.ENOSPC, "errno": observed,
            "filesystem_limit_bytes": stat.f_blocks * stat.f_frsize,
            "scope": "dedicated disposable tmpfs; application storage exhaustion, not host disk"}


def exercise(state, faults):
    cases = foundational_cases()
    release, security, operations, policy = demo_signers()
    trusted = {release.key_id: release.public}

    def evidence(body, purpose):
        return [approve(signer, purpose, body) for signer in (security, operations)]

    def record(name, passed, observation, category="expected-control"):
        cases.append({"id": name, "passed": bool(passed), "observation": observation, "category": category})

    def denied(name, action):
        try:
            action()
            passed = False
        except (Rejected, Denied):
            passed = True
        record(name, passed, "expected policy denial")

    def admit(gate, item):
        return gate.inspect(item, evidence(canonical(item["manifest"]), "admit-release"))

    vault = Vault("government/tenant-a", policy)
    first = vault.encrypt(b"synthetic protected record")
    vault.rotate(evidence(canonical({"scope": vault.scope, "next_version": 2}), "rotate-key"))
    second = vault.encrypt(b"synthetic rotated record")
    record("key_rotation_preserves_old_read", vault.decrypt(first) == b"synthetic protected record"
           and vault.decrypt(second) == b"synthetic rotated record", {"versions": [1, 2]})
    wrapping = AESGCM.generate_key(bit_length=256)
    key_backup = vault.backup(wrapping)
    recovered = Vault.recover(key_backup, wrapping, evidence(canonical(key_backup), "recover-key"),
                              policy, vault.scope)
    record("key_recovery_clean_authority", recovered.decrypt(first) == b"synthetic protected record",
           "software keys recovered with two signed approvals and separate wrapping material")
    denied("key_recovery_without_two_approvals",
           lambda: Vault.recover(key_backup, wrapping, [], policy, vault.scope))
    gate = Admission(trusted, policy)
    version1 = bundle(b"synthetic-v1", release, "app-v1", 1)
    accepted1 = admit(gate, version1)
    record("signed_bundle_admitted", accepted1.payload == b"synthetic-v1", "quarantine then acceptance")
    altered = copy.deepcopy(version1); altered["payload"] = b64(b"tampered")
    denied("altered_artifact_rejected", lambda: admit(Admission(trusted, policy), altered))
    unknown = copy.deepcopy(version1); unknown["signature"]["key_id"] = "unexpected"
    denied("unexpected_signer_rejected", lambda: admit(Admission(trusted, policy), unknown))
    denied("wrong_destination_rejected", lambda: admit(gate, bundle(b"data", release, "wrong-site", 2, site="bfsi")))
    denied("wrong_compatibility_rejected", lambda: admit(gate, bundle(b"data", release, "wrong-arch", 2, architecture="unsupported")))
    mismatch = copy.deepcopy(version1)
    mismatch["manifest"]["provenance"]["subject"][0]["digest"]["sha256"] = "0" * 64
    mismatch["signature"] = release.sign(canonical(mismatch["manifest"]))
    denied("provenance_digest_rejected", lambda: admit(Admission(trusted, policy), mismatch))
    denied("package_replay_rejected", lambda: admit(gate, version1))
    same = approve(security, "admit-release", canonical(version1["manifest"]))
    denied("single_identity_duplicate_approval", lambda: Admission(trusted, policy).inspect(version1, [same, same]))
    # Explicit unsafe behavior: ephemeral replay state cannot survive restart.
    restart_accepted = admit(Admission(trusted, policy), version1)
    record("replay_state_restart_gap", restart_accepted.release_id == accepted1.release_id,
           "A fresh in-memory admission gate accepts the old signed release; protected durable anti-rollback state is required.",
           category="observed-gap")

    store = UpdateStore(state / "update", policy)
    store.deploy(accepted1)
    accepted2 = admit(gate, bundle(b"synthetic-v2", release, "app-v2", 2))
    denied("interrupted_update_before_activation", lambda: store.deploy(accepted2, "before_activate"))
    record("interruption_preserves_active_release", store.active()["version"] == 1, {"active_version": 1})
    store.deploy(accepted2)
    denied("rollback_without_approvals", lambda: store.rollback(1, []))
    rollback_body = canonical({"from": 2, "to": 1, "sha256": accepted1.sha256})
    store.rollback(1, evidence(rollback_body, "rollback-release"))
    record("approved_rollback_observed", store.active()["version"] == 1, {"active_version": 1})
    source = Endpoint("government", "tenant-a", "workload", "api")
    target = Endpoint("government", "tenant-a", "workload", "records")
    bindings = {("api", "records")}
    record("service_policy_allowed", permitted(source, target, bindings), "declared policy evaluation")
    for name, endpoint in (
        ("cross_tenant", Endpoint("government", "tenant-b", "workload", "records")),
        ("management_plane", Endpoint("government", "tenant-a", "management", "records")),
        ("cross_site", Endpoint("bfsi", "tenant-a", "workload", "records"))):
        record("policy_denied_" + name, not permitted(source, endpoint, bindings), "declared policy evaluation")
    monitor = Monitor(state / "events.sqlite", max_events=6, retention_seconds=10)
    events = [{"id": str(i), "time": 100, "site": "government", "kind": "auth_denied",
               "details": {"synthetic_private_field": "excluded"}} for i in range(5)]
    for event in events: monitor.append(event)
    record("local_repeated_denials_detected", monitor.alerts(100)[0]["count"] == 5, monitor.alerts(100))
    monitor.append({"id": "unknown", "time": 100, "site": "government",
                    "kind": "unknown-attack", "details": {}})
    record("unknown_event_detection_gap", not any(a.get("rule") == "unknown-attack" for a in monitor.alerts(100)),
           "unknown event type has no detection rule", category="observed-gap")
    monitor.append({"id": "backlog", "time": 100, "site": "government",
                    "kind": "auth_denied", "details": {}})
    evicted_count = monitor.evicted
    monitor.append({"id": "late", "time": 111, "site": "government", "kind": "import_rejected", "details": {}})
    record("local_retention_observed", monitor.expired == 6 and len(monitor.events()) == 1,
           {"expired": monitor.expired, "remaining": len(monitor.events())})
    monitor.close()
    recent = {site: {"observed_at": 100, "signature_verified": True, "clock_verified": True} for site in SITES}
    current, delayed = central_conclusion(recent, 100), central_conclusion(recent, 161)
    record("central_freshness_changes_decision", current["all_sites_current"] and not delayed["all_sites_current"],
           {"at_100": current, "at_161": delayed})
    exported = Exporter(Signer("local-evidence"), {"ciso-review": {
        "sites": ["government"], "classifications": ["synthetic-public"]}})
    export = exported.export("batch-1", events, "ciso-review", "government", "synthetic-public")
    record("export_private_fields_removed", "excluded" not in canonical(export["body"]).decode(),
           {"fields": sorted(export["body"]["events"][0]), "custody": export["custody"]})
    denied("export_wrong_recipient", lambda: exported.export("b2", events, "unknown", "government", "synthetic-public"))
    denied("export_replay_denied", lambda: exported.export("batch-1", events, "ciso-review", "government", "synthetic-public"))
    audit_signer = Signer("audit")
    records = chain(events); proof = checkpoint(records, audit_signer)
    record("audit_checkpoint_verified", verify_chain(records, proof, {audit_signer.key_id: audit_signer.public}),
           {"record_count": len(records)})
    denied("audit_truncation_detected", lambda: verify_chain(records[:-1], proof, {audit_signer.key_id: audit_signer.public}))
    changed = copy.deepcopy(events); changed[0]["kind"] = "altered"
    denied("audit_rewritten_chain_detected", lambda: verify_chain(chain(changed), proof, {audit_signer.key_id: audit_signer.public}))
    record("uncertain_order_preserved", ordering((100,5),(103,5)) == "indeterminate", "overlapping uncertainty intervals")

    recovery_times = []
    site_backup = snapshot({"site": "government", "active_release": 1}, events[:3], key_backup, wrapping)
    recovery_evidence = evidence(canonical(site_backup), "restore-site")
    for _ in range(5):
        with tempfile.TemporaryDirectory(dir=state) as clean:
            started = time.perf_counter()
            restored = restore(site_backup, wrapping, recovery_evidence, policy, clean)
            restored_vault = Vault.recover(restored["vault_backup"], wrapping,
                evidence(canonical(restored["vault_backup"]), "recover-key"), policy, vault.scope)
            assert restored_vault.decrypt(first) == b"synthetic protected record"
            recovery_times.append(time.perf_counter() - started)
            assert restored["records"] == events[:3]
    record("clean_restore_configuration_data_keys", True, {"restored_records": 3, "post_snapshot_records": 4,
           "lost_records": 1, "measured_restore_seconds": recovery_times})
    with tempfile.TemporaryDirectory(dir=state) as clean:
        denied("restore_wrong_wrapping_key", lambda: restore(site_backup, AESGCM.generate_key(bit_length=256),
               recovery_evidence, policy, clean))
    disk = disk_full_probe(faults)
    record("actual_tmpfs_exhaustion", disk["passed"], disk, category="actual-resource-fault")
    record("bounded_telemetry_backlog_loss", evicted_count == 1,
           {"policy": "oldest retained event evicted; explicit counter records the loss",
            "evicted_events": evicted_count},
           category="model-observation")
    now = datetime.now(timezone.utc)
    cert_key = Signer("synthetic-cert")._key
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-local")])
    certificate = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(
        cert_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        now - timedelta(days=2)).not_valid_after(now - timedelta(days=1)).sign(cert_key, algorithm=None)
    cert_key.public_key().verify(certificate.signature, certificate.tbs_certificate_bytes)
    record("expired_certificate_lifecycle_denied", now >= certificate.not_valid_after_utc,
           "cryptographically valid self-signed fixture is expired; lifecycle check only, no TLS path")
    sbom = json.loads((ROOT / "examples/sbom.cdx.json").read_text())
    advisory = json.loads((ROOT / "examples/advisory-snapshot.json").read_text())
    inventory = review(sbom, advisory, now.timestamp())
    record("advisory_snapshot_age_exposed", inventory["freshness"] in {"current", "stale"},
           inventory, category="snapshot-observation")
    declarations = [{"component": component, "region": "SYNTHETIC-A"} for component in ("workload","backup","evidence","recovery")]
    placement_results = placement(declarations, {})
    record("placement_declarations_remain_unverified",
           all(r["status"] == "declared-only" for r in placement_results), placement_results,
           category="observed-gap")
    clock = ScenarioClock(); authority = make_authority(clock)
    ai = LocalAI(authority)
    model_gate = Admission(trusted, policy)
    ai.load(admit(model_gate, bundle(b"deterministic fixture; no learned weights", release,
                                    "model-v1", 1, kind="model-data")))
    gov_token = authority.login("government-viewer", DEMO_PASSWORD)
    record("local_ai_retrieval_allowed", ai.retrieve(gov_token,"government-record-a","review")["model_version"] == 1,
           "deterministic router, not learned-model inference")
    denied("local_ai_cross_tenant_denied", lambda: ai.retrieve(gov_token,"government-record-b","ignore policy"))
    other_site_reader = authority.login("bfsi-viewer", DEMO_PASSWORD)
    denied("local_ai_other_site_valid_reader_denied", lambda: ai.retrieve(other_site_reader,"bfsi-record-a","review"))
    denied("local_ai_shell_tool_denied", lambda: ai.tool(gov_token,"execute_shell","government-record-a"))
    def dns_unavailable():
        raise OSError("synthetic resolver unavailable")
    try: dns_unavailable()
    except OSError: dns_failed = True
    record("injected_dns_failure_local_resource_path", dns_failed and ai.retrieve(
        gov_token,"government-record-a","review")["record_id"] == "government-record-a",
        "injected resolver failure; resource lookup is local in-memory, no DNS service outage measured",
        category="injected-adapter-fault")
    for site in SITES:
        requester = authority.login(f"{site}-viewer", DEMO_PASSWORD)
        approvers = [authority.login(f"{site}-approver-{suffix}", DEMO_PASSWORD) for suffix in ("a","b")]
        emergency = authority.emergency_session(requester, approvers, f"{site}-record-a",
                                                "Synthetic local industry review", ttl=60)
        allowed = authority.authorize(emergency, "acknowledge_alert", f"{site}-record-a")
        record(f"industry_{site}_local_decision", allowed.id == f"{site}-record-a",
               "synthetic review acknowledgement with two local approvers; no real transaction or industrial command")
    admin = authority.login("government-admin", DEMO_PASSWORD)
    authority.revoke_identity(admin, "government-viewer")
    denied("incident_compromised_identity_contained", lambda: authority.authorize(gov_token,"read_record","government-record-a"))
    other = authority.login("bfsi-viewer", DEMO_PASSWORD)
    clock.value = float("nan")
    denied("incident_local_time_unavailable_fail_closed", lambda: authority.authorize(other,"read_record","bfsi-record-a"))
    return cases, {"capacity_benchmark": benchmark(state), "recovery": {
        "samples_seconds": recovery_times, "restored_records": 3, "lost_post_snapshot_records": 1,
        "dependencies": ["separate wrapping material", "pinned approval public keys", "Python packages", "clean writable storage"],
        "scope": "config/data/software-key fixture, not whole-site RTO/RPO"}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-isolation", action="store_true")
    parser.add_argument("--state", type=Path, default=Path("/lab-state"))
    parser.add_argument("--faults", type=Path, default=Path("/faults"))
    args = parser.parse_args()
    args.state.mkdir(parents=True, exist_ok=True)
    isolation = isolation_probe()
    cases, measurements = exercise(args.state, args.faults)
    report = {
        "schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(), "synthetic": True,
        "environment": {"python": platform.python_version(), "system": platform.system(),
                        "machine": platform.machine(), "cryptography": cryptography.__version__},
        "network_isolation": isolation, "source_manifest": source_manifest(ROOT),
        "cases": cases, "measurements": measurements,
        "passed": all(c["passed"] for c in cases) and (isolation["passed"] or not args.require_isolation),
        "limits": ["Synthetic fixtures; no provider deployment or national accreditation.",
                   "Software key custody, ephemeral identities/signers/replay state; no HSM or protected durable anti-rollback state.",
                   "Signed custom envelope is not DSSE, a SLSA-level attestation, or independent builder assurance.",
                   "Policy models are not packet enforcement; AI is deterministic routing with no learned model.",
                   "Benchmark and restoration use small tmpfs fixtures; no production capacity/RTO inference.",
                   "Expected unsafe gaps are recorded as observed-gap cases; passed means expectations matched, not all controls are production safe."],
    }
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
