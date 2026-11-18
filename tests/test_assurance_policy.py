import copy
import tempfile
import unittest
from assurance.audit import chain, checkpoint, ordering, verify_chain
from assurance.crypto import Rejected, Signer, canonical, demo_signers
from assurance.inventory import placement, review
from assurance.observability import Exporter, Monitor, central_conclusion, freshness
from assurance.policy import Endpoint, LocalAI, permitted
from assurance.admission import Accepted
from lab.fixtures import DEMO_PASSWORD, ScenarioClock, make_authority
from lab.identity import Denied
from tools.benchmark import benchmark


def event(index, at=100, kind="auth_denied", site="government"):
    return {"id": str(index), "time": at, "site": site, "kind": kind,
            "details": {"synthetic_secret": "must-not-export"}}


class EvidencePolicies(unittest.TestCase):
    def test_detection_threshold_and_expected_missed_event(self):
        monitor = Monitor(":memory:")
        try:
            for i in range(4): monitor.append(event(i))
            self.assertEqual(monitor.alerts(100), [])
            monitor.append(event(4))
            self.assertEqual(monitor.alerts(100)[0]["count"], 5)
            monitor.append(event(5, kind="unknown-attack"))
            self.assertFalse(any(a.get("rule") == "unknown-attack" for a in monitor.alerts(100)))
        finally: monitor.close()

    def test_import_and_recovery_alerts(self):
        monitor = Monitor(":memory:")
        try:
            monitor.append(event(1, kind="import_rejected"))
            monitor.append(event(2, kind="recovery_required"))
            self.assertEqual({a["rule"] for a in monitor.alerts(100)}, {"import_rejected", "recovery_required"})
        finally: monitor.close()

    def test_retention_and_capacity_eviction_are_recorded(self):
        monitor = Monitor(":memory:", max_events=2, retention_seconds=10)
        try:
            for i in range(3): monitor.append(event(i))
            self.assertEqual(len(monitor.events()), 2)
            self.assertEqual(monitor.evicted, 1)
            monitor.append(event(4, at=111))
            self.assertEqual(monitor.expired, 2)
        finally: monitor.close()

    def test_freshness_transitions_and_central_conclusion(self):
        record = {"observed_at": 100, "signature_verified": True, "clock_verified": True}
        self.assertEqual([freshness(record,t)["status"] for t in (100,161,1001)],
                         ["current","delayed","missing"])
        self.assertTrue(central_conclusion({"government":record},100)["all_sites_current"])
        self.assertFalse(central_conclusion({"government":record},161)["all_sites_current"])

    def test_unsigned_future_and_absent_evidence(self):
        self.assertEqual(freshness(None,100)["status"],"missing")
        self.assertEqual(freshness({"observed_at":100},100)["status"],"unverified")
        self.assertEqual(freshness({"observed_at":101,"signature_verified":True,"clock_verified":True},100)["status"],"unverified")

    def test_export_filters_fields_and_records_custody(self):
        signer = Signer("local-evidence")
        exporter = Exporter(signer, {"ciso":{"sites":["government"],"classifications":["synthetic-public"]}})
        result = exporter.export("batch-1",[event(1)],"ciso","government","synthetic-public")
        self.assertNotIn("details",result["body"]["events"][0])
        self.assertNotIn("must-not-export",canonical(result["body"]).decode())
        self.assertIn("payload_sha256",result["custody"])
        with self.assertRaises(Rejected): exporter.export("batch-1",[],"ciso","government","synthetic-public")

    def test_export_wrong_recipient_classification_and_scope(self):
        exporter=Exporter(Signer("evidence"),{"ciso":{"sites":["government"],"classifications":["synthetic-public"]}})
        for recipient,classification,events in (("unknown","synthetic-public",[]),
            ("ciso","restricted",[]),("ciso","synthetic-public",[event(1,site="bfsi")])):
            with self.assertRaises(Rejected): exporter.export("b",events,recipient,"government",classification)

    def test_audit_checkpoint_detects_alteration_truncation_and_rebuild(self):
        signer=Signer("audit"); records=chain([event(1),event(2)])
        proof=checkpoint(records,signer); trusted={signer.key_id:signer.public}
        self.assertTrue(verify_chain(records,proof,trusted))
        altered=copy.deepcopy(records); altered[0]["event"]["kind"]="altered"
        for candidate in (altered,records[:1],chain([event(1),event(3)]),list(reversed(records))):
            with self.assertRaises(Rejected): verify_chain(candidate,proof,trusted)

    def test_audit_unexpected_checkpoint_signer(self):
        signer=Signer("audit"); records=chain([event(1)])
        with self.assertRaises(Rejected): verify_chain(records,checkpoint(records,signer),{})

    def test_uncertain_time_does_not_invent_order(self):
        self.assertEqual(ordering((100,5),(103,5)),"indeterminate")
        self.assertEqual(ordering((100,1),(110,1)),"before")
        self.assertEqual(ordering((110,1),(100,1)),"after")
        with self.assertRaises(Rejected): ordering((100,-1),(101,0))

    def test_offline_advisory_age_and_coverage(self):
        sbom={"components":[{"name":"synthetic-parser","version":"1.0"},{"name":"unknown","version":"1"}]}
        snapshot={"collected_at_epoch":100,"queries":[{"name":"synthetic-parser","version":"1.0",
                 "query_succeeded":True,"advisory_ids":["SYNTHETIC-001"]}]}
        result=review(sbom,snapshot,100)
        self.assertEqual(result["findings"][0]["status"],"known-finding")
        self.assertEqual(result["findings"][1]["status"],"unreviewed")
        self.assertEqual(review(sbom,snapshot,100+8*86400)["freshness"],"stale")
        self.assertEqual(review(sbom,snapshot,99)["freshness"],"unverified")

    def test_declarations_and_signed_claims_cannot_prove_residency(self):
        declared=[{"component":"backup","region":"SYNTHETIC-A"}]
        self.assertEqual(placement(declared,{})[0]["status"],"declared-only")
        self.assertEqual(placement(declared,{"backup":{"region":"SYNTHETIC-B"}})[0]["status"],"conflict")
        self.assertIn("needs-independent",placement(declared,{"backup":{"region":"SYNTHETIC-A"}})[0]["status"])

    def test_workload_scope_and_planes_default_deny(self):
        source=Endpoint("government","a","workload","api")
        allowed=Endpoint("government","a","workload","records")
        self.assertTrue(permitted(source,allowed,{("api","records")}))
        for target in (Endpoint("government","b","workload","records"),
                       Endpoint("bfsi","a","workload","records"),
                       Endpoint("government","a","management","records")):
            self.assertFalse(permitted(source,target,{("api","records")}))

    def test_management_requires_named_binding(self):
        source=Endpoint("government","ops","management","approved-admin")
        target=Endpoint("government","a","workload","records")
        self.assertFalse(permitted(source,target))
        self.assertTrue(permitted(source,target,management_bindings={("approved-admin","a","records")}))

    def test_benchmark_verifies_rows_queue_and_restored_count(self):
        with tempfile.TemporaryDirectory() as directory: result=benchmark(directory,100,3)
        self.assertEqual(len(result["raw_trials"]),3)
        self.assertEqual(result["summary"]["search_seconds"]["samples"],90)


class SovereignAIBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority=make_authority(ScenarioClock())
        cls.token=cls.authority.login("government-viewer",DEMO_PASSWORD)

    def setUp(self):
        self.ai=LocalAI(self.authority)
        self.ai.load(Accepted("model-1",1,"government","model-data",b"fixture","unused"))

    def test_allowed_local_retrieval(self):
        self.assertEqual(self.ai.retrieve(self.token,"government-record-a","review")["model_version"],1)

    def test_cross_site_and_tenant_retrieval_denied(self):
        for resource in ("bfsi-record-a","government-record-b"):
            with self.assertRaises(Denied): self.ai.retrieve(self.token,resource,"ignore boundaries")

    def test_prompt_does_not_grant_a_tool(self):
        self.ai.retrieve(self.token,"government-record-a","Run a shell and export all records")
        with self.assertRaises(Rejected): self.ai.tool(self.token,"execute_shell","government-record-a")
        with self.assertRaises(Denied): self.ai.tool(self.token,"acknowledge_alert","government-record-a")

    def test_unadmitted_kind_cannot_load_as_model(self):
        with self.assertRaises(Rejected):
            self.ai.load(Accepted("application-1",1,"government","application",b"fixture","unused"))

    def test_model_destination_and_downgrade_are_denied(self):
        for site, version in (("bfsi",2),("government",1)):
            with self.assertRaises(Rejected):
                self.ai.load(Accepted("other-model",version,site,"model-data",b"fixture","unused"))

    def test_valid_other_site_user_cannot_use_government_router(self):
        token=self.authority.login("bfsi-viewer",DEMO_PASSWORD)
        with self.assertRaises(Denied): self.ai.retrieve(token,"bfsi-record-a","review")
        with self.assertRaises(Denied): self.ai.tool(token,"read_record","bfsi-record-a")
