from copy import deepcopy
import unittest

from lab.fixtures import DEMO_PASSWORD, ScenarioClock, make_authority
from lab.identity import Authority, ClockFault, Denied


class IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = make_authority()

    def setUp(self):
        self.clock = ScenarioClock()
        self.authority = Authority(self.clock)
        self.authority.principals = deepcopy(self.template.principals)
        self.authority.resources = deepcopy(self.template.resources)

    def login(self, suffix="viewer", site="government", **kwargs):
        return self.authority.login(f"{site}-{suffix}", DEMO_PASSWORD, **kwargs)

    def emergency(self, ttl=30):
        return self.authority.emergency_session(
            self.login(), [self.login("approver-a"), self.login("approver-b")],
            "government-record-a", "Synthetic emergency review", ttl,
        )

    def test_valid_login_and_read(self):
        resource = self.authority.authorize(self.login(), "read_record", "government-record-a")
        self.assertTrue(resource.body["synthetic"])

    def test_wrong_password_and_unknown_identity_are_denied(self):
        for principal, password in (("government-viewer", "wrong"), ("unknown", DEMO_PASSWORD)):
            with self.subTest(principal=principal), self.assertRaises(Denied):
                self.authority.login(principal, password)

    def test_unknown_token_action_and_resource_are_denied(self):
        token = self.login()
        for supplied_token, action, resource in (
            ("fabricated-token", "read_record", "government-record-a"),
            (token, "delete_everything", "government-record-a"),
            (token, "read_record", "unknown-resource"),
        ):
            with self.subTest(action=action, resource=resource), self.assertRaises(Denied):
                self.authority.authorize(supplied_token, action, resource)

    def test_cross_site_and_tenant_are_denied(self):
        token = self.login()
        for resource in ("bfsi-record-a", "government-record-b"):
            with self.subTest(resource=resource), self.assertRaises(Denied):
                self.authority.authorize(token, "read_record", resource)

    def test_role_separates_read_from_action(self):
        with self.assertRaises(Denied):
            self.authority.authorize(self.login(), "acknowledge_alert", "government-record-a")
        self.authority.authorize(self.login("analyst"), "acknowledge_alert", "government-record-a")

    def test_expired_session_is_denied_at_boundary(self):
        token = self.login(ttl=5)
        self.clock.value += 5
        with self.assertRaises(Denied):
            self.authority.authorize(token, "read_record", "government-record-a")

    def test_role_expiry_is_checked_on_existing_session(self):
        token, admin = self.login("analyst"), self.login("admin")
        self.authority.grant_role(admin, "government-analyst", "analyst", 5)
        self.clock.value += 5
        with self.assertRaises(Denied):
            self.authority.authorize(token, "acknowledge_alert", "government-record-a")

    def test_role_revocation_is_immediate(self):
        token, admin = self.login(), self.login("admin")
        self.authority.revoke_role(admin, "government-viewer", "viewer")
        with self.assertRaises(Denied):
            self.authority.authorize(token, "read_record", "government-record-a")

    def test_identity_revocation_invalidates_session_and_login(self):
        token, admin = self.login(), self.login("admin")
        self.authority.revoke_identity(admin, "government-viewer")
        with self.assertRaises(Denied):
            self.authority.authorize(token, "read_record", "government-record-a")
        with self.assertRaises(Denied):
            self.login()

    def test_unprivileged_and_cross_site_admin_cannot_revoke(self):
        for actor in (self.login(), self.login("admin", "bfsi")):
            with self.subTest(actor="redacted"), self.assertRaises(Denied):
                self.authority.revoke_identity(actor, "government-analyst")

    def test_admin_cannot_self_grant_or_delegate_privileged_role(self):
        admin = self.login("admin")
        with self.assertRaises(Denied):
            self.authority.grant_role(admin, "government-admin", "viewer", 10)
        with self.assertRaises(Denied):
            self.authority.grant_role(admin, "government-viewer", "identity_admin", 10)

    def test_service_identity_is_scoped_and_cannot_approve(self):
        service = self.login("service")
        self.authority.authorize(service, "read_record", "government-record-a")
        with self.assertRaises(Denied):
            self.authority.authorize(service, "approve_emergency", "government-record-a")

    def test_two_distinct_approvers_allow_bounded_emergency(self):
        emergency = self.emergency()
        self.authority.authorize(emergency, "acknowledge_alert", "government-record-a")

    def test_duplicate_fabricated_and_wrong_scope_approvals_are_denied(self):
        requester, first = self.login(), self.login("approver-a")
        for approvals in ([first, first], [first, "forged"], [first, self.login("approver-b", "bfsi")]):
            with self.subTest(approvals="redacted"), self.assertRaises(Denied):
                self.authority.emergency_session(requester, approvals, "government-record-a", "Synthetic review")

    def test_self_approval_is_denied(self):
        requester = self.login("approver-a")
        with self.assertRaises(Denied):
            self.authority.emergency_session(
                requester, [requester, self.login("approver-b")],
                "government-record-a", "Synthetic review",
            )

    def test_emergency_cannot_change_scope_or_administer_identities(self):
        emergency = self.emergency()
        with self.assertRaises(Denied):
            self.authority.authorize(emergency, "read_record", "government-record-b")
        with self.assertRaises(Denied):
            self.authority.revoke_identity(emergency, "government-analyst")

    def test_emergency_expires_and_approval_revocation_is_effective(self):
        emergency = self.emergency(ttl=5)
        self.clock.value += 5
        with self.assertRaises(Denied):
            self.authority.authorize(emergency, "acknowledge_alert", "government-record-a")
        emergency = self.emergency()
        admin = self.login("admin")
        self.authority.revoke_role(admin, "government-approver-a", "emergency_approver")
        with self.assertRaises(Denied):
            self.authority.authorize(emergency, "acknowledge_alert", "government-record-a")

    def test_clock_rollback_and_unavailable_time_fail_closed(self):
        token = self.login()
        self.clock.value -= 1
        with self.assertRaises(ClockFault):
            self.authority.authorize(token, "read_record", "government-record-a")
        self.authority.clock = lambda: float("nan")
        with self.assertRaises(ClockFault):
            self.login()
        def unavailable():
            raise OSError("synthetic unavailable clock")
        self.authority.clock = unavailable
        with self.assertRaises(ClockFault):
            self.login()

    def test_invalid_duration_is_rejected(self):
        for value in (0, -1, True, float("nan"), float("inf"), 901):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.login(ttl=value)

    def test_audit_contains_no_credentials_or_tokens(self):
        token = self.login()
        self.authority.authorize(token, "read_record", "government-record-a")
        serialized = repr(self.authority.audit)
        self.assertNotIn(DEMO_PASSWORD, serialized)
        self.assertNotIn(token, serialized)
