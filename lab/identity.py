"""In-memory, scoped identity reference; standard-library primitives only.

Authority, resources, sessions, and audit events are ephemeral. A reviewed
production IdP, durable state, trusted time, TLS, MFA, and rate controls are
separate work. Credentials in lab fixtures are intentionally public examples.
"""
from dataclasses import dataclass, field
import hashlib
import hmac
import math
import secrets
import threading
import time

PASSWORD_ITERATIONS = 600_000
ROLE_ACTIONS = {
    "viewer": frozenset({"read_record"}),
    "analyst": frozenset({"read_record", "acknowledge_alert"}),
    "service_reader": frozenset({"read_record"}),
    "identity_admin": frozenset({"revoke_identity", "grant_role", "revoke_role"}),
    "emergency_approver": frozenset({"approve_emergency"}),
}
DELEGATABLE_ROLES = frozenset({"viewer", "analyst", "service_reader"})
EMERGENCY_ACTIONS = frozenset({"read_record", "acknowledge_alert"})


class Denied(Exception):
    """Authentication, scope, expiry, or policy denial."""


class ClockFault(Denied):
    """Unusable or backward clock; no continued authorization."""


def _duration(value, maximum):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or not 0 < value <= maximum):
        raise ValueError(f"duration must be finite, positive, and at most {maximum}")
    return value


@dataclass(frozen=True)
class Resource:
    id: str
    site_id: str
    tenant_id: str
    body: dict = field(default_factory=dict)


@dataclass
class Principal:
    id: str
    site_id: str
    tenant_id: str
    kind: str
    salt: bytes
    password_hash: bytes
    active: bool = True
    roles: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Session:
    principal_id: str
    expires_at: float
    emergency_resource_id: str | None = None
    approval_ids: tuple = ()


class Authority:
    def __init__(self, clock=time.time):
        self.clock = clock
        self.principals = {}
        self.resources = {}
        self.sessions = {}
        self.audit = []
        self._floor = None
        self._lock = threading.RLock()

    def _now(self):
        try:
            now = self.clock()
        except Exception as error:
            raise ClockFault("local clock unavailable") from error
        if (isinstance(now, bool) or not isinstance(now, (int, float))
                or not math.isfinite(now) or now < 0):
            raise ClockFault("local clock unavailable")
        if self._floor is not None and now < self._floor:
            raise ClockFault("local clock moved backward")
        self._floor = now
        return now

    def _event(self, event, subject, result, resource_id=None):
        # Never include passwords or session tokens in evidence.
        self.audit.append({
            "event": event, "subject": subject, "result": result,
            "resource_id": resource_id, "observed_time": self._floor,
        })

    def add_principal(self, principal_id, site_id, tenant_id, password, roles, kind="human"):
        """Trusted bootstrap only; never exposed through the HTTP service."""
        with self._lock:
            now = self._now()
            if principal_id in self.principals:
                raise ValueError("duplicate principal")
            if any(not isinstance(value, str) or not value.strip()
                   for value in (principal_id, site_id, tenant_id)):
                raise ValueError("principal and scope IDs required")
            if not isinstance(password, str) or not 16 <= len(password) <= 256:
                raise ValueError("lab passphrase must contain 16 to 256 characters")
            if kind not in {"human", "service"} or not isinstance(roles, dict) or not roles:
                raise ValueError("principal kind and nonempty role map required")
            for role, expiry in roles.items():
                if role not in ROLE_ACTIONS:
                    raise ValueError("unknown bootstrap role")
                if (isinstance(expiry, bool) or not isinstance(expiry, (int, float))
                        or not math.isfinite(expiry) or expiry <= now):
                    raise ValueError("bootstrap role expiry must be finite and in the future")
            salt = secrets.token_bytes(16)
            digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ITERATIONS)
            self.principals[principal_id] = Principal(
                principal_id, site_id, tenant_id, kind, salt, digest, roles=dict(roles),
            )

    def add_resource(self, resource):
        """Trusted store registration: request-supplied tenant claims are unused."""
        with self._lock:
            if (not isinstance(resource, Resource) or resource.id in self.resources
                    or any(not isinstance(value, str) or not value.strip()
                           for value in (resource.id, resource.site_id, resource.tenant_id))):
                raise ValueError("unique, scoped resource required")
            self.resources[resource.id] = resource

    def _has_role(self, principal, role, now):
        return principal.active and principal.roles.get(role, 0) > now

    def login(self, principal_id, password, ttl=900):
        with self._lock:
            _duration(ttl, 900)
            now = self._now()
            principal = self.principals.get(principal_id) if isinstance(principal_id, str) else None
            if not isinstance(password, str) or len(password) > 256:
                raise Denied("invalid credentials")
            # Dummy work for an unknown principal; no external identity lookup.
            salt = principal.salt if principal else b"synthetic-dummy!"
            digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ITERATIONS)
            valid = principal and principal.active and hmac.compare_digest(digest, principal.password_hash)
            if not valid or not any(self._has_role(principal, role, now) for role in principal.roles):
                self._event("login", "unknown" if not principal else principal.id, "denied")
                raise Denied("invalid credentials")
            token = secrets.token_urlsafe(32)
            self.sessions[token] = Session(principal.id, now + ttl)
            self._event("login", principal.id, "allowed")
            return token

    def _session(self, token, now):
        session = self.sessions.get(token) if isinstance(token, str) else None
        principal = self.principals.get(session.principal_id) if session else None
        if not session or session.expires_at <= now or not principal or not principal.active:
            raise Denied("invalid or expired session")
        return session, principal

    def _check(self, token, action, resource, now):
        session, principal = self._session(token, now)
        if (principal.site_id, principal.tenant_id) != (resource.site_id, resource.tenant_id):
            raise Denied("scope denied")
        if session.emergency_resource_id is not None:
            if action not in EMERGENCY_ACTIONS or resource.id != session.emergency_resource_id:
                raise Denied("emergency scope denied")
            for approver_id in session.approval_ids:
                approver = self.principals.get(approver_id)
                if (not approver or not self._has_role(approver, "emergency_approver", now)
                        or (approver.site_id, approver.tenant_id) != (resource.site_id, resource.tenant_id)):
                    raise Denied("emergency approval no longer valid")
            return principal
        if not any(
            action in ROLE_ACTIONS[role] and self._has_role(principal, role, now)
            for role in principal.roles
        ):
            raise Denied("action denied")
        return principal

    def authorize(self, token, action, resource_id):
        with self._lock:
            now = self._now()
            resource = self.resources.get(resource_id) if isinstance(resource_id, str) else None
            try:
                if not resource or not isinstance(action, str):
                    raise Denied("resource or action denied")
                principal = self._check(token, action, resource, now)
            except Denied:
                self._event("authorize", "unresolved", "denied", resource_id if isinstance(resource_id, str) else None)
                raise
            self._event("authorize", principal.id, "allowed", resource.id)
            return resource

    def _admin_target(self, actor_token, action, principal_id, now):
        target = self.principals.get(principal_id)
        if not target:
            raise Denied("unknown target")
        context = Resource(f"identity:{target.id}", target.site_id, target.tenant_id)
        return self._check(actor_token, action, context, now), target

    def revoke_identity(self, actor_token, principal_id):
        with self._lock:
            now = self._now()
            actor, target = self._admin_target(actor_token, "revoke_identity", principal_id, now)
            target.active = False
            self.sessions = {token: session for token, session in self.sessions.items()
                             if session.principal_id != principal_id}
            self._event("revoke_identity", actor.id, "allowed", f"identity:{target.id}")

    def grant_role(self, actor_token, principal_id, role, ttl):
        with self._lock:
            _duration(ttl, 3600)
            now = self._now()
            actor, target = self._admin_target(actor_token, "grant_role", principal_id, now)
            if (not isinstance(role, str) or role not in DELEGATABLE_ROLES
                    or not target.active or actor.id == target.id):
                raise Denied("role cannot be delegated")
            target.roles[role] = now + ttl
            self._event("grant_role", actor.id, "allowed", f"identity:{target.id}")

    def revoke_role(self, actor_token, principal_id, role):
        with self._lock:
            now = self._now()
            actor, target = self._admin_target(actor_token, "revoke_role", principal_id, now)
            target.roles.pop(role, None)
            self._event("revoke_role", actor.id, "allowed", f"identity:{target.id}")

    def emergency_session(self, requester_token, approval_tokens, resource_id, reason, ttl=300):
        with self._lock:
            _duration(ttl, 300)
            now = self._now()
            _, requester = self._session(requester_token, now)
            resource = self.resources.get(resource_id) if isinstance(resource_id, str) else None
            if (requester.kind != "human" or not resource
                    or (requester.site_id, requester.tenant_id) != (resource.site_id, resource.tenant_id)
                    or not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 200
                    or not isinstance(approval_tokens, (list, tuple)) or len(approval_tokens) != 2):
                raise Denied("emergency request denied")
            approvers = []
            for token in approval_tokens:
                approver = self._check(token, "approve_emergency", resource, now)
                if (approver.kind != "human" or approver.id == requester.id
                        or not self._has_role(approver, "emergency_approver", now)
                        or (approver.site_id, approver.tenant_id) != (resource.site_id, resource.tenant_id)):
                    raise Denied("emergency approval denied")
                approvers.append(approver.id)
            if len(set(approvers)) != 2:
                raise Denied("two independent approvers required")
            token = secrets.token_urlsafe(32)
            self.sessions[token] = Session(requester.id, now + ttl, resource.id, tuple(approvers))
            self._event("emergency_session", requester.id, "allowed", resource.id)
            return token
