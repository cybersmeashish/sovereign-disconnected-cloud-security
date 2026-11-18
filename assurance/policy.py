"""Trusted-endpoint policy model; it does not install packet-filter rules."""
from dataclasses import dataclass
from .crypto import Rejected
from lab.identity import Denied


@dataclass(frozen=True)
class Endpoint:
    site: str
    tenant: str
    plane: str
    service: str


def permitted(source, destination, service_bindings=(), management_bindings=()):
    if (source.plane not in {"management", "workload", "evidence"}
            or destination.plane not in {"management", "workload", "evidence"}
            or source.site != destination.site):
        return False
    if source.plane == "management" and destination.plane == "workload":
        return (source.service, destination.tenant, destination.service) in management_bindings
    if source.tenant != destination.tenant:
        return False
    if source.plane == "workload" and destination.plane in {"workload", "evidence"}:
        return (source.service, destination.service) in service_bindings
    return False


class LocalAI:
    """Deterministic fixture router, with no learned model or external calls."""
    def __init__(self, authority, site="government"):
        self.authority, self.site = authority, site
        self.model_version = None

    def load(self, accepted):
        if (accepted.kind != "model-data" or accepted.site != self.site
                or self.model_version is not None and accepted.version <= self.model_version):
            raise Rejected("admitted, site-matched newer model-data required")
        self.model_version = accepted.version

    def _resource(self, record_id):
        resource = self.authority.resources.get(record_id) if isinstance(record_id, str) else None
        if not resource or resource.site_id != self.site:
            raise Denied("AI site scope denied")

    def retrieve(self, token, record_id, prompt):
        if self.model_version is None or not isinstance(prompt, str) or len(prompt) > 1000:
            raise Rejected("model or prompt unavailable")
        self._resource(record_id)
        resource = self.authority.authorize(token, "read_record", record_id)
        return {"record_id": resource.id, "model_version": self.model_version,
                "answer": "Synthetic local review; human decision required."}

    def tool(self, token, name, record_id):
        actions = {"read_record": "read_record", "acknowledge_alert": "acknowledge_alert"}
        if name not in actions:
            raise Rejected("tool not permitted")
        self._resource(record_id)
        resource = self.authority.authorize(token, actions[name], record_id)
        return {"tool": name, "resource_id": resource.id, "synthetic": True}
