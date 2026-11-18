"""Only synthetic records and publicly documented demonstration credentials."""
from dataclasses import dataclass
from .identity import Authority, Resource

DEMO_PASSWORD = "synthetic-only-passphrase"
SITES = ("government", "bfsi", "oil-gas")


@dataclass
class ScenarioClock:
    value: float = 2_000_000_000

    def __call__(self):
        return self.value


def make_authority(clock=None, sites=SITES):
    clock = clock or ScenarioClock()
    authority = Authority(clock)
    for site in sites:
        for suffix, role, kind in (
            ("viewer", "viewer", "human"), ("analyst", "analyst", "human"),
            ("admin", "identity_admin", "human"),
            ("approver-a", "emergency_approver", "human"),
            ("approver-b", "emergency_approver", "human"),
            ("service", "service_reader", "service"),
        ):
            authority.add_principal(
                f"{site}-{suffix}", site, "tenant-a", DEMO_PASSWORD,
                {role: clock() + 3600}, kind=kind,
            )
        authority.add_resource(Resource(
            f"{site}-record-a", site, "tenant-a",
            {"synthetic": True, "process": {
                "government": "citizen-service status",
                "bfsi": "transaction-review status",
                "oil-gas": "maintenance-review status",
            }[site], "state": "awaiting review"},
        ))
        authority.add_resource(Resource(
            f"{site}-record-b", site, "tenant-b",
            {"synthetic": True, "state": "another tenant"},
        ))
    return authority
