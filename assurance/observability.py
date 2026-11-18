"""Local telemetry, bounded retention, evidence freshness and disclosure."""
from collections import Counter
from datetime import datetime, timezone
import json
import math
import sqlite3
from .crypto import Rejected, canonical, digest


class Monitor:
    def __init__(self, path, max_events=100, retention_seconds=600):
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, time REAL, site TEXT, kind TEXT, payload TEXT)")
        self.maximum, self.retention = max_events, retention_seconds
        self.expired = self.evicted = 0

    def close(self):
        self.db.close()

    def append(self, event):
        if (set(event) != {"id", "time", "site", "kind", "details"}
                or any(not isinstance(event[k], str) or not event[k] for k in ("id", "site", "kind"))
                or isinstance(event["time"], bool) or not isinstance(event["time"], (float, int))
                or not math.isfinite(event["time"]) or not isinstance(event["details"], dict)):
            raise Rejected("event schema denied")
        encoded = canonical(event)
        if len(encoded) > 8192:
            raise Rejected("event too large")
        with self.db:
            self.db.execute("INSERT INTO events VALUES (?,?,?,?,?)",
                            (event["id"], event["time"], event["site"], event["kind"], encoded.decode()))
            old = self.db.execute("SELECT COUNT(*) FROM events WHERE time < ?",
                                  (event["time"] - self.retention,)).fetchone()[0]
            self.db.execute("DELETE FROM events WHERE time < ?", (event["time"] - self.retention,))
            self.expired += old
            count = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            excess = max(0, count - self.maximum)
            if excess:
                self.db.execute("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY time,id LIMIT ?)",
                                (excess,))
                self.evicted += excess

    def events(self):
        return [json.loads(row[0]) for row in self.db.execute("SELECT payload FROM events ORDER BY time,id")]

    def alerts(self, now):
        recent = [e for e in self.events() if 0 <= now - e["time"] <= 60]
        denials = Counter(e["site"] for e in recent if e["kind"] == "auth_denied")
        alerts = [{"rule": "repeated-auth-denials", "site": site, "count": count}
                  for site, count in sorted(denials.items()) if count >= 5]
        alerts.extend({"rule": e["kind"], "site": e["site"], "event_id": e["id"]}
                      for e in recent if e["kind"] in {"import_rejected", "recovery_required"})
        return alerts


def freshness(record, now, current_window=60, delayed_window=900):
    if record is None:
        return {"status": "missing", "age_seconds": None}
    observed = record.get("observed_at")
    if (record.get("signature_verified") is not True or record.get("clock_verified") is not True
            or isinstance(observed, bool) or not isinstance(observed, (float, int))
            or not math.isfinite(observed) or not math.isfinite(now) or observed > now):
        return {"status": "unverified", "age_seconds": None}
    age = now - observed
    status = "current" if age <= current_window else "delayed" if age <= delayed_window else "missing"
    return {"status": status, "age_seconds": age}


def central_conclusion(sites, now):
    states = {site: freshness(record, now) for site, record in sites.items()}
    return {"sites": states, "all_sites_current": bool(states) and
            all(state["status"] == "current" for state in states.values())}


class Exporter:
    def __init__(self, signer, recipients):
        self.signer, self.recipients, self.seen = signer, recipients, set()

    def export(self, batch_id, events, recipient, site, classification):
        policy = self.recipients.get(recipient)
        if (not policy or site not in policy["sites"] or classification not in policy["classifications"]
                or not isinstance(batch_id, str) or not batch_id or batch_id in self.seen):
            raise Rejected("recipient, classification, scope or replay denied")
        if any(e.get("site") != site for e in events):
            raise Rejected("cross-site export denied")
        filtered = [{k: event[k] for k in ("id", "site", "kind", "time")} for event in events]
        body = {"batch_id": batch_id, "recipient": recipient, "site": site,
                "classification": classification, "events": filtered}
        custody = {"payload_sha256": digest(canonical(body)), "recipient": recipient,
                   "batch_id": batch_id, "sender_key_id": self.signer.key_id,
                   "created_at": datetime.now(timezone.utc).isoformat()}
        self.seen.add(batch_id)
        return {"body": body, "custody": custody,
                "signature": self.signer.sign(canonical({"body": body, "custody": custody}))}
