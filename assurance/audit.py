"""Hash chaining needs an independently trusted signed checkpoint."""
import math
from .crypto import Rejected, canonical, digest, verify


def chain(events):
    records, previous = [], "0" * 64
    for sequence, event in enumerate(events, 1):
        body = {"sequence": sequence, "previous": previous, "event": event}
        previous = digest(canonical(body))
        records.append({**body, "hash": previous})
    return records


def checkpoint(records, signer):
    body = {"count": len(records), "head": records[-1]["hash"] if records else "0" * 64}
    return {"body": body, "signature": signer.sign(canonical(body))}


def verify_chain(records, trusted_checkpoint, public_keys):
    verify(canonical(trusted_checkpoint["body"]), trusted_checkpoint["signature"], public_keys)
    expected = chain([record["event"] for record in records])
    if records != expected:
        raise Rejected("audit chain changed")
    body = {"count": len(records), "head": records[-1]["hash"] if records else "0" * 64}
    if body != trusted_checkpoint["body"]:
        raise Rejected("checkpoint mismatch: truncation or replacement")
    return True


def interval(wall_time, uncertainty):
    if (any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v)
            for v in (wall_time, uncertainty)) or uncertainty < 0):
        raise Rejected("invalid time uncertainty")
    return wall_time - uncertainty, wall_time + uncertainty


def ordering(first, second):
    a, b = interval(*first), interval(*second)
    if a[1] < b[0]:
        return "before"
    if b[1] < a[0]:
        return "after"
    return "indeterminate"
