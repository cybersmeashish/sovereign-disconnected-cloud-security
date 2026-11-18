"""Encrypted synthetic backup and restoration into an empty directory."""
import json
import os
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .crypto import Rejected, approvals, b64, canonical, digest, unb64


def snapshot(config, records, vault_backup, wrapping_key):
    payload = canonical({"config": config, "records": records, "vault_backup": vault_backup})
    nonce = os.urandom(12)
    return {"schema": "synthetic-snapshot-v1", "nonce": b64(nonce),
            "ciphertext": b64(AESGCM(wrapping_key).encrypt(nonce, payload, b"synthetic-snapshot-v1")),
            "plaintext_sha256": digest(payload)}


def restore(backup, wrapping_key, evidence, policy, directory):
    approvals(canonical(backup), "restore-site", evidence, policy)
    if backup.get("schema") != "synthetic-snapshot-v1":
        raise Rejected("snapshot schema denied")
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    if any(target.iterdir()):
        raise Rejected("clean restoration directory required")
    try:
        raw = AESGCM(wrapping_key).decrypt(
            unb64(backup["nonce"]), unb64(backup["ciphertext"]), b"synthetic-snapshot-v1")
        if digest(raw) != backup["plaintext_sha256"]:
            raise Rejected("snapshot digest denied")
        data = json.loads(raw)
        if set(data) != {"config", "records", "vault_backup"}:
            raise Rejected("snapshot content denied")
    except (InvalidTag, ValueError, KeyError) as error:
        raise Rejected("snapshot restoration failed") from error
    temporary = target / "restored.tmp"
    temporary.write_bytes(raw)
    os.replace(temporary, target / "restored.json")
    return data
