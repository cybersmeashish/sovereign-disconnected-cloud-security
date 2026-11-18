"""Maintained Ed25519/AES-GCM primitives; ephemeral lab custody only."""
import base64
import hashlib
import json
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Rejected(ValueError):
    """An assurance gate rejected an untrusted input."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def b64(data):
    return base64.b64encode(data).decode()


def unb64(value):
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise Rejected("invalid binary encoding") from error


class Signer:
    def __init__(self, key_id):
        self.key_id = key_id
        self._key = Ed25519PrivateKey.generate()

    @property
    def public(self):
        return self._key.public_key().public_bytes_raw()

    def sign(self, message):
        return {"key_id": self.key_id, "signature": b64(self._key.sign(message))}


def verify(message, envelope, trusted):
    if not isinstance(envelope, dict) or set(envelope) != {"key_id", "signature"}:
        raise Rejected("invalid signature envelope")
    key_id = envelope["key_id"]
    if not isinstance(key_id, str) or key_id not in trusted:
        raise Rejected("unexpected signer")
    try:
        Ed25519PublicKey.from_public_bytes(trusted[key_id]).verify(
            unb64(envelope["signature"]), message,
        )
    except (InvalidSignature, ValueError, TypeError) as error:
        raise Rejected("signature verification failed") from error
    return key_id


def approve(signer, purpose, body):
    return signer.sign(canonical({"purpose": purpose, "digest": digest(body)}))


def approvals(body, purpose, envelopes, policy):
    """Policy supplies pinned public keys and duties; inputs cannot assign roles."""
    if not isinstance(envelopes, list) or len(envelopes) != 2:
        raise Rejected("two independent approvals required")
    public_keys = {name: item["public"] for name, item in policy.items()}
    if len(set(public_keys.values())) != len(public_keys):
        raise Rejected("approval identities must have distinct keys")
    message = canonical({"purpose": purpose, "digest": digest(body)})
    identities = [verify(message, envelope, public_keys) for envelope in envelopes]
    duties = {policy[name]["duty"] for name in identities}
    if len(set(identities)) != 2 or duties != {"security", "operations"}:
        raise Rejected("security and operations must approve independently")
    return identities


class Vault:
    """Simulated software custody; no HSM, threshold encryption or durable store."""
    def __init__(self, scope, approval_policy):
        self.scope, self.policy = scope, approval_policy
        self.version = 1
        self.keys = {1: AESGCM.generate_key(bit_length=256)}

    def rotate(self, evidence):
        body = canonical({"scope": self.scope, "next_version": self.version + 1})
        approvals(body, "rotate-key", evidence, self.policy)
        self.version += 1
        self.keys[self.version] = AESGCM.generate_key(bit_length=256)
        return self.version

    def encrypt(self, plaintext):
        header = {"scope": self.scope, "version": self.version}
        nonce = os.urandom(12)
        return {**header, "nonce": b64(nonce), "ciphertext": b64(
            AESGCM(self.keys[self.version]).encrypt(nonce, plaintext, canonical(header))
        )}

    def decrypt(self, record):
        if record.get("scope") != self.scope or type(record.get("version")) is not int:
            raise Rejected("key scope or version denied")
        version = record["version"]
        if version not in self.keys:
            raise Rejected("key version unavailable")
        try:
            return AESGCM(self.keys[version]).decrypt(
                unb64(record["nonce"]), unb64(record["ciphertext"]),
                canonical({"scope": self.scope, "version": version}),
            )
        except (InvalidTag, KeyError, ValueError) as error:
            raise Rejected("encrypted record integrity failed") from error

    def backup(self, wrapping_key):
        header = {"scope": self.scope, "format": "software-vault-backup-v1"}
        payload = canonical({"version": self.version,
                             "keys": {str(k): b64(v) for k, v in self.keys.items()}})
        nonce = os.urandom(12)
        return {**header, "nonce": b64(nonce),
                "ciphertext": b64(AESGCM(wrapping_key).encrypt(nonce, payload, canonical(header)))}

    @classmethod
    def recover(cls, record, wrapping_key, evidence, policy, expected_scope):
        approvals(canonical(record), "recover-key", evidence, policy)
        header = {"scope": expected_scope, "format": "software-vault-backup-v1"}
        if record.get("scope") != expected_scope or record.get("format") != header["format"]:
            raise Rejected("recovery scope denied")
        try:
            payload = json.loads(AESGCM(wrapping_key).decrypt(
                unb64(record["nonce"]), unb64(record["ciphertext"]), canonical(header)))
            version = payload["version"]
            keys = {int(k): unb64(v) for k, v in payload["keys"].items()}
            if type(version) is not int or version not in keys or any(len(k) != 32 for k in keys.values()):
                raise Rejected("invalid recovered key material")
        except (InvalidTag, KeyError, ValueError) as error:
            raise Rejected("recovery failed") from error
        vault = cls(expected_scope, policy)
        vault.version, vault.keys = version, keys
        return vault


def demo_signers():
    release, security, operations = Signer("release"), Signer("security"), Signer("operations")
    policy = {s.key_id: {"public": s.public, "duty": s.key_id} for s in (security, operations)}
    return release, security, operations, policy
