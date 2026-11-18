"""Actual OpenSSL ML-KEM/ML-DSA compatibility experiments; ephemeral keys."""
import argparse
import hmac
import json
from pathlib import Path
import platform
import subprocess
import tempfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from assurance.crypto import Signer, unb64


def exercise(openssl):
    def command(*args, required=True):
        result = subprocess.run([openssl, *args], capture_output=True, timeout=20)
        if required and result.returncode:
            raise RuntimeError(result.stderr.decode())
        return result
    version = command("version").stdout.decode().strip()
    cases = []
    with tempfile.TemporaryDirectory(prefix="sovereign-pq-") as directory:
        root = Path(directory)
        kem, public, ciphertext = (str(root / name) for name in ("kem.pem", "kem-public.pem", "cipher.bin"))
        secret_a, secret_b = str(root / "a.bin"), str(root / "b.bin")
        command("genpkey", "-algorithm", "ML-KEM-768", "-out", kem)
        command("pkey", "-in", kem, "-pubout", "-out", public)
        command("pkeyutl", "-encap", "-pubin", "-inkey", public, "-out", ciphertext, "-secret", secret_a)
        command("pkeyutl", "-decap", "-inkey", kem, "-in", ciphertext, "-secret", secret_b)
        cases.append({"id": "mlkem_roundtrip", "passed": hmac.compare_digest(
            Path(secret_a).read_bytes(), Path(secret_b).read_bytes()),
            "shared_secret_bytes": len(Path(secret_a).read_bytes()),
            "ciphertext_bytes": Path(ciphertext).stat().st_size})
        altered = bytearray(Path(ciphertext).read_bytes()); altered[0] ^= 1
        Path(ciphertext).write_bytes(altered)
        result = command("pkeyutl", "-decap", "-inkey", kem, "-in", ciphertext,
                         "-secret", secret_b, required=False)
        differs = result.returncode != 0 or not hmac.compare_digest(Path(secret_a).read_bytes(), Path(secret_b).read_bytes())
        cases.append({"id": "mlkem_altered_ciphertext", "passed": differs,
                      "observation": "error or a different secret; implicit rejection may return success"})
        message, signature = str(root / "message"), str(root / "signature")
        Path(message).write_bytes(b"synthetic release approval")
        private, public = str(root / "dsa.pem"), str(root / "dsa-public.pem")
        command("genpkey", "-algorithm", "ML-DSA-65", "-out", private)
        command("pkey", "-in", private, "-pubout", "-out", public)
        command("pkeyutl", "-sign", "-rawin", "-inkey", private, "-in", message, "-out", signature)
        result = command("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public,
                         "-in", message, "-sigfile", signature)
        cases.append({"id": "mldsa_roundtrip", "passed": result.returncode == 0,
                      "signature_bytes": Path(signature).stat().st_size})
        Path(message).write_bytes(b"altered release approval")
        result = command("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public,
                         "-in", message, "-sigfile", signature, required=False)
        cases.append({"id": "mldsa_altered_message", "passed": result.returncode != 0})
        wrong = str(root / "wrong.pem")
        command("genpkey", "-algorithm", "ML-DSA-65", "-out", wrong)
        command("pkey", "-in", wrong, "-pubout", "-out", public)
        Path(message).write_bytes(b"synthetic release approval")
        result = command("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public,
                         "-in", message, "-sigfile", signature, required=False)
        cases.append({"id": "mldsa_unexpected_key", "passed": result.returncode != 0})
        signer = Signer("classical-interop")
        Path(public).write_bytes(Ed25519PublicKey.from_public_bytes(signer.public).public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        Path(signature).write_bytes(unb64(signer.sign(Path(message).read_bytes())["signature"]))
        result = command("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public,
                         "-in", message, "-sigfile", signature)
        cases.append({"id": "ed25519_cryptography_openssl_interop", "passed": result.returncode == 0})
    return {"openssl": version, "environment": {"system": platform.system(), "machine": platform.machine()},
            "cases": cases, "passed": all(case["passed"] for case in cases),
            "limits": "Host CLI experiments only. No TLS/hybrid integration, certificate migration, SLH-DSA test, production deployment or FIPS validation. Ephemeral keys and shared secrets are deleted."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = exercise(args.openssl)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "cases": len(report["cases"]), "openssl": report["openssl"]}))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
