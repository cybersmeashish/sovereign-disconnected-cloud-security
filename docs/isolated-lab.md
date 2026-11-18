# 06 — Reproducible isolated-site reference lab

The environment uses a digest-pinned official Python 3.12 image, standard-library code, synthetic records, and a loopback-only HTTP service. No packages are downloaded during the lab run.

## Prepare while connected

From the repository root, with a running Docker engine:

```bash
docker pull python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
docker build --network=none --pull=false -t ashish-sovereign-lab:contributions-01-07 .
python3 -m unittest discover -s tests -v
```

The base-image fetch and preparation may require registry access. Keep that preparation separate from the isolated execution being evaluated. The image digest is a reproducibility input, not an asserted publisher signature or provenance attestation.

## Run with external networking disabled

```bash
python3 -m tools.run_isolated_lab --output evidence/local/isolation-report.json
```

The runner creates a uniquely named container with `--network none`, a read-only root filesystem, all capabilities dropped, no-new-privileges, a non-root user, and bounded processes/memory/CPU. It inspects the actual configuration, starts the lab, compares source hashes inside the image with the current checkout, captures the result, and removes only that disposable container.

It requires:

- only the Linux loopback interface;
- no default IPv4 route;
- an attempted TCP connection to the documentation-only address `192.0.2.1:443` returning kernel `ENETUNREACH`, rather than treating a timeout as proof;
- successful local loopback login and record access, alongside the expected authorization denials;
- matching source manifests and a zero container exit status.

The workload exercises three logical Government/BFSI/Oil & Gas fixtures in one container. It is not three independently deployed sovereign sites. The dependency checker supplies modeled outage results; DNS, registries, PKI, monitoring platforms, signature verification and recovery services are not deployed here.

For Podman, build the same image and pass `--runtime podman`. Docker is the observed verification environment; Podman support is an unverified CLI compatibility path.

[Offline identity](offline-identity.md) · [Verification](verification.md) · [Docker's network-none documentation](https://docs.docker.com/engine/network/drivers/none/)
