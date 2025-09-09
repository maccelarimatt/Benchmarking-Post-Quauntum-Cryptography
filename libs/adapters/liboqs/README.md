# pqcbench-liboqs

liboqs-backed adapters for KEM (Kyber/ML-KEM, HQC) and signatures (Dilithium/ML-DSA, Falcon, SPHINCS+, XMSSMT).

## Installation

This package expects the python bindings for liboqs (PyPI package name: `oqs`):

```
pip install --index-url https://openquantumsafe.jfrog.io/artifactory/api/pypi/pypi-oqs/simple oqs
```

If the above fails (no matching distribution), you’re likely on an unsupported Python/platform combo for the prebuilt wheels. Either:

- Upgrade to a supported Python (3.10–3.12 recommended) and try again, or
- Build from source following the liboqs‑python README: https://github.com/open-quantum-safe/liboqs-python#installation

Depending on your platform, you may need to install the liboqs C library and build tools (cmake, ninja, OpenSSL) first. See Open Quantum Safe docs for details.

If `python-oqs` is not available at runtime, the adapters automatically fall back to placeholders so the CLI/GUI still run.

## Selecting parameter sets

Adapters pick a sensible default by probing enabled algorithms in your liboqs build. You can override the selection via environment variables:

- `PQCBENCH_KYBER_ALG` (e.g., `ML-KEM-768`, `Kyber768`, `ML-KEM-1024`)
- `PQCBENCH_HQC_ALG` (e.g., `HQC-128`, `HQC-192`, `HQC-256`)
- `PQCBENCH_DILITHIUM_ALG` (e.g., `ML-DSA-65`, `Dilithium2`, `ML-DSA-87`)
- `PQCBENCH_FALCON_ALG` (e.g., `Falcon-512`, `Falcon-1024`)
- `PQCBENCH_SPHINCS_ALG` (e.g., `SPHINCS+-SHA2-128f-simple`)
- `PQCBENCH_XMSSMT_ALG` (e.g., `XMSSMT-SHA2_20/2_256`)

Example:

```
export PQCBENCH_KYBER_ALG=ML-KEM-1024
export PQCBENCH_DILITHIUM_ALG=ML-DSA-65
```

Run a quick check via the CLI:

```
pqcbench list-algos
run-kyber --runs 5 --export results/kyber.json
run-dilithium --runs 5 --message-size 1024 --export results/dilithium.json
```
