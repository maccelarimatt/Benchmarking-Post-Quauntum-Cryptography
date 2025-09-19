# pqcbench-cli

Command-line interface for running micro-benchmarks and simple traces over classical and post-quantum algorithms.

Features
- Runs KEM and Signature ops with repeatable timing loops
- Exports JSON summaries and optional raw, single-run traces
- Discovers algorithms via adapter registry (RSA and liboqs-backed PQC)

Quick start
- Activate the repo virtualenv and install dev deps: `python -m venv .venv && source .venv/bin/activate && pip install -r requirements-dev.txt`
- List available algorithms: `pqcbench list-algos`
- Probe liboqs mechanisms: `pqcbench probe-oqs`

One-command runners
- `run-kyber`, `run-hqc`, `run-rsa-oaep`
- `run-dilithium`, `run-falcon`, `run-sphincsplus`, `run-xmssmt`, `run-rsa-pss`, `run-mayo`

Examples
- `run-kyber --runs 20 --export results/kyber.json`
- `run-dilithium --runs 50 --message-size 4096 --export results/dilithium.json`
- Warm runs (reuse process/caches): add `--no-cold` to any runner, e.g. `run-rsa-oaep --no-cold --runs 50`

Environment overrides
- Prefer `PQCBENCH_*` variables to select a mechanism; legacy `*_MECH` also works.
  - `PQCBENCH_KYBER_ALG` (e.g., `ML-KEM-768`, `Kyber1024`)
  - `PQCBENCH_HQC_ALG` (e.g., `HQC-192`)
  - `PQCBENCH_DILITHIUM_ALG` (e.g., `ML-DSA-65`)
  - `PQCBENCH_FALCON_ALG` (e.g., `Falcon-512`)
  - `PQCBENCH_SPHINCS_ALG` (e.g., `SPHINCS+-SHA2-128s-simple`)
  - `PQCBENCH_XMSSMT_ALG` (e.g., `XMSSMT-SHA2_20/2_256`)

Notes
- Memory metrics are included when `psutil` is available.
- On Windows use PowerShell wrappers under `scripts/` if preferred.
- By default runs are "cold" (each iteration in a fresh process). Use `--no-cold` to keep CPU caches/warmed code paths between runs for in-process benchmarking.
