# pqcbench-cli

Command-line interface for running micro-benchmarks and simple traces over classical and post-quantum algorithms.

Features
- Runs KEM and Signature ops with repeatable timing loops
- Ships single-command runners for ML-KEM/Kyber, HQC, BIKE, Classic McEliece, FrodoKEM, NTRU, NTRU Prime, and signature suites (ML-DSA/Dilithium, Falcon, SPHINCS+, SLH-DSA, CROSS, MAYO, SNOVA, UOV, XMSSMT) plus RSA baselines
- Exports JSON summaries and optional raw, single-run traces
- Discovers algorithms via adapter registry (RSA and liboqs-backed PQC)

Quick start
- Activate the repo virtualenv and install dev deps: `python -m venv .venv && source .venv/bin/activate && pip install -r requirements-dev.txt`
- List available algorithms: `pqcbench list-algos`
- Probe liboqs mechanisms: `pqcbench probe-oqs`
- Run every test suite: `pqcbench run-tests` (add `--skip-liboqs` if liboqs bindings are not set up)

One-command runners
- KEMs: `run-kyber`, `run-hqc`, `run-bike`, `run-classic-mceliece`, `run-frodokem`, `run-ntru`, `run-ntruprime`, `run-rsa-oaep`
- Signatures: `run-dilithium`, `run-falcon`, `run-sphincsplus`, `run-slh-dsa`, `run-cross`, `run-snova`, `run-uov`, `run-xmssmt`, `run-mayo`, `run-rsa-pss`

Examples
- `run-kyber --runs 20 --export results/kyber.json`
- `run-dilithium --runs 50 --message-size 4096 --export results/dilithium.json`
- Warm runs (reuse process/caches): add `--no-cold` to any runner, e.g. `run-rsa-oaep --no-cold --runs 50`

Environment overrides
- Prefer `PQCBENCH_*` variables to select a mechanism; legacy `*_MECH` also works.
  - KEMs: `PQCBENCH_KYBER_ALG`, `PQCBENCH_HQC_ALG`, `PQCBENCH_BIKE_ALG`, `PQCBENCH_CLASSIC_MCELIECE_ALG`, `PQCBENCH_FRODOKEM_ALG`, `PQCBENCH_NTRU_ALG`, `PQCBENCH_NTRUPRIME_ALG`
  - Signatures: `PQCBENCH_DILITHIUM_ALG`, `PQCBENCH_FALCON_ALG`, `PQCBENCH_SPHINCS_ALG`, `PQCBENCH_SLH_DSA_ALG`, `PQCBENCH_XMSSMT_ALG`, `PQCBENCH_CROSS_ALG`, `PQCBENCH_MAYO_ALG`, `PQCBENCH_SNOVA_ALG`, `PQCBENCH_UOV_ALG`

Notes
- Memory metrics are included when `psutil` is available.
- On Windows use PowerShell wrappers under `scripts/` if preferred.
- By default runs are "cold" (each iteration in a fresh process). Use `--no-cold` to keep CPU caches/warmed code paths between runs for in-process benchmarking.
