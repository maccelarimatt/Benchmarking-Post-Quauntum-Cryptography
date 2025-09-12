
# PQC Investigation – Modular Monorepo

A modular, multi-package repository for benchmarking classical and post‑quantum cryptography (RSA‑OAEP, RSA‑PSS, Kyber/ML‑KEM, HQC, Dilithium/ML‑DSA, Falcon/FN‑DSA, SPHINCS+, XMSSMT, MAYO) with ACVP validation, a CLI, and a Flask GUI.

## Quick start (dev)
```bash
# Linux/macOS (PowerShell script also included for Windows)
python -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-dev.txt
pre-commit install
pytest -q
pqcbench --help   # CLI entry point
FLASK_APP=apps/gui/src/webapp/app.py flask run
```

## Environment with liboqs (HQC, XMSS/XMSSMT enabled)

If you need full PQC support via liboqs (Kyber, HQC, Dilithium, Falcon, SPHINCS+, XMSS/XMSSMT), build from source using the helper script. This ensures HQC and XMSSMT are enabled.

Prereqs:
- Build tools: `git`, `cmake`, `ninja` (optional but recommended)
- OpenSSL 3.x (recommended). On macOS: `brew install cmake ninja openssl@3`

Steps:
```bash
# If its showing (base)
conda deactivate

$PY312 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements-dev.txt

#python3 -m venv .venv && source .venv/bin/activate

# Build and install liboqs + python bindings locally under .local/oqs
scripts/setup_oqs.sh --branch main   # or omit to use main

# Export runtime env so Python can find the shared lib
source scripts/env.example.sh

# Install repo packages (editable)
#pip install -r requirements-dev.txt

pqcbench probe-oqs

# Sanity check
# Just run this again if it cant find the algorithms
pqcbench list-algos
#pip uninstall -y oqs
#bash scripts/setup_oqs.sh --branch 0.10.0
#source scripts/env.example.sh
#pqcbench list-algos 
run-kyber --runs 5 --export results/kyber.json
run-hqc --runs 5 --export results/hqc.json
run-xmssmt --runs 3 --export results/xmssmt.json



## If you add a new PQC, run the following:
pip install --upgrade pip setuptools wheel
pip install -r requirements-dev.txt
```

Notes:
- The script enables a broad set of algorithms (not a minimal build) and links with OpenSSL if available.
- On macOS, ensure `DYLD_LIBRARY_PATH` includes `.local/oqs/lib`; on Linux, ensure `LD_LIBRARY_PATH` does. The `scripts/env.example.sh` does this for you.
- You can pin `--branch` to a liboqs release tag (e.g., `0.10.0`) for stability.
- To select parameter sets, set env vars like `PQCBENCH_KYBER_ALG=ML-KEM-1024` or `PQCBENCH_XMSSMT_ALG=XMSSMT-SHA2_20/2_256`.

## Repo map
```
.
├─ apps/
│  ├─ cli/            # CLI app: runs algos, ACVP checks, benchmarks
│  └─ gui/            # Flask GUI for demos/visualisations
├─ libs/
│  ├─ core/           # Interfaces, registry, metrics, shared utils
│  └─ adapters/
│     ├─ liboqs/      # PQC adapters using liboqs (Kyber, Dilithium, Falcon, etc.)
│     └─ rsa/         # Classical RSA-OAEP / RSA-PSS adapter
├─ acvp/              # ACVP harness, vector management
├─ benchmarks/        # Reproducible benchmark scenarios + scripts
├─ tests/             # Unit + integration tests
├─ docs/              # Optional: MkDocs (or Sphinx) docs scaffold
├─ results/           # CSV/JSON benchmark outputs (gitignored)
├─ scripts/           # Dev/setup utilities
├─ .github/workflows/ # CI
└─ requirements-dev.txt
```

## Design principles
- **Interfaces first:** algorithm‑agnostic `KEM` and `Signature` protocols define the contract.
- **Adapters:** each algorithm lives behind a small adapter package (e.g., `pqcbench_liboqs`, `pqcbench_rsa`).
- **Registry:** adapters self‑register; the CLI/GUI discover algorithms at runtime without import spaghetti.
- **ACVP harness:** vectors in `acvp/vectors` (tracked with Git LFS), scripts in `acvp/harness`.
- **Benchmarks:** deterministic scenarios; outputs are machine‑readable (CSV/JSON) and versioned.
- **Separation of concerns:** GUI/CLI never talk to liboqs/crypto directly—only via the core interfaces.

Replace `@studentA` / `@studentB` in `CODEOWNERS` with your GitHub handles.


## One-command runners (installed via editable install)
After `pip install -r requirements-dev.txt`, the following commands are available:
```
run-kyber         # KEM
run-hqc           # KEM
run-rsa-oaep      # KEM-style wrapper
run-dilithium     # SIG
run-falcon        # SIG
run-sphincsplus   # SIG
run-xmssmt        # SIG
run-rsa-pss       # SIG
run-mayo          # SIG
```
Each supports `--runs N` and (for signatures) `--message-size BYTES`, plus `--export results/<file>.json`.
Examples:
```
run-kyber --runs 50 --export results/kyber.json
run-dilithium --runs 50 --message-size 4096 --export results/dilithium.json
```
On Windows you can also use the wrappers in `scripts\run_*.ps1`.

## Selecting PQC parameter sets

The liboqs-backed adapters auto-detect available algorithms. You can override the chosen parameter set via environment variables (if supported by your liboqs build):

- `PQCBENCH_KYBER_ALG` (e.g., `ML-KEM-768`, `ML-KEM-1024`, `Kyber768`)
- `PQCBENCH_HQC_ALG` (e.g., `HQC-128`, `HQC-192`, `HQC-256`)
- `PQCBENCH_DILITHIUM_ALG` (e.g., `ML-DSA-65`, `Dilithium2`)
- `PQCBENCH_FALCON_ALG` (e.g., `Falcon-512`)
- `PQCBENCH_SPHINCS_ALG` (e.g., `SPHINCS+-SHA2-128f-simple`)
- `PQCBENCH_XMSSMT_ALG` (e.g., `XMSSMT-SHA2_20/2_256`)
- `PQCBENCH_MAYO_ALG` (e.g., `MAYO-1`, `MAYO-2`, `MAYO-3`, `MAYO-5`)

Example:

```
export PQCBENCH_KYBER_ALG=ML-KEM-1024
export PQCBENCH_DILITHIUM_ALG=ML-DSA-65
```

Compatibility: legacy `*_MECH` env vars (e.g., `KYBER_MECH`) are also honored,
but `PQCBENCH_*` takes precedence when both are set.

### Metrics captured
- Latency per operation: `mean_ms`, `min_ms`, `max_ms`, and per-run `series`.
- Sizes: `public_key_len`, `secret_key_len`, and `ciphertext_len`/`signature_len`.
- Memory footprint: peak RSS delta per run (`mem_series_kb`) with summary fields
  `mem_mean_kb`, `mem_min_kb`, `mem_max_kb` when `psutil` is available. If `psutil`
  is not installed, these fields are omitted or null.
