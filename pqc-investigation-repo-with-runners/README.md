
# PQC Investigation – Modular Monorepo

A modular, multi-package repository for benchmarking classical and post‑quantum cryptography (RSA‑OAEP, RSA‑PSS, Kyber/ML‑KEM, HQC, Dilithium/ML‑DSA, Falcon/FN‑DSA, SPHINCS+, XMSSMT) with ACVP validation, a CLI, and a Flask GUI.

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
```
Each supports `--runs N` and (for signatures) `--message-size BYTES`, plus `--export results/<file>.json`.
Examples:
```
run-kyber --runs 50 --export results/kyber.json
run-dilithium --runs 50 --message-size 4096 --export results/dilithium.json
```
On Windows you can also use the wrappers in `scripts\run_*.ps1`.
