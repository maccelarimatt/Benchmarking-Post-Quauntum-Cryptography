# Analysis of Post-Quantum Cryptography (PQC Investigation)

This repository is a modular, multi-package workspace for benchmarking and analyzing classical and post-quantum cryptography. It brings together reusable libraries, algorithm adapters, a Typer-based CLI, a Flask GUI, ACVP tooling, and native extensions so you can evaluate RSA-OAEP, RSA-PSS, ML-KEM (Kyber), HQC, ML-DSA (Dilithium), Falcon, SPHINCS+, XMSSMT, and MAYO under a single workflow.

## Highlights
- Editable multi-package layout (`libs/core`, `libs/adapters/*`, `apps/cli`, `apps/gui`) with shared pytest and linting tooling.
- Benchmark runners capture latency, memory, key sizes, and security estimates with reproducible JSON exports.
- Flask GUI demonstrates the image-encryption pipeline, entropy analytics, and optional LLM-backed commentary for benchmark comparisons.
- Security estimator models classical and quantum costs, produces runtime scaling projections, and performs secret-key sanity checks.
- Baseline CSV bundles, curated benchmark captures, and scripts recreate the published tables and figures.
- Helper scripts build liboqs with HQC/XMSSMT support and compile an optional native C backend for tighter timing.

## Design principles
- Interface-first architecture: shared `KEM`/`Signature` protocols and adapter traits live in `libs/core`, so new algorithms implement a consistent contract.
- Adapter isolation: each scheme family ships as a thin package inside `libs/adapters/*`, keeping third-party dependencies and build steps scoped.
- Registry-driven discovery: adapters self-register with `pqcbench.registry`, letting the CLI, GUI, and tests load algorithms without hard-coded imports.
- Deterministic benchmarking: runners set seeds, capture metadata (git commit, CPU profile, environment), and emit JSON so results are reproducible.
- Documentation and test parity: every feature has a README entry and pytest coverage (`tests/`, `tests/gui/`, `liboqs-python/tests/`) to enforce shared terminology.

## Quick start (development setup)

Prerequisites:
- Python 3.11 or newer
- pip and virtualenv support (`python -m venv`)
- Git, CMake >= 3.24, and Ninja (recommended for native builds)
- OpenSSL 3.x when compiling liboqs

### One-command bootstrap

If you prefer an automated setup, the helper scripts clone the Open Quantum Safe repositories, create the virtual environment, install dependencies, run the native CMake build, and configure development tooling in a single run.

Windows PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup_dev.ps1
```

macOS/Linux (or Git Bash on Windows):
```bash
bash scripts/setup_dev.sh
```

Optional flags:
- `--force-clone` re-clones `liboqs` and `liboqs-python` even if the directories already exist.
- `--skip-native-build` configures the environment without rebuilding `native/`.

The script pins everything to the tested stack: Python dependencies follow `requirements-dev.txt`, while `liboqs` (`b02d0c9`) and `liboqs-python` (`f70842e`) are checked out at known-good commits so future upstream changes do not affect local testing.

Manual steps remain documented below for reference.

1. Create and activate a virtual environment.

   Windows (PowerShell):
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   macOS/Linux:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install the editable packages and common tooling.

   ```bash
   python -m pip install --upgrade pip setuptools wheel
   pip install -r requirements-dev.txt
   cmake -S native -B native/build -DPQCBENCH_ENABLE_LIBOQS_TESTS=ON
   cmake --build native/build
   pip install -e libs/core
   pip install -e libs/adapters/native
   ```

   The helper scripts `scripts/setup_dev.sh` and `scripts/setup_dev.ps1` perform the same steps if you prefer a single command.

3. Run smoke tests.

   ```bash
   pytest -q
   pqcbench run-tests
   ```

4. Inspect the CLI and GUI entry points.

   ```bash
   pqcbench --help
   FLASK_APP=apps/gui/src/webapp/app.py flask run
   ```

   Windows PowerShell:
   ```powershell
   $env:FLASK_APP = 'apps/gui/src/webapp/app.py'
   flask run
   ```

## CLI workflows

The Typer CLI shipped by `apps/cli` exposes these top-level commands:
- `pqcbench list-algos` — enumerate registered algorithms from the adapter registry.
- `pqcbench demo <name>` — run a one-shot keygen plus encapsulation/signature cycle.
- `pqcbench run-tests [--skip-liboqs] [PYTEST ARGS...]` — launch pytest for the repo (and liboqs-python tests when available).
- `pqcbench probe-oqs` — list liboqs KEM/SIG mechanisms detected in the current environment.

After installing the editable packages you also get dedicated benchmark runners:

```bash
run-kyber       # KEM
run-hqc         # KEM
run-rsa-oaep    # KEM-style wrapper over RSA-OAEP
run-rsa-pss     # Signature (RSA-PSS)
run-dilithium   # Signature (ML-DSA / Dilithium)
run-falcon      # Signature
run-sphincsplus # Signature
run-xmssmt      # Stateful signature family
run-mayo        # Signature (MAYO)
```

Each runner accepts `--runs`, `--tests` (to include known-answer tests), `--message-size` for signatures, and `--export results/<file>.json` for structured output. PowerShell wrappers live under `scripts\run_*.ps1` for convenience on Windows.

### Metrics recorded by runners
- Latency per operation (mean, median, min, max, standard deviation, and per-run series).
- Key, ciphertext, and signature lengths for comparison across algorithms.
- Expansion ratios (ciphertext-to-shared-secret for KEMs, signature-to-message for signatures).
- Resident memory deltas per run when `psutil` is installed.
- Secret-key Hamming weight/distance summaries to flag distribution anomalies (e.g., HQC constant weight).
- Security estimator block summarising classical, quantum, and surface-code resource projections when enabled.
- Runtime scaling predictions using built-in or custom device profiles.

### Security estimator overview
- Core module: `libs/core/src/pqcbench/security_estimator.py` combines classical hardness tables, optional lattice estimators, and RSA surface-code models.
- Inputs: adapter metadata (parameter sets, key sizes), measured latency, and optional CLI flags (`--sec-*`, `--quantum-arch`, `--rsa-model`).
- Outputs: per-algorithm JSON sections capturing classical bits, quantum bits, runtime projections, logical qubits, Toffoli/T counts, and failure probabilities.
- Integrations: GUI panels render the same data, CSV mergers in `benchmarks/` preserve the security block, and native runs inherit the estimator via shared interfaces.
- Extensibility: drop-in estimator hooks allow you to add new PQC families or swap lattice back-ends without modifying consumer code.

### Selecting parameter sets

The liboqs-backed adapters auto-detect supported mechanisms. Override them with environment variables before launching the CLI or GUI:
- `PQCBENCH_KYBER_ALG` (for example `ML-KEM-768` or `Kyber1024`)
- `PQCBENCH_HQC_ALG` (for example `HQC-192`)
- `PQCBENCH_DILITHIUM_ALG`
- `PQCBENCH_FALCON_ALG`
- `PQCBENCH_SPHINCS_ALG`
- `PQCBENCH_XMSSMT_ALG`
- `PQCBENCH_MAYO_ALG`

Example:

```bash
export PQCBENCH_KYBER_ALG=ML-KEM-1024
export PQCBENCH_DILITHIUM_ALG=ML-DSA-65
```

Legacy `*_MECH` variables are still honoured but the `PQCBENCH_*` family takes precedence.

### Security estimator flags

Add the following options to any `run-*` command to emit extended security analysis:
- `--sec-adv` — attempt a detailed lattice estimator; otherwise fall back to NIST category floors but note the downgrade.
- `--sec-rsa-phys` — include surface-code physical resource estimates for RSA (ignored for PQC algorithms).
- `--sec-phys-error-rate <rate>` — physical error rate per operation (default `1e-3`).
- `--sec-cycle-time-ns <ns>` — surface-code cycle time in nanoseconds (default `1000`).
- `--sec-fail-prob <probability>` — total failure probability budget (default `1e-2`).
- `--sec-profile floor|classical|quantum` — choose the lattice modelling depth.
- `--quantum-arch superconducting-2025|iontrap-2025` — use preset surface-code parameters.
- `--rsa-model ge2019` — pick the RSA resource model constants (extendable).

### Runtime scaling configuration

Runtime scaling extrapolates benchmark measurements to other devices using compute and bandwidth proxies:
- `PQCBENCH_BASELINE_PROFILE` pins the detected host to a known profile (e.g., `macbookpro16_i9_9880h`, `intel_i9_14900k`).
- `PQCBENCH_BASELINE_COMPUTE_SCORE` (and optional `PQCBENCH_BASELINE_COMPUTE_METRIC`) overrides the measured compute proxy.
- `PQCBENCH_BASELINE_BANDWIDTH_SCORE` preloads a memcpy bandwidth proxy when you already have STREAM-style data.
- `PQCBENCH_DEVICE_PROFILES` points to a JSON file describing custom target profiles (shape documented in `libs/core/src/pqcbench/runtime_scaling.py`).
- `PQCBENCH_RUNTIME_TARGETS=profile_a,profile_b` selects which targets to include in exports.
- `PQCBENCH_RUNTIME_ALPHA` (and the specialised `PQCBENCH_RUNTIME_ALPHA_KEYGEN`, `_ENCAPS`, `_SIGN`, `_VERIFY`, etc.) adjust the compute/bandwidth weighting by stage.

The runners automatically measure a memcpy proxy when possible so you get compute-only projections even if you skip custom tuning.

## GUI workflows

The Flask GUI under `apps/gui` renders the same registry, benchmark exports, and security estimator in an interactive dashboard. Launch it from the repo root:

```bash
export FLASK_APP=apps/gui/src/webapp/app.py
flask run
```

Key features:
- Image encryption pipeline with original, ciphertext, and decrypted previews.
- Entropy heatmaps and per-channel histograms for quick visual sanity checks.
- Baseline comparisons that align CLI exports with curated CSV bundles.
- Runtime scaling and security estimator sections that mirror CLI output.
- Optional LLM panel that summarises benchmark deltas and highlights notable metrics.

Consult `apps/gui/README.md` for widget-level details, sample datasets, and test coverage notes (`tests/gui/`).

### Optional LLM summariser

1. Copy `apps/gui/.env.example` to `apps/gui/.env` or set equivalent environment variables.
2. Choose a provider with `LLM_PROVIDER`:
   - `openai_compatible` — OpenAI, vLLM, LM Studio, etc. Configure `LLM_BASE_URL`, `LLM_MODEL`, and `LLM_API_KEY` when required.
   - `huggingface` — Hugging Face Inference API. Provide `HF_API_KEY` and optionally `HF_MODEL`.
   - `ollama` — Local Ollama server; ensure it is running and set `LLM_MODEL` if you want something other than the default `llama3.1:8b`.
3. Install the optional HTTP dependency (already listed in `requirements-dev.txt`):
   ```bash
   pip install requests
   ```
4. Restart `flask run` so the configuration is picked up.

When no provider is configured the GUI falls back to a deterministic heuristic summariser and surfaces a warning banner instead of failing the workflow.

## Optional components

### liboqs support

The repository includes helpers to build liboqs with HQC and XMSSMT enabled and to install the Python bindings locally:

```bash
./scripts/setup_oqs.sh --branch main   # or pick a release tag, e.g. 0.10.0
source scripts/env.example.sh          # exports LD_LIBRARY_PATH / DYLD_LIBRARY_PATH / PATH entries
pqcbench probe-oqs                     # verify mechanisms now load
```

The script stages the build under `.local/oqs`. On Windows you can execute the script through WSL or follow the same steps manually. Remember to activate the virtual environment and re-run `source scripts/env.example.sh` (or translate it to PowerShell) before launching the CLI or GUI so the shared library can be located.

### Native C backend

For tighter timing and memory measurements you can build the optional native backend:

```bash
cmake -S native -B native/build -DCMAKE_BUILD_TYPE=Release
cmake --build native/build --config Release
pip install -e libs/core
pip install -e libs/adapters/native
```

If the shared library is not discovered automatically, point `PQCBENCH_NATIVE_LIB` at the compiled artifact (for example `native/build/Release/pqcbench_native.dll` on Windows). Enable liboqs-backed unit tests inside the native project with `cmake -S native -B native/build -DPQCBENCH_ENABLE_LIBOQS_TESTS=ON` and rebuild.

## Benchmarks, baselines, and data
- `benchmarks/run_benchmarks.py`, `run_category_floor_matrix.py`, and `render_category_floor_graphs.py` reproduce published tables and plots; see `benchmarks/README.md` and `benchmarks/category-floor-matrix.md` for scenarios.
- `baselines/*.csv` capture curated latency and security data for flagship devices.
- `Tested Benchmarks/` contains harvested runs from hardware such as the Ryzen 5700X and MacBook Pro i9-9880H.
- CLI and GUI exports belong in `results/` (gitignored). Use `python benchmarks/merge_results.py` to collate the directory into `results/security_metrics.csv`.
- `acvp/` holds the ACVP harness, scripts, and test vectors (check out with Git LFS).
- `tools/forensic_probe.py` and `tools/forensic_report.py` support deeper key and ciphertext analysis, while `tools/sidechannel/README.md` outlines how to integrate dudect-style leakage tests.

## Testing and quality gates
- `pytest` at the repository root exercises the core libraries, CLI runners, and GUI utilities (via `tests/` and `tests/gui/`).
- `pqcbench run-tests --skip-liboqs` runs the same suite without probing liboqs; drop the flag once `oqs` is installed to include `liboqs-python/tests`.
- Optional: enable native vector checks via `cmake -S native -B native/build -DPQCBENCH_ENABLE_LIBOQS_TESTS=ON`.
- Optional: run side-channel skeletons documented in `tools/sidechannel/` to generate dudect t-scores for result bundles.

## Documentation

Extended guides live under `docs/` and are ready to publish with MkDocs or Sphinx:
- `docs/algorithm-implementations.md` — backend overview and benchmarking notes per algorithm family.
- `docs/image-encryption-pipeline.md` — GUI walkthrough.
- `docs/llm-integration-guide.md` — configuration tips for the assistant panel.
- `docs/security/` — estimator models, RSA resource analysis, brute-force baselines, side-channel methodology, and native backend checklists.
- `docs/testing/validation-coverage.md` — coverage snapshot for runners and adapters.
- `docs/issues/` — known caveats and troubleshooting notes.

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
│     ├─ native/      # Optional native bridge for C backend
│     └─ rsa/         # Classical RSA-OAEP / RSA-PSS adapter
├─ acvp/              # ACVP harness, vector management
├─ baselines/         # Curated baseline CSV bundles
├─ benchmarks/        # Reproducible benchmark scenarios + scripts
├─ docs/              # MkDocs-ready documentation scaffold
├─ liboqs/            # Upstream liboqs checkout (optional)
├─ liboqs-python/     # Vendored liboqs Python bindings for tests
├─ native/            # CMake project for native backend
├─ results/           # CSV/JSON benchmark outputs (gitignored)
├─ scripts/           # Dev/setup utilities and runner helpers
├─ tests/             # Unit + integration tests (core, CLI, GUI)
├─ tools/             # Forensic utilities and side-channel skeletons
├─ Tested Benchmarks/ # Captured runs for reference hardware
├─ .github/workflows/ # CI pipelines
└─ requirements-dev.txt
```

## Useful scripts
- `scripts/setup_dev.sh` / `scripts/setup_dev.ps1` — bootstrap development dependencies.
- `scripts/setup_oqs.sh` — build and install liboqs + bindings locally.
- `scripts/run_*.ps1` — Windows shortcuts for the `run-*` runners.
- `scripts/env.example.sh` — environment template for sourcing liboqs paths.

## Further reading

For deeper coverage of the security estimator, runtime scaling model, and native instrumentation refer to `docs/security/README.md` and the inline documentation inside `libs/core/src/pqcbench/security_estimator.py` and `runtime_scaling.py`. If you add new algorithms or adapters, update the relevant package README, baseline CSV, and documentation entry alongside the core implementation.
