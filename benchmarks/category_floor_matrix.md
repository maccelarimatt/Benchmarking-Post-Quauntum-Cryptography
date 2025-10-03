# Category Floor Benchmark Matrix

This document describes how to run `run_category_floor_matrix.py` and how to interpret the CSV and metadata it produces.

## Running the script

```
python benchmarks/run_category_floor_matrix.py [options]
```

Common options:
- `--runs N` (default `40`): number of iterations per operation for each pass. Use a smaller value (e.g. `--runs 2`) for smoke tests.
- `--categories C [C ...]` (default `1 3 5`): NIST floor categories to include. Each category maps to the floors 128, 192, and 256 bits respectively.
- `--message-size BYTES` (default `1024`): message size used when benchmarking signature algorithms.
- `--memory-interval SECONDS` (default `0.0005`): sampling interval for memory measurements during the memory pass. Timing-only passes ignore this value.
- `--output PATH` (default `results/category_floor_benchmarks.csv`): CSV destination. Use `--append` to accumulate multiple sessions.
- `--metadata PATH` (default `results/category_floor_benchmarks.meta.json`): JSON metadata snapshot describing the run.

Example (quick smoke test):
```
python benchmarks/run_category_floor_matrix.py --runs 2 --output results/test.csv --metadata results/test.meta.json
```

The script automatically cycles through the requested NIST floors (Cat 1/3/5 by default). For each category it resolves parameter-set overrides via the same `security_levels.resolve_security_override` helper used by the UI (e.g., ML-KEM-512 for Cat 1, ML-KEM-768 for Cat 3, ML-KEM-1024 for Cat 5) before instantiating the adapters. That keeps CLI behaviour aligned with the app and avoids manual environment tweaks.

Two measurement passes are collected per (category, algorithm) pair:
1. **timing** – disables memory sampling for the cleanest latency measurements.
2. **memory** – enables high-frequency memory sampling (default 0.5 ms interval) for peak-RSS and tracemalloc statistics.

Each pass executes cold measurements (fresh child processes) for every operation exposed by the adapter (`keygen`, `encapsulate`, `decapsulate`, `sign`, `verify`).

## CSV layout

Each row corresponds to a single `(algorithm, operation, measurement_pass)` tuple. Columns are:

| Column | Description |
| --- | --- |
| `session_id` | UTC timestamp identifier shared by all rows from one invocation. |
| `timestamp_iso` | UTC time when the row was written (ISO 8601). |
| `measurement_pass` | Either `timing` or `memory`. |
| `algo` | Registry key (e.g. `kyber`, `dilithium`). |
| `kind` | `KEM` or `SIG`. |
| `family` | Mechanism family from `pqcbench.params` (e.g. `ML-KEM`). |
| `mechanism` | Most specific mechanism string reported by the adapter or security estimator. |
| `category_label` | Human-readable category (`cat-1`, `cat-3`, `cat-5`). |
| `category_number` | Numeric category (1, 3, or 5). |
| `category_floor_bits` | Bit-strength floor sourced from parameter hints. |
| `parameter_notes` | Notes stored in the parameter hint. |
| `parameter_extras_json` | JSON-encoded parameter extras (e.g. key sizes). Empty string when unavailable. |
| `runs` | Iteration count for the operation. |
| `operation` | Name of the measured primitive (`keygen`, `encapsulate`, etc.). |
| `mean_ms` / `median_ms` / `stddev_ms` | Summary statistics for wall-clock time in milliseconds. |
| `min_ms` / `max_ms` / `range_ms` | Extremes of the timing samples. |
| `ci95_low_ms` / `ci95_high_ms` | 95% confidence interval for the mean latency. |
| `mem_mean_kb` / `mem_median_kb` / `mem_stddev_kb` | Peak memory summary in kilobytes (only populated during the memory pass). |
| `mem_min_kb` / `mem_max_kb` / `mem_range_kb` | Min/Max/Range of peak memory samples. |
| `mem_ci95_low_kb` / `mem_ci95_high_kb` | 95% confidence interval for peak memory. |
| `series_json` | JSON list of per-run latencies (ms). |
| `mem_series_json` | JSON list of per-run peak memory values (KB). Empty for timing-only pass. |
| `runtime_scaling_json` | JSON representation of runtime scaling projections (if available). |
| `meta_json` | JSON snapshot of adapter metadata (mechanism strings, key sizes, environment info). |
| `security_classical_bits` / `security_quantum_bits` | Headline security estimates returned by `estimate_for_summary`. |
| `security_shor_breakable` | Boolean flag indicating if Shor’s algorithm breaks the scheme. |
| `security_notes` | Additional context from the estimator. |
| `security_mechanism` | Mechanism identifier used by the estimator. |
| `security_extras_json` | JSON-encoded estimator extras (e.g. model choice, brute-force summary). |
| `pass_config_json` | JSON blob describing how the pass was configured (memory enabled, interval, run count).

## Metadata JSON

The metadata file captures run-level information:
- `session_id`, `generated_at` – identifiers matching the CSV.
- `runs`, `message_size`, `memory_interval_seconds`, `categories` – command-line settings.
- `algorithms` – array of algorithm descriptors (name, kind, mechanism, category floor, notes, extras).
- `output_csv`, `row_count` – where the CSV was written and how many rows were produced.
- `failures` – any algorithms or passes that failed to execute (empty when all succeed).
- `environment` – machine context collected from `_collect_environment_meta()` (CPU model, OS, dependency commits, etc.).

Both files are intentionally JSON-friendly so they can be consumed by notebooks, dashboards, or batch pipelines for further analysis.

## Rendering graphs

After collecting metrics you can visualise the results with:

```
python benchmarks/render_category_floor_graphs.py [--csv PATH] [--session SESSION_ID] [--passes timing memory]
```

Graphs are written to `results/graphs/<session_id>/` (the `results/` tree is already ignored by Git). The renderer produces:

- `latency_timing_<kind>.png` / `latency_memory_<kind>.png`: grouped mean-latency bar charts per operation for KEM and SIG algorithms.
- `memory_peak_<kind>.png`: peak RSS bars (memory pass only).
- `security_vs_latency_<pass>.png`: scatter plot of classical security bits vs keygen latency, annotated per algorithm.

The script requires `matplotlib` (`pip install matplotlib`). It defaults to the latest session in the CSV; use `--session` to override.

Per-category subdirectories are created automatically (e.g. `category_1/`, `category_3/`, `category_5/`) containing the same set of plots filtered to algorithms whose parameter hints map to the corresponding floor. This makes it easy to compare Cat‑1, Cat‑3, and Cat‑5 families side by side.
