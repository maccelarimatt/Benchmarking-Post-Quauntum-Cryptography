# Benchmark Entrypoints

PQCbench ships two command-line drivers in `benchmarks/`.

- `run_benchmarks.py` – a **smoke test** that times each adapter’s `keygen`
  operation a few times. No category overrides, no memory sampling, no security
  estimator. Use this only to confirm that adapters import correctly.
- `run_category_floor_matrix.py` – the **full benchmark suite**. It walks every
  registered algorithm through the Cat‑1/3/5 parameter floors, records timing
  *and* memory statistics (optionally warm passes), captures environment and
  security metadata, and can fan out to graph rendering, side-channel probes,
  and downstream reports. This is the script you almost always want.

## Quick smoke test (`run_benchmarks.py`)

```bash
python benchmarks/run_benchmarks.py --runs 5
```

What you get
- mean/CI timing for `keygen` only
- JSON summary at `results/bench_summary.json`
- Optional extras: `--render-graphs`, `--run-side-channel` (mirrors the flags
  described below but with reduced scope)

Limitations
- no memory data, no category selection, no warm passes
- ignores security estimators and per-operation timings
- unsuitable for publication-quality numbers

## Full suite (`run_category_floor_matrix.py`)

```bash
python benchmarks/run_category_floor_matrix.py --runs 50 --warm --render-graphs \
  --graph-args -- --output-dir results/graphs/latest --passes timing timing-warm memory \
  --run-side-channel --side-channel-options "--all-categories --iterations 800 \
    --render-plots --plot-dir results/forensic_latest_report \
    --render-report --report-format markdown \
    --report-output results/forensic_latest_report/summary.md"
```

Highlights
- sweeps Cat‑1/3/5 (per algorithm overrides handled automatically)
- collects timing *and* memory passes; add `--warm` for in-process passes
- optional CSV, JSONL, Parquet, and metadata artefacts
- integrates with `render_category_floor_graphs.py` via `--render-graphs`
- chains into the forensic side-channel probe (plots + Markdown report)

Key options
- `--runs` – iterations per operation/pass (default 40)
- `--categories 1 3 5` – pick NIST floors to benchmark
- `--message-size` – signature message length
- `--memory-interval` – sampling cadence for memory passes
- `--rsa-max-category` – cap RSA baseline categories (e.g. `3` to skip 15 360‑bit)
- `--jsonl-output`, `--parquet-output` – structured exports
- `--render-graphs`, `--graph-args -- …` – post-run graph generation
- `--run-side-channel`, `--side-channel-options "…"` – forensic probe hand-off

Outputs
- CSV: `results/category_floor_benchmarks.csv`
- Metadata JSON: `results/category_floor_benchmarks.meta.json`
- Optional JSONL / Parquet (if requested)
- Graphs: under `results/graphs/<session>/`
- Forensic artefacts: JSON + plots/captions + Markdown report in
  `results/forensic_latest_report/`

## Recommendations

1. Start with the full suite (`run_category_floor_matrix.py`) – it is the only
   script designed for reproducible, publishable results.
2. Use the smoke test only when you need a very fast “does this adapter load?”
   check.
3. Keep `--runs` ≥ 40 for timing consistency; stick to ≥ 800 iterations inside
   the side-channel probe when you need statistical confidence.

