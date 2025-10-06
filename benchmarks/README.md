
# Benchmarks

This script is jut a test one, use run_category_floor_matrix.py for the proper benchmarks

- Define repeatable scenarios in JSON/YAML.
- Scripts write machine-readable CSV/JSON into `results/`.

Usage
- Run a simple batch over registered adapters: `python benchmarks/run_benchmarks.py`
- Add `--render-graphs` to call the graph renderer once benchmarking completes (pass extra flags to the renderer after `--graph-args --`).
- Pass `--run-side-channel` to launch the forensic leakage probe after benchmarks (forward additional probe flags via `--side-channel-options "<flags>"`).
- Edit `benchmarks/scenarios.json` to track named experiment settings.
- Build the native C backend (`native/`) and install `pqcbench_native` if you
  want adapters to call directly into liboqs/OpenSSL during benchmarks.

Example end-to-end run

```bash
python benchmarks/run_benchmarks.py --runs 10 --render-graphs \
  --run-side-channel --side-channel-options "--all-categories --render-plots --iterations 500"
```

This benchmarks each registered adapter, renders category-floor graphs, then invokes
`tools/forensic_probe.py --all-categories --render-plots --iterations 500` so timing
and leakage statistics (with plots/CSV) are captured alongside the benchmark results.

## Category floor harness

`run_category_floor_matrix.py` runs the full timing/memory passes across Cat-1/3/5 and
produces CSV/JSONL/Parquet summaries. New helper flags mirror the lightweight runner:

- `--render-graphs` triggers `render_category_floor_graphs.py` once data is written
  (override with `--graph-script`, pass extra arguments via `--graph-args -- ...`).
- `--run-side-channel` launches the forensic probe after graphing; forward specific
  probe options with `--side-channel-options "<flags>"`.

Example:

```bash
python benchmarks/run_category_floor_matrix.py --runs 50 --warm --render-graphs \
  --graph-args -- --output-dir results/graphs/cat_floor --passes timing timing-warm \
  --run-side-channel --side-channel-options "--all-categories --render-plots --iterations 600"

python benchmarks/run_category_floor_matrix.py --runs 1  --rsa-max-category 3 --render-graphs \ 
  --run-side-channel --side-channel-options "--all-categories --render-plots --iterations 10 --alg kyber"

python benchmarks/run_category_floor_matrix.py --runs 1  --rsa-max-category 3 --render-graphs \ 
  --run-side-channel --side-channel-options "--all-categories --render-plots --iterations 10 --alg kyber --render-report --report-format markdown --report-output results/forensic_latest_report/summary.md"
```  

This captures timing/memory statistics (including warm passes), renders grouped graphs
for each session/category, and then executes the side-channel probe with matching
category coverage and graphical/CSV output.

Output
- Default summary path: `results/bench_summary.json`
- Per-algorithm CLI summaries can be produced with `run-<algo> --export results/<algo>.json`
