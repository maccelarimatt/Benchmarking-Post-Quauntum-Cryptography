
# Benchmarks

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

Output
- Default summary path: `results/bench_summary.json`
- Per-algorithm CLI summaries can be produced with `run-<algo> --export results/<algo>.json`

python benchmarks/run_category_floor_matrix.py --runs 1 --rsa-max-category 3 --render-graphs
