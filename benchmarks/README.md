
# Benchmarks

- Define repeatable scenarios in JSON/YAML.
- Scripts write machine-readable CSV/JSON into `results/`.

Usage
- Run a simple batch over registered adapters: `python benchmarks/run_benchmarks.py`
- Add `--render-graphs` to call the graph renderer once benchmarking completes (pass extra flags to the renderer after `--graph-args --`).
- Edit `benchmarks/scenarios.json` to track named experiment settings.
- Build the native C backend (`native/`) and install `pqcbench_native` if you
  want adapters to call directly into liboqs/OpenSSL during benchmarks.

Output
- Default summary path: `results/bench_summary.json`
- Per-algorithm CLI summaries can be produced with `run-<algo> --export results/<algo>.json`

python benchmarks/run_category_floor_matrix.py --runs 1 --rsa-max-category 3 --render-graphs