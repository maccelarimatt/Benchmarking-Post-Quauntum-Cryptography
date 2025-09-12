
# Benchmarks

- Define repeatable scenarios in JSON/YAML.
- Scripts write machine-readable CSV/JSON into `results/`.

Usage
- Run a simple batch over registered adapters: `python benchmarks/run_benchmarks.py`
- Edit `benchmarks/scenarios.json` to track named experiment settings.

Output
- Default summary path: `results/bench_summary.json`
- Per-algorithm CLI summaries can be produced with `run-<algo> --export results/<algo>.json`
