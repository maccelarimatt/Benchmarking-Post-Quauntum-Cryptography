
from __future__ import annotations

import argparse
import json
import math
import pathlib
import shlex
import statistics
import subprocess
import sys
import time

from pqcbench import registry
from pqcbench.metrics import BenchmarkResult, MetricRecord

"""Simple batch benchmark driver.

Runs a lightweight timing loop over available adapters' keygen to demonstrate
batch collection. Results are written to `results/bench_summary.json`.
"""

HERE = pathlib.Path(__file__).parent
GRAPH_SCRIPT = HERE / "render_category_floor_graphs.py"
SIDE_CHANNEL_SCRIPT = HERE.parent / "tools" / "forensic_probe.py"
RESULTS = HERE.parent / "results"
RESULTS.mkdir(exist_ok=True)

try:
    _CI_Z = statistics.NormalDist().inv_cdf(0.975)
except Exception:
    _CI_Z = 1.959964


def tictoc(fn, runs=5):
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    mean = sum(times) / len(times)
    std = statistics.pstdev(times) if len(times) > 1 else 0.0
    if len(times) > 1:
        sample_std = statistics.stdev(times)
        margin = _CI_Z * (sample_std / math.sqrt(len(times)))
        ci_low = mean - margin
        ci_high = mean + margin
    else:
        ci_low = mean
        ci_high = mean
    return mean, std, ci_low, ci_high


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run simple PQC benchmark suite.")
    parser.add_argument(
        "--runs",
        type=int,
        default=5,
        help="Number of repetitions per algorithm (default: 5).",
    )
    parser.add_argument(
        "--render-graphs",
        action="store_true",
        help="Invoke the category floor graph renderer after benchmarks finish.",
    )
    parser.add_argument(
        "--graph-script",
        type=pathlib.Path,
        default=GRAPH_SCRIPT,
        help="Override the graph renderer script location.",
    )
    parser.add_argument(
        "--graph-args",
        nargs=argparse.REMAINDER,
        default=None,
        help="Additional arguments forwarded to the graph renderer (must follow '--').",
    )
    parser.add_argument(
        "--run-side-channel",
        action="store_true",
        help="Run the forensic side-channel probe after benchmarks (and any rendered graphs).",
    )
    parser.add_argument(
        "--side-channel-options",
        type=str,
        default="",
        help="Extra options appended to the side-channel probe command (e.g. \"--all-categories --render-plots\").",
    )
    return parser.parse_args(argv)


def _run_graph_renderer(script_path: pathlib.Path, extra_args: list[str] | None) -> None:
    if not script_path.exists():
        print(f"Graph renderer not found at {script_path}. Skipping graph generation.")
        return

    cmd = [sys.executable, str(script_path)]
    if extra_args:
        cmd.extend(extra_args)

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        print(f"Graph renderer exited with status {exc.returncode}. Command: {' '.join(cmd)}")


def _run_side_channel(script_path: pathlib.Path, options: str) -> None:
    if not script_path.exists():
        print(f"Side-channel probe not found at {script_path}. Skipping side-channel run.")
        return

    cmd = [sys.executable, str(script_path)]
    if options:
        cmd.extend(shlex.split(options))

    print(f"Running side-channel probe: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        print(f"Side-channel probe exited with status {exc.returncode}. Command: {' '.join(cmd)}")


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    records = []
    for name, cls in registry.list().items():
        obj = cls()
        if hasattr(obj, "keygen"):
            mean, std, ci_low, ci_high = tictoc(lambda: obj.keygen(), runs=args.runs)
            records.append(
                MetricRecord(
                    algo=name,
                    op="keygen",
                    runs=args.runs,
                    mean_ms=mean,
                    stddev_ms=std,
                    ci95_low_ms=ci_low,
                    ci95_high_ms=ci_high,
                )
            )
    result = BenchmarkResult(records=records, notes="placeholder timings")
    out = RESULTS / "bench_summary.json"
    out.write_text(json.dumps([r.__dict__ for r in result.records], indent=2))
    print(f"Wrote {out}")

    if args.render_graphs:
        extra = args.graph_args or []
        # argparse.REMAINDER keeps the leading '--' when provided; drop it for readability.
        if extra[:1] == ["--"]:
            extra = extra[1:]
        _run_graph_renderer(args.graph_script, extra)

    if args.run_side_channel:
        _run_side_channel(SIDE_CHANNEL_SCRIPT, args.side_channel_options)

if __name__ == "__main__":
    main()
