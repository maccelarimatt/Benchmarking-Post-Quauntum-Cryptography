
from __future__ import annotations
import time, statistics, json, pathlib, math
from pqcbench import registry
from pqcbench.metrics import MetricRecord, BenchmarkResult

"""Simple batch benchmark driver.

Runs a lightweight timing loop over available adapters' keygen to demonstrate
batch collection. Results are written to `results/bench_summary.json`.
"""

HERE = pathlib.Path(__file__).parent
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

def main():
    records = []
    for name, cls in registry.list().items():
        obj = cls()
        if hasattr(obj, "keygen"):
            mean, std, ci_low, ci_high = tictoc(lambda: obj.keygen(), runs=5)
            records.append(
                MetricRecord(
                    algo=name,
                    op="keygen",
                    runs=5,
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

if __name__ == "__main__":
    main()
