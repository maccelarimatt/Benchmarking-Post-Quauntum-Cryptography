
from __future__ import annotations
import time, statistics, json, pathlib
from pqcbench import registry
from pqcbench.metrics import MetricRecord, BenchmarkResult

HERE = pathlib.Path(__file__).parent
RESULTS = HERE.parent / "results"
RESULTS.mkdir(exist_ok=True)

def tictoc(fn, runs=5):
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter()-t0)*1000)
    return (sum(times)/len(times)), ( (sum((x - (sum(times)/len(times)))**2 for x in times)/len(times)) ** 0.5 )

def main():
    records = []
    for name, cls in registry.list().items():
        obj = cls()
        if hasattr(obj, "keygen"):
            mean, std = tictoc(lambda: obj.keygen(), runs=5)
            records.append(MetricRecord(algo=name, op="keygen", runs=5, mean_ms=mean, stddev_ms=std))
    result = BenchmarkResult(records=records, notes="placeholder timings")
    out = RESULTS / "bench_summary.json"
    out.write_text(json.dumps([r.__dict__ for r in result.records], indent=2))
    print(f"Wrote {out}")

if __name__ == "__main__":
    main()
