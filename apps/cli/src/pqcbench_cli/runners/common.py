
from __future__ import annotations
"""Shared benchmarking utilities for CLI runners.

Includes adapter bootstrap, timing/memory measurement, JSON export helpers,
and per-kind (KEM/SIG) micro-benchmark orchestrators.
"""
import time, json, pathlib, base64
from dataclasses import dataclass, asdict
from typing import Callable, Dict, Any, List, Tuple
from pqcbench import registry

def _load_adapters() -> None:
    import importlib, traceback
    for mod in ("pqcbench_rsa", "pqcbench_liboqs"):
        try:
            importlib.import_module(mod)
        except Exception as e:
            print(f"[adapter import error] {mod}: {e}")
            traceback.print_exc()

_load_adapters()


@dataclass
class OpStats:
    runs: int
    mean_ms: float
    min_ms: float
    max_ms: float
    series: List[float]
    # Memory footprint metrics (peak RSS delta per run)
    mem_mean_kb: float | None = None
    mem_min_kb: float | None = None
    mem_max_kb: float | None = None
    mem_series_kb: List[float] | None = None

@dataclass
class AlgoSummary:
    algo: str
    kind: str   # 'KEM' or 'SIG'
    ops: Dict[str, OpStats]
    meta: Dict[str, Any]

def measure(fn: Callable[[], None], runs: int) -> OpStats:
    """Measure time and memory footprint.

    - Time: measure wall-clock latency per run (ms)
    - Memory: sample process RSS during the function call and record peak delta (KB)

    If psutil is unavailable, memory metrics are left as None.
    """
    times: List[float] = []
    mem_peaks_kb: List[float] = []

    # Optional psutil-based sampler
    try:
        import psutil  # type: ignore
        import threading
        import os

        proc = psutil.Process(os.getpid())

        class _MemSampler:
            def __init__(self) -> None:
                self._stop = threading.Event()
                self._peak_rss = 0
                self._baseline = 0

            def start(self) -> None:
                # Establish a baseline RSS before the measurement
                try:
                    self._baseline = int(proc.memory_info().rss)
                except Exception:
                    self._baseline = 0

                self._stop.clear()
                self._peak_rss = 0
                self._thread = threading.Thread(target=self._run, daemon=True)
                self._thread.start()

            def stop(self) -> float:
                self._stop.set()
                self._thread.join(timeout=0.5)
                # Return peak delta in KB (avoid negatives)
                delta = max(0, self._peak_rss - self._baseline)
                return delta / 1024.0

            def _run(self) -> None:
                # Sample at ~1 kHz (best effort; OS granularity applies)
                while not self._stop.is_set():
                    try:
                        rss = int(proc.memory_info().rss)
                        if rss > self._peak_rss:
                            self._peak_rss = rss
                    except Exception:
                        pass
                    # Busy wait would distort timings; sleep a tiny interval
                    time.sleep(0.001)

        sampler_factory: Callable[[], _MemSampler] | None = lambda: _MemSampler()
    except Exception:
        sampler_factory = None

    for _ in range(runs):
        sampler = sampler_factory() if sampler_factory else None
        if sampler:
            sampler.start()
        t0 = time.perf_counter()
        fn()
        dt = (time.perf_counter() - t0) * 1000.0
        times.append(dt)
        if sampler:
            mem_peaks_kb.append(sampler.stop())

    mean = sum(times) / len(times)

    # Summarize memory metrics if available; otherwise leave as None
    if mem_peaks_kb:
        mem_mean = sum(mem_peaks_kb) / len(mem_peaks_kb)
        mem_min = min(mem_peaks_kb)
        mem_max = max(mem_peaks_kb)
        return OpStats(
            runs=runs,
            mean_ms=mean,
            min_ms=min(times),
            max_ms=max(times),
            series=times,
            mem_mean_kb=mem_mean,
            mem_min_kb=mem_min,
            mem_max_kb=mem_max,
            mem_series_kb=mem_peaks_kb,
        )
    else:
        return OpStats(
            runs=runs,
            mean_ms=mean,
            min_ms=min(times),
            max_ms=max(times),
            series=times,
        )

def _build_export_payload(summary: AlgoSummary, *, security_opts: dict | None = None) -> dict:
    """Construct the JSON payload including security estimates."""
    # Attach security estimates (best-effort; never fail export on estimator issues)
    try:
        from pqcbench.security_estimator import estimate_for_summary, EstimatorOptions  # type: ignore
        opts = None
        if security_opts is not None:
            opts = EstimatorOptions(
                lattice_use_estimator=bool(security_opts.get("lattice_use_estimator", False)),
                lattice_model=security_opts.get("lattice_model"),
                lattice_profile=security_opts.get("lattice_profile"),
                rsa_surface=bool(security_opts.get("rsa_surface", False)),
                rsa_model=security_opts.get("rsa_model"),
                quantum_arch=security_opts.get("quantum_arch"),
                phys_error_rate=float(security_opts.get("phys_error_rate", 1e-3)),
                cycle_time_s=float(security_opts.get("cycle_time_s", 1e-6)),
                target_total_fail_prob=float(security_opts.get("target_total_fail_prob", 1e-2)),
            )
        security = estimate_for_summary(summary, options=opts)
    except Exception as _e:
        security = {"error": "security estimator unavailable"}

    return {
        "algo": summary.algo,
        "kind": summary.kind,
        "ops": {k: asdict(v) for k, v in summary.ops.items()},
        "meta": summary.meta,
        "security": security,
    }


def export_json(summary: AlgoSummary, export_path: str | None, *, security_opts: dict | None = None) -> None:
    if not export_path:
        return
    # Normalize Windows-style separators on POSIX if users pass e.g. "results\file.json"
    if "\\" in export_path and ":" not in export_path:
        export_path = export_path.replace("\\", "/")
    path = pathlib.Path(export_path)
    # Resolve relative paths to the repository root so results/ always lands at repo root
    if not path.is_absolute():
        path = _repo_root() / path
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(_build_export_payload(summary, security_opts=security_opts), f, indent=2)

def _export_json_blob(data: dict, export_path: str | None) -> None:
    if not export_path:
        return
    # Normalize Windows separators for relative paths
    if "\\" in export_path and ":" not in export_path:
        export_path = export_path.replace("\\", "/")
    path = pathlib.Path(export_path)
    if not path.is_absolute():
        path = _repo_root() / path
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def _b64(x: bytes | bytearray | None) -> str | None:
    if x is None:
        return None
    return base64.b64encode(bytes(x)).decode("ascii")

def _repo_root() -> pathlib.Path:
    """Best-effort detection of the repository root (directory containing .git).
    Falls back to the current working directory if not found.
    """
    here = pathlib.Path(__file__).resolve()
    for p in (here, *here.parents):
        if (p / ".git").exists():
            return p
    return pathlib.Path.cwd()

def run_kem(name: str, runs: int) -> AlgoSummary:
    """Run a KEM micro-benchmark for the registered algorithm `name`.

    Measures wall-clock latency (and optional memory deltas) for:
    - keygen
    - encapsulate
    - decapsulate

    Fresh keys are generated for each run of encapsulate/decapsulate to avoid
    reusing state and to keep comparisons fair.
    """
    cls = registry.get(name)
    ops = {}
    # measure keygen
    def do_keygen():
        _ = cls().keygen()
    ops["keygen"] = measure(do_keygen, runs)
    # For enc/dec we need fresh keys each time to be fair
    def do_encapsulate():
        pk, sk = cls().keygen()
        _ = cls().encapsulate(pk)
    ops["encapsulate"] = measure(do_encapsulate, runs)
    def do_decapsulate():
        pk, sk = cls().keygen()
        ct, ss = cls().encapsulate(pk)
        _ = cls().decapsulate(sk, ct)
    ops["decapsulate"] = measure(do_decapsulate, runs)
    # meta (sizes are placeholders if adapters are not real yet)
    instance = cls()
    pk, sk = instance.keygen()
    ct, ss = cls().encapsulate(pk)
    meta = {
        "public_key_len": len(pk) if isinstance(pk, (bytes, bytearray)) else None,
        "secret_key_len": len(sk) if isinstance(sk, (bytes, bytearray)) else None,
        "ciphertext_len": len(ct) if isinstance(ct, (bytes, bytearray)) else None,
        "shared_secret_len": len(ss) if isinstance(ss, (bytes, bytearray)) else None,
        "mechanism": getattr(instance, "mech", None),
    }
    return AlgoSummary(algo=name, kind="KEM", ops=ops, meta=meta)

def run_sig(name: str, runs: int, message_size: int) -> AlgoSummary:
    """Run a signature micro-benchmark for the registered algorithm `name`.

    Measures wall-clock latency (and optional memory deltas) for:
    - keygen
    - sign (with fresh keys per run)
    - verify (with fresh keys/signature per run)
    """
    cls = registry.get(name)
    ops = {}
    msg = b"x" * message_size
    def do_keygen():
        _ = cls().keygen()
    ops["keygen"] = measure(do_keygen, runs)
    def do_sign():
        pk, sk = cls().keygen()
        _ = cls().sign(sk, msg)
    ops["sign"] = measure(do_sign, runs)
    def do_verify():
        pk, sk = cls().keygen()
        sig = cls().sign(sk, msg)
        _ = cls().verify(pk, msg, sig)
    ops["verify"] = measure(do_verify, runs)
    instance = cls()
    pk, sk = instance.keygen()
    sig = instance.sign(sk, msg)
    meta = {
        "public_key_len": len(pk) if isinstance(pk, (bytes, bytearray)) else None,
        "secret_key_len": len(sk) if isinstance(sk, (bytes, bytearray)) else None,
        "signature_len": len(sig) if isinstance(sig, (bytes, bytearray)) else None,
        "message_size": message_size,
        "mechanism": getattr(instance, "mech", None),
    }
    return AlgoSummary(algo=name, kind="SIG", ops=ops, meta=meta)


# -------- Raw trace exporters (single illustrative run) --------

def export_trace_kem(name: str, export_path: str | None) -> None:
    if not export_path:
        return
    cls = registry.get(name)
    algo = cls()
    pk, sk = algo.keygen()
    ct, ss = algo.encapsulate(pk)
    ss_dec = algo.decapsulate(sk, ct)
    trace = {
        "algo": name,
        "kind": "KEM",
        "trace": {
            "keygen": {"public_key": _b64(pk), "secret_key": _b64(sk)},
            "encapsulate": {"ciphertext": _b64(ct), "shared_secret": _b64(ss)},
            "decapsulate": {"shared_secret": _b64(ss_dec), "matches": (ss == ss_dec)},
        }
    }
    _export_json_blob(trace, export_path)

def export_trace_sig(name: str, message_size: int, export_path: str | None) -> None:
    if not export_path:
        return
    cls = registry.get(name)
    algo = cls()
    pk, sk = algo.keygen()
    msg = b"x" * int(message_size)
    sig = algo.sign(sk, msg)
    ok = algo.verify(pk, msg, sig)
    trace = {
        "algo": name,
        "kind": "SIG",
        "trace": {
            "keygen": {"public_key": _b64(pk), "secret_key": _b64(sk)},
            "message": _b64(msg),
            "sign": {"signature": _b64(sig)},
            "verify": {"ok": bool(ok)},
        }
    }
    _export_json_blob(trace, export_path)
