
from __future__ import annotations
"""Shared benchmarking utilities for CLI runners.

Includes adapter bootstrap, timing/memory measurement, JSON export helpers,
and per-kind (KEM/SIG) micro-benchmark orchestrators.
"""

import base64
import copy
import json
import math
import multiprocessing
import os
import pathlib
import platform
import statistics
import subprocess
import sys
import threading
import time

from dataclasses import dataclass, asdict
from typing import Callable, Dict, Any, List, Tuple, Optional, Sequence, Iterable
from pqcbench import registry
from pqcbench.runtime_scaling import (
    RuntimeScalingResult,
    apply_runtime_scaling,
    load_device_profiles,
)
from functools import partial
from pqcbench.key_analysis import (
    DEFAULT_PAIR_SAMPLE_LIMIT,
    DEFAULT_SECRET_KEY_SAMPLES,
    derive_model,
    prepare_keys_for_analysis,
    summarize_secret_keys,
)

_MP_CONTEXT = multiprocessing.get_context('spawn')
_MEMORY_SAMPLE_INTERVAL = 0.0015  # seconds between RSS samples
_HERE = pathlib.Path(__file__).resolve()
_NATIVE_WARNED = False

try:
    _PROJECT_ROOT = next(p for p in _HERE.parents if (p / "libs").exists())
except StopIteration:
    _PROJECT_ROOT = _HERE.parents[0]

for rel in (
    pathlib.Path("libs/core/src"),
    pathlib.Path("libs/adapters/native/src"),
    pathlib.Path("libs/adapters/liboqs/src"),
    pathlib.Path("libs/adapters/rsa/src"),
):
    candidate = _PROJECT_ROOT / rel
    if candidate.exists():
        candidate_str = str(candidate)
        if candidate_str not in sys.path:
            sys.path.append(candidate_str)

_ADAPTER_PATHS = {
    "pqcbench_rsa": _PROJECT_ROOT / "libs" / "adapters" / "rsa" / "src",
    "pqcbench_liboqs": _PROJECT_ROOT / "libs" / "adapters" / "liboqs" / "src",
    "pqcbench_native": _PROJECT_ROOT / "libs" / "adapters" / "native" / "src",
}

_RUNTIME_DEVICE_PROFILES = load_device_profiles(os.environ.get("PQCBENCH_DEVICE_PROFILES"))

_ENVIRONMENT_CACHE: Dict[str, Any] | None = None
_ADAPTER_INSTANCE_CACHE: Dict[str, Any] = {}

try:
    _CI_Z = statistics.NormalDist().inv_cdf(0.975)
except Exception:
    _CI_Z = 1.959964


def _read_git_commit(repo_path: pathlib.Path) -> str | None:
    if not repo_path.exists():
        return None
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if out:
            return out
    except Exception:
        pass
    git_dir = repo_path / ".git"
    try:
        if git_dir.is_file():
            content = git_dir.read_text(encoding="utf-8").strip()
            if content.startswith("gitdir:"):
                git_dir = (repo_path / content.split(":", 1)[1].strip()).resolve()
    except Exception:
        return None
    head_path = git_dir / "HEAD"
    if not head_path.exists():
        return None
    try:
        head = head_path.read_text(encoding="utf-8").strip()
    except Exception:
        return None
    if head.startswith("ref:"):
        ref = head.split(":", 1)[1].strip()
        ref_path = git_dir / ref
        if ref_path.exists():
            try:
                return ref_path.read_text(encoding="utf-8").strip() or None
            except Exception:
                return None
        return None
    return head or None


def _detect_cpu_model() -> str | None:
    system = platform.system()
    try:
        if system == "Darwin":
            out = subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
            if out:
                return out
        elif system == "Linux":
            cpuinfo = pathlib.Path("/proc/cpuinfo")
            if cpuinfo.exists():
                for line in cpuinfo.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.lower().startswith("model name"):
                        return line.split(":", 1)[1].strip()
        elif system == "Windows":
            # Prefer a descriptive name (e.g., "Intel(R) Core(TM) i9-12900K @ 3.20GHz")
            # 1) Try PowerShell CIM (modern Windows)
            try:
                out = subprocess.check_output(
                    [
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)"
                    ],
                    stderr=subprocess.DEVNULL,
                    text=True,
                ).strip()
                if out:
                    return out
            except Exception:
                pass
            # 2) Fallback to WMIC (deprecated but often available)
            try:
                out = subprocess.check_output(
                    ["wmic", "cpu", "get", "Name"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                # Output typically includes a header line 'Name' and one or more name lines
                lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
                if len(lines) >= 2:
                    # Join multiple CPU entries if present
                    name = "; ".join(lines[1:])
                    if name:
                        return name
            except Exception:
                pass
            # 3) Environment fallback (less descriptive)
            val = os.environ.get("PROCESSOR_IDENTIFIER")
            if val:
                return val
    except Exception:
        pass
    uname = platform.uname()
    fallbacks = [
        getattr(uname, "processor", ""),
        getattr(uname, "machine", ""),
        platform.processor(),
    ]
    for val in fallbacks:
        if val:
            return val
    return None


def _detect_pqclean_commit() -> str | None:
    config = _PROJECT_ROOT / "liboqs" / "scripts" / "copy_from_upstream" / "copy_from_upstream.yml"
    if not config.exists():
        return None
    try:
        lines = config.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return None
    active_name = None
    fallback_commit = None
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("name:"):
            active_name = line.split(":", 1)[1].strip()
            continue
        if line.startswith("git_commit:") and active_name:
            commit = line.split(":", 1)[1].strip().strip("'\"")
            if active_name == "pqclean" and commit:
                return commit
            if active_name == "oldpqclean" and commit and not fallback_commit:
                fallback_commit = commit
    return fallback_commit


def _collect_cmake_flags(cache_path: pathlib.Path) -> Dict[str, str]:
    flags: Dict[str, str] = {}
    if not cache_path.exists():
        return flags
    try:
        for raw in cache_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not raw or raw.startswith("#") or raw.startswith("//"):
                continue
            if "=" not in raw:
                continue
            key_part, value = raw.split("=", 1)
            key = key_part.split(":", 1)[0]
            if "FLAGS" in key or key in {"CMAKE_BUILD_TYPE"}:
                val = value.strip()
                if val:
                    flags[key] = val
    except Exception:
        return {}
    return flags


def _detect_build_flags() -> Dict[str, Dict[str, str]] | None:
    out: Dict[str, Dict[str, str]] = {}
    native_cache = _PROJECT_ROOT / "native" / "build" / "CMakeCache.txt"
    native_flags = _collect_cmake_flags(native_cache)
    if native_flags:
        out["native"] = native_flags
    liboqs_cache = _PROJECT_ROOT / "native" / "build" / "liboqs_build" / "CMakeCache.txt"
    liboqs_flags = _collect_cmake_flags(liboqs_cache)
    if liboqs_flags:
        out["liboqs"] = liboqs_flags
    return out or None


def _collect_environment_meta() -> Dict[str, Any]:
    global _ENVIRONMENT_CACHE
    if _ENVIRONMENT_CACHE is None:
        info: Dict[str, Any] = {}
        cpu_model = _detect_cpu_model()
        if cpu_model:
            info["cpu_model"] = cpu_model
        try:
            info["os"] = platform.platform(aliased=True)
        except Exception:
            pass
        info["python"] = platform.python_version()
        deps: Dict[str, str] = {}
        liboqs_commit = _read_git_commit(_PROJECT_ROOT / "liboqs")
        if liboqs_commit:
            deps["liboqs_commit"] = liboqs_commit
        pqclean_commit = _detect_pqclean_commit()
        if pqclean_commit:
            deps["pqclean_commit"] = pqclean_commit
        if deps:
            info["dependencies"] = deps
        build_flags = _detect_build_flags()
        if build_flags:
            info["build_flags"] = build_flags
        _ENVIRONMENT_CACHE = info
    return copy.deepcopy(_ENVIRONMENT_CACHE)


def _get_adapter_instance(name: str):
    adapter = _ADAPTER_INSTANCE_CACHE.get(name)
    if adapter is not None:
        return adapter
    cls = registry.get(name)
    adapter = cls()
    _ADAPTER_INSTANCE_CACHE[name] = adapter
    return adapter


def reset_adapter_cache(name: Optional[str] = None) -> None:
    """Drop cached adapter instances so env-driven overrides take effect."""
    if name is None:
        _ADAPTER_INSTANCE_CACHE.clear()
        return
    _ADAPTER_INSTANCE_CACHE.pop(name, None)


def _value_in_range(value: Any, range_list: Any) -> Optional[List[float]]:
    try:
        val = float(value)
    except (TypeError, ValueError):
        return None
    if not (isinstance(range_list, (list, tuple)) and len(range_list) == 2):
        return None
    try:
        lo = float(range_list[0])
        hi = float(range_list[1])
    except (TypeError, ValueError):
        return None
    if lo > hi:
        lo, hi = hi, lo
    slack = max(1.0, abs(hi - lo) * 0.01)
    if lo - slack <= val <= hi + slack:
        return [lo, hi]
    return None


def _format_runtime(seconds: Any) -> Optional[str]:
    try:
        sec = float(seconds)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(sec) or sec <= 0.0:
        return None
    if sec < 1.0:
        return f"{sec * 1000.0:.0f}ms"
    if sec < 120.0:
        return f"{sec:.1f}s"
    minutes = sec / 60.0
    if minutes < 120.0:
        return f"{minutes:.1f}m"
    hours = sec / 3600.0
    if hours < 48.0:
        return f"{hours:.1f}h"
    days = sec / 86400.0
    if days < 730.0:
        return f"{days:.1f}d"
    years = sec / 31557600.0
    return f"{years:.1f}y"


def _format_quantity(value: Any, unit: str = "", precision: int = 1) -> Optional[str]:
    try:
        val = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(val):
        return None
    abs_val = abs(val)
    divisor = 1.0
    suffix = ""
    for threshold, marker in ((1e12, "T"), (1e9, "B"), (1e6, "M"), (1e3, "k")):
        if abs_val >= threshold:
            divisor = threshold
            suffix = marker
            break
    formatted = f"{val / divisor:.{precision}f}{suffix}"
    if unit:
        formatted += unit
    return formatted


def _ensure_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    if value in (None, ""):
        return []
    return [str(value)]


def _compute_ci95(mean: float, samples: Sequence[float]) -> Tuple[float, float]:
    if not samples:
        return mean, mean
    if len(samples) < 2:
        return mean, mean
    try:
        std = statistics.stdev(samples)
    except statistics.StatisticsError:
        return mean, mean
    if std == 0:
        return mean, mean
    margin = _CI_Z * (std / math.sqrt(len(samples)))
    return mean - margin, mean + margin


def _load_adapters() -> None:
    import importlib, importlib.util, traceback
    modules = ("pqcbench_rsa", "pqcbench_liboqs", "pqcbench_native")
    global _NATIVE_WARNED
    for mod in modules:
        spec = importlib.util.find_spec(mod)
        if spec is None:
            candidate = _ADAPTER_PATHS.get(mod)
            if candidate and candidate.exists():
                if str(candidate) not in sys.path:
                    sys.path.append(str(candidate))
                spec = importlib.util.find_spec(mod)
        if spec is None:
            if mod == "pqcbench_native" and not _NATIVE_WARNED:
                print("[adapter optional] pqcbench_native not installed; build native/ or install the package to enable the C backend.")
                _NATIVE_WARNED = True
            continue
        try:
            module = importlib.import_module(mod)
        except Exception as e:
            print(f"[adapter import error] {mod}: {e}")
            traceback.print_exc()
        else:
            if mod == "pqcbench_native" and not getattr(module, "_available", False):
                if not _NATIVE_WARNED:
                    print("[adapter optional] pqcbench_native shared library not found. Build native/ (cmake --build) or set PQCBENCH_NATIVE_LIB to the compiled library path.")
                    _NATIVE_WARNED = True

_load_adapters()


@dataclass
class OpStats:
    runs: int
    mean_ms: float
    min_ms: float
    max_ms: float
    median_ms: float
    stddev_ms: float
    ci95_low_ms: float
    ci95_high_ms: float
    range_ms: float
    series: List[float]
    # Memory footprint metrics (per-run process delta / Python peak)
    mem_mean_kb: float | None = None
    mem_min_kb: float | None = None
    mem_max_kb: float | None = None
    mem_median_kb: float | None = None
    mem_stddev_kb: float | None = None
    mem_ci95_low_kb: float | None = None
    mem_ci95_high_kb: float | None = None
    mem_range_kb: float | None = None
    mem_series_kb: List[float] | None = None
    runtime_scaling: RuntimeScalingResult | None = None

@dataclass
class AlgoSummary:
    algo: str
    kind: str   # 'KEM' or 'SIG'
    ops: Dict[str, OpStats]
    meta: Dict[str, Any]

def measure(
    fn: Callable[[], None],
    runs: int,
    *,
    cold: bool = True,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    capture_memory: bool = True,
    memory_interval: float | None = None,
) -> OpStats:
    """Measure time and memory footprint in isolated runs.

    Every iteration executes in a fresh Python process so caches, allocator pools,
    and liboqs state from previous runs cannot influence the measurement.
    Reported memory captures the peak unique RSS delta observed during the run
    (sampled every ~1.5 ms by default) merged with the Python heap peak (KB).
    If psutil or tracemalloc are unavailable, or `capture_memory` is False, the
    memory fields remain None. Set `memory_interval` to control the sampling
    cadence (seconds) when memory capture is enabled.
    """
    times: List[float] = []
    mem_peaks_kb: List[float] = []
    interval = _MEMORY_SAMPLE_INTERVAL if memory_interval is None else float(memory_interval)

    for i in range(runs):
        if cold:
            dt_ms, mem_kb = _run_isolated(fn, capture_memory=capture_memory, memory_interval=interval)
        else:
            dt_ms, mem_kb = _single_run_metrics(fn, capture_memory=capture_memory, memory_interval=interval)
        times.append(dt_ms)
        if mem_kb is not None:
            mem_peaks_kb.append(mem_kb)
        try:
            if progress_cb is not None:
                progress_cb(i + 1, runs)
        except Exception:
            # Never let progress reporting break measurements
            pass

    mean = sum(times) / len(times)
    median = statistics.median(times)
    stddev = statistics.pstdev(times) if len(times) > 1 else 0.0
    min_time = min(times)
    max_time = max(times)
    range_ms = max_time - min_time
    ci_low, ci_high = _compute_ci95(mean, times)

    if mem_peaks_kb:
        mem_mean = sum(mem_peaks_kb) / len(mem_peaks_kb)
        mem_min = min(mem_peaks_kb)
        mem_max = max(mem_peaks_kb)
        mem_median = statistics.median(mem_peaks_kb)
        mem_stddev = statistics.pstdev(mem_peaks_kb) if len(mem_peaks_kb) > 1 else 0.0
        mem_range = mem_max - mem_min
        mem_ci_low, mem_ci_high = _compute_ci95(mem_mean, mem_peaks_kb)
        return OpStats(
            runs=runs,
            mean_ms=mean,
            min_ms=min_time,
            max_ms=max_time,
            median_ms=median,
            stddev_ms=stddev,
            ci95_low_ms=ci_low,
            ci95_high_ms=ci_high,
            range_ms=range_ms,
            series=times,
            mem_mean_kb=mem_mean,
            mem_min_kb=mem_min,
            mem_max_kb=mem_max,
            mem_median_kb=mem_median,
            mem_stddev_kb=mem_stddev,
            mem_ci95_low_kb=mem_ci_low,
            mem_ci95_high_kb=mem_ci_high,
            mem_range_kb=mem_range,
            mem_series_kb=mem_peaks_kb,
        )
    else:
        return OpStats(
            runs=runs,
            mean_ms=mean,
            min_ms=min_time,
            max_ms=max_time,
            median_ms=median,
            stddev_ms=stddev,
            ci95_low_ms=ci_low,
            ci95_high_ms=ci_high,
            range_ms=range_ms,
            series=times,
        )


def measure_factory(
    factory: Callable[[], Callable[[], None]],
    runs: int,
    *,
    cold: bool = True,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    capture_memory: bool = True,
    memory_interval: float | None = None,
) -> OpStats:
    """Measure only the core operation produced by `factory`.

    The `factory` runs inside the child process before timing starts to prepare
    fresh inputs (e.g., keygen, message, ciphertext). The returned zero-arg
    callable is then executed under timing/memory monitoring so that only the
    stage operation itself is measured.
    """
    times: List[float] = []
    mem_peaks_kb: List[float] = []
    interval = _MEMORY_SAMPLE_INTERVAL if memory_interval is None else float(memory_interval)

    for i in range(runs):
        if cold:
            dt_ms, mem_kb = _run_isolated_factory(factory, capture_memory=capture_memory, memory_interval=interval)
        else:
            op = factory()
            dt_ms, mem_kb = _single_run_metrics(op, capture_memory=capture_memory, memory_interval=interval)
        times.append(dt_ms)
        if mem_kb is not None:
            mem_peaks_kb.append(mem_kb)
        try:
            if progress_cb is not None:
                progress_cb(i + 1, runs)
        except Exception:
            pass

    mean = sum(times) / len(times)
    median = statistics.median(times)
    stddev = statistics.pstdev(times) if len(times) > 1 else 0.0
    min_time = min(times)
    max_time = max(times)
    range_ms = max_time - min_time
    ci_low, ci_high = _compute_ci95(mean, times)

    if mem_peaks_kb:
        mem_mean = sum(mem_peaks_kb) / len(mem_peaks_kb)
        mem_min = min(mem_peaks_kb)
        mem_max = max(mem_peaks_kb)
        mem_median = statistics.median(mem_peaks_kb)
        mem_stddev = statistics.pstdev(mem_peaks_kb) if len(mem_peaks_kb) > 1 else 0.0
        mem_range = mem_max - mem_min
        mem_ci_low, mem_ci_high = _compute_ci95(mem_mean, mem_peaks_kb)
        return OpStats(
            runs=runs,
            mean_ms=mean,
            min_ms=min_time,
            max_ms=max_time,
            median_ms=median,
            stddev_ms=stddev,
            ci95_low_ms=ci_low,
            ci95_high_ms=ci_high,
            range_ms=range_ms,
            series=times,
            mem_mean_kb=mem_mean,
            mem_min_kb=mem_min,
            mem_max_kb=mem_max,
            mem_median_kb=mem_median,
            mem_stddev_kb=mem_stddev,
            mem_ci95_low_kb=mem_ci_low,
            mem_ci95_high_kb=mem_ci_high,
            mem_range_kb=mem_range,
            mem_series_kb=mem_peaks_kb,
        )
    else:
        return OpStats(
            runs=runs,
            mean_ms=mean,
            min_ms=min_time,
            max_ms=max_time,
            median_ms=median,
            stddev_ms=stddev,
            ci95_low_ms=ci_low,
            ci95_high_ms=ci_high,
            range_ms=range_ms,
            series=times,
        )


def _run_isolated(
    fn: Callable[[], None],
    *,
    capture_memory: bool = True,
    memory_interval: float = _MEMORY_SAMPLE_INTERVAL,
) -> Tuple[float, float | None]:
    """Execute `fn` in a fresh process and return (time_ms, memory_kb)."""
    parent_conn, child_conn = _MP_CONTEXT.Pipe(duplex=False)
    proc = _MP_CONTEXT.Process(
        target=_isolated_worker,
        args=(fn, child_conn, bool(capture_memory), float(memory_interval)),
    )
    proc.start()
    child_conn.close()
    try:
        result = parent_conn.recv()
    except EOFError:
        proc.join()
        raise RuntimeError("Benchmark worker exited without reporting results.")
    finally:
        parent_conn.close()
    proc.join()
    status = result.get("status")
    if status == "ok":
        return result["time_ms"], result["mem_kb"]
    err = result.get("error") or "unknown error"
    tb = result.get("traceback")
    message = f"Benchmark worker failed: {err}"
    if tb:
        message = f"{message}\n{tb}"
    raise RuntimeError(message)


def _run_isolated_factory(
    factory: Callable[[], Callable[[], None]],
    *,
    capture_memory: bool = True,
    memory_interval: float = _MEMORY_SAMPLE_INTERVAL,
) -> Tuple[float, float | None]:
    """Execute factory->op in a fresh process and return (time_ms, memory_kb).

    The factory runs before timing to prepare inputs; only the returned op
    callable is measured under timing/memory monitoring.
    """
    parent_conn, child_conn = _MP_CONTEXT.Pipe(duplex=False)
    proc = _MP_CONTEXT.Process(
        target=_isolated_worker_factory,
        args=(factory, child_conn, bool(capture_memory), float(memory_interval)),
    )
    proc.start()
    child_conn.close()
    try:
        result = parent_conn.recv()
    except EOFError:
        proc.join()
        raise RuntimeError("Benchmark worker exited without reporting results.")
    finally:
        parent_conn.close()
    proc.join()
    status = result.get("status")
    if status == "ok":
        return result["time_ms"], result["mem_kb"]
    err = result.get("error") or "unknown error"
    tb = result.get("traceback")
    message = f"Benchmark worker failed: {err}"
    if tb:
        message = f"{message}\n{tb}"
    raise RuntimeError(message)


def _isolated_worker(
    fn: Callable[[], None],
    conn,
    capture_memory: bool,
    memory_interval: float,
) -> None:
    """Child-process entry point for isolated measurements."""
    try:
        dt, mem_kb = _single_run_metrics(
            fn,
            capture_memory=capture_memory,
            memory_interval=memory_interval,
        )
        conn.send({"status": "ok", "time_ms": dt, "mem_kb": mem_kb})
    except Exception as exc:
        import traceback
        conn.send({
            "status": "error",
            "error": repr(exc),
            "traceback": traceback.format_exc(),
        })
    finally:
        conn.close()


def _isolated_worker_factory(
    factory: Callable[[], Callable[[], None]],
    conn,
    capture_memory: bool,
    memory_interval: float,
) -> None:
    """Child-process entry point for factory-based isolated measurements."""
    try:
        # Prepare inputs before timing begins
        op = factory()
        dt, mem_kb = _single_run_metrics(
            op,
            capture_memory=capture_memory,
            memory_interval=memory_interval,
        )
        conn.send({"status": "ok", "time_ms": dt, "mem_kb": mem_kb})
    except Exception as exc:
        import traceback
        conn.send({
            "status": "error",
            "error": repr(exc),
            "traceback": traceback.format_exc(),
        })
    finally:
        conn.close()


def _single_run_metrics(
    fn: Callable[[], None],
    *,
    capture_memory: bool = True,
    memory_interval: float = _MEMORY_SAMPLE_INTERVAL,
) -> Tuple[float, float | None]:
    """Run `fn` exactly once, capturing time (and optionally memory usage)."""
    import os
    import gc
    import time as _time

    interval = _MEMORY_SAMPLE_INTERVAL if memory_interval <= 0 else memory_interval
    gc.collect()
    baseline_bytes: int | None = None
    after_bytes: int | None = None
    rss_peak_kb: float | None = None
    proc = None
    monitor_stop: threading.Event | None = None
    monitor_thread: threading.Thread | None = None
    peak_bytes_holder: list[int | None] = []
    monitor_enabled = False
    sample_process_bytes: Callable[[], int] | None = None

    if capture_memory:
        try:
            import psutil  # type: ignore

            proc = psutil.Process(os.getpid())

            def _sample_process_bytes() -> int:
                try:
                    full = proc.memory_full_info()
                    uss = getattr(full, "uss", None)
                    if uss is not None:
                        return int(uss)
                except Exception:
                    pass
                return int(proc.memory_info().rss)

            sample_process_bytes = _sample_process_bytes
            baseline_bytes = sample_process_bytes()
            monitor_stop = threading.Event()
            peak_bytes_holder = [baseline_bytes]

            def _monitor_peak() -> None:
                base = baseline_bytes if baseline_bytes is not None else 0
                local_peak = base
                wait_interval = interval if interval > 0 else _MEMORY_SAMPLE_INTERVAL
                while not monitor_stop.is_set():
                    try:
                        sample = _sample_process_bytes()
                        if sample is not None and sample > local_peak:
                            local_peak = sample
                    except Exception:
                        pass
                    if monitor_stop.wait(wait_interval):
                        break
                try:
                    sample = _sample_process_bytes()
                    if sample is not None and sample > local_peak:
                        local_peak = sample
                except Exception:
                    pass
                peak_bytes_holder[0] = local_peak

            monitor_thread = threading.Thread(
                target=_monitor_peak,
                name="pqcbench-memmon",
                daemon=True,
            )
            monitor_thread.start()
            monitor_enabled = True
        except Exception:
            proc = None  # type: ignore
            monitor_stop = None
            monitor_thread = None
            peak_bytes_holder = []
            monitor_enabled = False
            sample_process_bytes = None

    tracemalloc = None  # type: ignore
    use_tracemalloc = False
    if capture_memory:
        try:
            import tracemalloc  # type: ignore

            tracemalloc.start()
            use_tracemalloc = True
        except Exception:
            tracemalloc = None  # type: ignore
            use_tracemalloc = False

    t0 = _time.perf_counter()
    try:
        fn()
    finally:
        if monitor_stop is not None:
            monitor_stop.set()
        if monitor_thread is not None:
            monitor_thread.join(timeout=0.5)
    dt_ms = (_time.perf_counter() - t0) * 1000.0

    rss_peak_bytes: int | None = None
    if peak_bytes_holder:
        candidate = peak_bytes_holder[0]
        if isinstance(candidate, int):
            rss_peak_bytes = candidate

    if monitor_enabled and sample_process_bytes is not None and baseline_bytes is not None:
        try:
            after_bytes = sample_process_bytes()
        except Exception:
            after_bytes = None
        gc.collect()

    candidate_deltas: List[float] = []
    if baseline_bytes is not None:
        if rss_peak_bytes is not None:
            candidate_deltas.append(max(0.0, float(rss_peak_bytes - baseline_bytes)))
        if after_bytes is not None:
            candidate_deltas.append(max(0.0, float(after_bytes - baseline_bytes)))
    if candidate_deltas:
        rss_peak_kb = max(candidate_deltas) / 1024.0

    py_peak_kb: float | None = None
    if use_tracemalloc and tracemalloc is not None:
        try:
            _, peak_bytes = tracemalloc.get_traced_memory()
            py_peak_kb = peak_bytes / 1024.0
        finally:
            tracemalloc.stop()

    if py_peak_kb is not None:
        rss_peak_kb = max(rss_peak_kb or 0.0, py_peak_kb)

    if not capture_memory:
        rss_peak_kb = None

    gc.collect()
    return dt_ms, rss_peak_kb


def _kem_keygen_factory(name: str) -> Callable[[], None]:
    """Return an operation that runs keygen after adapter setup."""
    adapter = _get_adapter_instance(name)

    def _op() -> None:
        adapter.keygen()

    return _op


def _sig_keygen_factory(name: str) -> Callable[[], None]:
    """Return an operation that runs signature keygen after adapter setup."""
    adapter = _get_adapter_instance(name)

    def _op() -> None:
        adapter.keygen()

    return _op


def _kem_encapsulate_factory(name: str) -> Callable[[], None]:
    """Prepare fresh key, return op that only runs encapsulate."""
    adapter = _get_adapter_instance(name)
    pk, _ = adapter.keygen()

    def _op() -> None:
        adapter.encapsulate(pk)

    return _op


def _kem_decapsulate_factory(name: str) -> Callable[[], None]:
    """Prepare fresh keys and ciphertext, return op that only runs decapsulate."""
    adapter = _get_adapter_instance(name)
    pk, sk = adapter.keygen()
    ct, _ = adapter.encapsulate(pk)

    def _op() -> None:
        adapter.decapsulate(sk, ct)

    return _op


def _sig_sign_factory(name: str, message_size: int) -> Callable[[], None]:
    """Prepare fresh key and message, return op that only runs sign."""
    adapter = _get_adapter_instance(name)
    msg = b"x" * int(message_size)
    _, sk = adapter.keygen()

    def _op() -> None:
        adapter.sign(sk, msg)

    return _op


def _sig_verify_factory(name: str, message_size: int) -> Callable[[], None]:
    """Prepare fresh keys/message/signature, return op that only runs verify."""
    adapter = _get_adapter_instance(name)
    msg = b"x" * int(message_size)
    pk, sk = adapter.keygen()
    sig = adapter.sign(sk, msg)

    def _op() -> None:
        adapter.verify(pk, msg, sig)

    return _op


def _standardize_security(summary: AlgoSummary, sec: Dict[str, Any]) -> Dict[str, Any]:
    """Create a standardized, compact security block from estimator output.

    The goal is to remove repetition and provide a uniform shape across algorithms
    while preserving important details. Family-specific extras are grouped under
    'parameters', 'resources', and 'estimates'.
    """
    extras = dict(sec.get("extras") or {})
    algo = summary.algo
    mechanism = sec.get("mechanism") or summary.meta.get("mechanism")

    # Infer family
    fam = None
    if isinstance(extras.get("params"), dict):
        fam = extras["params"].get("family")
    if not fam:
        fam_map = {
            "rsa-oaep": "RSA",
            "rsa-pss": "RSA",
            "kyber": "ML-KEM",
            "dilithium": "ML-DSA",
            "falcon": "Falcon",
            "hqc": "HQC",
            "sphincsplus": "SPHINCS+",
            "sphincs+": "SPHINCS+",
            "xmssmt": "XMSSMT",
            "mayo": "MAYO",
        }
        fam = fam_map.get(algo)

    # Common header
    if not mechanism:
        mod_bits = extras.get("modulus_bits")
        if algo == "rsa-oaep":
            bits = int(mod_bits or 2048)
            mechanism = f"RSA-{bits}-OAEP"
        elif algo == "rsa-pss":
            bits = int(mod_bits or 2048)
            mechanism = f"RSA-{bits}-PSS"

    out: Dict[str, Any] = {
        "mechanism": mechanism,
        "family": fam,
        "category_floor": extras.get("category_floor"),
        "nist_category": extras.get("nist_category"),
        "classical_bits": sec.get("classical_bits"),
        "quantum_bits": sec.get("quantum_bits"),
        "shor_breakable": bool(sec.get("shor_breakable")),
        "notes": sec.get("notes"),
    }

    # Estimator info (if applicable)
    est_name = extras.get("estimator_model")
    est_profile = extras.get("lattice_profile")
    est_available = extras.get("estimator_available")
    if est_available is None:
        est_available = bool(est_name) and not str(est_name).startswith("unavailable")
    if est_name or est_profile or extras.get("estimator_reference"):
        out["estimator"] = {
            "name": est_name,
            "profile": est_profile,
            "available": bool(est_available),
        }
        if extras.get("estimator_reference"):
            out["estimator"]["reference"] = extras.get("estimator_reference")

    # Parameters per family (best-effort)
    params: Dict[str, Any] | None = None
    if algo == "kyber":
        params = (extras.get("mlkem", {}) or {}).get("kyber_params")
    elif algo == "dilithium":
        params = (extras.get("mldsa", {}) or {}).get("dilithium_params")
    elif algo == "falcon":
        params = (extras.get("falcon", {}) or {}).get("params")
    elif algo in ("sphincsplus", "sphincs+"):
        sx = (extras.get("sphincs") or {})
        params = {
            "hash_output_bits": sx.get("hash_output_bits"),
            "variant": sx.get("variant"),
            "family": sx.get("family"),
        }
    elif algo == "xmssmt":
        xx = (extras.get("xmss") or {})
        params = {
            "hash_output_bits": xx.get("hash_output_bits"),
            "tree_height": (xx.get("structure") or {}).get("tree_height"),
            "layers": (xx.get("structure") or {}).get("layers"),
        }
    elif algo == "hqc":
        # Parameters for HQC are not currently stored in params.py by default
        params = None
    elif algo in ("rsa-oaep", "rsa-pss"):
        params = {"modulus_bits": extras.get("modulus_bits")}
    elif algo == "mayo":
        params = (extras.get("mayo", {}) or {}).get("params")
    # Fallback to ParamHint if nothing else
    if not params and isinstance(extras.get("params"), dict):
        ph = extras["params"]
        params = {k: ph.get(k) for k in ("mechanism", "notes")}
        # Include any extras provided in ParamHint
        if isinstance(ph.get("extras"), dict):
            params.update(ph["extras"])  # type: ignore
    params = params or {}
    if extras.get("sizes_bytes"):
        params.setdefault("sizes_bytes", extras.get("sizes_bytes"))
    if params:
        out["parameters"] = params

    # Resources (RSA-specific)
    if algo in ("rsa-oaep", "rsa-pss"):
        logical = extras.get("logical") or {}
        res = {
            "logical": logical,
            "t_counts": extras.get("t_counts"),
            "rsa_model": extras.get("rsa_model"),
            "shor_model_notes": extras.get("shor_model_notes"),
            "log2_n_bits": extras.get("log2_n_bits"),
        }
        if extras.get("t_count_assumptions"):
            res["t_count_assumptions"] = extras.get("t_count_assumptions")
        if extras.get("surface"):
            res["surface"] = extras.get("surface")
        if extras.get("shor_profiles"):
            res["shor_profiles"] = extras.get("shor_profiles")
        out["resources"] = res

    # Estimates (curated or algorithm-specific)
    estimates: Dict[str, Any] = {}
    # Lattice curated
    module_cost: Dict[str, Any] | None = None
    if algo == "kyber":
        mlkem = (extras.get("mlkem", {}) or {})
        module_cost = mlkem.get("module_lwe_cost") if isinstance(mlkem, dict) else None
        ce = mlkem.get("curated_estimates") if isinstance(mlkem, dict) else None
        if ce:
            if isinstance(ce, dict):
                ce.setdefault("source", "core-svp-spec-table")
            estimates["curated"] = ce
        consts = mlkem.get("core_svp_constants") if isinstance(mlkem, dict) else None
        if consts:
            out.setdefault("assumptions", {})["core_svp_constants"] = consts
    elif algo == "dilithium":
        mldsa = (extras.get("mldsa", {}) or {})
        module_cost = mldsa.get("module_lwe_cost") if isinstance(mldsa, dict) else None
        ce = mldsa.get("curated_estimates") if isinstance(mldsa, dict) else None
        if ce:
            if isinstance(ce, dict):
                ce.setdefault("source", "literature-range")
            estimates["curated"] = ce
        consts = mldsa.get("core_svp_constants") if isinstance(mldsa, dict) else None
        if consts:
            out.setdefault("assumptions", {})["core_svp_constants"] = consts
    elif algo == "falcon":
        falcon_block = (extras.get("falcon", {}) or {})
        ce = falcon_block.get("curated_estimates") if isinstance(falcon_block, dict) else None
        if ce:
            if isinstance(ce, dict):
                ce.setdefault("source", "curated-range")
            estimates["curated"] = ce
            estimates["calculated"] = {
                "profile": "curated-range",
                "attack": "design-target",
                "classical_bits": ce.get("classical_bits_mid"),
                "quantum_bits": ce.get("quantum_bits_mid"),
                "classical_bits_range": ce.get("classical_bits_range"),
                "quantum_bits_range": ce.get("quantum_bits_range"),
                "source": ce.get("source"),
            }
        consts = falcon_block.get("core_svp_constants") if isinstance(falcon_block, dict) else None
        if consts:
            out.setdefault("assumptions", {})["core_svp_constants"] = consts
        bkz_model = falcon_block.get("bkz_model") if isinstance(falcon_block, dict) else None
        if bkz_model:
            out.setdefault("details", {})["falcon_bkz_model"] = bkz_model
            # Promote a simple headline from BKZ model so the GUI table can show it
            try:
                attacks = bkz_model.get("attacks") or []
                c_const = (bkz_model.get("core_svp_constants") or {}).get("classical", 0.292)
                q_const = (bkz_model.get("core_svp_constants") or {}).get("quantum", 0.265)
                best = None
                for a_entry in attacks:
                    bsucc = a_entry.get("beta_success")
                    if isinstance(bsucc, (int, float)):
                        c_bits = c_const * float(bsucc)
                        q_bits = q_const * float(bsucc)
                        tup = (c_bits, a_entry.get("attack"), float(bsucc), q_bits)
                        if best is None or c_bits < best[0]:
                            best = tup
                if best is not None:
                    out.setdefault("details", {})["falcon_bkz_projection"] = {
                        "attack": best[1],
                        "beta": best[2],
                        "classical_bits": best[0],
                        "quantum_bits": best[3],
                        "source": "falcon-bkz-curve",
                    }
            except Exception:
                pass
    elif algo in ("sphincsplus", "sphincs+"):
        sx = extras.get("sphincs") or {}
        if sx.get("curated_estimates"):
            ce = sx.get("curated_estimates")
            if isinstance(ce, dict):
                ce.setdefault("source", "curated-range")
            estimates["curated"] = ce
        if sx.get("hash_costs"):
            estimates["hash_costs"] = sx.get("hash_costs")
        sanity = sx.get("sanity")
        if sanity:
            estimates["sanity"] = sanity
        structure = sx.get("structure")
        if structure:
            out.setdefault("parameters", {}).update({
                "layers": structure.get("layers"),
                "hypertree_height": structure.get("hypertree_height"),
                "fors_trees": structure.get("fors_trees"),
                "fors_height": structure.get("fors_height"),
                "winternitz_w": structure.get("winternitz_w"),
            })
    elif algo == "xmssmt":
        xx = extras.get("xmss") or {}
        if xx.get("hash_costs"):
            estimates["hash_costs"] = xx.get("hash_costs")
    elif algo == "hqc":
        if isinstance(extras.get("isd"), dict):
            estimates["hqc_isd"] = extras["isd"]
        else:
            keys = [
                "isd_model",
                "isd_time_bits_classical",
                "isd_mem_bits_classical",
                "isd_time_bits_quantum_grover",
                "isd_time_bits_quantum_conservative",
            ]
            isd = {k: extras.get(k) for k in keys if k in extras}
            if isd:
                estimates["hqc_isd"] = isd
        curated = extras.get("curated_estimates")
        if isinstance(curated, dict):
            curated = curated.copy()
            curated.setdefault("source", curated.get("source", "hqc-round3-design"))
            estimates["curated"] = curated
            estimates["calculated"] = {
                "profile": "design-target",
                "attack": "design-target",
                "classical_bits": curated.get("classical_bits_mid"),
                "quantum_bits": curated.get("quantum_bits_mid"),
                "classical_bits_range": curated.get("classical_bits_range"),
                "quantum_bits_range": curated.get("quantum_bits_range"),
                "source": curated.get("source"),
            }
    elif algo == "mayo":
        my = extras.get("mayo") or {}
        if my.get("curated_estimates"):
            ce = my.get("curated_estimates")
            if isinstance(ce, dict):
                ce = ce.copy()
                ce.setdefault("source", "design-target")
            estimates["curated"] = ce
            if isinstance(ce, dict):
                estimates.setdefault("calculated", {
                    "profile": "mq-design",
                    "attack": "design-target",
                    "classical_bits": ce.get("classical_bits_mid"),
                    "quantum_bits": ce.get("quantum_bits_mid"),
                    "classical_bits_range": ce.get("classical_bits_range"),
                    "quantum_bits_range": ce.get("quantum_bits_range"),
                    "source": ce.get("source"),
                })
        if my.get("checks"):
            estimates["checks"] = my.get("checks")

    # Ensure a standardized "calculated" block for all PQCs so GUI tables can render rows consistently
    if "calculated" not in estimates:
        try:
            if algo == "hqc":
                isd = extras.get("isd") or {}
                stern = (isd.get("stern_entropy") or {})
                bjmm = (isd.get("bjmm") or {})
                c_candidates = []
                q_candidates = []
                if isinstance(stern.get("time_bits_classical"), (int, float)):
                    c_candidates.append((float(stern["time_bits_classical"]), "stern"))
                if isinstance(bjmm.get("time_bits_classical"), (int, float)):
                    c_candidates.append((float(bjmm["time_bits_classical"]), "bjmm"))
                if isinstance(stern.get("time_bits_quantum_grover"), (int, float)):
                    q_candidates.append((float(stern["time_bits_quantum_grover"]), "stern"))
                if isinstance(bjmm.get("time_bits_quantum_grover"), (int, float)):
                    q_candidates.append((float(bjmm["time_bits_quantum_grover"]), "bjmm"))
                if c_candidates:
                    c_best = min(c_candidates, key=lambda t: t[0])
                    # Pair quantum with the same attack if available; else take min
                    q_for_best = None
                    for v, name in q_candidates:
                        if name == c_best[1]:
                            q_for_best = v
                            break
                    if q_for_best is None and q_candidates:
                        q_for_best = min(q_candidates, key=lambda t: t[0])[0]
                    c_vals = [v for v, _ in c_candidates]
                    q_vals = [v for v, _ in q_candidates] if q_candidates else None
                    estimates["calculated"] = {
                        "profile": "isd",
                        "attack": c_best[1],
                        "classical_bits": c_best[0],
                        "quantum_bits": q_for_best,
                        "classical_bits_range": [min(c_vals), max(c_vals)] if len(c_vals) >= 2 else None,
                        "quantum_bits_range": ([min(q_vals), max(q_vals)] if (q_vals and len(q_vals) >= 2) else None),
                        "source": "isd-heuristic",
                    }
            elif algo in ("sphincsplus", "sphincs+"):
                sx = extras.get("sphincs") or {}
                ce = sx.get("curated_estimates") or {}
                if ce:
                    estimates["calculated"] = {
                        "profile": "hash",
                        "attack": "collision/preimage",
                        "classical_bits": ce.get("classical_bits_mid"),
                        "quantum_bits": ce.get("quantum_bits_mid"),
                        "classical_bits_range": ce.get("classical_bits_range"),
                        "quantum_bits_range": ce.get("quantum_bits_range"),
                        "source": "curated-range",
                    }
            elif algo == "xmssmt":
                xx = extras.get("xmss") or {}
                hc = xx.get("hash_costs") or {}
                cb = hc.get("collision_bits")
                qb = hc.get("quantum_collision_bits")
                if isinstance(cb, (int, float)):
                    estimates["calculated"] = {
                        "profile": "hash",
                        "attack": "collision",
                        "classical_bits": float(cb),
                        "quantum_bits": float(qb) if isinstance(qb, (int, float)) else None,
                        "classical_bits_range": None,
                        "quantum_bits_range": None,
                        "source": "hash-model",
                    }
            elif algo == "mayo":
                my = extras.get("mayo") or {}
                checks = my.get("checks") or {}
                rank_bits = (checks.get("rank_attack") or {}).get("bits")
                minrank_bits = (checks.get("minrank") or {}).get("bits")
                candidates = []
                if isinstance(rank_bits, (int, float)):
                    candidates.append((float(rank_bits), "rank"))
                if isinstance(minrank_bits, (int, float)):
                    candidates.append((float(minrank_bits), "minrank"))
                if candidates:
                    best = min(candidates, key=lambda t: t[0])
                    estimates["calculated"] = {
                        "profile": "mq",
                        "attack": best[1],
                        "classical_bits": best[0],
                        "quantum_bits": best[0],  # no standard quantum speedup model applied here
                        "classical_bits_range": [min(v for v, _ in candidates), max(v for v, _ in candidates)] if len(candidates) >= 2 else None,
                        "quantum_bits_range": None,
                    }
        except Exception:
            pass

    # Propagate curated ranges into the calculated block when available.
    calc_block = estimates.get("calculated") if isinstance(estimates, dict) else None
    curated_block = estimates.get("curated") if isinstance(estimates, dict) else None
    if isinstance(calc_block, dict) and isinstance(curated_block, dict):
        for value_key, range_key in (("classical_bits", "classical_bits_range"), ("quantum_bits", "quantum_bits_range")):
            if calc_block.get(range_key) is not None:
                continue
            range_val = curated_block.get(range_key)
            if not (isinstance(range_val, list) and len(range_val) == 2):
                continue
            value = calc_block.get(value_key)
            if isinstance(value, (int, float)):
                lo, hi = range_val
                if isinstance(lo, (int, float)) and isinstance(hi, (int, float)) and lo <= value <= hi:
                    calc_block[range_key] = range_val
            else:
                calc_block[range_key] = range_val

    if module_cost:
        headline = module_cost.get("headline") or {}
        estimates["calculated"] = {
            "profile": "core-svp",
            "attack": headline.get("attack"),
            "classical_bits": headline.get("classical_bits"),
            "quantum_bits": headline.get("quantum_bits"),
            "classical_bits_range": None,
            "quantum_bits_range": None,
        }
        model_block = {
            "model": module_cost.get("model"),
            "source": module_cost.get("source"),
            "params": module_cost.get("params"),
            "sigma_error": module_cost.get("sigma_error"),
            "sigma_secret": module_cost.get("sigma_secret"),
        }
        out.setdefault("assumptions", {})["module_lwe_model"] = model_block
        core_details = {}
        if module_cost.get("primal"):
            core_details["primal"] = module_cost["primal"]
        if module_cost.get("dual"):
            core_details["dual"] = module_cost["dual"]
        if module_cost.get("headline"):
            core_details["headline"] = module_cost["headline"]
        if core_details:
            out.setdefault("details", {})["module_lwe_core_svp"] = core_details
        if module_cost.get("reference"):
            out.setdefault("assumptions", {})["module_lwe_reference"] = module_cost["reference"]

        calc_block = estimates.get("calculated")
        curated_block = estimates.get("curated")
        if isinstance(calc_block, dict) and isinstance(curated_block, dict):
            for value_key, range_key in (("classical_bits", "classical_bits_range"), ("quantum_bits", "quantum_bits_range")):
                if calc_block.get(range_key) is not None:
                    continue
                range_val = curated_block.get(range_key)
                if not (isinstance(range_val, list) and len(range_val) == 2):
                    continue
                value = calc_block.get(value_key)
                if isinstance(value, (int, float)):
                    lo, hi = range_val
                    if isinstance(lo, (int, float)) and isinstance(hi, (int, float)) and lo <= value <= hi:
                        calc_block[range_key] = range_val
                else:
                    calc_block[range_key] = range_val

    # Lattice estimator details
    if "classical_sieve" in extras or "qram_assisted" in extras or "beta" in extras:
        lat = {}
        if isinstance(extras.get("classical_sieve"), dict):
            lat["classical_sieve_bits"] = extras["classical_sieve"].get("bits")
        if isinstance(extras.get("qram_assisted"), dict):
            lat["qram_sieve_bits"] = extras["qram_assisted"].get("bits")
        if extras.get("beta") is not None:
            lat["beta"] = extras.get("beta")
        if lat:
            estimates["lattice"] = lat

    if estimates:
        out["estimates"] = estimates

    # Brute-force baseline (educational). Copy through directly for visibility.
    if isinstance(extras.get("bruteforce"), dict):
        out["bruteforce"] = extras["bruteforce"]

    out["headline"] = _build_security_headline(out, extras)
    out["detail_rows"] = _build_security_details(out, extras)

    return out


def _build_security_headline(out: Dict[str, Any], extras: Dict[str, Any]) -> Dict[str, Any]:
    family = (out.get("family") or "").upper()
    estimates = out.get("estimates") or {}
    curated = estimates.get("curated") if isinstance(estimates, dict) else None
    calc = estimates.get("calculated") if isinstance(estimates, dict) else None
    details = out.get("details") or {}
    params = out.get("parameters") or {}
    category_floor = out.get("category_floor")
    nist_category = out.get("nist_category")
    estimator_block = out.get("estimator") or {}

    def _fallback_floor(reason: Optional[str] = None) -> Dict[str, Any]:
        classical = float(category_floor or 0.0)
        if family in {"SPHINCS+", "XMSSMT", "XMSS"}:
            quantum = classical / 2.0 if classical else None
        else:
            quantum = classical
        notes: List[str] = []
        if reason:
            notes.append(reason)
        if estimator_block and not estimator_block.get("available", True):
            notes.append("Estimator unavailable; showing NIST category floor.")
        return {
            "nist_category": nist_category,
            "category_floor": category_floor,
            "classical_bits": classical,
            "quantum_bits": quantum,
            "classical_bits_range": None,
            "quantum_bits_range": None,
            "estimator": estimator_block.get("name") or "floor",
            "model": estimator_block.get("profile"),
            "attack": None,
            "notes": notes,
        }

    def _curated_summary(label: str, attack: Optional[str] = None, prefer_calc: bool = False) -> Dict[str, Any]:
        src = curated if isinstance(curated, dict) else None
        target = calc if (prefer_calc and isinstance(calc, dict)) else src
        if not target:
            return _fallback_floor(None)
        classical = target.get("classical_bits") or target.get("classical_bits_mid")
        quantum = target.get("quantum_bits") or target.get("quantum_bits_mid")
        notes: List[str] = []
        if src and src is not target and src.get("classical_bits_mid") is not None:
            notes.append("Curated design target shown; raw estimator output available in details.")
        if src and src.get("source"):
            notes.append(f"Source: {src['source']}")
        return {
            "nist_category": nist_category,
            "category_floor": category_floor,
            "classical_bits": float(classical) if classical is not None else None,
            "quantum_bits": float(quantum) if quantum is not None else None,
            "classical_bits_range": _value_in_range(classical, target.get("classical_bits_range")) if target else None,
            "quantum_bits_range": _value_in_range(quantum, target.get("quantum_bits_range")) if target else None,
            "estimator": label,
            "model": target.get("profile") or estimator_block.get("profile"),
            "attack": target.get("attack") or attack,
            "notes": notes,
        }

    if family == "ML-KEM":
        module = (details.get("module_lwe_core_svp") or {})
        headline_entry = module.get("headline") or module.get("primal") or {}
        classical = headline_entry.get("classical_bits")
        quantum = headline_entry.get("quantum_bits")
        if classical is not None and quantum is not None:
            ranges = curated if isinstance(curated, dict) else {}
            class_range = _value_in_range(classical, ranges.get("classical_bits_range"))
            quant_range = _value_in_range(quantum, ranges.get("quantum_bits_range"))
            notes: List[str] = []
            attack_label = headline_entry.get("attack")
            beta = headline_entry.get("beta")
            dim = headline_entry.get("dimension")
            samples = headline_entry.get("samples")
            if attack_label:
                notes.append(
                    f"Headline attack: {attack_label} (β={beta}, dim={dim}, samples={samples})."
                )
            if module.get("primal") and headline_entry is not module.get("primal"):
                notes.append("Primal attack available in details; headline shows lower-cost path.")
            if ranges.get("source"):
                notes.append(f"Curated range: {ranges['source']}")
            ref = (out.get("assumptions") or {}).get("module_lwe_reference") or extras.get("estimator_reference")
            if ref:
                notes.append(f"Reference: {ref}")
            if params:
                notes.append(f"Module parameters: k={params.get('k')}, n={params.get('n')}, q={params.get('q')}.")
            return {
                "nist_category": nist_category,
                "category_floor": category_floor,
                "classical_bits": float(classical),
                "quantum_bits": float(quantum),
                "classical_bits_range": class_range,
                "quantum_bits_range": quant_range,
                "estimator": "core-svp",
                "model": "module-LWE",
                "attack": attack_label,
                "notes": notes,
            }
        return _fallback_floor("Module-LWE headline unavailable.")

    if family == "ML-DSA":
        module = (details.get("module_lwe_core_svp") or {})
        headline_entry = module.get("headline") or module.get("primal") or {}
        classical = headline_entry.get("classical_bits")
        quantum = headline_entry.get("quantum_bits")
        if classical is not None and quantum is not None:
            ranges = curated if isinstance(curated, dict) else {}
            class_range = _value_in_range(classical, ranges.get("classical_bits_range"))
            quant_range = _value_in_range(quantum, ranges.get("quantum_bits_range"))
            attack_label = headline_entry.get("attack")
            beta = headline_entry.get("beta")
            dim = headline_entry.get("dimension")
            samples = headline_entry.get("samples")
            notes: List[str] = []
            if attack_label:
                notes.append(
                    f"Headline attack: {attack_label} (β={beta}, dim={dim}, samples={samples})."
                )
            if module.get("primal") and headline_entry is not module.get("primal"):
                notes.append("Primal attack available in details; headline shows lower-cost path.")
            if params:
                notes.append(
                    f"Module parameters: k={params.get('k')}, l={params.get('l')}, n={params.get('n')}, q={params.get('q')}.")
            if not class_range and ranges.get("classical_bits_mid") is not None:
                notes.append("Spec core-SVP value lies outside literature range; showing table headline.")
            if ranges.get("source"):
                notes.append(f"Curated range: {ranges['source']}")
            ref = (out.get("assumptions") or {}).get("module_lwe_reference") or extras.get("estimator_reference")
            if ref:
                notes.append(f"Reference: {ref}")
            return {
                "nist_category": nist_category,
                "category_floor": category_floor,
                "classical_bits": float(classical),
                "quantum_bits": float(quantum),
                "classical_bits_range": class_range,
                "quantum_bits_range": quant_range,
                "estimator": "core-svp",
                "model": "module-LWE",
                "attack": attack_label,
                "notes": notes,
            }
        return _fallback_floor("Module-LWE headline unavailable.")

    if family == "FALCON":
        if isinstance(curated, dict):
            headline = _curated_summary("curated-range (Falcon BKZ)")
            headline.setdefault("notes", []).append(
                "Core-SVP constants: classical 0.292, quantum 0.265."
            )
            if isinstance(calc, dict):
                headline.setdefault("notes", []).append(
                    "BKZ projection available in details; curated range used for summary."
                )
            if params:
                headline.setdefault("notes", []).append(
                    f"Parameters: n={params.get('n')}, q={params.get('q')} (NTRU lattice)."
                )
            return headline
        if isinstance(calc, dict):
            notes = ["Using BKZ projection output."]
            if params:
                notes.append(f"Parameters: n={params.get('n')}, q={params.get('q')}.")
            return {
                "nist_category": nist_category,
                "category_floor": category_floor,
                "classical_bits": float(calc.get("classical_bits")) if calc.get("classical_bits") is not None else None,
                "quantum_bits": float(calc.get("quantum_bits")) if calc.get("quantum_bits") is not None else None,
                "classical_bits_range": _value_in_range(calc.get("classical_bits"), calc.get("classical_bits_range")),
                "quantum_bits_range": _value_in_range(calc.get("quantum_bits"), calc.get("quantum_bits_range")),
                "estimator": calc.get("profile") or "bkz",
                "model": "NTRU lattice",
                "attack": calc.get("attack"),
                "notes": notes,
            }
        return _fallback_floor(None)

    if family == "HQC":
        if isinstance(curated, dict):
            headline = _fallback_floor(None)
            notes = ["Showing NIST category floor for HQC headline cells."]
            notes.append("Design targets (Stern/BJMM) available in details.")
            design_mid = curated.get("classical_bits_mid")
            design_quant = curated.get("quantum_bits_mid")
            if design_mid is not None and design_quant is not None:
                notes.append(
                    f"Design target (details): classical ≈ {design_mid}, quantum ≈ {design_quant}."
                )
            if estimates.get("hqc_isd"):
                notes.append("ISD heuristics (Stern/BJMM) recorded under details.")
            if curated.get("source"):
                notes.append(f"Source: {curated['source']}")
            headline["notes"] = notes
            return headline
        return _fallback_floor("Using NIST category floor for HQC.")

    if family in {"SPHINCS+", "XMSSMT", "XMSS"}:
        target = calc if isinstance(calc, dict) else curated
        family_block = (extras.get("sphincs") or extras.get("xmss") or {})
        if target:
            classical = target.get("classical_bits") or target.get("classical_bits_mid")
            quantum = target.get("quantum_bits") or target.get("quantum_bits_mid")
            notes = [
                "Hash-based security: collision ≈ n/2 bits (classical); quantum collision ≈ n/3 via Grover/BHT.",
            ]
            hash_info = (family_block.get("hash_costs") or {})
            if hash_info:
                notes.append(
                    f"Hash costs: collision {hash_info.get('collision_bits')} bits, preimage {hash_info.get('preimage_bits')} bits."
                )
            structure = family_block.get("structure") or {}
            if structure:
                notes.append(
                    "Structure: " + ", ".join([f"{k}={v}" for k, v in structure.items() if v is not None])
                )
            return {
                "nist_category": nist_category,
                "category_floor": category_floor,
                "classical_bits": float(classical) if classical is not None else None,
                "quantum_bits": float(quantum) if quantum is not None else None,
                "classical_bits_range": _value_in_range(classical, target.get("classical_bits_range")),
                "quantum_bits_range": _value_in_range(quantum, target.get("quantum_bits_range")),
                "estimator": target.get("profile") or "hash",
                "model": "hash-based",
                "attack": target.get("attack"),
                "notes": notes,
            }
        return _fallback_floor(None)

    if family == "MAYO":
        if isinstance(curated, dict):
            notes = ["Design target per MAYO submission."]
            if (estimates.get("checks")):
                notes.append("Rank / minrank heuristic checks available in details.")
            if params:
                notes.append(
                    f"Structure: n={params.get('n')}, m={params.get('m')}, oil={params.get('oil')}, vinegar={params.get('vinegar')}, q={params.get('q')}"
                )
            return {
                "nist_category": nist_category,
                "category_floor": category_floor,
                "classical_bits": float(curated.get("classical_bits_mid")),
                "quantum_bits": float(curated.get("quantum_bits_mid")),
                "classical_bits_range": _value_in_range(curated.get("classical_bits_mid"), curated.get("classical_bits_range")),
                "quantum_bits_range": _value_in_range(curated.get("quantum_bits_mid"), curated.get("quantum_bits_range")),
                "estimator": "mq design-target",
                "model": "MQ (whipping)",
                "attack": "design-target",
                "notes": notes,
            }
        return _fallback_floor("Using category floor for MAYO.")

    if family == "RSA":
        notes = ["Classical strength per NIST SP 800-57 mapping.", "Quantum security broken by Shor (0 bits)."]
        shor_profiles = extras.get("shor_profiles") or {}
        target_modulus_bits: Optional[int] = None
        if isinstance(params, dict):
            try:
                target_modulus_bits = int(round(float(params.get("modulus_bits"))))
            except (TypeError, ValueError):
                target_modulus_bits = None
        if shor_profiles:
            notes.append("Surface-code resource estimates available in details.")
            scenario_entries = shor_profiles.get("scenarios") or []
            scenario_notes: List[str] = []
            for entry in scenario_entries:
                mod_bits = entry.get("modulus_bits")
                if target_modulus_bits is not None:
                    try:
                        entry_bits = int(round(float(mod_bits)))
                    except (TypeError, ValueError):
                        entry_bits = None
                    if entry_bits is None or entry_bits != target_modulus_bits:
                        continue
                for scenario in entry.get("scenarios") or []:
                    label = scenario.get("label") or "scenario"
                    parts: List[str] = []
                    runtime_fmt = _format_runtime(scenario.get("runtime_seconds"))
                    if runtime_fmt:
                        parts.append(f"runtime≈{runtime_fmt}")
                    qubits_fmt = _format_quantity(scenario.get("phys_qubits_total"), " qubits")
                    if qubits_fmt:
                        parts.append(f"qubits≈{qubits_fmt}")
                    factories = scenario.get("factory_count")
                    if factories:
                        parts.append(f"factories={int(factories)}")
                    code_distance = scenario.get("code_distance")
                    if code_distance:
                        parts.append(f"d={int(code_distance)}")
                    summary = ", ".join(parts) if parts else "n/a"
                    label_bits = f"{label}@{int(mod_bits)}" if isinstance(mod_bits, (int, float)) and mod_bits else label
                    scenario_notes.append(f"{label_bits}: {summary}")
            if scenario_notes:
                max_notes = 4
                notes.extend(scenario_notes[:max_notes])
                if len(scenario_notes) > max_notes:
                    notes.append(f"(+{len(scenario_notes) - max_notes} more scenarios)")
        logical = extras.get("logical") or {}
        if logical:
            log_qubits = _format_quantity(logical.get("logical_qubits"), " qubits") or str(int(logical.get("logical_qubits", logical.get("qubits", 0)) or 0))
            toffoli = logical.get("toffoli")
            tof_fmt = _format_quantity(toffoli, " Toffoli") if toffoli is not None else None
            summary_bits = f"Logical qubits ≈ {log_qubits}"
            if tof_fmt:
                summary_bits += f"; Toffoli count ≈ {tof_fmt}"
            notes.append(summary_bits)
        return {
            "nist_category": nist_category,
            "category_floor": category_floor,
            "classical_bits": float(out.get("classical_bits")) if out.get("classical_bits") is not None else None,
            "quantum_bits": float(out.get("quantum_bits")) if out.get("quantum_bits") is not None else None,
            "classical_bits_range": None,
            "quantum_bits_range": None,
            "estimator": "SP 800-57 mapping",
            "model": "NFS / Shor",
            "attack": "NFS",
            "notes": notes,
        }

    if isinstance(curated, dict):
        return _curated_summary(estimator_block.get("name") or "curated", attack=curated.get("attack"))

    if isinstance(calc, dict):
        classical = calc.get("classical_bits")
        quantum = calc.get("quantum_bits")
        return {
            "nist_category": nist_category,
            "category_floor": category_floor,
            "classical_bits": float(classical) if classical is not None else None,
            "quantum_bits": float(quantum) if quantum is not None else None,
            "classical_bits_range": _value_in_range(classical, calc.get("classical_bits_range")),
            "quantum_bits_range": _value_in_range(quantum, calc.get("quantum_bits_range")),
            "estimator": calc.get("profile") or estimator_block.get("name"),
            "model": None,
            "attack": calc.get("attack"),
            "notes": [],
        }

    return _fallback_floor(None)


def _build_security_details(out: Dict[str, Any], extras: Dict[str, Any]) -> List[Tuple[str, str]]:
    family = (out.get("family") or "").upper()
    details = out.get("details") or {}
    estimates = out.get("estimates") or {}
    params = out.get("parameters") or {}
    rows: List[Tuple[str, str]] = []

    def add(label: str, value: Any, precision: int = 2) -> None:
        if value in (None, ""):
            return
        if isinstance(value, float):
            fmt = f"{{:.{precision}f}}"
            rows.append((label, fmt.format(value)))
        else:
            rows.append((label, str(value)))

    if family == "ML-KEM":
        module_block = (details.get("module_lwe_core_svp") or {})
        headline_entry = module_block.get("headline") or {}
        if headline_entry:
            add("Headline attack", headline_entry.get("attack"))
            add("Headline β", headline_entry.get("beta"))
            add("Headline samples", headline_entry.get("samples"))
            add("Headline dimension", headline_entry.get("dimension"))
        primal = module_block.get("primal") or {}
        if primal:
            add("BKZ β", primal.get("beta"))
            add("Samples", primal.get("samples"))
            add("Dimension", primal.get("dimension"))
            add("Sieving dimension", primal.get("sieving_dimension"))
            add("log₂ memory", primal.get("log2_memory"))
        if params:
            add("Parameters", f"k={params.get('k')}, n={params.get('n')}, q={params.get('q')}")

    elif family == "ML-DSA":
        module_block = (details.get("module_lwe_core_svp") or {})
        headline_entry = module_block.get("headline") or {}
        if headline_entry:
            add("Headline attack", headline_entry.get("attack"))
            add("Headline β", headline_entry.get("beta"))
            add("Headline samples", headline_entry.get("samples"))
            add("Headline dimension", headline_entry.get("dimension"))
        primal = module_block.get("primal") or {}
        if primal:
            add("BKZ β", primal.get("beta"))
            add("Samples", primal.get("samples"))
            add("Dimension", primal.get("dimension"))
            add("log₂ memory", primal.get("log2_memory"))
        if params:
            add("Parameters", f"k={params.get('k')}, l={params.get('l')}, n={params.get('n')}, q={params.get('q')}")

    elif family == "FALCON":
        bkz = (details.get("falcon_bkz_model") or {})
        attacks = bkz.get("attacks") if isinstance(bkz, dict) else None
        best_attack = None
        if attacks:
            for entry in attacks:
                if entry.get("success"):
                    best_attack = entry
                    break
        if best_attack:
            add("BKZ attack", best_attack.get("attack"))
            add("β success", best_attack.get("beta_success"))
            curve = best_attack.get("beta_curve") or []
            if curve:
                add("Classical bits", curve[0].get("classical_bits"))
                add("Quantum bits", curve[0].get("quantum_bits"))
        if params:
            add("Parameters", f"n={params.get('n')}, q={params.get('q')}")

    elif family == "HQC":
        isd = estimates.get("hqc_isd") or {}
        stern = isd.get("stern_entropy") or {}
        bjmm = isd.get("bjmm") or {}
        add("Stern time bits", stern.get("time_bits_classical"))
        add("Stern memory bits", stern.get("memory_bits_classical"))
        add("BJMM time bits", bjmm.get("time_bits_classical"))
        add("Grover factor", isd.get("grover_factor"))
        hqc_params = ((extras.get("params") or {}).get("extras")) or {}
        if hqc_params:
            add("Parameters", f"n={hqc_params.get('n')}, k={hqc_params.get('k')}, w={hqc_params.get('w')}")

    elif family in {"SPHINCS+", "XMSSMT", "XMSS"}:
        family_block = (extras.get("sphincs") or extras.get("xmss") or {})
        hash_block = family_block.get("hash_costs") or {}
        add("Hash output bits", family_block.get("hash_output_bits"), precision=0)
        add("Collision bits", hash_block.get("collision_bits"))
        add("Quantum collision bits", hash_block.get("quantum_collision_bits"))
        add("Preimage bits", hash_block.get("preimage_bits"))
        structure = family_block.get("structure") or {}
        if structure:
            add("Structure", ", ".join([f"{k}={v}" for k, v in structure.items() if v is not None]))

    elif family == "MAYO":
        checks = estimates.get("checks") or {}
        rank = (checks.get("rank_attack") or {}).get("bits")
        minrank = (checks.get("minrank") or {}).get("bits")
        oil_guess = checks.get("oil_guess_bits")
        add("Rank attack bits", rank)
        add("MinRank bits", minrank)
        add("Oil guess bits", oil_guess)
        if params:
            add("Parameters", f"n={params.get('n')}, m={params.get('m')}, oil={params.get('oil')}, vinegar={params.get('vinegar')}, q={params.get('q')}")

    elif family == "RSA":
        logical = extras.get("logical") or {}
        add("Logical qubits", logical.get("logical_qubits") or logical.get("qubits"))
        add("Toffoli count", logical.get("toffoli"))
        t_counts = extras.get("t_counts") or {}
        add("Catalyzed T-count", t_counts.get("catalyzed"))
        add("Textbook T-count", t_counts.get("textbook"))
        shor_profiles = extras.get("shor_profiles") or {}
        scenario_entries = shor_profiles.get("scenarios") or []
        total_scenarios = 0
        target_modulus_bits: Optional[int] = None
        if isinstance(params, dict):
            try:
                target_modulus_bits = int(round(float(params.get("modulus_bits"))))
            except (TypeError, ValueError):
                target_modulus_bits = None
        for entry in scenario_entries:
            mod_bits = entry.get("modulus_bits")
            if target_modulus_bits is not None:
                try:
                    entry_bits = int(round(float(mod_bits)))
                except (TypeError, ValueError):
                    entry_bits = None
                if entry_bits is None or entry_bits != target_modulus_bits:
                    continue
            for scenario in entry.get("scenarios") or []:
                total_scenarios += 1
                label = scenario.get("label") or "scenario"
                runtime_fmt = _format_runtime(scenario.get("runtime_seconds"))
                qubits_fmt = _format_quantity(scenario.get("phys_qubits_total"), " qubits")
                factories = scenario.get("factory_count")
                code_distance = scenario.get("code_distance")
                util = scenario.get("factory_utilization_actual")
                parts: List[str] = []
                if runtime_fmt:
                    parts.append(f"runtime≈{runtime_fmt}")
                if qubits_fmt:
                    parts.append(f"qubits≈{qubits_fmt}")
                if factories:
                    parts.append(f"factories={int(factories)}")
                if code_distance:
                    parts.append(f"d={int(code_distance)}")
                if isinstance(util, (int, float)) and math.isfinite(util):
                    parts.append(f"util≈{util:.2f}")
                summary = "; ".join(parts) if parts else "n/a"
                label_bits = f"{label} @{int(mod_bits)}-bit" if isinstance(mod_bits, (int, float)) and mod_bits else label
                add(label_bits, summary)
        if total_scenarios:
            add("Surface scenarios", total_scenarios)

    return rows
def _build_export_payload(
    summary: AlgoSummary,
    *,
    security_opts: dict | None = None,
    validation: Dict[str, Any] | None = None,
) -> dict:
    """Construct the JSON payload including security estimates, standardized."""
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
        security_raw = estimate_for_summary(summary, options=opts)
        security_std = _standardize_security(summary, security_raw)
    except Exception as _e:
        security_raw = {"error": "security estimator unavailable"}
        security_std = security_raw

    payload = {
        "algo": summary.algo,
        "kind": summary.kind,
        "ops": {k: asdict(v) for k, v in summary.ops.items()},
        "meta": summary.meta,
        "security": security_std,
    }
    if validation is not None:
        payload["validation"] = validation
    return payload


class _ACVPTally:
    __slots__ = ("cases", "passes", "fails", "fail_examples")

    def __init__(self) -> None:
        self.cases = 0
        self.passes = 0
        self.fails = 0
        self.fail_examples: List[Dict[str, Any]] = []

    def record(self, ok: bool, context: str, output: str) -> None:
        self.cases += 1
        if ok:
            self.passes += 1
            return
        self.fails += 1
        if len(self.fail_examples) < 3:
            self.fail_examples.append({
                "context": context,
                "output": output.strip(),
            })


def _acvp_skip(
    reason: str,
    *,
    mechanism: str | None,
    status: str = "skipped",
    source: str = "acvp",
) -> Dict[str, Any]:
    return {
        "vectorset": None,
        "mechanism": mechanism,
        "cases": 0,
        "passes": 0,
        "fails": 0,
        "status": status,
        "reason": reason,
        "source": source,
    }


def _liboqs_build_dir() -> pathlib.Path:
    return _PROJECT_ROOT / "native" / "build" / "liboqs_build"


def _liboqs_vectors_dir() -> pathlib.Path:
    return _PROJECT_ROOT / "liboqs" / "tests" / "ACVP_Vectors"


def _prepend_path(value: str | None, path: str) -> str:
    if not value:
        return path
    return f"{path}:{value}"


def _run_acvp_binary(binary: pathlib.Path, args: Sequence[str]) -> Tuple[bool, str]:
    env = os.environ.copy()
    build_dir = _liboqs_build_dir()
    lib_dir = build_dir / "lib"
    env.setdefault("OQS_BUILD_DIR", str(build_dir))
    env["LD_LIBRARY_PATH"] = _prepend_path(env.get("LD_LIBRARY_PATH"), str(lib_dir))
    if sys.platform == "darwin":  # ensure dyld can load liboqs.dylib
        env["DYLD_LIBRARY_PATH"] = _prepend_path(env.get("DYLD_LIBRARY_PATH"), str(lib_dir))
    proc = subprocess.run(
        [str(binary), *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(binary.parent),
    )
    combined = proc.stdout
    if proc.stderr:
        if combined:
            combined += "\n"
        combined += proc.stderr
    return proc.returncode == 0, combined


def _normalise_ml_kem_name(mechanism: str | None) -> str | None:
    if not mechanism:
        return None
    mech = mechanism.strip()
    if mech in {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}:
        return mech
    alias = mech.replace(" ", "").replace("_", "-").upper()
    mapping = {
        "KYBER512": "ML-KEM-512",
        "KYBER768": "ML-KEM-768",
        "KYBER1024": "ML-KEM-1024",
    }
    return mapping.get(alias)


def _normalise_ml_dsa_name(mechanism: str | None) -> str | None:
    if not mechanism:
        return None
    mech = mechanism.strip()
    if mech in {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}:
        return mech
    mapping = {
        "DILITHIUM2": "ML-DSA-44",
        "DILITHIUM3": "ML-DSA-65",
        "DILITHIUM5": "ML-DSA-87",
    }
    alias = mech.replace("-", "").replace("_", "").upper()
    return mapping.get(alias)


def _load_acvp_json(path: pathlib.Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _run_acvp_ml_kem(mechanism: str | None) -> Dict[str, Any]:
    mech = _normalise_ml_kem_name(mechanism)
    if mech is None:
        return _acvp_skip("Mechanism not covered by ML-KEM ACVP vectors", mechanism=mechanism)

    binary = _liboqs_build_dir() / "tests" / "vectors_kem"
    if not binary.exists():
        return _acvp_skip(
            "liboqs vectors_kem binary not available (configure native/ with -DPQCBENCH_ENABLE_LIBOQS_TESTS=ON)",
            mechanism=mech,
            status="missing_binary",
        )

    vectors_dir = _liboqs_vectors_dir()
    keygen_path = vectors_dir / "ML-KEM-keyGen-FIPS203" / "internalProjection.json"
    encdec_path = vectors_dir / "ML-KEM-encapDecap-FIPS203" / "internalProjection.json"
    if not keygen_path.exists() or not encdec_path.exists():
        return _acvp_skip(
            "ACVP vector files for ML-KEM are missing (ensure Git LFS assets are fetched)",
            mechanism=mech,
            status="missing_vectors",
        )

    tally = _ACVPTally()

    def _record(ok: bool, group: str, tc: Any, output: str) -> None:
        context = f"{group} tcId={tc}"
        tally.record(ok, context, output)

    keygen = _load_acvp_json(keygen_path)
    for variant in keygen.get("testGroups", []):
        if variant.get("parameterSet") != mech:
            continue
        for test_case in variant.get("tests", []):
            d = test_case.get("d")
            z = test_case.get("z")
            pk = test_case.get("ek")
            sk = test_case.get("dk")
            if None in (d, z, pk, sk):
                _record(False, "keygen", test_case.get("tcId"), "missing fields in vector")
                continue
            ok, output = _run_acvp_binary(binary, [mech, "keyGen", d + z, pk, sk])
            _record(ok, "keygen", test_case.get("tcId"), output)

    encdec = _load_acvp_json(encdec_path)
    for variant in encdec.get("testGroups", []):
        if variant.get("parameterSet") != mech:
            continue
        func = variant.get("function")
        if func == "encapsulation":
            stage = "encap"
            for test_case in variant.get("tests", []):
                pk = test_case.get("ek")
                msg = test_case.get("m")
                k = test_case.get("k")
                ct = test_case.get("c")
                if None in (pk, msg, k, ct):
                    _record(False, stage, test_case.get("tcId"), "missing fields in vector")
                    continue
                ok, output = _run_acvp_binary(binary, [mech, "encDecAFT", msg, pk, k, ct])
                _record(ok, stage, test_case.get("tcId"), output)
        elif func == "decapsulation":
            stage = "decap"
            for test_case in variant.get("tests", []):
                sk = test_case.get("dk")
                k = test_case.get("k")
                ct = test_case.get("c")
                if None in (sk, k, ct):
                    _record(False, stage, test_case.get("tcId"), "missing fields in vector")
                    continue
                ok, output = _run_acvp_binary(binary, [mech, "encDecVAL", sk, k, ct])
                _record(ok, stage, test_case.get("tcId"), output)

    status = "ok" if tally.fails == 0 and tally.cases > 0 else ("failed" if tally.fails else "no_cases")
    result = {
        "vectorset": "ML-KEM:FIPS203",
        "mechanism": mech,
        "cases": tally.cases,
        "passes": tally.passes,
        "fails": tally.fails,
        "status": status,
    }
    if tally.fail_examples:
        result["fail_examples"] = tally.fail_examples
    return result


def _run_acvp_ml_dsa(mechanism: str | None) -> Dict[str, Any]:
    mech = _normalise_ml_dsa_name(mechanism)
    if mech is None:
        return _acvp_skip("Mechanism not covered by ML-DSA ACVP vectors", mechanism=mechanism)

    binary = _liboqs_build_dir() / "tests" / "vectors_sig"
    if not binary.exists():
        return _acvp_skip(
            "liboqs vectors_sig binary not available (configure native/ with -DPQCBENCH_ENABLE_LIBOQS_TESTS=ON)",
            mechanism=mech,
            status="missing_binary",
        )

    vectors_dir = _liboqs_vectors_dir()
    keygen_path = vectors_dir / "ML-DSA-keyGen-FIPS204" / "internalProjection.json"
    siggen_path = vectors_dir / "ML-DSA-sigGen-FIPS204" / "internalProjection.json"
    sigver_path = vectors_dir / "ML-DSA-sigVer-FIPS204" / "internalProjection.json"
    for p in (keygen_path, siggen_path, sigver_path):
        if not p.exists():
            return _acvp_skip(
                "ACVP vector files for ML-DSA are missing (ensure Git LFS assets are fetched)",
                mechanism=mech,
                status="missing_vectors",
            )

    tally = _ACVPTally()

    def _record(ok: bool, stage: str, tc: Any, output: str) -> None:
        context = f"{stage} tcId={tc}"
        tally.record(ok, context, output)

    keygen = _load_acvp_json(keygen_path)
    for variant in keygen.get("testGroups", []):
        if variant.get("parameterSet") != mech:
            continue
        for test_case in variant.get("tests", []):
            seed = test_case.get("seed")
            pk = test_case.get("pk")
            sk = test_case.get("sk")
            if None in (seed, pk, sk):
                _record(False, "sig.keygen", test_case.get("tcId"), "missing fields in vector")
                continue
            ok, output = _run_acvp_binary(binary, [mech, "keyGen", seed, pk, sk])
            _record(ok, "sig.keygen", test_case.get("tcId"), output)

    siggen = _load_acvp_json(siggen_path)
    for variant in siggen.get("testGroups", []):
        if variant.get("parameterSet") != mech:
            continue
        signature_interface = variant.get("signatureInterface")
        deterministic = bool(variant.get("deterministic"))
        for test_case in variant.get("tests", []):
            sk = test_case.get("sk")
            message = test_case.get("message")
            signature = test_case.get("signature")
            if None in (sk, message, signature):
                _record(False, "sig.gen", test_case.get("tcId"), "missing fields in vector")
                continue
            rnd = "0" * 64 if deterministic else (test_case.get("rnd") or test_case.get("additionalRandomness") or "")
            if signature_interface == "internal":
                ok, output = _run_acvp_binary(binary, [mech, "sigGen_int", sk, message, signature, rnd])
            else:
                context_val = test_case.get("context", "")
                ok, output = _run_acvp_binary(binary, [mech, "sigGen_ext", sk, message, signature, context_val, rnd])
            _record(ok, "sig.gen", test_case.get("tcId"), output)

    sigver = _load_acvp_json(sigver_path)
    for variant in sigver.get("testGroups", []):
        if variant.get("parameterSet") != mech:
            continue
        signature_interface = variant.get("signatureInterface")
        for test_case in variant.get("tests", []):
            pk = test_case.get("pk")
            message = test_case.get("message")
            signature = test_case.get("signature")
            test_passed = "1" if test_case.get("testPassed") else "0"
            if None in (pk, message, signature):
                _record(False, "sig.ver", test_case.get("tcId"), "missing fields in vector")
                continue
            if signature_interface == "internal":
                ok, output = _run_acvp_binary(binary, [mech, "sigVer_int", pk, message, signature, test_passed])
            else:
                context_val = test_case.get("context", "")
                ok, output = _run_acvp_binary(binary, [mech, "sigVer_ext", pk, message, signature, context_val, test_passed])
            _record(ok, "sig.ver", test_case.get("tcId"), output)

    status = "ok" if tally.fails == 0 and tally.cases > 0 else ("failed" if tally.fails else "no_cases")
    result = {
        "vectorset": "ML-DSA:FIPS204",
        "mechanism": mech,
        "cases": tally.cases,
        "passes": tally.passes,
        "fails": tally.fails,
        "status": status,
    }
    if tally.fail_examples:
        result["fail_examples"] = tally.fail_examples
    return result


_SPHINCS_TO_SLH: Dict[str, Tuple[str, str]] = {
    "SPHINCS+-SHA2-128f-simple": ("SLH_DSA_PURE_SHA2_128F", "SLH-DSA-SHA2-128f"),
    "SPHINCS+-SHA2-128s-simple": ("SLH_DSA_PURE_SHA2_128S", "SLH-DSA-SHA2-128s"),
    "SPHINCS+-SHAKE-128f-simple": ("SLH_DSA_PURE_SHAKE_128F", "SLH-DSA-SHAKE-128f"),
    "SPHINCS+-SHAKE-128s-simple": ("SLH_DSA_PURE_SHAKE_128S", "SLH-DSA-SHAKE-128s"),
    "SLH_DSA_PURE_SHA2_128S": ("SLH_DSA_PURE_SHA2_128S", "SLH-DSA-SHA2-128s"),
    "SLH_DSA_PURE_SHA2_128F": ("SLH_DSA_PURE_SHA2_128F", "SLH-DSA-SHA2-128f"),
    "SLH_DSA_PURE_SHA2_192S": ("SLH_DSA_PURE_SHA2_192S", "SLH-DSA-SHA2-192s"),
    "SLH_DSA_PURE_SHA2_192F": ("SLH_DSA_PURE_SHA2_192F", "SLH-DSA-SHA2-192f"),
    "SLH_DSA_PURE_SHA2_256S": ("SLH_DSA_PURE_SHA2_256S", "SLH-DSA-SHA2-256s"),
    "SLH_DSA_PURE_SHA2_256F": ("SLH_DSA_PURE_SHA2_256F", "SLH-DSA-SHA2-256f"),
    "SLH_DSA_PURE_SHAKE_128S": ("SLH_DSA_PURE_SHAKE_128S", "SLH-DSA-SHAKE-128s"),
    "SLH_DSA_PURE_SHAKE_128F": ("SLH_DSA_PURE_SHAKE_128F", "SLH-DSA-SHAKE-128f"),
    "SLH_DSA_PURE_SHAKE_192S": ("SLH_DSA_PURE_SHAKE_192S", "SLH-DSA-SHAKE-192s"),
    "SLH_DSA_PURE_SHAKE_192F": ("SLH_DSA_PURE_SHAKE_192F", "SLH-DSA-SHAKE-192f"),
    "SLH_DSA_PURE_SHAKE_256S": ("SLH_DSA_PURE_SHAKE_256S", "SLH-DSA-SHAKE-256s"),
    "SLH_DSA_PURE_SHAKE_256F": ("SLH_DSA_PURE_SHAKE_256F", "SLH-DSA-SHAKE-256f"),
}


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


_RSA_STATIC_VECTORS = {
    "sk_der": _b64d(
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC1jsJOD3Zn9H1op+YGJOY6DDXyaS6loFMt9IEddRT5RyqDj1Sp6xIsm1A4BCBnGV4wGHt75BkKQKXyxFQj/6NIjd42OAdNiz7OtqqELVI5RDZ3DsfT1OqhztYig/AOAScWH8qESBIt5L7IE7uS8Ao5yza5mO3Wds+GSizPWAvIfMqK5K9iqIoXm2DIlmIf4VZsd6lFkY6I0NPHXjMG/Rla5yvd9ahgkUdAL7gyqH2dWKhWfXcTA+JWXeqrlNur7WESie5XKl+d3KYHLIQIvvzDSO6fJTTHuVdDnRWCCRMeF8cers+E4BMqsbm77g+Dem5bAJlbktPlb7rFDMIdWnGbAgMBAAECggEAKlcKCjFB8DlMm8D3/DvTsvrRA+Cyn651Z3SrPablxsJpcDfXSy8GVH+94+pWciSw2e+DsJ8/lawA504QvzppJkzrYuKLFXLhKUzhFCULlU5Kk1ZPlJ+FPknhlzgEngd3yYmNbW7vSmObeEZdyoUPJW42K282G/smJ0+aBpqmWNEYzwlfJz6qGFghAQRqwf30mvJVrSqZO0uptrJB8q70mtI35xgInfJOTKPNMCxqWNOwP4mrHzbNiJmGGRWG4XcZtAPq9DJ4//kn7AmLSs8VxHWnNNa4j1bMuhQEZCHzzZgJj6z+T3rZcqCEX0BMAdlC9Dh9WgmgpJ5Y8b884sacaQKBgQDX4KBE8L01MI8cN9R7nvU6zJXZofv4YghpY3g/kojO/+3LwuCI+Kjwldmxia8Udf9zTZVHosGEVqe+UJJq/7JIQDH1pRhsIxqvzy9UFAJUB9qTkqHZhJbr1zCXbyLTkepeb+ACY1KWpFFOr2e7BMpahF841vfQouPBXczWuZnfUwKBgQDXTTWHuOJSofvJzTW23AflCaKAhz83ZeP+lKQ4oj4D7MuErskuv9JbuY1DJ0bN4FX7RLB/OJ3gjPsdAre8Pa4502WZImfkexCfOVAWHPKVsebPp57C5wUJ8swcYoG/r1rxAh0MsJIV5cK3UOMr5gor0QL8qXB26CWOBFQ352IDmQKBgQDQS3H48xxtbQw42vnPygGumWZhVnWsJNMe9RY6qOYObU0CFWfXYa6IbN5e+o2PPYectpg6RaVZTs+Nx2pviYZ5Rk+uSH03IewHBO8Svje84tMZHxvBqLiCmODOzTIaWCl+s42+YB15MtUtCfwZrLae/ihuzKTSj8kYc6xI50679wKBgEyTFF/iPPSg0hmzF9Cir1ghth86exxr68wm98WAxsfEl5noRHuRE/M1qm1g8cjVah9FDfUhoN01pzZpOgoEcgv1COSPHR5hOsc2rio/P3RIYswmVMwDOIKSTVAnJPiVGKYxVz2lK0AIiNmENlftqF5vJz3P0cUoyfqZxY5giDa5AoGANWf/dI45LHCpBL1chcsTOR/E5tHIwC3LFUIMdrGaXcRuRtp52MLCv51ceMP2zNbdcvfz8jje1TJKrC4AHCsvpwfwOhfWoCvbEuWlreh9yuP8o3422soNOnkA4/rIb2LajKHFi/pUvS5RgYSM6ymehdUovOwEUySqqA9b9XWivww="
    ),
    "pk_der": _b64d(
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtY7CTg92Z/R9aKfmBiTmOgw18mkupaBTLfSBHXUU+Ucqg49UqesSLJtQOAQgZxleMBh7e+QZCkCl8sRUI/+jSI3eNjgHTYs+zraqhC1SOUQ2dw7H09Tqoc7WIoPwDgEnFh/KhEgSLeS+yBO7kvAKOcs2uZjt1nbPhkosz1gLyHzKiuSvYqiKF5tgyJZiH+FWbHepRZGOiNDTx14zBv0ZWucr3fWoYJFHQC+4Mqh9nVioVn13EwPiVl3qq5Tbq+1hEonuVypfndymByyECL78w0junyU0x7lXQ50VggkTHhfHHq7PhOATKrG5u+4Pg3puWwCZW5LT5W+6xQzCHVpxmwIDAQAB"
    ),
    "oaep": {
        "ciphertext": _b64d(
            "eE91giavI7HD6b2kH1goIJrP+arV+ea8McpQnLNeOku6+6BumFOXoIuA5LRrJPtArDyvtznSII+uY1EOrIx4WFlPVVlsbchaPSt2KLdUM/72Psdf+gywB6VxHWKW7Fb9gb9j+na2r+tr0iCdXPZa7mXyEv1eCQxKK+Ao6qBc/5FgFXSY9Ab1sr/kmzVJI/ZREfBI5FCSOgaPA8JuXoGNp9Y0l2nFVr+ruebdTlOvhl3hUx7yVu+9b25GIGbWoIybr98aDCGQVVI9M4tsZqZtIrkK4yE928ZDqCRBmwR6SjP0TqDb5SnNNLjx88QGNocvqai5XaG8EYqgqGgFwuG2MQ=="
        ),
        "secret": _b64d("bytuIjX5yRxmvbHsmbKlLZtwTrSshF+ladz1/KD3YS0="),
    },
    "pss": {
        "message": _b64d("UlNBIFBTUyBzYW1wbGUgbWVzc2FnZSBmb3IgcHFjYmVuY2g="),
        "signature": _b64d(
            "G5NBnFBxqPgtQHNL/Zr4Gir0+StWYmUxR4XINSyy9tFzFXfgOmI+X+Z6BP8k7L6u50zCBEyuC873tQaK2PMcmJQ++N5OKEiLQ9sapY50U28AA5iNUc2ahr42pObqExmeRk2ZS6Etzxnq8Zxpt5luoVgMgcAFSenpfcKJ5EHgIcUsk1VG9ks0jKbWrY+mCkTpKUbXQtBVzZJOJ4De4pd96upag9GsWe0JCggyQfnEfMwTMjTw/qnR+EriU953zcokAIQkZmEjet1oOi+hlECiW0VcIXPbSINkGDIap76uTJCFJX1QBjIzHXrbHXuSdnm2H1HNkjBvUwDUrPX1ZhMWfw=="
        ),
    },
}


def _slh_format_name(sig_name: str) -> str:
    name = sig_name.replace("PURE_", "")
    start = 8
    idx = name.find("PREHASH_")
    if idx >= 0:
        end = idx + 8
        name = name[:start] + name[end:]
    name = name.replace("_", "-")
    name = name[:-1] + name[-1].lower()
    return name


def _slh_test_sig_name(variant: Dict[str, Any], test_case: Dict[str, Any]) -> str:
    sig_name = variant.get("parameterSet", "")
    sig_name = sig_name.replace("-", "_")
    sig_name = sig_name[:-1] + sig_name[-1].upper()
    if variant.get("preHash") != "preHash":
        sig_name = sig_name[:7] + "_PURE" + sig_name[7:]
    else:
        hash_alg = str(test_case.get("hashAlg", "")).replace("-", "_")
        sig_name = sig_name[:7] + "_" + hash_alg + "_PREHASH" + sig_name[7:]
    return sig_name


def _run_acvp_slh_dsa(mechanism: str | None) -> Dict[str, Any]:
    mapping = _SPHINCS_TO_SLH.get(mechanism or "")
    if mapping is None:
        return _acvp_skip(
            "ACVP vectors currently cover SPHINCS+ (SLH-DSA) simple profiles only",
            mechanism=mechanism,
        )

    sig_name, expected_param = mapping
    param_set = expected_param

    binary = _liboqs_build_dir() / "tests" / "vectors_sig"
    if not binary.exists():
        return _acvp_skip(
            "liboqs vectors_sig binary not available (configure native/ with -DPQCBENCH_ENABLE_LIBOQS_TESTS=ON)",
            mechanism=mechanism,
            status="missing_binary",
        )

    vectors_dir = _liboqs_vectors_dir()
    keygen_path = vectors_dir / "SLH-DSA-keyGen-FIPS205" / "internalProjection.json"
    siggen_path = vectors_dir / "SLH-DSA-sigGen-FIPS205" / "internalProjection.json"
    sigver_path = vectors_dir / "SLH-DSA-sigVer-FIPS205" / "internalProjection.json"
    for path in (keygen_path, siggen_path, sigver_path):
        if not path.exists():
            return _acvp_skip(
                "ACVP vector files for SLH-DSA are missing (ensure Git LFS assets are fetched)",
                mechanism=mechanism,
                status="missing_vectors",
            )

    tally = _ACVPTally()

    def _record(ok: bool, stage: str, tc: Any, output: str) -> None:
        context = f"{stage} tcId={tc}"
        tally.record(ok, context, output)

    keygen = _load_acvp_json(keygen_path)
    for variant in keygen.get("testGroups", []):
        if variant.get("parameterSet") != param_set:
            continue
        for test_case in variant.get("tests", []):
            sk_seed = test_case.get("skSeed")
            sk_prf = test_case.get("skPrf")
            pk_seed = test_case.get("pkSeed")
            pk = test_case.get("pk")
            sk = test_case.get("sk")
            if None in (sk_seed, sk_prf, pk_seed, pk, sk):
                _record(False, "sig.keygen", test_case.get("tcId"), "missing fields in vector")
                continue
            ok, output = _run_acvp_binary(
                binary,
                [sig_name, "keyGen", sk_seed, sk_prf, pk_seed, pk, sk],
            )
            _record(ok, "sig.keygen", test_case.get("tcId"), output)

    siggen = _load_acvp_json(siggen_path)
    for variant in siggen.get("testGroups", []):
        for test_case in variant.get("tests", []):
            if _slh_test_sig_name(variant, test_case) != sig_name:
                continue
            sk = test_case.get("sk")
            message = test_case.get("message")
            signature = test_case.get("signature")
            if None in (sk, message, signature):
                _record(False, "sig.gen", test_case.get("tcId"), "missing fields in vector")
                continue
            deterministic = bool(variant.get("deterministic"))
            rnd = "" if deterministic else (test_case.get("additionalRandomness") or test_case.get("rnd") or "")
            if variant.get("signatureInterface") == "internal":
                ok, output = _run_acvp_binary(
                    binary,
                    [sig_name, "sigGen_int", sk, message, signature, rnd],
                )
            else:
                context_val = test_case.get("context", "")
                ok, output = _run_acvp_binary(
                    binary,
                    [sig_name, "sigGen_ext", sk, message, signature, context_val, rnd],
                )
            _record(ok, "sig.gen", test_case.get("tcId"), output)

    sigver = _load_acvp_json(sigver_path)
    for variant in sigver.get("testGroups", []):
        for test_case in variant.get("tests", []):
            if _slh_test_sig_name(variant, test_case) != sig_name:
                continue
            message = test_case.get("message")
            signature = test_case.get("signature")
            pk = test_case.get("pk")
            test_passed = "1" if test_case.get("testPassed") else "0"
            if None in (message, signature, pk):
                _record(False, "sig.ver", test_case.get("tcId"), "missing fields in vector")
                continue
            if variant.get("signatureInterface") == "internal":
                ok, output = _run_acvp_binary(
                    binary,
                    [sig_name, "sigVer_int", pk, message, signature, test_passed],
                )
            else:
                context_val = test_case.get("context", "")
                ok, output = _run_acvp_binary(
                    binary,
                    [sig_name, "sigVer_ext", pk, message, signature, context_val, test_passed],
                )
            _record(ok, "sig.ver", test_case.get("tcId"), output)

    status = "ok" if tally.fails == 0 and tally.cases > 0 else ("failed" if tally.fails else "no_cases")
    result = {
        "source": "acvp",
        "vectorset": "SLH-DSA:FIPS205",
        "mechanism": mechanism,
        "cases": tally.cases,
        "passes": tally.passes,
        "fails": tally.fails,
        "status": status,
    }
    if tally.fail_examples:
        result["fail_examples"] = tally.fail_examples
    return result


_KAT_KEM_SUPPORTED = {
    "BIKE-L1",
    "BIKE-L3",
    "BIKE-L5",
    "HQC-128",
    "HQC-192",
    "HQC-256",
    "HQC-128-1-CCA2",
    "HQC-192-1-CCA2",
    "HQC-256-1-CCA2",
    "Classic-McEliece-348864",
    "Classic-McEliece-348864f",
    "Classic-McEliece-460896",
    "Classic-McEliece-460896f",
    "Classic-McEliece-6688128",
    "Classic-McEliece-6688128f",
    "Classic-McEliece-6960119",
    "Classic-McEliece-6960119f",
    "Classic-McEliece-8192128",
    "Classic-McEliece-8192128f",
    "FrodoKEM-640-AES",
    "FrodoKEM-640-SHAKE",
    "FrodoKEM-976-AES",
    "FrodoKEM-976-SHAKE",
    "FrodoKEM-1344-AES",
    "FrodoKEM-1344-SHAKE",
    "NTRU-HPS-2048-509",
    "NTRU-HPS-2048-677",
    "NTRU-HPS-4096-821",
    "NTRU-HPS-4096-1229",
    "NTRU-HRSS-701",
    "NTRU-HRSS-1373",
    "sntrup761",
}


_KAT_SIG_SUPPORTED = {
    "SPHINCS+-SHA2-128f-simple",
    "SPHINCS+-SHA2-128s-simple",
    "SPHINCS+-SHA2-192f-simple",
    "SPHINCS+-SHA2-192s-simple",
    "SPHINCS+-SHA2-256f-simple",
    "SPHINCS+-SHA2-256s-simple",
    "SPHINCS+-SHAKE-128f-simple",
    "SPHINCS+-SHAKE-128s-simple",
    "SPHINCS+-SHAKE-192f-simple",
    "SPHINCS+-SHAKE-192s-simple",
    "SPHINCS+-SHAKE-256f-simple",
    "SPHINCS+-SHAKE-256s-simple",
    "SPHINCS+-SHA2-128f-robust",
    "SPHINCS+-SHA2-128s-robust",
    "SPHINCS+-SHA2-192f-robust",
    "SPHINCS+-SHA2-192s-robust",
    "SPHINCS+-SHA2-256f-robust",
    "SPHINCS+-SHA2-256s-robust",
    "SPHINCS+-SHAKE-128f-robust",
    "SPHINCS+-SHAKE-128s-robust",
    "SPHINCS+-SHAKE-192f-robust",
    "SPHINCS+-SHAKE-192s-robust",
    "SPHINCS+-SHAKE-256f-robust",
    "SPHINCS+-SHAKE-256s-robust",
    "Falcon-512",
    "Falcon-1024",
    "MAYO-1",
    "MAYO-2",
    "MAYO-3",
    "MAYO-5",
    "cross-rsdp-128-balanced",
    "cross-rsdp-128-fast",
    "cross-rsdp-128-small",
    "cross-rsdp-192-balanced",
    "cross-rsdp-192-fast",
    "cross-rsdp-192-small",
    "cross-rsdp-256-balanced",
    "cross-rsdp-256-fast",
    "cross-rsdp-256-small",
    "cross-rsdpg-128-balanced",
    "cross-rsdpg-128-fast",
    "cross-rsdpg-128-small",
    "cross-rsdpg-192-balanced",
    "cross-rsdpg-192-fast",
    "cross-rsdpg-192-small",
    "cross-rsdpg-256-balanced",
    "cross-rsdpg-256-fast",
    "cross-rsdpg-256-small",
    "OV-Is",
    "OV-Ip",
    "OV-III",
    "OV-V",
    "OV-Is-pkc",
    "OV-Ip-pkc",
    "OV-III-pkc",
    "OV-V-pkc",
    "OV-Is-pkc-skc",
    "OV-Ip-pkc-skc",
    "OV-III-pkc-skc",
    "OV-V-pkc-skc",
    "SNOVA_24_5_5",
    "SNOVA_25_8_3",
    "SNOVA_29_6_5",
    "SNOVA_37_8_4",
    "SNOVA_37_17_2",
    "SNOVA_49_11_3",
    "SNOVA_56_25_2",
    "SNOVA_60_10_4",
    "SLH_DSA_PURE_SHA2_128S",
    "SLH_DSA_PURE_SHA2_128F",
    "SLH_DSA_PURE_SHA2_192S",
    "SLH_DSA_PURE_SHA2_192F",
    "SLH_DSA_PURE_SHA2_256S",
    "SLH_DSA_PURE_SHA2_256F",
    "SLH_DSA_PURE_SHAKE_128S",
    "SLH_DSA_PURE_SHAKE_128F",
    "SLH_DSA_PURE_SHAKE_192S",
    "SLH_DSA_PURE_SHAKE_192F",
    "SLH_DSA_PURE_SHAKE_256S",
    "SLH_DSA_PURE_SHAKE_256F",
}


_KAT_SIG_STFL_SUPPORTED = {
    "XMSSMT-SHA2_20/2_256",
    "XMSSMT-SHA2_20/4_256",
    "XMSSMT-SHA2_40/2_256",
    "XMSSMT-SHA2_40/4_256",
    "XMSSMT-SHA2_40/8_256",
    "XMSSMT-SHA2_60/3_256",
    "XMSSMT-SHA2_60/6_256",
    "XMSSMT-SHA2_60/12_256",
    "XMSSMT-SHAKE_20/2_256",
    "XMSSMT-SHAKE_20/4_256",
    "XMSSMT-SHAKE_40/2_256",
    "XMSSMT-SHAKE_40/4_256",
    "XMSSMT-SHAKE_40/8_256",
    "XMSSMT-SHAKE_60/3_256",
    "XMSSMT-SHAKE_60/6_256",
    "XMSSMT-SHAKE_60/12_256",
}


def _normalise_identifier(mechanism: str | None, supported: Iterable[str]) -> str | None:
    if not mechanism:
        return None
    mech = mechanism.strip()
    if not mech:
        return None
    if mech in supported:
        return mech
    mech_norm = mech.replace("_", "-").lower()
    for candidate in supported:
        if candidate.replace("_", "-").lower() == mech_norm:
            return candidate
    return None


def _run_liboqs_kat(
    binary_name: str,
    mechanism: str | None,
    *,
    supported: Iterable[str],
    unknown_reason: str,
    vectorset_prefix: str,
) -> Dict[str, Any]:
    mech = _normalise_identifier(mechanism, supported)
    if mech is None:
        return _acvp_skip(
            unknown_reason,
            mechanism=mechanism,
            status="unsupported",
            source="liboqs_kat",
        )

    binary = _liboqs_build_dir() / "tests" / binary_name
    if not binary.exists():
        return _acvp_skip(
            f"liboqs {binary_name} binary not available (configure native/ with -DPQCBENCH_ENABLE_LIBOQS_TESTS=ON)",
            mechanism=mech,
            status="missing_binary",
            source="liboqs_kat",
        )

    ok, output = _run_acvp_binary(binary, [mech, "--all"])
    tally = _ACVPTally()
    tally.record(ok, f"{binary_name} --all", output)

    status = "ok" if ok else "failed"
    result = {
        "source": "liboqs_kat",
        "vectorset": f"{vectorset_prefix}:{mech}",
        "mechanism": mech,
        "cases": tally.cases,
        "passes": tally.passes,
        "fails": tally.fails,
        "status": status,
    }
    if not ok and tally.fail_examples:
        result["fail_examples"] = tally.fail_examples
    return result


def _run_kat_kem(mechanism: str | None) -> Dict[str, Any]:
    return _run_liboqs_kat(
        "kat_kem",
        mechanism,
        supported=_KAT_KEM_SUPPORTED,
        unknown_reason="KEM mechanism not recognised for liboqs KAT fallback",
        vectorset_prefix="kat_kem",
    )


def _run_kat_falcon(mechanism: str | None) -> Dict[str, Any]:
    return _run_liboqs_kat(
        "kat_sig",
        mechanism,
        supported={"Falcon-512", "Falcon-1024"},
        unknown_reason="Falcon mechanism not recognised for liboqs KAT fallback",
        vectorset_prefix="kat_sig",
    )


def _run_kat_sig(mechanism: str | None) -> Dict[str, Any]:
    return _run_liboqs_kat(
        "kat_sig",
        mechanism,
        supported=_KAT_SIG_SUPPORTED,
        unknown_reason="Signature mechanism not recognised for liboqs KAT fallback",
        vectorset_prefix="kat_sig",
    )


def _run_kat_sig_stfl(mechanism: str | None) -> Dict[str, Any]:
    return _run_liboqs_kat(
        "kat_sig_stfl",
        mechanism,
        supported=_KAT_SIG_STFL_SUPPORTED,
        unknown_reason="Stateful signature mechanism not recognised for liboqs KAT fallback",
        vectorset_prefix="kat_sig_stfl",
    )


def _run_kat_rsa_oaep() -> Dict[str, Any]:
    try:
        rsa_cls = registry.get("rsa-oaep")
    except KeyError:
        return _acvp_skip(
            "rsa-oaep adapter not available",
            mechanism="rsa-oaep",
            status="missing_adapter",
            source="builtin_kat",
        )

    rsa_kem = rsa_cls()
    tally = _ACVPTally()
    try:
        recovered = rsa_kem.decapsulate(
            _RSA_STATIC_VECTORS["sk_der"],
            _RSA_STATIC_VECTORS["oaep"]["ciphertext"],
        )
        ok = recovered == _RSA_STATIC_VECTORS["oaep"]["secret"]
        output = "match" if ok else "mismatch"
    except Exception as exc:
        ok = False
        output = f"error: {exc}"
    tally.record(ok, "rsa-oaep kat", output)

    result = {
        "source": "builtin_kat",
        "vectorset": "rsa-oaep:static-v1",
        "mechanism": "rsa-oaep",
        "cases": tally.cases,
        "passes": tally.passes,
        "fails": tally.fails,
        "status": "ok" if ok else "failed",
    }
    if not ok:
        result["fail_examples"] = tally.fail_examples
    return result


def _run_kat_rsa_pss() -> Dict[str, Any]:
    try:
        rsa_cls = registry.get("rsa-pss")
    except KeyError:
        return _acvp_skip(
            "rsa-pss adapter not available",
            mechanism="rsa-pss",
            status="missing_adapter",
            source="builtin_kat",
        )

    rsa_sig = rsa_cls()
    tally = _ACVPTally()
    try:
        ok = rsa_sig.verify(
            _RSA_STATIC_VECTORS["pk_der"],
            _RSA_STATIC_VECTORS["pss"]["message"],
            _RSA_STATIC_VECTORS["pss"]["signature"],
        )
        output = "verified" if ok else "verification failed"
    except Exception as exc:
        ok = False
        output = f"error: {exc}"
    tally.record(ok, "rsa-pss kat", output)

    result = {
        "source": "builtin_kat",
        "vectorset": "rsa-pss:static-v1",
        "mechanism": "rsa-pss",
        "cases": tally.cases,
        "passes": tally.passes,
        "fails": tally.fails,
        "status": "ok" if ok else "failed",
    }
    if not ok:
        result["fail_examples"] = tally.fail_examples
    return result


def run_acvp_validation(summary: AlgoSummary) -> Tuple[Dict[str, Any], List[str]]:
    mechanism = summary.meta.get("mechanism") if isinstance(summary.meta, dict) else None
    if summary.kind == "KEM":
        algo = summary.algo.lower()
        if algo in {"kyber", "ml-kem"} or (mechanism and "ML-KEM" in mechanism):
            result = _run_acvp_ml_kem(mechanism)
        elif algo in {"hqc"}:
            result = _run_kat_kem(mechanism)
        elif algo in {"bike", "classic-mceliece", "frodokem", "ntru", "ntruprime"}:
            result = _run_kat_kem(mechanism)
        elif algo in {"rsa-oaep"}:
            result = _run_kat_rsa_oaep()
        else:
            result = _acvp_skip(
                "Unsupported KEM for automated validation",
                mechanism=mechanism,
                status="unsupported",
            )
    elif summary.kind == "SIG":
        algo = summary.algo.lower()
        if algo in {"dilithium", "ml-dsa"} or (mechanism and ("ML-DSA" in mechanism or "Dilithium" in mechanism)):
            result = _run_acvp_ml_dsa(mechanism)
        elif algo in {"sphincs+", "sphincsplus"} or (mechanism and mechanism.startswith("SPHINCS+")):
            result = _run_acvp_slh_dsa(mechanism)
            if result.get("status") == "skipped" and "simple profiles only" in result.get("reason", ""):
                fallback = _run_kat_sig(mechanism)
                if fallback.get("status") != "unsupported":
                    result = fallback
        elif algo == "falcon" or (mechanism and mechanism.startswith("Falcon")):
            result = _run_kat_falcon(mechanism)
        elif algo == "rsa-pss":
            result = _run_kat_rsa_pss()
        elif algo == "mayo":
            result = _run_kat_sig(mechanism)
        elif algo == "cross":
            result = _run_kat_sig(mechanism)
        elif algo == "slh-dsa":
            if mechanism and mechanism in _SPHINCS_TO_SLH:
                result = _run_acvp_slh_dsa(mechanism)
            else:
                result = _run_kat_sig(mechanism)
        elif algo == "snova":
            result = _run_kat_sig(mechanism)
        elif algo == "uov":
            result = _run_kat_sig(mechanism)
        elif algo in {"xmssmt", "xmss"}:
            result = _run_kat_sig_stfl(mechanism)
        else:
            result = _acvp_skip(
                "Unsupported signature algorithm for validation",
                mechanism=mechanism,
                status="unsupported",
            )
    else:
        result = _acvp_skip(
            "Unsupported algorithm kind for ACVP runner",
            mechanism=mechanism,
            status="unsupported",
        )

    git_sha = _read_git_commit(_PROJECT_ROOT / "liboqs")
    if git_sha:
        result.setdefault("git_sha", git_sha)
    else:
        result.setdefault("git_sha", None)

    logs: List[str] = []
    algo_label = mechanism or summary.algo
    status = result.get("status")
    source = result.get("source", "acvp")
    prefix = "[ACVP]" if source == "acvp" else "[KAT]"
    if status == "ok":
        logs.append(
            f"{prefix} {algo_label}: {result.get('passes', 0)}/{result.get('cases', 0)} cases passed"
        )
    elif status in {"skipped", "missing_binary", "missing_vectors", "unsupported"}:
        reason = result.get("reason") or "not run"
        logs.append(f"{prefix} {algo_label}: skipped ({reason})")
    elif status == "no_cases":
        logs.append(f"{prefix} {algo_label}: no matching validation cases")
    else:
        logs.append(
            f"{prefix} {algo_label}: {result.get('fails', 0)} failures out of {result.get('cases', 0)} cases"
        )
        for fail in result.get("fail_examples", [])[:3]:
            ctx = fail.get("context")
            tail = fail.get("output", "").splitlines()
            msg = tail[-1] if tail else ""
            logs.append(f"        {ctx}: {msg}")

    return result, logs


def export_json(
    summary: AlgoSummary,
    export_path: str | None,
    *,
    security_opts: dict | None = None,
    validation: Dict[str, Any] | None = None,
) -> None:
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
        json.dump(
            _build_export_payload(
                summary,
                security_opts=security_opts,
                validation=validation,
            ),
            f,
            indent=2,
        )

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


def _sample_secret_key_analysis(name: str, adapter, mechanism: str | None, kind: str) -> Dict[str, Any] | None:
    """Collect lightweight Hamming-weight/distance stats across fresh keygens."""
    try:
        keys: List[bytes] = []
        for _ in range(DEFAULT_SECRET_KEY_SAMPLES):
            try:
                _, sk = adapter.keygen()
            except Exception:
                continue
            if not isinstance(sk, (bytes, bytearray)):
                return None
            sk_bytes = bytes(sk)
            if not sk_bytes:
                continue
            keys.append(sk_bytes)
        if len(keys) < 4:
            return None

        family = None
        hint = None
        try:
            from pqcbench.params import find as find_params  # type: ignore

            if mechanism:
                hint = find_params(mechanism)
            if not hint:
                hint = find_params(name)
            if hint:
                family = hint.family
        except Exception:
            hint = None
            family = None

        model = derive_model(family, hint)
        prepared = prepare_keys_for_analysis(
            keys, family=family, mechanism=mechanism
        )
        if not prepared.keys:
            return None
        summary = summarize_secret_keys(
            prepared.keys,
            model=model,
            pair_sample_limit=DEFAULT_PAIR_SAMPLE_LIMIT,
            coefficients=prepared.coefficients,
            coefficient_meta=prepared.context.get("ternary_coefficients")
            if prepared.context
            else None,
        )
        context: Dict[str, Any] = {
            "algo": name,
            "kind": kind,
            "family": family,
            "mechanism": mechanism,
            "sampled_keys": len(keys),
        }
        if hint:
            context.update(
                {
                    "category_floor": hint.category_floor,
                    "param_notes": hint.notes,
                }
            )
        if prepared.context:
            context.update(prepared.context)
        summary["context"] = context
        if prepared.warnings:
            summary.setdefault("warnings", []).extend(prepared.warnings)
        return summary
    except Exception as exc:
        return {"method": "bitstring_hw_hd_v1", "error": repr(exc)}

from typing import Callable as _CallableOptional


def run_kem(
    name: str,
    runs: int,
    *,
    cold: bool = True,
    capture_memory: bool = True,
    memory_interval: float | None = None,
    progress: Optional[_CallableOptional[[str, str, int, int], None]] = None,
) -> AlgoSummary:
    """Run a KEM micro-benchmark for the registered algorithm `name`.

    Measures wall-clock latency (and optional memory deltas) for:
    - keygen
    - encapsulate
    - decapsulate

    Fresh keys are generated for each run of encapsulate/decapsulate to avoid
    reusing state and to keep comparisons fair.
    """
    ops: Dict[str, OpStats] = {}
    def _p(stage: str):
        if progress is None:
            return None
        return lambda i, total: progress(stage, name, i, total)

    ops["keygen"] = measure_factory(
        partial(_sig_keygen_factory, name),
        runs,
        cold=cold,
        progress_cb=_p("keygen"),
        capture_memory=capture_memory,
        memory_interval=memory_interval,
    )
    # Ensure encapsulate/decapsulate timings exclude setup (keygen, prior steps)
    ops["encapsulate"] = measure_factory(
        partial(_kem_encapsulate_factory, name),
        runs,
        cold=cold,
        progress_cb=_p("encapsulate"),
        capture_memory=capture_memory,
        memory_interval=memory_interval,
    )
    ops["decapsulate"] = measure_factory(
        partial(_kem_decapsulate_factory, name),
        runs,
        cold=cold,
        progress_cb=_p("decapsulate"),
        capture_memory=capture_memory,
        memory_interval=memory_interval,
    )
    adapter = _get_adapter_instance(name)
    adapter_cls = adapter.__class__
    mod = getattr(adapter_cls, "__module__", "") or getattr(adapter, "__module__", "")
    if "pqcbench_liboqs" in mod:
        _backend = "liboqs"
    elif "pqcbench_native" in mod:
        _backend = "native"
    elif "pqcbench_rsa" in mod:
        _backend = "rsa"
    else:
        _backend = "unknown"
    pk, sk = adapter.keygen()
    ct, ss = adapter.encapsulate(pk)
    _ct_len = len(ct) if isinstance(ct, (bytes, bytearray)) else None
    _ss_len = len(ss) if isinstance(ss, (bytes, bytearray)) else None
    _ct_expansion = None
    try:
        if _ct_len is not None and _ss_len and _ss_len > 0:
            _ct_expansion = float(_ct_len) / float(_ss_len)
    except Exception:
        _ct_expansion = None
    meta = {
        "public_key_len": len(pk) if isinstance(pk, (bytes, bytearray)) else None,
        "secret_key_len": len(sk) if isinstance(sk, (bytes, bytearray)) else None,
        "ciphertext_len": _ct_len,
        "shared_secret_len": _ss_len,
        "ciphertext_expansion_ratio": _ct_expansion,
        # Prefer common attributes for the concrete mechanism/version name,
        # and fall back to native adapters' `algorithm` attribute when present.
        "mechanism": getattr(adapter, "mech", None)
        or getattr(adapter, "alg", None)
        or getattr(adapter, "_mech", None)
        or getattr(adapter, "algorithm", None),
        "run_mode": ("cold" if cold else "warm"),
        "backend": _backend,
    }
    analysis = _sample_secret_key_analysis(name, adapter, meta.get("mechanism"), "KEM")
    if analysis:
        meta["secret_key_analysis"] = analysis
    env_meta = _collect_environment_meta()
    if env_meta:
        meta["environment"] = env_meta
    cpu_model = env_meta.get("cpu_model") if isinstance(env_meta, dict) else None
    apply_runtime_scaling(
        ops,
        algo=name,
        cpu_model=cpu_model,
        profiles=_RUNTIME_DEVICE_PROFILES,
    )
    return AlgoSummary(algo=name, kind="KEM", ops=ops, meta=meta)


def run_sig(
    name: str,
    runs: int,
    message_size: int,
    *,
    cold: bool = True,
    capture_memory: bool = True,
    memory_interval: float | None = None,
    progress: Optional[_CallableOptional[[str, str, int, int], None]] = None,
) -> AlgoSummary:
    """Run a signature micro-benchmark for the registered algorithm `name`.

    Measures wall-clock latency (and optional memory deltas) for:
    - keygen
    - sign (with fresh keys per run)
    - verify (with fresh keys/signature per run)
    """
    ops: Dict[str, OpStats] = {}
    def _p(stage: str):
        if progress is None:
            return None
        return lambda i, total: progress(stage, name, i, total)

    ops["keygen"] = measure_factory(
        partial(_kem_keygen_factory, name),
        runs,
        cold=cold,
        progress_cb=_p("keygen"),
        capture_memory=capture_memory,
        memory_interval=memory_interval,
    )
    # Ensure sign/verify timings exclude setup (keygen, sign)
    ops["sign"] = measure_factory(
        partial(_sig_sign_factory, name, message_size),
        runs,
        cold=cold,
        progress_cb=_p("sign"),
        capture_memory=capture_memory,
        memory_interval=memory_interval,
    )
    ops["verify"] = measure_factory(
        partial(_sig_verify_factory, name, message_size),
        runs,
        cold=cold,
        progress_cb=_p("verify"),
        capture_memory=capture_memory,
        memory_interval=memory_interval,
    )
    adapter = _get_adapter_instance(name)
    adapter_cls = adapter.__class__
    mod = getattr(adapter_cls, "__module__", "") or getattr(adapter, "__module__", "")
    if "pqcbench_liboqs" in mod:
        _backend = "liboqs"
    elif "pqcbench_native" in mod:
        _backend = "native"
    elif "pqcbench_rsa" in mod:
        _backend = "rsa"
    else:
        _backend = "unknown"
    pk, sk = adapter.keygen()
    msg = b"x" * message_size
    sig = adapter.sign(sk, msg)
    _sig_len = len(sig) if isinstance(sig, (bytes, bytearray)) else None
    _sig_expansion = None
    try:
        if _sig_len is not None and message_size and int(message_size) > 0:
            _sig_expansion = float(_sig_len) / float(int(message_size))
    except Exception:
        _sig_expansion = None
    meta = {
        "public_key_len": len(pk) if isinstance(pk, (bytes, bytearray)) else None,
        "secret_key_len": len(sk) if isinstance(sk, (bytes, bytearray)) else None,
        "signature_len": _sig_len,
        "message_size": message_size,
        "signature_expansion_ratio": _sig_expansion,
        # Prefer common attributes for the concrete mechanism/version name,
        # and fall back to native adapters' `algorithm` attribute when present.
        "mechanism": getattr(adapter, "mech", None)
        or getattr(adapter, "alg", None)
        or getattr(adapter, "_mech", None)
        or getattr(adapter, "algorithm", None),
        "run_mode": ("cold" if cold else "warm"),
        "backend": _backend,
    }
    mechanism_name = str(meta.get("mechanism") or name or "").upper()
    if mechanism_name.startswith("MAYO") and meta.get("secret_key_len") == 24:
        meta.setdefault(
            "secret_key_note",
            "Secret key serialisation is a 24-byte seed expanded to the full private state by pqmayo/liboqs.",
        )
        meta.setdefault("secret_key_seed_bytes", meta["secret_key_len"])

    hash_name = getattr(adapter, "hash_algorithm_name", None)
    if hash_name:
        meta.setdefault("signature_hash", hash_name)
    hash_digest_size = getattr(adapter, "hash_digest_size", None)
    if isinstance(hash_digest_size, int):
        meta.setdefault("signature_hash_bytes", hash_digest_size)
    salt_len = getattr(adapter, "salt_length", None)
    if isinstance(salt_len, int):
        meta.setdefault("pss_salt_length", salt_len)
    mgf_hash_name = getattr(adapter, "mgf_hash_algorithm_name", None)
    if mgf_hash_name:
        meta.setdefault("pss_mgf_hash", mgf_hash_name)

    analysis = _sample_secret_key_analysis(name, adapter, meta.get("mechanism"), "SIG")
    if analysis:
        meta["secret_key_analysis"] = analysis
    env_meta = _collect_environment_meta()
    if env_meta:
        meta["environment"] = env_meta
    cpu_model = env_meta.get("cpu_model") if isinstance(env_meta, dict) else None
    apply_runtime_scaling(
        ops,
        algo=name,
        cpu_model=cpu_model,
        profiles=_RUNTIME_DEVICE_PROFILES,
    )
    return AlgoSummary(algo=name, kind="SIG", ops=ops, meta=meta)


def export_trace_kem(name: str, export_path: str | None) -> None:
    if not export_path:
        return
    adapter = _get_adapter_instance(name)
    pk, sk = adapter.keygen()
    ct, ss = adapter.encapsulate(pk)
    ss_dec = adapter.decapsulate(sk, ct)
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
    adapter = _get_adapter_instance(name)
    pk, sk = adapter.keygen()
    msg = b"x" * int(message_size)
    sig = adapter.sign(sk, msg)
    ok = adapter.verify(pk, msg, sig)
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
