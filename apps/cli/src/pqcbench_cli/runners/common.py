
from __future__ import annotations
"""Shared benchmarking utilities for CLI runners.

Includes adapter bootstrap, timing/memory measurement, JSON export helpers,
and per-kind (KEM/SIG) micro-benchmark orchestrators.
"""
import time, json, pathlib, base64, multiprocessing, threading, sys
from dataclasses import dataclass, asdict
from typing import Callable, Dict, Any, List, Tuple
from pqcbench import registry
from functools import partial

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
    series: List[float]
    # Memory footprint metrics (per-run process delta / Python peak)
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
    """Measure time and memory footprint in isolated runs.

    Every iteration executes in a fresh Python process so caches, allocator pools,
    and liboqs state from previous runs cannot influence the measurement.
    Reported memory captures the peak unique RSS delta observed during the run
    (sampled every ~1.5 ms) merged with the Python heap peak (KB). If psutil or
    tracemalloc are unavailable, the fields remain None.
    """
    times: List[float] = []
    mem_peaks_kb: List[float] = []

    for _ in range(runs):
        dt_ms, mem_kb = _run_isolated(fn)
        times.append(dt_ms)
        if mem_kb is not None:
            mem_peaks_kb.append(mem_kb)

    mean = sum(times) / len(times)

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


def _run_isolated(fn: Callable[[], None]) -> Tuple[float, float | None]:
    """Execute `fn` in a fresh process and return (time_ms, memory_kb)."""
    parent_conn, child_conn = _MP_CONTEXT.Pipe(duplex=False)
    proc = _MP_CONTEXT.Process(target=_isolated_worker, args=(fn, child_conn))
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


def _isolated_worker(fn: Callable[[], None], conn) -> None:
    """Child-process entry point for isolated measurements."""
    try:
        dt, mem_kb = _single_run_metrics(fn)
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


def _single_run_metrics(fn: Callable[[], None]) -> Tuple[float, float | None]:
    """Run `fn` exactly once, capturing time and memory usage."""
    import os
    import gc
    import time as _time

    baseline_bytes: int | None = None
    after_bytes: int | None = None
    rss_peak_kb: float | None = None
    proc = None
    monitor_stop: threading.Event | None = None
    monitor_thread: threading.Thread | None = None
    peak_bytes_holder: list[int | None] = []

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

        gc.collect()
        baseline_bytes = _sample_process_bytes()
        monitor_stop = threading.Event()
        peak_bytes_holder = [baseline_bytes]

        def _monitor_peak() -> None:
            base = baseline_bytes if baseline_bytes is not None else 0
            local_peak = base
            while not monitor_stop.is_set():
                try:
                    sample = _sample_process_bytes()
                    if sample is not None and sample > local_peak:
                        local_peak = sample
                except Exception:
                    pass
                if monitor_stop.wait(_MEMORY_SAMPLE_INTERVAL):
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
    except Exception:
        proc = None  # type: ignore
        monitor_stop = None
        monitor_thread = None
        peak_bytes_holder = []

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

    if proc is not None and baseline_bytes is not None:
        try:
            after_bytes = _sample_process_bytes()
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

    gc.collect()
    return dt_ms, rss_peak_kb


def _kem_keygen_once(name: str) -> None:
    cls = registry.get(name)
    cls().keygen()


def _kem_encapsulate_once(name: str) -> None:
    cls = registry.get(name)
    pk, _ = cls().keygen()
    cls().encapsulate(pk)


def _kem_decapsulate_once(name: str) -> None:
    cls = registry.get(name)
    pk, sk = cls().keygen()
    ct, _ = cls().encapsulate(pk)
    cls().decapsulate(sk, ct)


def _sig_keygen_once(name: str) -> None:
    cls = registry.get(name)
    cls().keygen()


def _sig_sign_once(name: str, message_size: int) -> None:
    cls = registry.get(name)
    msg = b"x" * int(message_size)
    _, sk = cls().keygen()
    cls().sign(sk, msg)


def _sig_verify_once(name: str, message_size: int) -> None:
    cls = registry.get(name)
    msg = b"x" * int(message_size)
    pk, sk = cls().keygen()
    sig = cls().sign(sk, msg)
    cls().verify(pk, msg, sig)


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
    if est_name or est_profile:
        out["estimator"] = {
            "name": est_name,
            "profile": est_profile,
            "available": bool(est_name) and not str(est_name).startswith("unavailable"),
        }

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
    if params:
        out["parameters"] = params

    # Resources (RSA-specific)
    if algo in ("rsa-oaep", "rsa-pss"):
        res = {k: extras.get(k) for k in ("logical_qubits", "toffoli", "t_count", "meas_depth", "depth_form", "t_per_toffoli", "rsa_model")}
        if extras.get("surface"):
            res["surface"] = extras.get("surface")
        out["resources"] = res

    # Estimates (curated or algorithm-specific)
    estimates: Dict[str, Any] = {}
    # Lattice curated
    if algo == "kyber":
        ce = (extras.get("mlkem", {}) or {}).get("curated_estimates")
        if ce:
            estimates["curated"] = ce
    elif algo == "dilithium":
        ce = (extras.get("mldsa", {}) or {}).get("curated_estimates")
        if ce:
            estimates["curated"] = ce
        consts = (extras.get("mldsa", {}) or {}).get("core_svp_constants")
        if consts:
            out.setdefault("assumptions", {})["core_svp_constants"] = consts
    elif algo == "falcon":
        ce = (extras.get("falcon", {}) or {}).get("curated_estimates")
        if ce:
            estimates["curated"] = ce
        consts = (extras.get("falcon", {}) or {}).get("core_svp_constants")
        if consts:
            out.setdefault("assumptions", {})["core_svp_constants"] = consts
    elif algo in ("sphincsplus", "sphincs+"):
        sx = extras.get("sphincs") or {}
        if sx.get("curated_estimates"):
            estimates["curated"] = sx.get("curated_estimates")
        if sx.get("hash_costs"):
            estimates["hash_costs"] = sx.get("hash_costs")
    elif algo == "xmssmt":
        xx = extras.get("xmss") or {}
        if xx.get("hash_costs"):
            estimates["hash_costs"] = xx.get("hash_costs")
    elif algo == "hqc":
        # Coarse ISD exponents (if present)
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
    elif algo == "mayo":
        my = extras.get("mayo") or {}
        if my.get("curated_estimates"):
            estimates["curated"] = my.get("curated_estimates")
        if my.get("checks"):
            estimates["checks"] = my.get("checks")

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

    return out


def _build_export_payload(summary: AlgoSummary, *, security_opts: dict | None = None) -> dict:
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

    return {
        "algo": summary.algo,
        "kind": summary.kind,
        "ops": {k: asdict(v) for k, v in summary.ops.items()},
        "meta": summary.meta,
        "security": security_std,
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
    ops: Dict[str, OpStats] = {}
    ops["keygen"] = measure(partial(_kem_keygen_once, name), runs)
    ops["encapsulate"] = measure(partial(_kem_encapsulate_once, name), runs)
    ops["decapsulate"] = measure(partial(_kem_decapsulate_once, name), runs)
    instance = cls()
    pk, sk = instance.keygen()
    ct, ss = cls().encapsulate(pk)
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
        "mechanism": getattr(instance, "mech", None) or getattr(instance, "alg", None) or getattr(instance, "_mech", None),
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
    ops: Dict[str, OpStats] = {}
    ops["keygen"] = measure(partial(_sig_keygen_once, name), runs)
    ops["sign"] = measure(partial(_sig_sign_once, name, message_size), runs)
    ops["verify"] = measure(partial(_sig_verify_once, name, message_size), runs)
    instance = cls()
    pk, sk = instance.keygen()
    msg = b"x" * message_size
    sig = instance.sign(sk, msg)
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
        "mechanism": getattr(instance, "mech", None) or getattr(instance, "alg", None) or getattr(instance, "_mech", None),
    }
    return AlgoSummary(algo=name, kind="SIG", ops=ops, meta=meta)


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




