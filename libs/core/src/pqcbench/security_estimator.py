from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional
import math

"""Lightweight, per-algorithm security estimators.

This module provides fast, dependency-light estimates to attach to benchmark
summaries. The goal is comparability, not exact cryptanalysis.

Conventions:
- classical_bits: log2(work) floor based on NIST categories or standard heuristics
- quantum_bits: coarse estimate under generic speedups (e.g., Grover) where applicable
- shor_breakable: True for RSA variants (report quantum resources instead of bits)
- extras: algorithm-specific fields (e.g., logical_qubits, toffoli, depth, category)

Future extensions can add calls to external estimators (e.g., lattice-estimator)
behind feature flags.
"""


@dataclass
class SecMetrics:
    classical_bits: Optional[float]
    quantum_bits: Optional[float]
    shor_breakable: bool
    notes: str
    extras: Dict[str, Any]

@dataclass
class EstimatorOptions:
    lattice_use_estimator: bool = False
    lattice_model: str | None = None  # e.g., "core-svp", "q-core-svp" (informational)
    lattice_profile: str | None = None  # e.g., "floor", "classical", "quantum"
    rsa_surface: bool = False
    rsa_model: str | None = None  # e.g., "ge2019"
    quantum_arch: str | None = None  # e.g., "superconducting-2025", "iontrap-2025"
    phys_error_rate: float = 1e-3  # physical error rate per operation (default ~0.1%)
    cycle_time_s: float = 1e-6     # surface-code cycle time in seconds (default 1 µs)
    target_total_fail_prob: float = 1e-2  # acceptable total failure probability for the run


def _nist_floor_from_name(name: str) -> Optional[int]:
    n = name.lower()
    # Common mappings across PQC families
    if any(t in n for t in ["512", "-44", "128s", "128f", "128"]):
        return 128
    if any(t in n for t in ["768", "-65", "192s", "192f", "192"]):
        return 192
    if any(t in n for t in ["1024", "-87", "256s", "256f", "256"]):
        return 256
    return None


def _apply_quantum_arch_presets(opts: EstimatorOptions | None) -> EstimatorOptions | None:
    if not opts or not opts.quantum_arch:
        return opts
    arch = opts.quantum_arch.lower()
    # Coarse presets for demonstrative comparison
    if arch == "superconducting-2025":
        opts.phys_error_rate = 1e-3
        opts.cycle_time_s = 1e-6
    elif arch == "iontrap-2025":
        opts.phys_error_rate = 1e-4
        opts.cycle_time_s = 1e-5
    return opts


def _estimate_rsa_from_meta(kind: str, meta: Dict[str, Any], opts: Optional[EstimatorOptions]) -> SecMetrics:
    # Infer modulus bits from signature/ciphertext length if available; fallback to 2048
    n_bits: int
    if kind == "SIG":
        n_bits = int(meta.get("signature_len", 256)) * 8
    else:
        n_bits = int(meta.get("ciphertext_len", 256)) * 8
    # Very coarse logical resource model (abstract-level) for Shor factoring
    Q = 3 * n_bits  # logical qubits ~ 3n
    T = 0.3 * (n_bits ** 3)  # Toffoli count ~ 0.3 n^3
    D = 500 * (n_bits ** 2)  # measurement depth ~ O(n^2)
    # Optionally switch resource constants by model (currently placeholders)
    toffoli_coeff = 0.3
    qubit_coeff = 3.0
    depth_coeff = 500.0
    if opts and opts.rsa_model:
        model = opts.rsa_model.lower()
        if model == "ge2019":
            toffoli_coeff, qubit_coeff, depth_coeff = 0.3, 3.0, 500.0
        # Future models can be added here

    Q = qubit_coeff * n_bits
    T = toffoli_coeff * (n_bits ** 3)
    D = depth_coeff * (n_bits ** 2)

    metrics = SecMetrics(
        classical_bits=None,
        quantum_bits=None,
        shor_breakable=True,
        notes="RSA is polynomial-time breakable by Shor; report logical resources.",
        extras={
            "modulus_bits": n_bits,
            "logical_qubits": Q,
            "toffoli": T,
            "meas_depth": D,
            "rsa_model": (opts.rsa_model if opts and opts.rsa_model else "default"),
        },
    )

    # Optional: convert to surface-code physical qubits and runtime
    opts = _apply_quantum_arch_presets(opts)
    if opts and opts.rsa_surface:
        # Very coarse model. Assumptions (documented in output):
        # - Surface code threshold p_th ≈ 1e-2
        # - Logical error per operation p_L ≈ 0.1 * (p_phys/p_th)^((d+1)/2)
        # - Choose code distance d so that p_L * max(T, D) <= target_total_fail_prob / 10 (margin)
        p_th = 1e-2
        p_phys = float(opts.phys_error_rate)
        cycles = max(T, D)  # rough proxy for number of opportunities for logical failure
        target = max(1e-18, float(opts.target_total_fail_prob) / 10.0 / max(1.0, cycles))

        # Solve for smallest integer d such that 0.1*(p_phys/p_th)^((d+1)/2) <= target
        base = max(1e-12, p_phys / p_th)
        if base >= 1.0:
            d = 100  # absurdly large; indicates p_phys above threshold
        else:
            exp = math.log(target / 0.1, base)
            d = max(3, int(2 * exp - 1))

        # Physical qubits per logical qubit ~ k * d^2; pick k≈2 as a crude constant
        kq = 2.0
        phys_qubits = int(kq * (d ** 2) * Q)

        # Runtime: measurement depth inflated by ~O(d) surface cycles
        cycle_time_s = float(opts.cycle_time_s)
        runtime_s = float(D) * float(d) * cycle_time_s

        metrics.extras.update({
            "surface": {
                "code_distance": d,
                "phys_qubits_total": phys_qubits,
                "runtime_seconds": runtime_s,
                "assumptions": {
                    "p_phys": p_phys,
                    "p_thresh": p_th,
                    "cycle_time_s": cycle_time_s,
                    "target_total_fail_prob": float(opts.target_total_fail_prob),
                },
            }
        })
        metrics.notes += " With surface-code overhead (very rough)."

    return metrics


def _estimate_hash_based_from_name(name: str) -> SecMetrics:
    # SPHINCS+/XMSSMT: classical ≈ output bits; quantum ≈ half via Grover-type
    floor = _nist_floor_from_name(name) or 128
    return SecMetrics(
        classical_bits=float(floor),
        quantum_bits=float(floor) / 2.0,
        shor_breakable=False,
        notes="Hash-based: generic Grover/quantum-walk speedups assumed (≈√).",
        extras={"category_floor": floor},
    )


def _estimate_lattice_like_from_name(name: str, opts: Optional[EstimatorOptions]) -> SecMetrics:
    # ML-KEM/ML-DSA/Falcon: use NIST floor; do not compress to a single quantum number.
    # Prefer params module if mechanism is exact
    floor = None
    try:
        from pqcbench.params import find as find_params  # type: ignore
        ph = find_params(name)
        if ph:
            floor = ph.category_floor
            base_extras = {"params": ph.to_dict()}
        else:
            base_extras = {}
    except Exception:
        base_extras = {}
    floor = floor or (_nist_floor_from_name(name) or 128)
    metrics = SecMetrics(
        classical_bits=float(floor),
        quantum_bits=float(floor),  # conservative floor without Q-Core-SVP modeling
        shor_breakable=False,
        notes=(
            "Lattice-based: floor from NIST category; no Q-Core-SVP constants modeled."
        ),
        extras={"category_floor": floor, **base_extras},
    )
    # Feature-flagged attempt to use external lattice estimator (if available and parameters known)
    if opts and opts.lattice_use_estimator:
        est = _try_lattice_estimator(name)
        if est is not None:
            metrics.classical_bits = est.get("bits_classical", metrics.classical_bits)
            metrics.quantum_bits = est.get("bits_quantum", metrics.quantum_bits)
            metrics.extras.update({
                "beta": est.get("beta"),
                "estimator_model": est.get("model"),
                "lattice_profile": (opts.lattice_profile or "unknown"),
            })
            metrics.notes = "Lattice Estimator model (best-effort); see extras for assumptions."
        else:
            metrics.extras.update({
                "estimator_model": "unavailable (fallback to NIST floor)",
                "lattice_profile": (opts.lattice_profile or "floor"),
            })
    return metrics


def _estimate_hqc_from_name(name: str, opts: Optional[EstimatorOptions]) -> SecMetrics:
    # Code-based HQC: use category floor; note ISD assumptions
    floor = _nist_floor_from_name(name) or 128
    return SecMetrics(
        classical_bits=float(floor),
        quantum_bits=float(floor),
        shor_breakable=False,
        notes=(
            "Code-based (HQC): floor from ISD-based estimates; no polynomial-time quantum break."
        ),
        extras={"category_floor": floor},
    )


def _get_mechanism_for_algo(algo_name: str) -> Optional[str]:
    # Best-effort: instantiate the registered adapter and read a 'mech' or similar attribute
    try:
        from pqcbench import registry  # local import to avoid cycles at module import
        cls = registry.get(algo_name)
        obj = cls()
        mech = getattr(obj, "mech", None)
        if mech:
            return str(mech)
    except Exception:
        pass
    return None


def estimate_for_summary(summary: Any, options: Optional[EstimatorOptions] = None) -> Dict[str, Any]:
    """Compute a security estimate for a CLI AlgoSummary.

    Returns a dict suitable for embedding under the 'security' key in exports.
    """
    name = str(summary.algo)
    kind = str(summary.kind)
    mech = _get_mechanism_for_algo(name)  # may be None
    meta = dict(summary.meta or {})

    # Prefer a human-readable parameter/mech string when present
    param_hint = mech or meta.get("parameter", None) or meta.get("mechanism", None) or name
    metrics: SecMetrics

    if name in ("rsa-pss", "rsa-oaep"):
        metrics = _estimate_rsa_from_meta(kind, meta, options)
    elif name == "kyber":  # ML-KEM
        metrics = _estimate_lattice_like_from_name(param_hint, options)
        metrics.notes = "ML-KEM (Kyber): NIST floor; no Q-Core-SVP modeled."
    elif name == "dilithium":  # ML-DSA
        metrics = _estimate_lattice_like_from_name(param_hint, options)
        metrics.notes = "ML-DSA (Dilithium): NIST floor; no Q-Core-SVP modeled."
    elif name == "falcon":
        metrics = _estimate_lattice_like_from_name(param_hint, options)
        metrics.notes = "Falcon: category floor; no Q-sieving modeled."
    elif name == "hqc":
        metrics = _estimate_hqc_from_name(param_hint, options)
    elif name == "sphincsplus":
        metrics = _estimate_hash_based_from_name(param_hint)
    elif name == "xmssmt":
        metrics = _estimate_hash_based_from_name(param_hint)
    else:
        metrics = SecMetrics(
            classical_bits=None,
            quantum_bits=None,
            shor_breakable=False,
            notes="No estimator available for this algorithm.",
            extras={},
        )

    # Return a plain dict for easy JSON embedding
    out = asdict(metrics)
    if mech:
        out["mechanism"] = mech
    return out


def _try_lattice_estimator(param_hint: str) -> Optional[Dict[str, Any]]:
    """Best-effort integration with external lattice estimator libraries.

    Returns a dict with keys like {bits_classical, bits_quantum, beta, model}
    or None if unavailable.

    Note: Without full parameter tuples (n, q, k, etc.) this function
    currently uses only the mechanism/category as a coarse hint and thus
    cannot produce a precise estimate in this repository context.
    """
    try:
        # Try a commonly used package name; many distributions call into sage.
        import importlib
        # Prefer a pure-Python wrapper if present
        mod = None
        for name in ("lwe_estimator", "lattice_estimator"):
            try:
                mod = importlib.import_module(name)
                break
            except Exception:
                continue
        if mod is None:
            return None

        # We do not have scheme parameters; return a placeholder enriched with the mechanism.
        return {
            "model": f"{mod.__name__} (no parameters available; using NIST floor)",
            "beta": None,
            "bits_classical": None,
            "bits_quantum": None,
        }
    except Exception:
        return None
