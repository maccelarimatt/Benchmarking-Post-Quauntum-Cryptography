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

    # Classical security per SP 800-56B style mapping
    def _rsa_classical_strength(n: int) -> int:
        # Common NIST mapping: 2048≈112, 3072≈128, 7680≈192, 15360≈256
        # Use inclusive lower bounds
        if n < 2048:
            return 80
        if n < 3072:
            return 112
        if n < 7680:
            return 128
        if n < 15360:
            return 192
        return 256

    # Very coarse logical resource model (abstract-level) for Shor factoring
    # Defaults aligned with GE2019: ~0.3 n^3 Toffoli, ~3n logical qubits, depth ~ k n^2 log n
    toffoli_coeff = 0.3
    qubit_coeff = 3.0
    depth_coeff = 45.0  # choose so that depth(~n^2 log2 n) matches prior scale near n=2048
    depth_form = "n^2 log2 n"

    # Optionally switch resource constants by model (placeholders unless noted)
    if opts and opts.rsa_model:
        model = opts.rsa_model.lower()
        if model == "ge2019":
            toffoli_coeff, qubit_coeff, depth_coeff = 0.3, 3.0, 45.0
        elif model in ("ge2025", "fast2025"):
            # Heuristic 2025-style improvements knob: modest constant reductions
            toffoli_coeff, qubit_coeff, depth_coeff = 0.25, 2.5, 30.0
        # Additional models can be added here

    Q = qubit_coeff * n_bits  # logical qubits ~ c_q * n
    toffoli = toffoli_coeff * (n_bits ** 3)
    # measured depth ~ c_d * n^2 * log2 n
    D = depth_coeff * (n_bits ** 2) * max(1.0, math.log2(max(2, n_bits)))
    # Provide a rough T-count by Toffoli decomposition factor (typical 7 T per Toffoli)
    t_per_toffoli = 7.0
    t_count = toffoli * t_per_toffoli

    metrics = SecMetrics(
        classical_bits=float(_rsa_classical_strength(n_bits)),
        quantum_bits=None,
        shor_breakable=True,
        notes="RSA is polynomial-time breakable by Shor; report logical resources.",
        extras={
            "modulus_bits": n_bits,
            "logical_qubits": Q,
            "toffoli": toffoli,
            "t_count": t_count,
            "meas_depth": D,
            "depth_form": depth_form,
            "t_per_toffoli": t_per_toffoli,
            "rsa_model": (opts.rsa_model if opts and opts.rsa_model else "ge2019"),
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
        cycles = max(toffoli, D)  # rough proxy for number of opportunities for logical failure
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
    nist_category = {128: 1, 192: 3, 256: 5}.get(int(floor), None)
    return SecMetrics(
        classical_bits=float(floor),
        quantum_bits=float(floor) / 2.0,
        shor_breakable=False,
        notes="Hash-based (SLH-DSA family): Grover/quantum-walk √ speedup assumed.",
        extras={"category_floor": floor, "nist_category": nist_category},
    )


def _estimate_lattice_like_from_name(name: str, opts: Optional[EstimatorOptions]) -> SecMetrics:
    # ML-KEM/ML-DSA/Falcon: use NIST floor; do not compress to a single quantum number.
    # Prefer params module if mechanism is exact
    floor = None
    family = None
    try:
        from pqcbench.params import find as find_params  # type: ignore
        ph = find_params(name)
        if ph:
            floor = ph.category_floor
            family = ph.family
            base_extras = {"params": ph.to_dict()}
        else:
            base_extras = {}
    except Exception:
        base_extras = {}
    floor = floor or (_nist_floor_from_name(name) or 128)
    # Baseline metrics: category floors + explicit NIST category label
    nist_category = {128: 1, 192: 3, 256: 5}.get(int(floor), None)
    metrics = SecMetrics(
        classical_bits=float(floor),
        quantum_bits=float(floor),  # conservative floor without Q-Core-SVP modeling
        shor_breakable=False,
        notes=(
            "Lattice-based: floor from NIST category; enable --sec-adv for APS estimator."
        ),
        extras={"category_floor": floor, "nist_category": nist_category, **base_extras},
    )
    # Feature-flagged attempt to use external lattice estimator (if available and parameters known)
    if opts and opts.lattice_use_estimator:
        est = _try_lattice_estimator_with_params(name, family)
        if est is not None:
            # Attach estimator outputs when present
            b_class = est.get("bits_classical")
            b_qram = est.get("bits_qram")
            beta = est.get("beta")
            if isinstance(b_class, (int, float)):
                metrics.classical_bits = float(b_class)
            if isinstance(b_qram, (int, float)):
                metrics.quantum_bits = float(b_qram)
            metrics.extras.update({
                "beta": beta,
                "estimator_model": est.get("model"),
                "lattice_profile": (opts.lattice_profile or "classical"),
                "qram_assisted": {
                    "bits": b_qram,
                    "assumption": "Q-Core-SVP constant ~0.265; QRAM-assisted sieving",
                },
                "classical_sieve": {
                    "bits": b_class,
                    "assumption": "Core-SVP constant ~0.292",
                },
            })
            metrics.notes = "APS Lattice Estimator (best-effort): classical and QRAM-assisted costs."
        else:
            metrics.extras.update({
                "estimator_model": "unavailable (fallback to NIST floor)",
                "lattice_profile": (opts.lattice_profile or "floor"),
            })
            # If user requested estimator but it's unavailable, reflect that in notes
            metrics.notes = f"{family or 'Lattice'}: estimator unavailable; using NIST category floor."
    return metrics


def _estimate_hqc_from_name(name: str, opts: Optional[EstimatorOptions]) -> SecMetrics:
    # Code-based HQC: category floor plus closed-form ISD exponents when parameters are available
    floor = _nist_floor_from_name(name) or 128
    nist_category = {128: 1, 192: 3, 256: 5}.get(int(floor), None)

    def _H2(p: float) -> float:
        if p <= 0.0 or p >= 1.0:
            return 0.0
        return -(p * math.log2(p) + (1.0 - p) * math.log2(1.0 - p))

    def _log2_binom(n: int, t: int) -> float:
        if t < 0 or t > n or n <= 0:
            return 0.0
        p = float(t) / float(n)
        return float(n) * _H2(p)

    # Try to fetch (n, k, w) from params to compute ISD exponents (coarse Stern-style)
    extras: Dict[str, Any] = {"category_floor": floor, "nist_category": nist_category}
    try:
        from pqcbench.params import find as find_params  # type: ignore
        ph = find_params(name)
        if ph and ph.extras:
            n = int(ph.extras.get("n", 0) or 0)
            k = int(ph.extras.get("k", 0) or 0)
            w = int(ph.extras.get("w", 0) or 0)
            if n > 0 and k > 0 and 0 < w <= n:
                # Stern-like rough time exponent: C(n, w) / C(k, floor(w/2))
                logNw = _log2_binom(n, w)
                logKwh = _log2_binom(k, max(0, w // 2))
                time_bits_classical = max(0.0, logNw - logKwh)
                mem_bits_classical = max(0.0, 0.5 * time_bits_classical)  # heuristic BJMM/MMT memory fraction
                time_bits_quantum = 0.5 * time_bits_classical  # Grover-like √ speedup on dominant search
                extras.update({
                    "isd_model": "Stern-entropy (coarse)",
                    "isd_time_bits_classical": time_bits_classical,
                    "isd_mem_bits_classical": mem_bits_classical,
                    "isd_time_bits_quantum": time_bits_quantum,
                    "params": ph.to_dict(),
                    "no_known_polynomial_quantum": True,
                })
    except Exception:
        pass

    return SecMetrics(
        classical_bits=float(floor),
        quantum_bits=float(floor),
        shor_breakable=False,
        notes=(
            "Code-based (HQC): category floor; ISD exponents attached when (n,k,w) available; no known polynomial-time quantum attack."
        ),
        extras=extras,
    )


def _get_mechanism_for_algo(algo_name: str) -> Optional[str]:
    # Best-effort: instantiate the registered adapter and read a 'mech' or similar attribute
    try:
        from pqcbench import registry  # local import to avoid cycles at module import
        cls = registry.get(algo_name)
        obj = cls()
        mech = getattr(obj, "mech", None) or getattr(obj, "_mech", None)
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
        if "APS Lattice Estimator" not in metrics.notes:
            if options and options.lattice_use_estimator:
                metrics.notes = "ML-KEM (Kyber): estimator unavailable; using NIST category floor."
            else:
                metrics.notes = "ML-KEM (Kyber): NIST floor; enable --sec-adv for estimator."
    elif name == "dilithium":  # ML-DSA
        metrics = _estimate_lattice_like_from_name(param_hint, options)
        if "APS Lattice Estimator" not in metrics.notes:
            if options and options.lattice_use_estimator:
                metrics.notes = "ML-DSA (Dilithium): estimator unavailable; using NIST category floor."
            else:
                metrics.notes = "ML-DSA (Dilithium): NIST floor; enable --sec-adv for estimator."
    elif name == "falcon":
        metrics = _estimate_lattice_like_from_name(param_hint, options)
        if "APS Lattice Estimator" not in metrics.notes:
            if options and options.lattice_use_estimator:
                metrics.notes = "Falcon: estimator unavailable; using NIST category floor."
            else:
                metrics.notes = "Falcon: category floor; enable --sec-adv for estimator."
    elif name == "hqc":
        metrics = _estimate_hqc_from_name(param_hint, options)
    elif name == "sphincsplus":
        metrics = _estimate_hash_based_from_name(param_hint)
    elif name == "xmssmt":
        metrics = _estimate_hash_based_from_name(param_hint)
    elif name == "mayo":
        metrics = _estimate_mayo_from_name(param_hint)
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


def _try_lattice_estimator_with_params(mechanism: str, family: Optional[str]) -> Optional[Dict[str, Any]]:
    """Attempt to compute classical/QRAM costs and beta using external estimator.

    Falls back to None when estimator package is not available or parameters are
    insufficient. Uses coarse parameter hints from pqcbench.params when possible.
    """
    try:
        import importlib
        from pqcbench.params import find as find_params  # type: ignore
        ph = find_params(mechanism)
        if not ph:
            return None
        extras = ph.extras or {}
        # Only attempt for supported lattice families
        fam = family or ph.family
        if fam not in ("ML-KEM", "ML-DSA", "Falcon"):
            return None

        # Try to import an estimator module — many require Sage; keep this optional.
        mod = None
        for name in ("lwe_estimator", "lattice_estimator"):
            try:
                mod = importlib.import_module(name)
                break
            except Exception:
                continue
        if mod is None:
            return None

        # Without reliable API across installs, we cannot construct calls here.
        # Return a structured placeholder signalling that an estimator was found but
        # parameter integration is not wired in this environment.
        return {
            "model": f"{mod.__name__} (detected; parameters not wired)",
            "beta": None,
            "bits_classical": None,
            "bits_qram": None,
        }
    except Exception:
        return None


def _estimate_mayo_from_name(name: str) -> SecMetrics:
    """Coarse estimator for MAYO (multivariate MQ signatures).

    Without an established open-source estimator in this repo, provide
    category-based floors and label as MQ-based (not Shor-breakable).
    """
    # Map common Mayo variants to floors via params
    try:
        from pqcbench.params import find as find_params  # type: ignore
        ph = find_params(name)
        floor = ph.category_floor if ph else (_nist_floor_from_name(name) or 128)
        nist_category = {128: 1, 160: 2, 192: 3, 256: 5}.get(int(floor), None)
        return SecMetrics(
            classical_bits=float(floor),
            quantum_bits=float(floor),  # no widely accepted quantum speedup beyond generic
            shor_breakable=False,
            notes="MAYO (multivariate MQ): category floor; no algebraic attack model integrated.",
            extras={
                "category_floor": floor,
                "nist_category": nist_category,
                "params": (ph.to_dict() if ph else {}),
            },
        )
    except Exception:
        floor = _nist_floor_from_name(name) or 128
        nist_category = {128: 1, 160: 2, 192: 3, 256: 5}.get(int(floor), None)
        return SecMetrics(
            classical_bits=float(floor),
            quantum_bits=float(floor),
            shor_breakable=False,
            notes="MAYO (multivariate MQ): category floor.",
            extras={"category_floor": floor, "nist_category": nist_category},
        )
