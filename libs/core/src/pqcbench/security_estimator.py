from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional, Iterable, Tuple, List
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


@dataclass(frozen=True)
class ShorModelSpec:
    name: str
    qubit_linear: float
    qubit_log_coeff: float
    toffoli_cubic: float
    toffoli_cubic_log: float
    depth_quadratic: float
    depth_quadratic_log: float
    notes: str


@dataclass(frozen=True)
class FactorySpec:
    name: str
    logical_qubits: float
    cycles_per_batch_per_distance: float
    outputs_per_batch: float
    alpha: float = 2.5
    description: str = ""


SHOR_MODEL_LIBRARY: Dict[str, ShorModelSpec] = {
    "ge2019": ShorModelSpec(
        name="ge2019",
        qubit_linear=3.0,
        qubit_log_coeff=0.002,
        toffoli_cubic=0.3,
        toffoli_cubic_log=0.0005,
        depth_quadratic=500.0,
        depth_quadratic_log=1.0,
        notes=(
            "Gidney–Ekerå 2019 factoring cost model: Q = 3n + 0.002 n log2 n, "
            "Toffoli = (0.3 + 0.0005 log2 n) n^3, depth = (500 + log2 n) n^2"
        ),
    ),
}


FACTORY_LIBRARY: Dict[str, FactorySpec] = {
    "litinski-116-to-12": FactorySpec(
        name="litinski-116-to-12",
        logical_qubits=6000.0,
        cycles_per_batch_per_distance=5.0,
        outputs_per_batch=12.0,
        alpha=2.5,
        description=(
            "Two-stage |T⟩ distillation pipeline inspired by Litinski 2019; "
            "outputs 12 high-fidelity magic states after ~5·d code cycles per factory."
        ),
    ),
    "factory-lite-15-to-1": FactorySpec(
        name="factory-lite-15-to-1",
        logical_qubits=1500.0,
        cycles_per_batch_per_distance=10.0,
        outputs_per_batch=1.0,
        alpha=2.3,
        description=(
            "Single-level 15-to-1 T distillation factory; slower throughput but smaller footprint."
        ),
    ),
}


def _bkz_root_hermite(beta: float) -> float:
    """Return the root-Hermite factor δ0 associated with blocksize β."""
    if beta <= 2.0:
        return 1.0
    beta_f = float(beta)
    return ((beta_f / (2.0 * math.pi * math.e)) ** (1.0 / (2.0 * (beta_f - 1.0)))) * (
        (math.pi * beta_f) ** (1.0 / (2.0 * beta_f))
    )


def _stddev_centered_binomial(eta: Optional[int]) -> Optional[float]:
    if eta is None:
        return None
    if eta <= 0:
        return None
    return math.sqrt(float(eta) / 2.0)


def _stddev_uniform_eta(eta: Optional[int]) -> Optional[float]:
    if eta is None:
        return None
    if eta <= 0:
        return None
    # Variance for uniform {-eta, ..., eta}
    return math.sqrt(float(eta) * (float(eta) + 1.0) / 3.0)


def _module_lwe_sigma(extras: Dict[str, Any]) -> Optional[float]:
    if "sigma_e" in extras:
        try:
            sigma = float(extras["sigma_e"])
            return sigma if sigma > 0.0 else None
        except Exception:
            return None
    eta2 = extras.get("eta2")
    if eta2 is not None:
        return _stddev_centered_binomial(int(eta2))
    eta = extras.get("eta")
    if eta is not None:
        return _stddev_uniform_eta(int(eta))
    return None


def _module_lwe_secret_span(extras: Dict[str, Any]) -> Optional[int]:
    if "eta1" in extras:
        return max(1, int(extras["eta1"]))
    if "eta" in extras:
        return max(1, int(extras["eta"]))
    if "secret_bound" in extras:
        return max(1, int(extras["secret_bound"]))
    return None


def _module_lwe_dimension(extras: Dict[str, Any]) -> Optional[int]:
    try:
        n = int(extras.get("n", 0) or 0)
        k = int(extras.get("k", 0) or 0)
    except Exception:
        return None
    if n <= 0 or k <= 0:
        return None
    return n * k


def _module_lwe_alpha(q: int, sigma: float) -> Optional[float]:
    if q <= 0 or sigma <= 0.0:
        return None
    return math.sqrt(2.0 * math.pi) * sigma / float(q)


def _module_lwe_exponent_factor(k: int, q: int, adjustment: float = 0.0) -> float:
    # Tuned to reproduce published BKZ block sizes for Kyber/Dilithium families.
    k_eff = max(1, int(k))
    base = 0.565 + 1.4 / float(k_eff)
    if q > 0:
        q_norm = max(1.0, float(q) / 3000.0)
        base += 0.05 * math.log10(q_norm)
        if q >= 1_000_000:
            base += 0.025
    return max(0.35, base + adjustment)


def _solve_beta_for_alpha(alpha: float, n_eff: int, k_eff: int, q: int, adjustment: float = 0.0) -> Optional[int]:
    if alpha <= 0.0 or n_eff <= 0 or k_eff <= 0:
        return None
    exponent = _module_lwe_exponent_factor(k_eff, q, adjustment) * float(n_eff)
    target = 1.0 / alpha
    if target <= 1.0:
        return None
    for beta in range(40, 901):
        if _bkz_root_hermite(beta) ** exponent <= target:
            return beta
    return None


def _module_lwe_guess_cost_bits(guess_modules: int, n: int, secret_span: Optional[int]) -> float:
    if guess_modules <= 0 or n <= 0:
        return 0.0
    if secret_span is None:
        return float(guess_modules * n)
    return float(guess_modules * n * math.log2(2 * secret_span + 1))


def _module_lwe_attack_catalog(k: int) -> Iterable[Tuple[str, float, int]]:
    # (name, adjustment, max_guess_modules)
    yield ("primal-usvp", 0.0, 0)
    yield ("dual", -0.02, 0)
    # Allow small secret guessing for hybrid variants
    yield ("hybrid-1", -0.08, 1)
    yield ("hybrid-2", -0.10, 2)


def _module_lwe_cost_profiles(alpha: float, extras: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    dim = _module_lwe_dimension(extras)
    if dim is None:
        return None
    n = int(extras.get("n", 0) or 0)
    k = int(extras.get("k", 0) or 0)
    try:
        q = int(extras.get("q", 0) or 0)
    except Exception:
        q = 0
    if n <= 0 or k <= 0:
        return None
    secret_span = _module_lwe_secret_span(extras)

    profiles = [
        {
            "label": "aggressive",
            "classical_consts": (0.285, 0.292),
            "quantum_consts": (0.250, 0.260),
        },
        {
            "label": "conservative",
            "classical_consts": (0.292, 0.300),
            "quantum_consts": (0.260, 0.270),
        },
    ]

    profile_constants = {
        prof["label"]: {
            "classical_consts": list(prof["classical_consts"]),
            "quantum_consts": list(prof["quantum_consts"]),
        }
        for prof in profiles
    }

    attacks: list[Dict[str, Any]] = []
    for attack_name, adjustment, max_guess in _module_lwe_attack_catalog(k):
        best_entry: Optional[Dict[str, Any]] = None
        for guess in range(0, max_guess + 1):
            k_eff = max(1, k - guess)
            n_eff = n * k_eff
            beta = _solve_beta_for_alpha(alpha, n_eff, k_eff, q, adjustment)
            if beta is None:
                continue
            guess_bits = _module_lwe_guess_cost_bits(guess, n, secret_span)
            delta0 = _bkz_root_hermite(beta)
            attack_profiles: list[Dict[str, Any]] = []
            for prof in profiles:
                c_lo, c_hi = prof["classical_consts"]
                q_lo, q_hi = prof["quantum_consts"]
                classical_range = [c_lo * beta + guess_bits, c_hi * beta + guess_bits]
                quantum_range = [q_lo * beta + 0.5 * guess_bits, q_hi * beta + 0.5 * guess_bits]
                attack_profiles.append(
                    {
                        "profile": prof["label"],
                        "classical_bits_range": classical_range,
                        "quantum_bits_range": quantum_range,
                    }
                )
            entry = {
                "attack": attack_name,
                "guess_modules": guess,
                "beta": beta,
                "delta0": delta0,
                "profiles": attack_profiles,
            }
            if best_entry is None or beta < best_entry["beta"]:
                best_entry = entry
        if best_entry is not None:
            attacks.append(best_entry)

    if not attacks:
        return None

    # Aggregate best per profile
    per_profile: Dict[str, Dict[str, float]] = {}
    for prof in profiles:
        label = prof["label"]
        classical_lo = math.inf
        classical_hi = math.inf
        quantum_lo = math.inf
        quantum_hi = math.inf
        best_attack = None
        for attack in attacks:
            for detail in attack["profiles"]:
                if detail["profile"] != label:
                    continue
                c_lo, c_hi = detail["classical_bits_range"]
                q_lo, q_hi = detail["quantum_bits_range"]
                if c_lo < classical_lo:
                    classical_lo = c_lo
                    classical_hi = c_hi
                    quantum_lo = q_lo
                    quantum_hi = q_hi
                    best_attack = attack["attack"]
                elif math.isclose(c_lo, classical_lo, rel_tol=1e-9) and c_hi < classical_hi:
                    classical_hi = c_hi
                    quantum_lo = q_lo
                    quantum_hi = q_hi
                    best_attack = attack["attack"]
        if best_attack is None:
            continue
        per_profile[label] = {
            "attack": best_attack,
            "classical_bits_range": [classical_lo, classical_hi],
            "quantum_bits_range": [quantum_lo, quantum_hi],
            "headline_mid_classical": (classical_lo + classical_hi) / 2.0,
            "headline_mid_quantum": (quantum_lo + quantum_hi) / 2.0,
        }

    if not per_profile:
        return None

    agg_classical = [min(v["classical_bits_range"][0] for v in per_profile.values()), max(v["classical_bits_range"][1] for v in per_profile.values())]
    agg_quantum = [min(v["quantum_bits_range"][0] for v in per_profile.values()), max(v["quantum_bits_range"][1] for v in per_profile.values())]

    headline_label = "aggressive" if "aggressive" in per_profile else next(iter(per_profile))
    headline = per_profile[headline_label]

    return {
        "dimension": dim,
        "n": n,
        "k": k,
        "alpha": alpha,
        "attacks": attacks,
        "profiles": per_profile,
        "profile_constants": profile_constants,
        "headline": {
            "profile": headline_label,
            "attack": headline["attack"],
            "classical_bits": headline["headline_mid_classical"],
            "quantum_bits": headline["headline_mid_quantum"],
            "classical_bits_range": per_profile[headline_label]["classical_bits_range"],
            "quantum_bits_range": per_profile[headline_label]["quantum_bits_range"],
        },
        "classical_bits_range": agg_classical,
        "quantum_bits_range": agg_quantum,
    }


def _module_lwe_cost_summary(extras: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        q = int(extras.get("q", 0) or 0)
    except Exception:
        q = 0
    sigma = _module_lwe_sigma(extras)
    if q <= 0 or sigma is None or sigma <= 0.0:
        return None
    alpha = _module_lwe_alpha(q, sigma)
    if alpha is None or alpha <= 0.0:
        return None
    summary = _module_lwe_cost_profiles(alpha, extras)
    if summary:
        summary["sigma_e"] = sigma
        summary["alpha"] = alpha
        summary["q"] = q
    return summary


def _falcon_secret_sigma(n: int) -> float:
    # Falcon secrets follow a discrete Gaussian with stddev ≈ 1.17 across parameter sets.
    return 1.17


def _falcon_bkz_curves(extras: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        n = int(extras.get("n", 0) or 0)
        q = int(extras.get("q", 0) or 0)
    except Exception:
        return None
    if n <= 0 or q <= 0:
        return None

    dim = 2 * n
    log_det = float(n) * math.log(float(q))
    sigma = _falcon_secret_sigma(n)
    base_target = sigma * math.sqrt(2.0 * n)
    attacks: List[Dict[str, Any]] = []
    core_consts = {"classical": 0.292, "quantum": 0.262}
    ln2 = math.log(2.0)

    calibration_refs = {
        512: {"primal": 360, "dual": 400},
        1024: {"primal": 520, "dual": 560},
    }

    def _margin_bits(beta: float, log_target: float) -> float:
        ld = math.log(_bkz_root_hermite(beta))
        log_len = (dim - 1) * ld + (log_det / dim)
        return (log_target - log_len) / ln2

    for attack_name, factor in (("primal", 1.0), ("dual", 1.25)):
        target = base_target * factor
        log_target = math.log(target)
        beta_points: List[Dict[str, Any]] = []
        beta_success = None
        ref_beta = (calibration_refs.get(n) or {}).get(attack_name)
        ref_margin = None
        if ref_beta is not None:
            ref_margin = _margin_bits(ref_beta, log_target)
        max_beta = max(480, int((ref_beta or 0) + 40))
        for beta in range(100, max_beta + 1, 20):
            margin_bits = _margin_bits(beta, log_target)
            calibrated_margin = margin_bits
            if ref_margin is not None:
                calibrated_margin -= ref_margin
            success = calibrated_margin >= 0.0
            if success and beta_success is None:
                beta_success = beta
            beta_points.append(
                {
                    "beta": beta,
                    "classical_bits": core_consts["classical"] * beta,
                    "quantum_bits": core_consts["quantum"] * beta,
                    "success_margin_bits": margin_bits,
                    "calibrated_margin_bits": calibrated_margin,
                    "success": success,
                }
            )
        attacks.append(
            {
                "attack": attack_name,
                "target_norm": target,
                "calibration_reference": {
                    "beta": ref_beta,
                    "raw_margin_bits": ref_margin,
                }
                if ref_beta is not None
                else None,
                "beta_success": beta_success,
                "beta_curve": beta_points,
            }
        )

    return {
        "dimension": dim,
        "q": q,
        "sigma_secret": sigma,
        "determinant_log": log_det,
        "attacks": attacks,
        "core_svp_constants": core_consts,
        "notes": (
            "Heuristic BKZ curve for Falcon NTRU lattice; success_margin_bits>0 implies predicted BKZ length below target short vector."
        ),
    }


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


def _get_shor_model(name: Optional[str]) -> ShorModelSpec:
    if not name:
        return SHOR_MODEL_LIBRARY["ge2019"]
    key = name.lower()
    return SHOR_MODEL_LIBRARY.get(key, SHOR_MODEL_LIBRARY["ge2019"])


def _shor_logical_resources(n_bits: int, model_name: Optional[str]) -> Dict[str, float]:
    spec = _get_shor_model(model_name)
    n = float(n_bits)
    log2n = math.log2(max(2.0, n))
    logical_qubits = spec.qubit_linear * n + spec.qubit_log_coeff * n * log2n
    toffoli = (spec.toffoli_cubic + spec.toffoli_cubic_log * log2n) * (n ** 3)
    depth = (spec.depth_quadratic + spec.depth_quadratic_log * log2n) * (n ** 2)
    return {
        "model": spec.name,
        "modulus_bits": float(n_bits),
        "logical_qubits": logical_qubits,
        "toffoli": toffoli,
        "meas_depth": depth,
        "log2_n": log2n,
        "formulas": {
            "logical_qubits": "3n + 0.002 n log2 n" if spec.name == "ge2019" else "model-specific",
            "toffoli": "(0.3 + 0.0005 log2 n) n^3" if spec.name == "ge2019" else "model-specific",
            "meas_depth": "(500 + log2 n) n^2" if spec.name == "ge2019" else "model-specific",
        },
        "notes": spec.notes,
    }


def _get_factory_spec(name: Optional[str]) -> FactorySpec:
    if not name:
        return FACTORY_LIBRARY["litinski-116-to-12"]
    key = name.lower()
    return FACTORY_LIBRARY.get(key, FACTORY_LIBRARY["litinski-116-to-12"])


def _surface_logical_error(p_phys: float, d: int, p_th: float = 1e-2) -> float:
    base = max(1e-12, p_phys / p_th)
    if base >= 1.0:
        return 1.0
    exponent = (d + 1.0) / 2.0
    return 0.1 * (base ** exponent)


def _solve_surface_distance(
    *,
    p_phys: float,
    target_fail: float,
    logical_cycles: float,
    magic_states: float,
    p_th: float = 1e-2,
    max_distance: int = 121,
) -> Tuple[int, float]:
    target = max(1e-18, target_fail)
    total_ops = max(1.0, logical_cycles + magic_states)
    for d in range(3, max_distance + 1, 2):
        p_l = _surface_logical_error(p_phys, d, p_th)
        if p_l * total_ops <= target:
            return d, p_l
    return max_distance, _surface_logical_error(p_phys, max_distance, p_th)


def _factory_rate_per_cycle(spec: FactorySpec, d: int) -> float:
    cycles = spec.cycles_per_batch_per_distance * max(1.0, float(d))
    if cycles <= 0:
        return 0.0
    return spec.outputs_per_batch / cycles


def _shor_surface_profile(
    logical: Dict[str, float],
    *,
    scenario: Dict[str, Any],
) -> Dict[str, Any]:
    p_phys = float(scenario["phys_error_rate"])
    cycle_time_ns = float(scenario["cycle_time_ns"])
    target_fail = float(scenario["target_total_fail_prob"])
    p_th = float(scenario.get("p_thresh", 1e-2))
    factory_spec = _get_factory_spec(scenario.get("factory_spec"))
    factory_overbuild = max(0.01, float(scenario.get("factory_overbuild", 1.0)))
    alpha_data = float(scenario.get("alpha_data", 2.5))
    alpha_factory = float(scenario.get("alpha_factory", factory_spec.alpha))

    d, p_l = _solve_surface_distance(
        p_phys=p_phys,
        target_fail=target_fail,
        logical_cycles=float(logical["meas_depth"]),
        magic_states=float(logical["toffoli"]),
        p_th=p_th,
    )

    factory_rate_single = _factory_rate_per_cycle(factory_spec, d)
    required_rate = 0.0
    if logical["meas_depth"] > 0:
        required_rate = float(logical["toffoli"]) / float(logical["meas_depth"])
    target_rate = required_rate * factory_overbuild
    factory_count = 0
    if target_rate > 0 and factory_rate_single > 0:
        factory_count = max(1, int(math.ceil(target_rate / factory_rate_single)))
    elif factory_rate_single > 0 and required_rate > 0:
        factory_count = 1

    total_factory_rate = factory_rate_single * max(1, factory_count)
    factory_cycles = float("inf")
    if total_factory_rate > 0:
        factory_cycles = float(logical["toffoli"]) / total_factory_rate

    depth_cycles = float(logical["meas_depth"])
    runtime_cycles = max(depth_cycles, factory_cycles)

    cycle_time_s = cycle_time_ns * 1e-9
    runtime_seconds_depth = depth_cycles * cycle_time_s
    runtime_seconds_factory = factory_cycles * cycle_time_s
    runtime_seconds = runtime_cycles * cycle_time_s

    data_phys = alpha_data * float(logical["logical_qubits"]) * (d ** 2)
    factory_phys = alpha_factory * factory_spec.logical_qubits * (d ** 2) * max(0, factory_count)
    total_phys = data_phys + factory_phys

    failure_est = {
        "p_logical": p_l,
        "ops_bound": float(logical["meas_depth"]) + float(logical["toffoli"]),
        "budget": target_fail,
        "expected_failures": p_l * (float(logical["meas_depth"]) + float(logical["toffoli"])),
    }

    return {
        "label": scenario.get("label", "scenario"),
        "phys_error_rate": p_phys,
        "cycle_time_ns": cycle_time_ns,
        "target_total_fail_prob": target_fail,
        "p_thresh": p_th,
        "code_distance": d,
        "factory_spec": factory_spec.name,
        "factory_description": factory_spec.description,
        "factory_count": max(0, factory_count),
        "factory_rate_per_cycle": total_factory_rate,
        "factory_rate_needed": required_rate,
        "factory_cycles": factory_cycles,
        "runtime_seconds_depth": runtime_seconds_depth,
        "runtime_seconds_factory": runtime_seconds_factory,
        "runtime_seconds": runtime_seconds,
        "phys_qubits_total": total_phys,
        "phys_qubits_data": data_phys,
        "phys_qubits_factories": factory_phys,
        "failure_estimate": failure_est,
        "notes": scenario.get("notes", ""),
    }


def _default_shor_scenarios() -> List[Dict[str, Any]]:
    return [
        {
            "label": "ge-baseline",
            "phys_error_rate": 1e-3,
            "cycle_time_ns": 1000.0,
            "target_total_fail_prob": 1e-2,
            "factory_spec": "litinski-116-to-12",
            "factory_overbuild": 0.05,
            "notes": "Matches Gidney–Ekerå (2019) headline assumptions (1 µs cycle, p=1e-3).",
        },
        {
            "label": "optimistic",
            "phys_error_rate": 5e-4,
            "cycle_time_ns": 200.0,
            "target_total_fail_prob": 1e-3,
            "factory_spec": "litinski-116-to-12",
            "factory_overbuild": 1.0,
            "notes": "Improved error rates / faster cycles with proportional factory build-out.",
        },
        {
            "label": "conservative",
            "phys_error_rate": 2e-3,
            "cycle_time_ns": 5000.0,
            "target_total_fail_prob": 1e-1,
            "factory_spec": "factory-lite-15-to-1",
            "factory_overbuild": 1.5,
            "notes": "Slower ion-trap-style cadence with additional factories to compensate throughput.",
        },
    ]


def _estimate_rsa_from_meta(kind: str, meta: Dict[str, Any], opts: Optional[EstimatorOptions]) -> SecMetrics:
    """Security estimate for RSA variants (PSS, OAEP).

    Classical security:
    - RSA’s best known classical attack is the General Number Field Sieve (NFS),
      which has sub-exponential complexity L_N[1/3] = exp((c+o(1)) (ln N)^(1/3) (ln ln N)^(2/3)).
      Rather than fit an asymptotic model, we follow NIST SP 800-57 Part 1’s
      conservative strength mapping (RSA modulus bits → symmetric bits):
        2048→112, 3072→128, 7680→192, 15360→256. Non-standard sizes round down.

    Quantum security:
    - Shor’s algorithm factors integers in polynomial time. Accordingly, we set
      quantum_bits = 0.0 for RSA and attach resource estimates instead
      (logical qubits Q, Toffoli/T count, measured depth) following common
      closed-form scalings (Gidney–Ekerå style), with optional surface-code overhead.
    """
    # Infer modulus bits from signature/ciphertext length if available; fallback to 2048
    n_bits: int
    if kind == "SIG":
        n_bits = int(meta.get("signature_len", 256)) * 8
    else:
        n_bits = int(meta.get("ciphertext_len", 256)) * 8

    # Classical security per SP 800-56B style mapping
    def _rsa_classical_strength(n: int) -> int:
        # NIST SP 800-57 Part 1 mapping (rounded down for non-standard sizes):
        # 2048→112, 3072→128, 7680→192, 15360→256
        if n < 2048:
            return 80
        if n < 3072:
            return 112
        if n < 7680:
            return 128
        if n < 15360:
            return 192
        return 256

    model_name = opts.rsa_model if opts and opts.rsa_model else "ge2019"
    logical_main = _shor_logical_resources(n_bits, model_name)
    toffoli = float(logical_main["toffoli"])
    t_counts = {
        "catalyzed": toffoli * 4.0,
        "textbook": toffoli * 7.0,
    }

    metrics = SecMetrics(
        classical_bits=float(_rsa_classical_strength(n_bits)),
        quantum_bits=0.0,  # Shor polynomial-time break → effectively 0-bit quantum security
        shor_breakable=True,
        notes=(
            "RSA classical: NIST SP 800-57 strength mapping; quantum: Shor polynomial-time factoring. "
            "Logical costs follow Gidney–Ekerå (2019); Toffoli counts are primary with T-count ranges."
        ),
        extras={
            "modulus_bits": float(n_bits),
            "logical": logical_main,
            "logical_qubits": float(logical_main["logical_qubits"]),
            "toffoli": toffoli,
            "t_counts": t_counts,
            "t_count": t_counts["textbook"],  # backwards-compatible key
            "t_count_textbook": t_counts["textbook"],
            "t_count_catalyzed": t_counts["catalyzed"],
            "meas_depth": float(logical_main["meas_depth"]),
            "rsa_model": logical_main["model"],
            "log2_modulus_bits": float(logical_main["log2_n"]),
            "classical_strength_source": "NIST SP 800-57 Part 1 Rev.5",
            "shor_model_notes": logical_main.get("notes"),
        },
    )

    scenarios = _default_shor_scenarios()
    modulus_set = sorted({2048, 3072, 4096, n_bits})
    logical_entries = {bits: _shor_logical_resources(bits, model_name) for bits in modulus_set}

    scenario_entries: List[Dict[str, Any]] = []
    for bits in modulus_set:
        logical = logical_entries[bits]
        profiles = []
        for scenario in scenarios:
            profile = _shor_surface_profile(logical, scenario=scenario)
            profiles.append(profile)
        scenario_entries.append({
            "modulus_bits": float(bits),
            "logical": logical,
            "scenarios": profiles,
        })

    metrics.extras["shor_profiles"] = {
        "model": logical_main["model"],
        "scenarios": scenario_entries,
        "t_count_assumptions": {
            "primary_unit": "Toffoli",
            "t_mappings": {"catalyzed": 4.0, "textbook": 7.0},
        },
    }
    metrics.extras["t_count_assumptions"] = metrics.extras["shor_profiles"]["t_count_assumptions"]

    opts = _apply_quantum_arch_presets(opts)
    if opts and opts.rsa_surface:
        scenario = {
            "label": opts.quantum_arch or "custom",
            "phys_error_rate": float(opts.phys_error_rate),
            "cycle_time_ns": float(opts.cycle_time_s) * 1e9,
            "target_total_fail_prob": float(opts.target_total_fail_prob),
            "factory_spec": "litinski-116-to-12",
            "factory_overbuild": 1.0,
            "alpha_data": 2.5,
            "notes": "User-specified surface-code override",
        }
        metrics.extras["surface"] = _shor_surface_profile(logical_main, scenario=scenario)

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
    """Estimator for HQC (code-based KEM) with documented ISD theory.

    Theory (high level):
    - HQC security relies on the hardness of decoding random linear codes (syndrome
      decoding). Best known classical attacks are information-set decoding (ISD)
      and descendants (Prange, Stern, Dumer, BJMM, May–Ozerov). These algorithms
      have sub-exponential cost with exponents depending on (n, k, w).
    - Practical submissions (HQC-128/192/256) choose parameters so that the minimum
      of these attacks exceeds the target security (2^128/2^192/2^256 operations).

    What we compute here:
    - Baseline: report NIST category floors in classical_bits/quantum_bits to keep
      outputs comparable and resilient without external tools.
    - Enrichment: when (n, k, w) parameters are available (from pqcbench.params),
      attach both a Stern-style entropy approximation and a coarse BJMM-style
      meet-in-the-middle heuristic (log2 time and memory). Grover-style reductions
      and “conservative” partial quantum speedups are included, along with a
      small w-sensitivity sweep (Δw ∈ {−2,…,+2}). These provide order-of-magnitude
      intuition without implementing the full BJMM/May–Ozerov pipeline.
    """
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
                logNw = _log2_binom(n, w)
                logKwh = _log2_binom(k, max(0, w // 2))
                stern_time = max(0.0, logNw - logKwh)
                stern_mem = max(0.0, 0.5 * stern_time)

                def _bjmm_time(n: int, k: int, w: int) -> float:
                    # Simple heuristic inspired by BJMM/MMT: split weight into 4 partitions
                    half = max(1, w // 2)
                    quarter = max(1, w // 4)
                    log_kh = _log2_binom(k, half)
                    log_kq = _log2_binom(k, quarter)
                    log_nh = _log2_binom(n, half)
                    return max(0.0, logNw - 2.0 * log_kh + log_nh - log_kq)

                bjmm_time = _bjmm_time(n, k, w)
                bjmm_mem = max(0.0, 0.3 * bjmm_time)

                grover_factor = 0.5
                stern_quantum = stern_time * grover_factor
                bjmm_quantum = bjmm_time * grover_factor
                stern_conservative = stern_time * 0.9
                bjmm_conservative = bjmm_time * 0.9

                def _w_sensitivity(delta: int) -> Dict[str, float]:
                    w_adj = max(1, min(n, w + delta))
                    logNw_adj = _log2_binom(n, w_adj)
                    logKhalf = _log2_binom(k, max(0, w_adj // 2))
                    stern = max(0.0, logNw_adj - logKhalf)
                    bjmm = _bjmm_time(n, k, w_adj)
                    return {"stern": stern, "bjmm": bjmm, "w": w_adj}

                sensitivity = [_w_sensitivity(delta) for delta in (-2, -1, 0, 1, 2)]

                extras.update({
                    "params": ph.to_dict(),
                    "notes": {
                        "scope": "Coarse ISD heuristics; quasicyclic speedups ignored.",
                        "families": "Stern entropy vs. BJMM-style meet-in-the-middle.",
                        "quantum": "Grover-style √ speedup applied to dominant loops.",
                    },
                    "isd": {
                        "stern_entropy": {
                            "time_bits_classical": stern_time,
                            "memory_bits_classical": stern_mem,
                            "time_bits_quantum_grover": stern_quantum,
                            "time_bits_quantum_conservative": stern_conservative,
                        },
                        "bjmm": {
                            "time_bits_classical": bjmm_time,
                            "memory_bits_classical": bjmm_mem,
                            "time_bits_quantum_grover": bjmm_quantum,
                            "time_bits_quantum_conservative": bjmm_conservative,
                        },
                        "grover_factor": grover_factor,
                        "w_sensitivity": sensitivity,
                    },
                })
    except Exception:
        pass

    return SecMetrics(
        classical_bits=float(floor),
        quantum_bits=float(floor),
        shor_breakable=False,
        notes=(
            "Code-based (HQC): NIST category floor; Stern/BJMM-style ISD heuristics attached when parameters available. "
            "No known polynomial-time quantum attack; Grover-limited speedups applied to dominant loops."
        ),
        extras=extras,
    )


def _sphincs_parse_layers(name: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    import re

    hl_match = re.search(r"_(\d+)/(\d+)_", name)
    if hl_match:
        out["layers"] = int(hl_match.group(2))
        out["hypertree_height"] = int(hl_match.group(1))
    else:
        ht_match = re.search(r"_(\d+)_", name)
        if ht_match:
            out["hypertree_height"] = int(ht_match.group(1))

    fors_match = re.search(r"f(\d+)", name, re.IGNORECASE)
    if fors_match:
        out["fors_trees"] = int(fors_match.group(1))

    w_match = re.search(r"_w(\d+)", name, re.IGNORECASE)
    if w_match:
        out["winternitz_w"] = int(w_match.group(1))

    return out


def _estimate_sphincs_from_name(name: str) -> SecMetrics:
    """Enriched estimator for SPHINCS+ (stateless hash-based signatures).

    Theory (high level):
    - Security reduces to the underlying hash function’s collision/preimage resistance.
      The overall security is governed by the minimum workfactor among attacks on
      FORS/WOTS+/Merkle components. For standard parameter sets, the designers
      target ≈128/192/256 classical bits by appropriate choices of hash output n,
      tree heights, and counts.
    - Quantum: No Shor-style break exists for hashes; Grover-like search reduces
      preimage/collision exponents by ≈√ (so ≈half the “bits”).

    Approach in pqcbench:
    - Baseline: classical_bits = NIST category floor (128/192/256); quantum_bits = floor/2.
    - Enrichment: parse mechanism string to capture variant (128/192/256; s vs f; SHA2 vs SHAKE),
      and attach curated mid/range classical estimates from SPHINCS+ documentation. Provide
      indicative hash-based costs (preimage n, collision n/2) for context.
    """
    floor = _nist_floor_from_name(name) or 128
    # Determine n (hash output bits), family, and variant from the mechanism name
    mech_lower = str(name).lower()
    if "256" in mech_lower:
        n_bits = 256
    elif "192" in mech_lower:
        n_bits = 192
    else:
        n_bits = 128
    family = "SHA2" if "sha2" in mech_lower else ("SHAKE" if "shake" in mech_lower else None)
    variant = "small" if "-128s" in mech_lower or "-192s" in mech_lower or "-256s" in mech_lower else (
        "fast" if "-128f" in mech_lower or "-192f" in mech_lower or "-256f" in mech_lower else None
    )

    # Curated classical bits (mid) by variant; based on SPHINCS+ documentation tables
    curated_mid: float
    if n_bits == 128:
        curated_mid = 133.0 if variant == "small" else 128.0
    elif n_bits == 192:
        curated_mid = 196.0 if variant == "small" else 194.0
    else:  # 256
        curated_mid = 255.0 if variant == "small" else 254.0
    curated_lo = curated_mid - 2.0
    curated_hi = curated_mid + 2.0

    structure = {k: v for k, v in _sphincs_parse_layers(name).items() if v is not None}
    hint_extras: Dict[str, Any] = {}
    try:
        from pqcbench.params import find as find_params  # type: ignore
        ph = find_params(name)
        if ph and ph.extras:
            hint_extras = dict(ph.extras)
    except Exception:
        hint_extras = {}

    if hint_extras:
        if "full_height" in hint_extras:
            structure.setdefault("hypertree_height", hint_extras.get("full_height"))
        if "layers" in hint_extras:
            structure.setdefault("layers", hint_extras.get("layers"))
        if "wots_w" in hint_extras:
            structure.setdefault("winternitz_w", hint_extras.get("wots_w"))
        if "fors_trees" in hint_extras:
            structure.setdefault("fors_trees", hint_extras.get("fors_trees"))
        if "fors_height" in hint_extras:
            structure.setdefault("fors_height", hint_extras.get("fors_height"))

    if hint_extras:
        for key in list(structure.keys()):
            if structure[key] is None:
                structure.pop(key)
        hint_struct = {
            "hypertree_height": hint_extras.get("full_height"),
            "layers": hint_extras.get("layers"),
            "winternitz_w": hint_extras.get("wots_w"),
            "fors_trees": hint_extras.get("fors_trees"),
            "fors_height": hint_extras.get("fors_height"),
        }
        for k, v in hint_struct.items():
            if v is not None and k not in structure:
                structure[k] = v

    structure = {k: v for k, v in structure.items() if v is not None}

    extras = {
        "category_floor": floor,
        "nist_category": {128: 1, 192: 3, 256: 5}.get(int(floor), None),
        "sphincs": {
            "mechanism_hint": name,
            "family": family,
            "variant": variant,
            "hash_output_bits": n_bits,
            "hash_costs": {
                "preimage_bits": n_bits,
                "collision_bits": n_bits / 2.0,
            },
            "curated_estimates": {
                "classical_bits_mid": curated_mid,
                "classical_bits_range": [curated_lo, curated_hi],
                "quantum_bits_mid": round(curated_mid / 2.0, 1),
                "quantum_bits_range": [round(curated_lo / 2.0, 1), round(curated_hi / 2.0, 1)],
            },
            "structure": structure or None,
            "sanity": {
                "classical_floor_bits": float(floor),
                "quantum_floor_bits": float(floor) / 2.0,
                "hash_output_bits": n_bits,
                "fors_height": hint_extras.get("fors_height"),
                "fors_trees": hint_extras.get("fors_trees"),
            },
            "hint_params": hint_extras or None,
        },
    }

    return SecMetrics(
        classical_bits=float(floor),
        quantum_bits=float(floor) / 2.0,
        shor_breakable=False,
        notes=(
            "SPHINCS+: hash-based; classical bits follow category floor, quantum ≈ half via Grover. "
            "Variant/family parsed; curated estimates attached in extras.sphincs."
        ),
        extras=extras,
    )


def _estimate_xmss_from_name(name: str) -> SecMetrics:
    """Estimator for XMSS/XMSSMT (stateful hash-based signatures).

    Theory (high level):
    - Security reduces to hash collision/preimage resistance across WOTS+/Merkle
      components. Forgery cost is governed by the minimum among collision (~2^{n/2})
      and preimage (~2^n) complexities for n-bit hashes; collision typically wins.
    - Quantum: No Shor-style break for hashes; collision can be found in ~2^{n/3}
      (BHT-type) and preimages in ~2^{n/2} (Grover).

    Approach in pqcbench:
    - Parse hash output bits n from the mechanism string (e.g., "..._256").
    - Classical bits = min(category_floor, n/2). Quantum bits ≈ n/3, for context.
    - Attach parsed structure (tree height, layers) and indicative hash costs to extras.
    - Note: XMSS is stateful; key reuse voids security. This estimator assumes correct
      state management and standard parameters.
    """
    floor = _nist_floor_from_name(name) or 128
    mech = str(name)
    mech_lower = mech.lower()
    # Extract hash output bits n from suffix ..._256 / ..._192 / ..._512
    n_bits = 256 if "_256" in mech_lower else (192 if "_192" in mech_lower else (512 if "_512" in mech_lower else 256))
    # Try to parse XMSSMT height/layers pattern like ..._20/2_...
    H = None
    layers = None
    try:
        import re
        m = re.search(r"_(\d+)/(\d+)_", mech)
        if m:
            H = int(m.group(1))
            layers = int(m.group(2))
        else:
            # XMSS (single tree) like XMSS-SHA2_20_256 → pick the middle number as height
            m2 = re.search(r"_(\d+)_", mech)
            if m2:
                H = int(m2.group(1))
                layers = 1
    except Exception:
        pass

    classical_hash_bound = n_bits / 2.0  # collision bound
    quantum_hash_bound = n_bits / 3.0    # BHT-type collision bound (indicative)

    classical_bits = float(min(floor, classical_hash_bound))
    quantum_bits = float(quantum_hash_bound)

    extras = {
        "category_floor": floor,
        "nist_category": {128: 1, 192: 3, 256: 5}.get(int(floor), None),
        "xmss": {
            "mechanism_hint": mech,
            "hash_output_bits": n_bits,
            "structure": {"tree_height": H, "layers": layers},
            "hash_costs": {
                "collision_bits": classical_hash_bound,
                "preimage_bits": float(n_bits),
                "quantum_collision_bits": quantum_hash_bound,
                "quantum_preimage_bits": n_bits / 2.0,
            },
            "assumptions": {
                "notes": (
                    "Stateful scheme; assumes no key reuse. Security limited by hash collision/preimage."
                ),
            },
        },
    }

    return SecMetrics(
        classical_bits=classical_bits,
        quantum_bits=quantum_bits,
        shor_breakable=False,
        notes=(
            "XMSS/XMSSMT: hash-based; classical limited by collision ≈ n/2 bits, quantum ≈ n/3 bits (indicative). "
            "Parsed structure and hash costs attached in extras.xmss."
        ),
        extras=extras,
    )


def _get_mechanism_for_algo(algo_name: str) -> Optional[str]:
    # Best-effort: instantiate the registered adapter and read a 'mech' or similar attribute
    try:
        from pqcbench import registry  # local import to avoid cycles at module import
        cls = registry.get(algo_name)
        obj = cls()
        # Support multiple adapter styles: our RSA uses 'mech'; liboqs adapters use 'alg';
        # stateful/adapters may stash under '_mech'.
        mech = getattr(obj, "mech", None) or getattr(obj, "alg", None) or getattr(obj, "_mech", None)
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
    elif name == "kyber":  # ML-KEM (Kyber)
        metrics = _estimate_kyber_from_name(param_hint, options)
    elif name == "dilithium":  # ML-DSA (Dilithium)
        metrics = _estimate_dilithium_from_name(param_hint, options)
    elif name == "falcon":
        metrics = _estimate_falcon_from_name(param_hint, options)
    elif name == "hqc":
            metrics = _estimate_hqc_from_name(param_hint, options)
    elif name in ("sphincsplus", "sphincs+"):
        metrics = _estimate_sphincs_from_name(param_hint)
    elif name == "xmssmt":
        metrics = _estimate_xmss_from_name(param_hint)
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

    # Attach a brute-force baseline (educational; toy parameters only)
    try:
        from pqcbench.bruteforce import bruteforce_summary  # type: ignore
        bf = bruteforce_summary(
            algo=name,
            kind=kind,
            mechanism=mech,
            classical_bits=metrics.classical_bits,
            extras=metrics.extras,
        )
        metrics.extras["bruteforce"] = bf
    except Exception:
        # Never fail the estimator on auxiliary features
        pass

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
    """Estimator for MAYO (multivariate MQ signatures; UOV-style with "whipping").

    Theory (high level):
    - Security reduces to solving multivariate quadratic (MQ) systems over GF(q).
      Best-known attacks include Gröbner basis (F4/F5), relinearization/XL family,
      and structure-specific strategies (e.g., MinRank for some schemes). Complexity
      is governed by degree of regularity and system shape (variables n, equations m,
      oil/vinegar partition), with hardness maximized around m≈n for random systems.
    - Designers target NIST levels by parameter choice. In absence of an integrated
      MQ estimator, we report conservative category floors and attach sanity checks
      to highlight obviously weak inputs (e.g., underdefined thresholds).

    What we do here:
    - Baseline: classical_bits = NIST floor (e.g., MAYO-1 → 128). Quantum_bits = floor
      (no Shor-style break; limited generic speedups assumed inconsequential vs. algebraic attacks).
    - Enrichment: if parameter hints supply (n, m, q, oil, vinegar, k_submaps), compute
      indicative red flags:
        * Relinearization thresholds (Kipnis–Shamir style): n ≥ m(m+1) or n ≥ m(m+3)/2
          → potential polynomial-time; flag as insecure if triggered.
        * Naive oil-guess bound for classical UOV: cost ≈ q^o → bits = o·log2(q). For
          MAYO, "whipping" invalidates direct oil guessing; we report it for awareness
          but do not override floors unless egregiously low.
    """
    # Read category floor and any provided extras
    try:
        from pqcbench.params import find as find_params  # type: ignore
        ph = find_params(name)
    except Exception:
        ph = None

    floor = (ph.category_floor if ph else (_nist_floor_from_name(name) or 128))
    nist_category = {128: 1, 160: 2, 192: 3, 256: 5}.get(int(floor), None)

    extras: Dict[str, Any] = {
        "category_floor": floor,
        "nist_category": nist_category,
    }

    # Attempt to surface MAYO structural parameters if provided via ParamHint
    mayo_params: Dict[str, Any] | None = None
    try:
        ex = (ph.extras or {}) if ph else {}
        if ex:
            mayo_params = {
                "n_vars": ex.get("n"),
                "m_eqs": ex.get("m"),
                "field_q": ex.get("q"),
                "oil": ex.get("oil"),
                "vinegar": ex.get("vinegar"),
                "k_submaps": ex.get("k"),
            }
            n = int(ex.get("n", 0) or 0)
            m = int(ex.get("m", 0) or 0)
            q = int(ex.get("q", 0) or 0)
            o = int(ex.get("oil", 0) or 0)
            v = int(ex.get("vinegar", 0) or 0)
            log2_q = math.log2(q) if q > 1 else None

            underdef_ks = (n >= m * (m + 1)) if (n and m) else False
            ks_margin = (m * (m + 1) - n) if (n and m) else None
            underdef_miura = (n >= (m * (m + 3)) // 2) if (n and m) else False
            miura_margin = ((m * (m + 3)) // 2 - n) if (n and m) else None

            oil_guess_bits = (o * log2_q) if (o and log2_q is not None) else None

            rank_bits = None
            rank_risk = None
            if o and v and log2_q is not None:
                rank_bits = max(0.0, (v - o) * o * log2_q / max(1.0, v))
                rank_risk = "high" if rank_bits < 60 else ("medium" if rank_bits < 90 else "low")

            minrank_bits = None
            if o and log2_q is not None:
                minrank_bits = ((o + 1) / 2.0) * log2_q

            f4_degree = None
            f4_risk = None
            if n and m:
                f4_degree = max(2, math.ceil((n + o) / max(1, o + 1)))
                if f4_degree <= 6:
                    f4_risk = "high"
                elif f4_degree <= 8:
                    f4_risk = "medium"
                else:
                    f4_risk = "low"

            extras["mayo"] = {
                "params": mayo_params,
                "checks": {
                    "relinearization": {
                        "underdefined_ks": underdef_ks,
                        "ks_margin": ks_margin,
                        "underdefined_miura": underdef_miura,
                        "miura_margin": miura_margin,
                    },
                    "oil_guess_bits": oil_guess_bits,
                    "rank_attack": {
                        "bits": rank_bits,
                        "risk": rank_risk,
                    },
                    "minrank": {
                        "bits": minrank_bits,
                        "rank": (o + 1) if o else None,
                    },
                    "f4": {
                        "degree": f4_degree,
                        "risk": f4_risk,
                    },
                    "notes": (
                        "Whipping construction aims to resist naive oil guessing and rank attacks;"
                        " these heuristics are qualitative flags only."
                    ),
                },
            }
        else:
            extras["mayo"] = {"params": None}
    except Exception:
        extras["mayo"] = {"params": None}

    # Curated per-level note (when we only know the level label)
    curated = {"classical_bits_mid": float(floor), "quantum_bits_mid": float(floor)}
    extras["mayo"]= {**extras.get("mayo", {}), "curated_estimates": curated}

    return SecMetrics(
        classical_bits=float(floor),
        quantum_bits=float(floor),  # No established quantum speedup beyond minor factors
        shor_breakable=False,
        notes=(
            "MAYO (MQ/UOV-style): category floor baseline; attaches parameter checks when available. "
            "See extras.mayo for params and heuristic red flags (relinearization thresholds, oil-guess bits)."
        ),
        extras=extras,
    )


def _estimate_kyber_from_name(name: str, opts: Optional[EstimatorOptions]) -> SecMetrics:
    """Enriched estimator for ML-KEM (Kyber).

    Approach (documented for clarity):
    - Baseline: use NIST category floors for classical_bits and quantum_bits so results
      remain comparable across families without external tools.
    - Enrichment: attach Kyber-specific parameters and curated classical/quantum ranges
      based on public analyses (NIST FAQs, Kyber team docs, independent APS runs).
      For ML-KEM-512 (Kyber512), literature commonly cites ~2^160 operations with
      uncertainty ~2^140–2^180. We include this range in extras; quantum-assisted
      sieving is modelled as a ~10–15% reduction in the exponent (Core-SVP 0.292 →
      Q-Core-SVP ~0.265), i.e., multiply classical bits by ~0.90.
    - Advanced path: when --sec-adv is enabled and a lattice estimator is installed,
      our generic lattice path (_estimate_lattice_like_from_name + _try_lattice_estimator_with_params)
      will override floors and populate beta/bits. This function preserves that behaviour
      while adding Kyber-specific context.
    """
    # Start from the generic lattice baseline (floors + optional APS override)
    base = _estimate_lattice_like_from_name(name, opts)

    # Collect Kyber parameters when available (n, k, q, eta1/eta2), and compute n_LWE = n*k
    kyber_info: Dict[str, Any] = {}
    try:
        from pqcbench.params import find as find_params  # type: ignore
        # Try direct hint first; if not found, ask the registered adapter for its mechanism
        ph = find_params(name)
        if not ph:
            mech2 = _get_mechanism_for_algo("kyber")
            if mech2:
                ph = find_params(mech2)
        if ph and (ph.extras or ph.notes):
            ex = ph.extras or {}
            n = int(ex.get("n", 256) or 256)
            k = int(ex.get("k", 0) or (2 if "512" in ph.mechanism else (3 if "768" in ph.mechanism else (4 if "1024" in ph.mechanism else 0))))
            q = int(ex.get("q", 3329) or 3329)
            eta1 = ex.get("eta1")
            eta2 = ex.get("eta2")
            kyber_info = {
                "mechanism": ph.mechanism,
                "n": n,
                "k": k,
                "q": q,
                "eta1": eta1,
                "eta2": eta2,
                "n_lwe": (n * k) if k else None,
            }
    except Exception:
        pass

    module_cost = None
    cost_extras = {k: v for k, v in kyber_info.items() if v is not None}
    if cost_extras:
        module_cost = _module_lwe_cost_summary(cost_extras)
    if module_cost:
        base.classical_bits = float(module_cost["headline"]["classical_bits"])
        base.quantum_bits = float(module_cost["headline"]["quantum_bits"])
        base.extras.setdefault("mlkem", {})["module_lwe_cost"] = module_cost
        base.notes = (
            "ML-KEM module-LWE cost model: BKZ (primal/dual/hybrid) with Core-SVP constants. "
            "Category floor retained in extras.category_floor."
        )

    # Curated classical/quantum ranges for Kyber-512 based on public analyses
    curated: Dict[str, Any] = {}
    mech_lower = str(name).lower()
    if any(tok in mech_lower for tok in ("512", "kyber512", "ml-kem-512")):
        classical_lo = 140.0
        classical_mid = 160.0
        classical_hi = 180.0
        # Quantum-assisted sieving approximate reduction factor (0.265/0.292 ≈ 0.907)
        q_factor = 0.907
        quantum_mid = round(classical_mid * q_factor, 1)
        quantum_lo = round(classical_lo * 0.85, 1)  # allow a wider band for literature variance
        quantum_hi = round(classical_hi * 0.95, 1)
        curated = {
            "classical_bits_mid": classical_mid,
            "classical_bits_range": [classical_lo, classical_hi],
            "quantum_bits_mid": quantum_mid,
            "quantum_bits_range": [quantum_lo, quantum_hi],
            "assumptions": {
                "source_notes": (
                    "NIST analysis (~2^160) with uncertainty ~2^140–2^180; Kyber team ~2^151; "
                    "independent APS/BKZ models often 2^140–2^150. Quantum sieving reduces exponent by ~10–15%."
                ),
                "q_sieving_exponent_ratio": 0.265/0.292,
            },
        }

    mlkem_block = dict(base.extras.get("mlkem", {}) or {})
    if module_cost:
        mlkem_block["module_lwe_cost"] = module_cost
    mlkem_block["kyber_params"] = kyber_info or None
    mlkem_block["curated_estimates"] = curated or None
    base.extras["mlkem"] = mlkem_block

    if not module_cost:
        # Adjust notes only if advanced estimator did not populate a model
        if "APS Lattice Estimator" not in base.notes:
            if opts and opts.lattice_use_estimator and base.extras.get("estimator_model") == "unavailable (fallback to NIST floor)":
                base.notes = (
                    "ML-KEM (Kyber): estimator unavailable; using NIST category floor. "
                    "Kyber-specific curated ranges attached in extras.mlkem.curated_estimates."
                )
            else:
                base.notes = (
                    "ML-KEM (Kyber): NIST floor baseline; Kyber-specific curated ranges attached in extras. "
                    "Enable --sec-adv to use APS lattice estimator when available."
                )

    return base


def _estimate_falcon_from_name(name: str, opts: Optional[EstimatorOptions]) -> SecMetrics:
    """Enriched estimator for Falcon (FN-DSA; NTRU lattices).

    Theory (high level):
    - Falcon security reduces to finding short vectors in a q-ary NTRU lattice of
      roughly dimension 2n (n=512/1024). Following core-SVP, one selects a BKZ
      blocksize b at which an SVP oracle succeeds; bit-costs are then mapped via
      sieve models: classical ≈ 0.292·b, quantum ≈ 0.262·b (Falcon docs).

    Approach in pqcbench:
    - Baseline: keep NIST category floors for classical_bits/quantum_bits (Cat‑1
      and Cat‑5). This ensures stable cross-family comparisons even without tools.
    - Enrichment: attach Falcon parameters (n, q) and curated classical/quantum
      ranges for Falcon‑512/1024 from public sources. With --sec-adv and an APS
      estimator available, the generic lattice path can override floors.
    """
    base = _estimate_lattice_like_from_name(name, opts)

    # Pull Falcon parameters where available (n, q)
    falcon_info: Dict[str, Any] = {}
    try:
        from pqcbench.params import find as find_params  # type: ignore
        ph = find_params(name)
        if not ph:
            mech2 = _get_mechanism_for_algo("falcon")
            if mech2:
                ph = find_params(mech2)
        if ph and (ph.extras or ph.notes):
            ex = ph.extras or {}
            n = int(ex.get("n", 0) or 0)
            q = int(ex.get("q", 0) or 0)
            falcon_info = {
                "mechanism": ph.mechanism,
                "n": n or None,
                "q": q or None,
                "dim_lattice": (2 * n) if n else None,
            }
    except Exception:
        pass

    bkz_model = None
    if falcon_info:
        model_inputs = {k: v for k, v in falcon_info.items() if k in {"n", "q"} and v is not None}
        bkz_model = _falcon_bkz_curves(model_inputs)

    # Curated estimates (document constants and ranges)
    mech_lower = str(name).lower()
    curated: Dict[str, Any] = {}
    c_class, c_quant = 0.292, 0.262

    if any(tok in mech_lower for tok in ("falcon-512", "512")):
        classical_mid = 128.0
        classical_lo, classical_hi = 110.0, 140.0
        quantum_mid = round(classical_mid * (c_quant / c_class), 1)
        quantum_lo = round(classical_lo * (c_quant / c_class), 1)
        quantum_hi = round(classical_hi * (c_quant / c_class), 1)
        curated = {
            "classical_bits_mid": classical_mid,
            "classical_bits_range": [classical_lo, classical_hi],
            "quantum_bits_mid": quantum_mid,
            "quantum_bits_range": [quantum_lo, quantum_hi],
            "assumptions": {
                "core_svp_constants": {"classical": c_class, "quantum": c_quant},
                "notes": "Falcon-512: conservative mid with range; quantum via 0.262/0.292 scaling.",
            },
        }
    elif any(tok in mech_lower for tok in ("falcon-1024", "1024")):
        classical_mid = 212.0
        classical_lo, classical_hi = 200.0, 225.0
        quantum_mid = round(classical_mid * (c_quant / c_class), 1)
        quantum_lo = round(classical_lo * (c_quant / c_class), 1)
        quantum_hi = round(classical_hi * (c_quant / c_class), 1)
        curated = {
            "classical_bits_mid": classical_mid,
            "classical_bits_range": [classical_lo, classical_hi],
            "quantum_bits_mid": quantum_mid,
            "quantum_bits_range": [quantum_lo, quantum_hi],
            "assumptions": {
                "core_svp_constants": {"classical": c_class, "quantum": c_quant},
                "notes": "Falcon-1024: ~200–225 classical; quantum scaled by 0.262/0.292.",
            },
        }

    base.extras.update({
        "falcon": {
            "params": falcon_info or None,
            "curated_estimates": curated or None,
            "core_svp_constants": {"classical": c_class, "quantum": c_quant},
            "bkz_model": bkz_model,
        }
    })

    if "APS Lattice Estimator" not in base.notes:
        if opts and opts.lattice_use_estimator and base.extras.get("estimator_model") == "unavailable (fallback to NIST floor)":
            base.notes = (
                "Falcon: estimator unavailable; using NIST category floor. "
                "Falcon-specific curated ranges attached in extras.falcon.curated_estimates."
            )
        else:
            base.notes = (
                "Falcon: NIST floor baseline; Falcon-specific curated ranges attached in extras. "
                "Enable --sec-adv to use APS lattice estimator when available."
            )

    return base


def _estimate_dilithium_from_name(name: str, opts: Optional[EstimatorOptions]) -> SecMetrics:
    """Enriched estimator for ML-DSA (CRYSTALS-Dilithium).

    Theory (high level):
    - Dilithium security (unforgeability) reduces to problems in module lattices:
      Module-LWE (for key recovery paths) and Module-SIS (for direct forgery). The
      analysis used in the specification follows the "core-SVP" methodology: find
      a BKZ blocksize b such that an SVP oracle succeeds, then map b to a time
      exponent via sieve cost models.
    - Common mappings: classical sieve exponent ≈ 0.292·b; quantum sieve exponent
      ≈ 0.262·b (slightly below Kyber's 0.265 figure used by some sources). We use
      these as documentation constants; precise values depend on memory model and
      circuit accounting.

    Approach in pqcbench:
    - Baseline: provide NIST category floors in classical_bits/quantum_bits for
      comparability without external tools.
    - Enrichment: attach Dilithium parameters and curated classical/quantum ranges
      for common parameter sets (ML-DSA-44/65/87), reflecting public estimates.
      When --sec-adv is available and an APS estimator is installed, the generic
      lattice path may override floors and include beta/bits.
    """
    base = _estimate_lattice_like_from_name(name, opts)

    # Pull (k, l, n, q) from params where available
    dsa_info: Dict[str, Any] = {}
    try:
        from pqcbench.params import find as find_params  # type: ignore
        # Try direct hint first; if not found, ask adapter for mechanism
        ph = find_params(name)
        if not ph:
            mech2 = _get_mechanism_for_algo("dilithium")
            if mech2:
                ph = find_params(mech2)
        if ph and (ph.extras or ph.notes):
            ex = ph.extras or {}
            n = int(ex.get("n", 256) or 256)
            k = int(ex.get("k", 0) or 0)
            l = int(ex.get("l", 0) or 0)
            q = int(ex.get("q", 8380417) or 8380417)
            eta = ex.get("eta")
            dsa_info = {
                "mechanism": ph.mechanism,
                "n": n,
                "k": k,
                "l": l,
                "q": q,
                "eta": eta,
                "rank": (n * k) if k else None,
            }
    except Exception:
        pass

    module_cost = None
    if dsa_info:
        cost_extras = {k: v for k, v in dsa_info.items() if k in {"n", "k", "q", "eta", "eta1", "eta2", "sigma_e"} and v is not None}
        module_cost = _module_lwe_cost_summary(cost_extras)
        if module_cost:
            base.classical_bits = float(module_cost["headline"]["classical_bits"])
            base.quantum_bits = float(module_cost["headline"]["quantum_bits"])
            base.notes = (
                "ML-DSA module-LWE cost model: BKZ (primal/dual/hybrid) with Core-SVP constants. "
                "Category floor retained in extras.category_floor."
            )

    # Curated ranges per common sets, derived from public write-ups and spec notes
    mech_lower = str(name).lower()
    curated: Dict[str, Any] = {}
    # Classical/quantum sieve constants (documented; not enforced)
    c_class, c_quant = 0.292, 0.262

    if any(tok in mech_lower for tok in ("-44", "dilithium2", "ml-dsa-44")):
        # Level close to Cat-1/2. Public figures often cite low‑120s classical.
        classical_mid = 123.0
        classical_lo, classical_hi = 118.0, 130.0
        quantum_mid = round(classical_mid * (c_quant / c_class), 1)
        quantum_lo = round(classical_lo * (c_quant / c_class), 1)
        quantum_hi = round(classical_hi * (c_quant / c_class), 1)
        curated = {
            "classical_bits_mid": classical_mid,
            "classical_bits_range": [classical_lo, classical_hi],
            "quantum_bits_mid": quantum_mid,
            "quantum_bits_range": [quantum_lo, quantum_hi],
            "assumptions": {
                "core_svp_constants": {"classical": c_class, "quantum": c_quant},
                "notes": (
                    "Dilithium2 (ML-DSA-44) widely reported ≈ low‑120s classical; quantum via 0.262/0.292 scaling."
                ),
            },
        }
    elif any(tok in mech_lower for tok in ("-65", "dilithium3", "ml-dsa-65")):
        # Cat-3 target; public reports around mid‑140s classical.
        classical_mid = 146.0
        classical_lo, classical_hi = 140.0, 155.0
        quantum_mid = round(classical_mid * (c_quant / c_class), 1)
        quantum_lo = round(classical_lo * (c_quant / c_class), 1)
        quantum_hi = round(classical_hi * (c_quant / c_class), 1)
        curated = {
            "classical_bits_mid": classical_mid,
            "classical_bits_range": [classical_lo, classical_hi],
            "quantum_bits_mid": quantum_mid,
            "quantum_bits_range": [quantum_lo, quantum_hi],
            "assumptions": {
                "core_svp_constants": {"classical": c_class, "quantum": c_quant},
                "notes": "Dilithium3 (ML-DSA-65) ≈ mid‑140s classical in public estimates.",
            },
        }
    elif any(tok in mech_lower for tok in ("-87", "dilithium5", "ml-dsa-87")):
        # Cat-5 target; public reports ~200+ classical.
        classical_mid = 208.0
        classical_lo, classical_hi = 200.0, 220.0
        quantum_mid = round(classical_mid * (c_quant / c_class), 1)
        quantum_lo = round(classical_lo * (c_quant / c_class), 1)
        quantum_hi = round(classical_hi * (c_quant / c_class), 1)
        curated = {
            "classical_bits_mid": classical_mid,
            "classical_bits_range": [classical_lo, classical_hi],
            "quantum_bits_mid": quantum_mid,
            "quantum_bits_range": [quantum_lo, quantum_hi],
            "assumptions": {
                "core_svp_constants": {"classical": c_class, "quantum": c_quant},
                "notes": "Dilithium5 (ML-DSA-87) ≈ ~200–220 classical in common reports.",
            },
        }

    mldsa_block = dict(base.extras.get("mldsa", {}) or {})
    if module_cost:
        mldsa_block["module_lwe_cost"] = module_cost
    mldsa_block["dilithium_params"] = dsa_info or None
    mldsa_block["curated_estimates"] = curated or None
    mldsa_block["core_svp_constants"] = {"classical": c_class, "quantum": c_quant}
    base.extras["mldsa"] = mldsa_block

    if not module_cost:
        # Note refinement depending on estimator availability
        if "APS Lattice Estimator" not in base.notes:
            if opts and opts.lattice_use_estimator and base.extras.get("estimator_model") == "unavailable (fallback to NIST floor)":
                base.notes = (
                    "ML-DSA (Dilithium): estimator unavailable; using NIST category floor. "
                    "Dilithium-specific curated ranges attached in extras.mldsa.curated_estimates."
                )
            else:
                base.notes = (
                    "ML-DSA (Dilithium): NIST floor baseline; Dilithium-specific curated ranges attached in extras. "
                    "Enable --sec-adv to use APS lattice estimator when available."
                )

    return base
