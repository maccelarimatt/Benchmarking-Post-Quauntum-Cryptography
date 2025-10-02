from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional, Tuple, List
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
    lattice_profile: str | None = None  # e.g., "floor", "classical", "quantum" (None=auto)
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


SHOR_DATA_ALPHA_SCALE: float = 1.0
SHOR_FACTORY_ALPHA_SCALE: float = 1.0
SHOR_FACTORY_RATE_MULTIPLIER: float = 1.0
SHOR_FACTORY_COUNT_BASELINE: Optional[int] = None
_GE_CALIBRATION_DONE: bool = False


def _ge_baseline_target() -> Dict[str, float]:
    return {"runtime_seconds": 8 * 3600.0, "phys_qubits_total": 20_000_000.0}


def _ensure_ge_calibrated() -> None:
    global _GE_CALIBRATION_DONE, SHOR_FACTORY_RATE_MULTIPLIER
    global SHOR_DATA_ALPHA_SCALE, SHOR_FACTORY_ALPHA_SCALE, SHOR_FACTORY_SUPPLY_SCALE
    global SHOR_FACTORY_COUNT_BASELINE
    if _GE_CALIBRATION_DONE:
        return

    logical = _shor_logical_resources(2048, "ge2019")
    SHOR_FACTORY_RATE_MULTIPLIER = 1.0
    SHOR_DATA_ALPHA_SCALE = 1.0
    SHOR_FACTORY_ALPHA_SCALE = 1.0
    SHOR_FACTORY_SUPPLY_SCALE = 1.0
    base_scenario = {
        "phys_error_rate": 1e-3,
        "cycle_time_ns": 1000.0,
        "target_total_fail_prob": 1e-2,
        "factory_spec": "litinski-116-to-12",
        "factory_utilization_target": 1.3,
        "factory_rate_unit": "T",
        "t_per_toffoli": 4.0,
        "logical_op_weight_tof": 1.5,
        "logical_op_weight_depth": 1.0,
        "target_factory_utilization": 1.3,
    }
    targets = _ge_baseline_target()
    cycle_time_s = base_scenario["cycle_time_ns"] * 1e-9
    target_cycles = targets["runtime_seconds"] / cycle_time_s
    t_per_tof = base_scenario["t_per_toffoli"]
    total_magic = float(logical["toffoli"]) * t_per_tof
    desired_total_rate = total_magic / target_cycles
    factory_spec = _get_factory_spec(base_scenario["factory_spec"])

    candidate_rates = [0.1, 0.15, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.2]
    candidate_counts = range(2, 65)
    best = None

    for rate_scale in candidate_rates:
        scenario_probe = dict(base_scenario)
        scenario_probe["rate_multiplier"] = rate_scale
        profile_probe = _shor_surface_profile(logical, scenario=scenario_probe)
        d = int(profile_probe.get("code_distance", 21))
        base_single = _factory_rate_per_cycle(factory_spec, d, 1.0)

        for count in candidate_counts:
            supply_scale = desired_total_rate / (base_single * count)
            if supply_scale <= 0.05 or supply_scale > 10.0:
                continue
            scenario_eval = dict(base_scenario)
            scenario_eval.update(
                {
                    "rate_multiplier": rate_scale,
                    "factory_supply_scale": supply_scale,
                    "factory_count_override": count,
                }
            )
            profile_eval = _shor_surface_profile(logical, scenario=scenario_eval)
            runtime = profile_eval["runtime_seconds"]
            qubits = profile_eval["phys_qubits_total"]
            runtime_diff = abs(runtime - targets["runtime_seconds"]) / targets["runtime_seconds"]
            qubit_diff = abs(qubits - targets["phys_qubits_total"]) / targets["phys_qubits_total"]
            score = runtime_diff + 0.25 * qubit_diff
            if best is None or score < best[0]:
                best = (score, rate_scale, supply_scale, profile_eval)

    if best is None:
        _GE_CALIBRATION_DONE = True
        return

    _, best_rate, best_supply, best_profile = best
    SHOR_FACTORY_RATE_MULTIPLIER = best_rate
    SHOR_FACTORY_SUPPLY_SCALE = best_supply
    SHOR_FACTORY_COUNT_BASELINE = int(best_profile.get("factory_count", 0)) or None

    phys_scale = targets["phys_qubits_total"] / max(1e-9, best_profile["phys_qubits_total"])
    SHOR_DATA_ALPHA_SCALE = phys_scale
    SHOR_FACTORY_ALPHA_SCALE = phys_scale
    _GE_CALIBRATION_DONE = True



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
        try:
            return _stddev_centered_binomial(int(eta))
        except Exception:
            try:
                return _stddev_uniform_eta(int(eta))
            except Exception:
                return None
    return None


def _module_lwe_secret_sigma(extras: Dict[str, Any]) -> Optional[float]:
    if "sigma_s" in extras:
        try:
            sigma = float(extras["sigma_s"])
            return sigma if sigma > 0.0 else None
        except Exception:
            return None
    eta1 = extras.get("eta1")
    if eta1 is not None:
        return _stddev_centered_binomial(int(eta1))
    if "eta" in extras:
        try:
            return _stddev_centered_binomial(int(extras["eta"]))
        except Exception:
            return _stddev_uniform_eta(int(extras["eta"]))
    if "secret_bound" in extras:
        bound = int(extras["secret_bound"])
        if bound > 0:
            return math.sqrt(bound * (bound + 1) / 3.0)
    return None


def _module_lwe_sigmas(extras: Dict[str, Any]) -> Tuple[Optional[float], Optional[float]]:
    sigma_e = _module_lwe_sigma(extras)
    sigma_s = _module_lwe_secret_sigma(extras)
    return sigma_e, sigma_s


def _module_lwe_parameters(extras: Dict[str, Any]) -> Optional[Dict[str, int]]:
    try:
        n_base = int(extras.get("n", 0) or 0)
        k = int(extras.get("k", 0) or 0)
        q = int(extras.get("q", 0) or 0)
        l = int(extras.get("l", 0) or 0)
    except Exception:
        return None
    if n_base <= 0 or k <= 0 or q <= 0:
        return None
    n_secret = n_base * k
    m_min = n_base
    m_max_candidates = [ (k + 1) * n_base ]
    if l > 0:
        m_max_candidates.append((k + l) * n_base)
    sample_max = max(m_max_candidates)
    return {
        "n_base": n_base,
        "k": k,
        "n_secret": n_secret,
        "q": q,
        "sample_min": m_min,
        "sample_max": sample_max,
    }


_KYBER_CORE_SVP_TABLE: Dict[str, Dict[str, float]] = {
    "ml-kem-512": {
        "dimension": 1003.0,
        "beta": 403.0,
        "samples": 256.0,
        "classical_bits": 118.0,
        "quantum_bits": 107.0,
        "sieving_dimension": 375.0,
        "log2_memory": 93.8,
    },
    "kyber512": {
        "dimension": 1003.0,
        "beta": 403.0,
        "samples": 256.0,
        "classical_bits": 118.0,
        "quantum_bits": 107.0,
        "sieving_dimension": 375.0,
        "log2_memory": 93.8,
    },
    "ml-kem-768": {
        "dimension": 1424.0,
        "beta": 625.0,
        "samples": 384.0,
        "classical_bits": 182.0,
        "quantum_bits": 165.0,
        "sieving_dimension": 586.0,
        "log2_memory": 138.5,
    },
    "kyber768": {
        "dimension": 1424.0,
        "beta": 625.0,
        "samples": 384.0,
        "classical_bits": 182.0,
        "quantum_bits": 165.0,
        "sieving_dimension": 586.0,
        "log2_memory": 138.5,
    },
    "ml-kem-1024": {
        "dimension": 1885.0,
        "beta": 877.0,
        "samples": 512.0,
        "classical_bits": 256.0,
        "quantum_bits": 232.0,
        "sieving_dimension": 829.0,
        "log2_memory": 189.7,
    },
    "kyber1024": {
        "dimension": 1885.0,
        "beta": 877.0,
        "samples": 512.0,
        "classical_bits": 256.0,
        "quantum_bits": 232.0,
        "sieving_dimension": 829.0,
        "log2_memory": 189.7,
    },
}


_DILITHIUM_CORE_SVP_TABLE: Dict[str, Dict[str, float]] = {
    "ml-dsa-44": {
        "dimension": 2049.0,
        "beta": 433.0,
        "samples": 1024.0,
        "classical_bits": 158.6,
        "quantum_bits": 158.6 * (0.265 / 0.292),
        "sieving_dimension": 394.0,
        "log2_memory": 97.8,
    },
    "dilithium2": {
        "dimension": 2049.0,
        "beta": 433.0,
        "samples": 1024.0,
        "classical_bits": 158.6,
        "quantum_bits": 158.6 * (0.265 / 0.292),
        "sieving_dimension": 394.0,
        "log2_memory": 97.8,
    },
    "ml-dsa-65": {
        "dimension": 2654.0,
        "beta": 638.0,
        "samples": 1117.0,
        "classical_bits": 216.7,
        "quantum_bits": 216.7 * (0.265 / 0.292),
        "sieving_dimension": 587.0,
        "log2_memory": 138.7,
    },
    "dilithium3": {
        "dimension": 2654.0,
        "beta": 638.0,
        "samples": 1117.0,
        "classical_bits": 216.7,
        "quantum_bits": 216.7 * (0.265 / 0.292),
        "sieving_dimension": 587.0,
        "log2_memory": 138.7,
    },
    "ml-dsa-87": {
        "dimension": 3540.0,
        "beta": 883.0,
        "samples": 1491.0,
        "classical_bits": 285.4,
        "quantum_bits": 285.4 * (0.265 / 0.292),
        "sieving_dimension": 818.0,
        "log2_memory": 187.4,
    },
    "dilithium5": {
        "dimension": 3540.0,
        "beta": 883.0,
        "samples": 1491.0,
        "classical_bits": 285.4,
        "quantum_bits": 285.4 * (0.265 / 0.292),
        "sieving_dimension": 818.0,
        "log2_memory": 187.4,
    },
}


def _core_svp_primal_summary(params: Dict[str, int], sigma_e: float, sigma_s: Optional[float]) -> Optional[Dict[str, float]]:
    n_base = params["n_base"]
    k = params["k"]
    n_secret = params["n_secret"]
    q = params["q"]
    sigma = sigma_e
    if sigma_s is not None:
        sigma = max(sigma_e, sigma_s)
    if sigma <= 0.0 or q <= 0:
        return None

    m_min = params.get("sample_min", n_base)
    m_max = params.get("sample_max", (k + 1) * n_base)
    best: Optional[Dict[str, float]] = None
    ln_q = math.log(float(q))
    max_beta = 960

    for m in range(m_min, m_max + 1):
        d = m + n_secret + 1
        for beta in range(40, max_beta + 1):
            delta = _bkz_root_hermite(beta)
            if delta <= 0.0:
                continue
            ln_delta = math.log(delta)
            lhs = math.log(sigma) + 0.5 * math.log(beta)
            rhs = ln_delta * (2.0 * beta - d - 1.0) + (float(m) / float(d)) * ln_q
            if lhs > rhs:
                continue
            classical_bits = 0.292 * beta
            quantum_bits = 0.265 * beta
            entry = {
                "attack": "primal-usvp",
                "beta": float(beta),
                "samples": float(m),
                "dimension": float(d),
                "classical_bits": classical_bits,
                "quantum_bits": quantum_bits,
                "delta": delta,
                "margin": rhs - lhs,
            }
            if best is None or classical_bits < best["classical_bits"]:
                best = entry
            break
    return best


def _core_svp_dual_summary(params: Dict[str, int], sigma_e: float, sigma_s: Optional[float]) -> Optional[Dict[str, float]]:
    n_base = params["n_base"]
    k = params["k"]
    n_secret = params["n_secret"]
    q = params["q"]
    if sigma_e <= 0.0 or q <= 0:
        return None

    sigma = sigma_e if sigma_s is None else max(sigma_e, sigma_s)
    m_min = params.get("sample_min", n_base)
    m_max = params.get("sample_max", (k + 1) * n_base)
    best: Optional[Dict[str, float]] = None
    ln_q = math.log(float(q))
    target_adv = 0.5
    max_beta = 960

    for m in range(m_min, m_max + 1):
        d = m + n_secret
        for beta in range(40, max_beta + 1):
            delta = _bkz_root_hermite(beta)
            if delta <= 0.0:
                continue
            ln_ell = (d - 1.0) * math.log(delta) + (float(n_secret) / float(d)) * ln_q
            ell = math.exp(ln_ell)
            tau = (ell * sigma) / float(q)
            if tau <= 0.0 or tau > 1e154:
                continue
            try:
                tau_sq = tau * tau
            except OverflowError:
                continue
            exponent = -2.0 * (math.pi ** 2) * tau_sq
            if exponent < -745.0:
                advantage = 0.0
            elif exponent > 709.0:
                advantage = float("inf")
            else:
                try:
                    advantage = 4.0 * math.exp(exponent)
                except OverflowError:
                    advantage = float("inf")
            if advantage <= 0.0:
                continue
            repeats = 1.0
            if advantage < target_adv:
                repeats = max(1.0, (target_adv / advantage) ** 2 / (2.0 ** (0.2075 * beta)))
            cost_repeat = math.log2(repeats)
            classical_bits = 0.292 * beta + cost_repeat
            quantum_bits = 0.265 * beta + cost_repeat
            entry = {
                "attack": "dual",
                "beta": float(beta),
                "samples": float(m),
                "dimension": float(d),
                "advantage": advantage,
                "repeat_log2": cost_repeat,
                "classical_bits": classical_bits,
                "quantum_bits": quantum_bits,
                "delta": delta,
                "tau": tau,
            }
            if best is None or classical_bits < best["classical_bits"]:
                best = entry
            break
    return best


def _module_lwe_cost_summary(extras: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    params = _module_lwe_parameters(extras)
    if not params:
        return None
    sigma_e, sigma_s = _module_lwe_sigmas(extras)
    if sigma_e is None or sigma_e <= 0.0:
        return None

    primal = _core_svp_primal_summary(params, sigma_e, sigma_s)
    dual = _core_svp_dual_summary(params, sigma_e, sigma_s)

    if not primal and not dual:
        return None

    headline = None
    if primal and dual:
        headline = primal if primal["classical_bits"] <= dual["classical_bits"] else dual
    else:
        headline = primal or dual

    return {
        "model": "core-svp",
        "source": "core-svp-analytic",
        "params": params,
        "sigma_error": sigma_e,
        "sigma_secret": sigma_s,
        "primal": primal,
        "dual": dual,
        "headline": headline,
    }


def _dilithium_core_svp_table_entry(name: str) -> Optional[Dict[str, Any]]:
    entry = _DILITHIUM_CORE_SVP_TABLE.get(name.lower())
    if entry is None:
        return None
    result = dict(entry)
    result["attack"] = "primal-usvp"
    return result


def _kyber_core_svp_table_entry(name: str) -> Optional[Dict[str, Any]]:
    entry = _KYBER_CORE_SVP_TABLE.get(name.lower())
    if entry is None:
        return None
    result = dict(entry)
    result["attack"] = "primal-usvp"
    return result


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


SHOR_FACTORY_SUPPLY_SCALE: float = 1.0


def _factory_rate_per_cycle(spec: FactorySpec, d: int, supply_scale: float) -> float:
    cycles = spec.cycles_per_batch_per_distance * max(1.0, float(d))
    if cycles <= 0:
        return 0.0
    return (spec.outputs_per_batch * supply_scale) / cycles


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
    alpha_data = float(scenario.get("alpha_data", 2.5)) * SHOR_DATA_ALPHA_SCALE
    alpha_factory = float(scenario.get("alpha_factory", factory_spec.alpha)) * SHOR_FACTORY_ALPHA_SCALE
    tof_weight = float(scenario.get("logical_op_weight_tof", 1.0))
    depth_weight = float(scenario.get("logical_op_weight_depth", 1.0))
    rate_unit = scenario.get("factory_rate_unit", "T")
    rate_unit_norm = rate_unit.lower()
    t_per_tof = float(scenario.get("t_per_toffoli", 4.0)) if rate_unit_norm == "t" else 1.0
    rate_multiplier = float(scenario.get("rate_multiplier", SHOR_FACTORY_RATE_MULTIPLIER))
    supply_scale = float(scenario.get("factory_supply_scale", 1.0)) * SHOR_FACTORY_SUPPLY_SCALE
    util_target = float(scenario.get("factory_utilization_target", 0.85))
    util_target = min(max(util_target, 0.05), 10.0)
    legacy_overbuild = float(scenario.get("factory_overbuild", 0.0))

    d, p_l = _solve_surface_distance(
        p_phys=p_phys,
        target_fail=target_fail,
        logical_cycles=depth_weight * float(logical["meas_depth"]),
        magic_states=tof_weight * float(logical["toffoli"]),
        p_th=p_th,
    )

    factory_rate_single = _factory_rate_per_cycle(factory_spec, d, supply_scale)
    toffoli_total = float(logical["toffoli"])
    depth_cycles = float(logical["meas_depth"])
    toffoli_per_cycle = toffoli_total / depth_cycles if depth_cycles > 0 else 0.0

    if rate_unit_norm == "t":
        peak_rate = toffoli_per_cycle * t_per_tof
        total_magic = toffoli_total * t_per_tof
    else:
        peak_rate = toffoli_per_cycle
        total_magic = toffoli_total

    scaled_peak = peak_rate * rate_multiplier
    overbuild_factor = 1.0 + max(0.0, legacy_overbuild)
    target_rate = (scaled_peak * overbuild_factor) / max(util_target, 1e-6)

    if factory_rate_single <= 0:
        factory_count = 0
        total_factory_rate = 0.0
        factory_cycles = float("inf")
        utilization_actual = float("inf")
    else:
        base_count = max(1, int(math.ceil(target_rate / factory_rate_single))) if target_rate > 0 else 1
        candidate_counts = {max(1, base_count)}
        if base_count > 1:
            candidate_counts.add(base_count - 1)
        candidate_counts.add(base_count + 1)
        candidate_counts.add(max(1, base_count + 2))

        chosen = None
        for count in sorted(candidate_counts):
            if scenario.get("factory_count_override") is not None and count != max(
                0, int(scenario.get("factory_count_override", 0))
            ):
                continue
            available = factory_rate_single * count
            if available <= 0:
                continue
            candidate_cycles = total_magic / available if available > 0 else float("inf")
            runtime_cycles_candidate = max(depth_cycles, candidate_cycles)
            util_actual = scaled_peak / available if available > 0 else float("inf")
            util_penalty = abs(util_actual - util_target)
            score = runtime_cycles_candidate * (1.0 + 0.15 * util_penalty)
            if chosen is None or score < chosen[0]:
                chosen = (score, count, available, candidate_cycles, util_actual)

        if chosen is None:
            count = max(1, base_count)
            available = factory_rate_single * count
            candidate_cycles = total_magic / available if available > 0 else float("inf")
            util_actual = scaled_peak / available if available > 0 else float("inf")
        else:
            _, count, available, candidate_cycles, util_actual = chosen

        if scenario.get("factory_count_override") is not None:
            count = max(0, int(scenario.get("factory_count_override", 0)))
            available = factory_rate_single * max(1, count)
            candidate_cycles = total_magic / available if available > 0 else float("inf")
            util_actual = scaled_peak / available if available > 0 else float("inf")

        factory_count = max(0, count)
        total_factory_rate = factory_rate_single * max(1, factory_count)
        factory_cycles = candidate_cycles
        utilization_actual = util_actual

    runtime_cycles = max(depth_cycles, factory_cycles)
    limiting = "depth" if depth_cycles >= factory_cycles else "factory"
    if math.isinf(factory_cycles):
        limiting = "depth"

    cycle_time_s = cycle_time_ns * 1e-9
    runtime_seconds_depth = depth_cycles * cycle_time_s
    runtime_seconds_factory = factory_cycles * cycle_time_s
    runtime_seconds = runtime_cycles * cycle_time_s

    data_phys = alpha_data * float(logical["logical_qubits"]) * (d ** 2)
    factory_phys = alpha_factory * factory_spec.logical_qubits * (d ** 2) * max(0, factory_count)
    total_phys = data_phys + factory_phys
    backlog_ratio = scaled_peak / max(total_factory_rate, 1e-12) if total_factory_rate > 0 else float("inf")
    util_clip = min(1.0, backlog_ratio) if math.isfinite(backlog_ratio) else float("inf")

    logical_ops = depth_weight * float(logical["meas_depth"]) + tof_weight * float(logical["toffoli"])
    failure_est = {
        "p_logical": p_l,
        "ops_bound": logical_ops,
        "budget": target_fail,
        "expected_failures": p_l * logical_ops,
        "weights": {
            "depth_weight": depth_weight,
            "toffoli_weight": tof_weight,
        },
        "formula": "depth_weight*meas_depth + toffoli_weight*toffoli",
    }

    unit_suffix = "T_per_cycle" if rate_unit_norm == "t" else "toffoli_per_cycle"
    rate_fields = {
        "rate_unit": rate_unit,
        "toffoli_per_cycle": toffoli_per_cycle,
        f"factory_rate_peak_{unit_suffix}": scaled_peak,
        f"factory_rate_target_{unit_suffix}": target_rate,
        f"factory_rate_available_{unit_suffix}": total_factory_rate,
        f"factory_rate_single_{unit_suffix}": factory_rate_single,
        "t_per_toffoli_assumed": t_per_tof if rate_unit_norm == "t" else None,
        "rate_multiplier": rate_multiplier,
        "factory_supply_scale": supply_scale,
        "factory_utilization_target": util_target,
        "factory_utilization_actual": util_clip,
        "factory_backlog_ratio": backlog_ratio,
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
        "factory_cycles": factory_cycles,
        "runtime_seconds_depth": runtime_seconds_depth,
        "runtime_seconds_factory": runtime_seconds_factory,
        "runtime_seconds": runtime_seconds,
        "phys_qubits_total": total_phys,
        "phys_qubits_data": data_phys,
        "phys_qubits_factories": factory_phys,
        "factory_utilization_target": util_target,
        "factory_utilization_actual": util_clip,
        "limit": limiting,
        "failure_estimate": failure_est,
        "rate_details": rate_fields,
        "notes": scenario.get("notes", ""),
        "logical_op_weight_tof": tof_weight,
        "logical_op_weight_depth": depth_weight,
        "calibrated_against": scenario.get("calibrated_against"),
    }


def _default_shor_scenarios() -> List[Dict[str, Any]]:
    _ensure_ge_calibrated()
    return [
        {
            "label": "ge-baseline",
            "phys_error_rate": 1e-3,
            "cycle_time_ns": 1000.0,
            "target_total_fail_prob": 1e-2,
            "factory_spec": "litinski-116-to-12",
            "factory_rate_unit": "T",
            "t_per_toffoli": 4.0,
            "logical_op_weight_tof": 1.5,
            "logical_op_weight_depth": 1.0,
            "factory_utilization_target": 1.3,
            "target_factory_utilization": 1.3,
            "factory_count_override": SHOR_FACTORY_COUNT_BASELINE,
            "calibrated_against": "GE-2019-2048",
            "notes": "Matches Gidney–Ekerå (2019) headline assumptions (1 µs cycle, p=1e-3).",
        },
        {
            "label": "optimistic",
            "phys_error_rate": 5e-4,
            "cycle_time_ns": 200.0,
            "target_total_fail_prob": 1e-3,
            "factory_spec": "litinski-116-to-12",
            "factory_rate_unit": "T",
            "t_per_toffoli": 4.0,
            "target_factory_utilization": 0.8,
            "notes": "Improved error rates / faster cycles with proportional factory build-out.",
        },
        {
            "label": "conservative",
            "phys_error_rate": 2e-3,
            "cycle_time_ns": 5000.0,
            "target_total_fail_prob": 1e-1,
            "factory_spec": "factory-lite-15-to-1",
            "factory_rate_unit": "T",
            "t_per_toffoli": 7.0,
            "logical_op_weight_tof": 1.5,
            "target_factory_utilization": 0.75,
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
            "t_counts": t_counts,
            "rsa_model": logical_main["model"],
            "log2_n_bits": float(logical_main["log2_n"]),
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

    baseline_delta = None
    targets = _ge_baseline_target()
    baseline_entry = next(
        (entry for entry in scenario_entries if int(entry.get("modulus_bits", 0)) == 2048),
        None,
    )
    if baseline_entry:
        ge_profile = next(
            (sc for sc in baseline_entry.get("scenarios", []) if sc.get("label") == "ge-baseline"),
            None,
        )
        if ge_profile:
            runtime_target = targets["runtime_seconds"]
            qubits_target = targets["phys_qubits_total"]
            runtime_delta = (
                (ge_profile.get("runtime_seconds", runtime_target) - runtime_target) / runtime_target
            ) * 100.0
            qubit_delta = (
                (ge_profile.get("phys_qubits_total", qubits_target) - qubits_target) / qubits_target
            ) * 100.0
            baseline_delta = {
                "delta_runtime_pct": runtime_delta,
                "delta_phys_qubits_pct": qubit_delta,
            }

    metrics.extras["shor_profiles"] = {
        "model": logical_main["model"],
        "scenarios": scenario_entries,
        "t_count_assumptions": {
            "primary_unit": "Toffoli",
            "t_mappings": {"catalyzed": 4.0, "textbook": 7.0},
        },
    }
    metrics.extras["t_count_assumptions"] = metrics.extras["shor_profiles"]["t_count_assumptions"]
    metrics.extras["calibration"] = {
        "ge_reference": targets,
        "factory_rate_multiplier": SHOR_FACTORY_RATE_MULTIPLIER,
        "factory_supply_scale": SHOR_FACTORY_SUPPLY_SCALE,
        "data_alpha_scale": SHOR_DATA_ALPHA_SCALE,
        "factory_alpha_scale": SHOR_FACTORY_ALPHA_SCALE,
        "note": "Parameters scaled to reproduce GE-2019 RSA-2048 headline (≈8h, 20M qubits).",
    }
    if baseline_delta is not None:
        metrics.extras["calibration"]["baseline_delta_pct"] = baseline_delta

    opts = _apply_quantum_arch_presets(opts)
    if opts and opts.rsa_surface:
        scenario = {
            "label": opts.quantum_arch or "custom-speed",
            "phys_error_rate": float(opts.phys_error_rate),
            "cycle_time_ns": float(opts.cycle_time_s) * 1e9,
            "target_total_fail_prob": float(opts.target_total_fail_prob),
            "factory_spec": "litinski-116-to-12",
            "factory_utilization_target": 0.8,
            "alpha_data": 2.5,
            "factory_rate_unit": "T",
            "t_per_toffoli": 4.0,
            "notes": "User-specified surface-code override (speed-optimised profile)",
            "profile_kind": "custom",
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
        extras={
            "category_floor": floor,
            "nist_category": nist_category,
            # Always surface the selected profile (or None) for UI transparency
            "lattice_profile": (opts.lattice_profile if opts and opts.lattice_profile else None),
            **base_extras,
        },
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
    return metrics


_HQC_CURATED_ESTIMATES: Dict[str, Dict[str, Any]] = {
    "hqc-128": {
        "classical_bits_mid": 128.0,
        "classical_bits_range": [126.0, 132.0],
        "quantum_bits_mid": 118.0,
        "quantum_bits_range": [114.0, 122.0],
        "source": "hqc-round3-design",
        "notes": "Design target per HQC submission; quantum via Grover-style square-root reduction.",
    },
    "hqc-192": {
        "classical_bits_mid": 192.0,
        "classical_bits_range": [188.0, 196.0],
        "quantum_bits_mid": 182.0,
        "quantum_bits_range": [176.0, 186.0],
        "source": "hqc-round3-design",
        "notes": "Design target per HQC submission; quantum via Grover-style square-root reduction.",
    },
    "hqc-256": {
        "classical_bits_mid": 256.0,
        "classical_bits_range": [250.0, 260.0],
        "quantum_bits_mid": 246.0,
        "quantum_bits_range": [238.0, 250.0],
        "source": "hqc-round3-design",
        "notes": "Design target per HQC submission; quantum via Grover-style square-root reduction.",
    },
}


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
    mech_norm = str(name or "").lower()
    if mech_norm.endswith("-1-cca2"):
        mech_norm = mech_norm.replace("-1-cca2", "")

    extras: Dict[str, Any] = {"category_floor": floor, "nist_category": nist_category}
    curated = _HQC_CURATED_ESTIMATES.get(mech_norm)
    if curated:
        extras["curated_estimates"] = curated.copy()
    try:
        from pqcbench.params import find as find_params  # type: ignore
        ph = find_params(name)
        if ph and ph.extras:
            if ph.extras.get("sizes_bytes"):
                extras.setdefault("sizes_bytes", ph.extras.get("sizes_bytes"))
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

    classical_bits = float(floor)
    quantum_bits = float(floor)
    if curated:
        classical_bits = float(curated.get("classical_bits_mid", classical_bits))
        quantum_bits = float(curated.get("quantum_bits_mid", quantum_bits))

    return SecMetrics(
        classical_bits=classical_bits,
        quantum_bits=quantum_bits,
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
                "source": "curated-range",
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
        import importlib, math as _math
        from pqcbench.params import find as find_params  # type: ignore

        ph = find_params(mechanism)
        if not ph:
            return None
        extras = ph.extras or {}
        fam = (family or ph.family)
        if fam not in ("ML-KEM", "ML-DSA"):
            # External LWE estimator integration is only attempted for LWE-like families
            return None

        # Compute module-LWE → LWE mapping
        n = int(extras.get("n", 0) or 0)
        k = int(extras.get("k", 0) or 0)
        q = int(extras.get("q", 0) or 0)
        if n <= 0 or k <= 0 or q <= 0:
            return None
        n_lwe = n * k
        # Noise
        sigma = _module_lwe_sigma(extras)
        if sigma is None or sigma <= 0.0:
            return None
        alpha = _module_lwe_alpha(q, sigma)
        if alpha is None or alpha <= 0.0:
            return None

        # Try to import an estimator module — many require Sage; optional.
        mod = None
        for name in ("lwe_estimator", "lattice_estimator"):
            try:
                mod = importlib.import_module(name)
                break
            except Exception:
                continue
        if mod is None:
            return None

        # Heuristics for secret distribution label
        secret_dist = "ternary" if (extras.get("eta1") or extras.get("eta")) else "binary"

        # Attempt common API: estimate_lwe(n, alpha, q, secret_distribution=..., m=None)
        result = None
        beta_est = None
        bits_classical = None
        try:
            if hasattr(mod, "estimate_lwe") and callable(getattr(mod, "estimate_lwe")):
                result = mod.estimate_lwe(n=n_lwe, alpha=alpha, q=q, secret_distribution=secret_dist, m=None)  # type: ignore[attr-defined]
        except Exception:
            result = None

        # Fallback: try a generic 'estimate' symbol
        if result is None:
            try:
                if hasattr(mod, "estimate") and callable(getattr(mod, "estimate")):
                    result = mod.estimate(n=n_lwe, alpha=alpha, q=q)  # type: ignore[attr-defined]
            except Exception:
                result = None

        # Interpret results from known patterns
        def _extract_bits_beta(obj: object) -> tuple[Optional[float], Optional[float]]:
            # Returns (bits_classical, beta)
            try:
                if obj is None:
                    return None, None
                # Direct float → bits
                if isinstance(obj, (int, float)):
                    return float(obj), None
                # Dict with per-attack entries containing 'rop' and optional 'beta'
                if isinstance(obj, dict):
                    best_bits = None
                    best_beta = None
                    # Flat dict
                    if "rop" in obj or "beta" in obj:
                        rop = obj.get("rop")
                        b = obj.get("beta")
                        if isinstance(rop, (int, float)):
                            best_bits = _math.log2(float(rop))
                        if isinstance(b, (int, float)):
                            best_beta = float(b)
                    # Nested per-attack
                    for key, val in obj.items():
                        if not isinstance(val, dict):
                            continue
                        rop = val.get("rop")
                        b = val.get("beta")
                        bits = None
                        if isinstance(rop, (int, float)):
                            bits = _math.log2(float(rop))
                        if bits is not None:
                            if best_bits is None or bits < best_bits:
                                best_bits = bits
                                best_beta = float(b) if isinstance(b, (int, float)) else best_beta
                    return best_bits, best_beta
            except Exception:
                return None, None
            return None, None

        bits_classical, beta_est = _extract_bits_beta(result)
        if bits_classical is None:
            return {
                "model": f"{mod.__name__} (detected; no parsable result)",
                "beta": beta_est,
                "bits_classical": None,
                "bits_qram": None,
            }

        # Quantum exponent via Q-Core-SVP ratio
        q_ratio = 0.265 / 0.292
        bits_qram = bits_classical * q_ratio

        return {
            "model": f"{mod.__name__}",
            "beta": beta_est,
            "bits_classical": bits_classical,
            "bits_qram": bits_qram,
            "params": {"n": n_lwe, "q": q, "alpha": alpha, "secret": secret_dist},
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
    nist_category = {128: 1, 192: 3, 256: 5}.get(int(floor), None)

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
            if ex.get("sizes_bytes"):
                mayo_params["sizes_bytes"] = ex.get("sizes_bytes")
                extras.setdefault("sizes_bytes", ex.get("sizes_bytes"))
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
    curated = {
        "classical_bits_mid": float(floor),
        "quantum_bits_mid": float(floor),
        "source": "curated-range",
    }
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
            if ex.get("sizes_bytes"):
                kyber_info["sizes_bytes"] = ex.get("sizes_bytes")
    except Exception:
        pass

    module_cost = None
    cost_extras = {k: v for k, v in kyber_info.items() if v is not None}
    if cost_extras:
        module_cost = _module_lwe_cost_summary(cost_extras)

    if kyber_info.get("sizes_bytes"):
        base.extras.setdefault("sizes_bytes", kyber_info.get("sizes_bytes"))

    table_entry = _kyber_core_svp_table_entry(name)
    if table_entry:
        module_cost = {
            "model": "core-svp-table",
            "source": "core-svp-spec-table",
            "params": {k: kyber_info.get(k) for k in ("n", "k", "q") if kyber_info.get(k) is not None},
            "sigma_error": kyber_info.get("eta2") and _stddev_centered_binomial(int(kyber_info["eta2"])) or 1.0,
            "sigma_secret": kyber_info.get("eta1") and _stddev_centered_binomial(int(kyber_info["eta1"])) or 1.0,
            "primal": table_entry,
            "dual": None,
            "headline": table_entry,
            "reference": "CRYSTALS-Kyber Round 4 specification, Table 4",
        }
    if module_cost:
        # Always attach the model details
        base.extras.setdefault("mlkem", {})["module_lwe_cost"] = module_cost
        # If an external estimator was used successfully, keep its headline bits
        using_external = bool(
            opts and opts.lattice_use_estimator and isinstance(base.extras.get("estimator_model"), str)
            and not str(base.extras.get("estimator_model")).startswith("unavailable")
        )
        if not using_external:
            # Respect lattice_profile when deciding headline numbers
            profile = (opts.lattice_profile.lower() if (opts and opts.lattice_profile) else None)
            if profile == "floor":
                # Keep category floors as the headline numbers
                pass
            elif profile == "classical":
                base.classical_bits = float(module_cost["headline"]["classical_bits"])
            else:
                # Auto/quantum: override both classical and quantum with model headline
                base.classical_bits = float(module_cost["headline"]["classical_bits"])
                base.quantum_bits = float(module_cost["headline"]["quantum_bits"])
        base.notes = (
            "ML-KEM module-LWE cost model: BKZ (primal/dual) core-SVP estimates. "
            "Category floor retained in extras.category_floor."
        )

    # Curated classical/quantum ranges for Kyber-512 based on public analyses
    curated: Dict[str, Any] = {}
    mech_lower = str(name).lower()
    if any(tok in mech_lower for tok in ("512", "kyber512", "ml-kem-512")):
        classical_mid = 118.0
        classical_lo = 113.0
        classical_hi = 123.0
        q_factor = 0.265 / 0.292
        quantum_mid = round(classical_mid * q_factor, 1)
        quantum_lo = round(classical_lo * q_factor, 1)
        quantum_hi = round(classical_hi * q_factor, 1)
        curated = {
            "classical_bits_mid": classical_mid,
            "classical_bits_range": [classical_lo, classical_hi],
            "quantum_bits_mid": quantum_mid,
            "quantum_bits_range": [quantum_lo, quantum_hi],
            "source": "core-svp-spec-table",
            "assumptions": {
                "source_notes": (
                    "Kyber specification Table 4 core-SVP hardness (β≈403 → 118 classical bits, 107 quantum bits)."
                ),
                "q_sieving_exponent_ratio": q_factor,
            },
        }
    elif any(tok in mech_lower for tok in ("768", "kyber768", "ml-kem-768")):
        classical_mid = 182.0
        classical_lo = 176.0
        classical_hi = 188.0
        q_factor = 0.265 / 0.292
        quantum_mid = round(classical_mid * q_factor, 1)
        quantum_lo = round(classical_lo * q_factor, 1)
        quantum_hi = round(classical_hi * q_factor, 1)
        curated = {
            "classical_bits_mid": classical_mid,
            "classical_bits_range": [classical_lo, classical_hi],
            "quantum_bits_mid": quantum_mid,
            "quantum_bits_range": [quantum_lo, quantum_hi],
            "source": "core-svp-spec-table",
            "assumptions": {
                "source_notes": (
                    "Kyber specification Table 4 core-SVP hardness (β≈625 → 182 classical bits, 165 quantum bits)."
                ),
                "q_sieving_exponent_ratio": q_factor,
            },
        }
    elif any(tok in mech_lower for tok in ("1024", "kyber1024", "ml-kem-1024")):
        classical_mid = 256.0
        classical_lo = 248.0
        classical_hi = 264.0
        q_factor = 0.265 / 0.292
        quantum_mid = round(classical_mid * q_factor, 1)
        quantum_lo = round(classical_lo * q_factor, 1)
        quantum_hi = round(classical_hi * q_factor, 1)
        curated = {
            "classical_bits_mid": classical_mid,
            "classical_bits_range": [classical_lo, classical_hi],
            "quantum_bits_mid": quantum_mid,
            "quantum_bits_range": [quantum_lo, quantum_hi],
            "source": "core-svp-spec-table",
            "assumptions": {
                "source_notes": (
                    "Kyber specification Table 4 core-SVP hardness (β≈877 → 256 classical bits, 232 quantum bits)."
                ),
                "q_sieving_exponent_ratio": q_factor,
            },
        }

    mlkem_block = dict(base.extras.get("mlkem", {}) or {})
    if module_cost:
        mlkem_block["module_lwe_cost"] = module_cost
    mlkem_block["kyber_params"] = kyber_info or None
    mlkem_block["curated_estimates"] = curated or None
    mlkem_block["core_svp_constants"] = {"classical": 0.292, "quantum": 0.265}
    base.extras["mlkem"] = mlkem_block
    if module_cost:
        base.extras["estimator_model"] = module_cost.get("model")
        if module_cost.get("reference"):
            base.extras["estimator_reference"] = module_cost["reference"]
        if module_cost.get("source") == "core-svp-spec-table":
            base.extras["estimator_available"] = False

    if not module_cost:
        # Adjust notes only if advanced estimator did not populate a model
        if "APS Lattice Estimator" not in base.notes:
            if opts and opts.lattice_use_estimator and not base.extras.get("estimator_model"):
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
            if ex.get("sizes_bytes"):
                falcon_info["sizes_bytes"] = ex.get("sizes_bytes")
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
            "source": "curated-range",
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
            "source": "curated-range",
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

    if falcon_info.get("sizes_bytes"):
        base.extras.setdefault("sizes_bytes", falcon_info.get("sizes_bytes"))

    if curated:
        base.classical_bits = float(curated["classical_bits_mid"])
        base.quantum_bits = float(curated.get("quantum_bits_mid")) if curated.get("quantum_bits_mid") is not None else base.quantum_bits
        base.extras["estimator_model"] = "curated-range"
        base.extras["lattice_profile"] = "curated"
        base.extras["estimator_available"] = False

    if "APS Lattice Estimator" not in base.notes:
        if opts and opts.lattice_use_estimator and not base.extras.get("estimator_model"):
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
                "n_lwe": (n * k) if k else None,
            }
            if ex.get("sizes_bytes"):
                dsa_info["sizes_bytes"] = ex.get("sizes_bytes")
                base.extras.setdefault("sizes_bytes", ex.get("sizes_bytes"))
    except Exception:
        pass

    module_cost = None
    if dsa_info:
        cost_extras = {
            key: value
            for key, value in dsa_info.items()
            if key in {"n", "k", "l", "q", "eta", "eta1", "eta2", "sigma_e"}
            and value is not None
        }
        module_cost = _module_lwe_cost_summary(cost_extras)
        if module_cost is None:
            table_entry = _dilithium_core_svp_table_entry(name)
            if table_entry:
                module_cost = {
                    "model": "core-svp-table",
                    "source": "core-svp-spec-table",
                    "params": {k: dsa_info.get(k) for k in ("n", "k", "l", "q") if dsa_info.get(k) is not None},
                    "sigma_error": _module_lwe_sigma(cost_extras) if cost_extras else None,
                    "sigma_secret": _module_lwe_secret_sigma(cost_extras) if cost_extras else None,
                    "primal": table_entry,
                    "dual": None,
                    "headline": table_entry,
                    "reference": "CRYSTALS-Dilithium Round 3 specification, Table 4",
                }
        if module_cost:
            # If an external estimator was used successfully, keep its headline bits
            using_external = bool(
                opts and opts.lattice_use_estimator and isinstance(base.extras.get("estimator_model"), str)
                and not str(base.extras.get("estimator_model")).startswith("unavailable")
            )
            if not using_external:
                # Respect lattice_profile for headline numbers
                profile = (opts.lattice_profile.lower() if (opts and opts.lattice_profile) else None)
                if profile == "floor":
                    pass
                elif profile == "classical":
                    base.classical_bits = float(module_cost["headline"]["classical_bits"])
                else:
                    base.classical_bits = float(module_cost["headline"]["classical_bits"])
                    base.quantum_bits = float(module_cost["headline"]["quantum_bits"])
            base.notes = (
                "ML-DSA module-LWE cost model: BKZ (primal/dual) core-SVP estimates. "
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
            "source": "literature-range",
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
            "source": "literature-range",
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
            "source": "literature-range",
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
    if module_cost:
        base.extras["estimator_model"] = module_cost.get("model")
        if module_cost.get("reference"):
            base.extras["estimator_reference"] = module_cost["reference"]
        if module_cost.get("source") == "core-svp-spec-table":
            base.extras["estimator_available"] = False

    if not module_cost:
        # Note refinement depending on estimator availability
        if "APS Lattice Estimator" not in base.notes:
            if opts and opts.lattice_use_estimator and not base.extras.get("estimator_model"):
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
