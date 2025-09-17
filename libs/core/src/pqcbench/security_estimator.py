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

    # Very coarse logical resource model (abstract-level) for Shor factoring.
    # We expose closed-form scalings to make assumptions explicit and tunable:
    # - logical_qubits Q ≈ c_q · n (register + ancillas), default c_q≈3
    # - Toffoli count ≈ c_T · n^3, default c_T≈0.3 (per GE2019-style constants)
    # - depth ≈ c_D · n^2 · log2 n (measurement/round depth model), c_D tuned
    # These are for communication/comparison, not prescriptive hardware budgets.
    toffoli_coeff = 0.3
    qubit_coeff = 3.0
    depth_coeff = 45.0  # calibrated so depth(~n^2 log2 n) is in a plausible range near n=2048
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
    # Provide a rough T-count via Toffoli decomposition (typical ≈7 T per Toffoli)
    t_per_toffoli = 7.0
    t_count = toffoli * t_per_toffoli

    metrics = SecMetrics(
        classical_bits=float(_rsa_classical_strength(n_bits)),
        quantum_bits=0.0,  # Shor polynomial-time break → effectively 0-bit quantum security
        shor_breakable=True,
        notes=(
            "RSA classical: NIST SP 800-57 strength mapping; quantum: Shor breaks (0 bits). "
            "Reporting logical resource estimates (Q, Toffoli/T, depth)."
        ),
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

    # Optional: convert to surface-code physical qubits and runtime.
    # Assumptions (communicated in the output):
    #  - Surface code threshold p_th ≈ 1e-2
    #  - Logical error per operation p_L ≈ 0.1 * (p_phys/p_th)^((d+1)/2)
    #  - Choose code distance d so that p_L * max(toffoli, depth) <= target budget / 10
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
      attach a coarse Stern-style entropy approximation of log2 time and memory.
      This provides an order-of-magnitude sense of ISD costs without implementing
      the full BJMM/May–Ozerov pipeline. Quantum “Grover-limited” speedups are
      noted as reductions on the exponent to illustrate impact on search-like steps.
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
                # Coarse Stern-style time exponent: success probability ~ C(k, ⌊w/2⌋) / C(n, w)
                # so expected trials ~ C(n, w) / C(k, ⌊w/2⌋); take log2 to get bit cost.
                logNw = _log2_binom(n, w)
                logKwh = _log2_binom(k, max(0, w // 2))
                time_bits_classical = max(0.0, logNw - logKwh)
                # Memory: heuristic fraction of time exponent (BJMM/MMT tend to trade memory for time)
                mem_bits_classical = max(0.0, 0.5 * time_bits_classical)
                # Quantum: two illustrative models
                #  (i) Grover-limited search on the dominant loop → √ speedup on trials
                time_bits_q_grover = 0.5 * time_bits_classical
                #  (ii) Conservative “partial speedup” (e.g., sieving-like steps only)
                time_bits_q_cons = 0.9 * time_bits_classical
                extras.update({
                    "isd_model": "Stern-entropy (coarse)",
                    "isd_time_bits_classical": time_bits_classical,
                    "isd_mem_bits_classical": mem_bits_classical,
                    "isd_time_bits_quantum_grover": time_bits_q_grover,
                    "isd_time_bits_quantum_conservative": time_bits_q_cons,
                    "params": ph.to_dict(),
                    # Notes to the reader about scope and assumptions
                    "notes": {
                        "scope": "Coarse Stern-style estimate; BJMM/May–Ozerov not explicitly modeled.",
                        "qc_structure": "Quasi-cyclic structure ignored in this coarse model.",
                        "quantum": "No known polynomial-time quantum decoder; Grover-like speedups only.",
                    },
                })
    except Exception:
        pass

    return SecMetrics(
        classical_bits=float(floor),
        quantum_bits=float(floor),
        shor_breakable=False,
        notes=(
            "Code-based (HQC): NIST category floor; attaches coarse ISD exponents when (n,k,w) available. "
            "No known polynomial-time quantum attack; Grover-limited speedups may apply to search components."
        ),
        extras=extras,
    )


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
            # Heuristic checks (documented; non-fatal unless blatantly broken)
            n = int(ex.get("n", 0) or 0)
            m = int(ex.get("m", 0) or 0)
            q = int(ex.get("q", 0) or 0)
            o = int(ex.get("oil", 0) or 0)
            underdef_ks = (n >= m * (m + 1)) if (n and m) else False
            underdef_miura = (n >= (m * (m + 3)) // 2) if (n and m) else False
            oil_guess_bits = (o * math.log2(q)) if (o and q) else None
            extras["mayo"] = {
                "params": mayo_params,
                "checks": {
                    "underdefined_ks": underdef_ks,
                    "underdefined_miura": underdef_miura,
                    "oil_guess_bits": oil_guess_bits,
                    "notes": (
                        "Whipping construction is intended to invalidate naive oil-guessing;"
                        " checks are informational and do not override floors."
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

    # Merge into extras and refine notes to reflect enrichment
    base.extras.update({
        "mlkem": {
            "kyber_params": kyber_info or None,
            "curated_estimates": curated or None,
        }
    })

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
            dsa_info = {
                "mechanism": ph.mechanism,
                "n": n,
                "k": k,
                "l": l,
                "q": q,
                "rank": (n * k) if k else None,
            }
    except Exception:
        pass

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

    base.extras.update({
        "mldsa": {
            "dilithium_params": dsa_info or None,
            "curated_estimates": curated or None,
            "core_svp_constants": {"classical": c_class, "quantum": c_quant},
        }
    })

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
