from __future__ import annotations
"""Brute-force baseline estimator (teaching/demo only).

This module provides a minimal, dependency-free baseline for "no-strategy"
brute force: enumerate a search space of size 2^b and measure/estimate the
time-to-success at various throughputs. It is intended purely for educational
context and sanity checks on toy/reduced parameters. It is NOT an attack plan
for real deployments.

Design goals:
- Keep API tiny and cross-family: produce a single dict per algorithm summary.
- Avoid large-number overflow by describing times primarily in years and logs.
- Be explicit about assumptions and selection of the search space (b bits).

Integration:
- The security estimator attaches this output to extras["bruteforce"]. The CLI
  standardizer then surfaces it under security.bruteforce in JSON exports.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import math


# Default throughputs to report (tries per second) — optimistic upper bounds.
DEFAULT_TRIES_PER_SEC: Tuple[float, ...] = (
    1e6,    # 1 million/s (single CPU/GPU)
    1e9,    # 1 billion/s (clustered, ASICs)
    1e12,   # 1 trillion/s (very optimistic)
)


SECONDS_PER_YEAR: float = 31_536_000.0


def _safe_pow2(bits: float) -> float:
    """Return 2**bits as float if representable; otherwise return math.inf.

    Python float overflows above ~1.8e308. 2**1024 ~ 1.8e308, so inputs up to
    about 1024 are safe. Above that, return inf and rely on log formatting.
    """
    try:
        # Guard against negative or NaN inputs; treat < 0 as 0 space.
        if not math.isfinite(bits) or bits < 0:
            return 0.0
        if bits > 1024:
            return math.inf
        return 2.0 ** float(bits)
    except OverflowError:
        return math.inf


def expected_years_to_bruteforce(space_bits: float, tries_per_sec: float) -> float:
    """Estimate expected years to cover a space of 2^space_bits at given rate.

    We report the *mean* time-to-first-success for a uniform one-hit space as
    roughly 2^b / rate years. For a simple teaching baseline, we omit constant
    factors (e.g., 1/2 for average position) since they are negligible relative
    to the exponent b.
    """
    trials = _safe_pow2(space_bits)
    if tries_per_sec <= 0 or trials == 0.0:
        return 0.0
    if math.isinf(trials):
        return math.inf
    seconds = trials / float(tries_per_sec)
    return seconds / SECONDS_PER_YEAR


def _pretty_years(y: float) -> Dict[str, float | str]:
    """Format years into a compact dict with scientific notation and log10.

    - value: numeric years (may be inf)
    - sci:   string in scientific notation, e.g., "1.08e+19"
    - log10: base-10 logarithm of years (inf yields inf)
    """
    if y <= 0:
        return {"value": 0.0, "sci": "0", "log10": -math.inf}
    if math.isinf(y):
        return {"value": None, "sci": "inf", "log10": None}
    log10y = math.log10(y)
    return {"value": y, "sci": f"{y:.3e}", "log10": log10y}


def _model_and_space_bits(
    *,
    algo: str,
    kind: str,
    mechanism: Optional[str],
    classical_bits: Optional[float],
    extras: Dict[str, object],
) -> Tuple[str, float, str]:
    """Pick a brute-force model tag and its b-bit search space for the algorithm.

    Heuristics (documented in the README):
    - RSA (PSS/OAEP): model = 'trial_division_factorization'; b ~ modulus_bits/2.
    - KEMs (Kyber/HQC): model = 'guess_shared_secret'; b ~ classical_bits floor.
    - Signatures (Dilithium/Falcon/SPHINCS+/XMSSMT/MAYO): model = 'random_forgery';
      b ~ classical_bits floor (acceptance ~ 2^-b per attempt).
    - Fallback: use classical_bits if present; otherwise 128.
    """
    algo_l = (algo or "").lower()
    mech_l = (mechanism or "").lower()
    model = "random_forgery"

    # RSA: derive modulus bits from extras or mechanism/meta when available.
    if algo_l in ("rsa-oaep", "rsa-pss"):
        model = "trial_division_factorization"
        n_bits = None
        # security_estimator stores modulus_bits under extras for RSA
        if isinstance(extras.get("modulus_bits"), (int, float)):
            n_bits = float(extras.get("modulus_bits"))
        # Fallback: parse a typical mechanism like "RSA-2048" if present
        if n_bits is None:
            try:
                import re
                m = re.search(r"rsa[-_]?(\d{3,5})", mech_l)
                if m:
                    n_bits = float(m.group(1))
            except Exception:
                pass
        # Last resort: assume 2048
        if n_bits is None or n_bits <= 0:
            n_bits = 2048.0
        return model, float(n_bits) / 2.0, "sqrt(n) trial division"

    # KEMs: enumerate candidate shared secrets (toy baseline), use security floor
    if kind.upper() == "KEM" or algo_l in ("kyber", "hqc"):
        model = "guess_shared_secret"
        b = float(classical_bits) if classical_bits else 128.0
        return model, b, "search space ~ 2^floor bits"

    # Hash-based signatures and lattice signatures: random forgery acceptance
    model = "random_forgery"
    b = float(classical_bits) if classical_bits else 128.0
    return model, b, "acceptance ~ 2^-b per try"


def bruteforce_summary(
    *,
    algo: str,
    kind: str,
    mechanism: Optional[str],
    classical_bits: Optional[float],
    extras: Dict[str, object] | None = None,
    tries_per_sec: Tuple[float, ...] = DEFAULT_TRIES_PER_SEC,
) -> Dict[str, object]:
    """Produce a standard brute-force baseline dictionary for an algorithm run.

    Returns a dict with keys:
      - model: tag indicating the brute-force style
      - space_bits: b such that the search space is 2^b
      - time_years: mapping of tries/sec -> years (with sci/log10 variants)
      - assumptions: human-readable notes on what b represents
      - rates: the list of tries/sec reported
      - guidance: lab-mode note about keeping toy bits small
    """
    extras = dict(extras or {})
    model, b, rationale = _model_and_space_bits(
        algo=algo, kind=kind, mechanism=mechanism, classical_bits=classical_bits, extras=extras
    )

    times: Dict[str, Dict[str, float | str]] = {}
    for r in tries_per_sec:
        y = expected_years_to_bruteforce(b, float(r))
        times[str(r)] = _pretty_years(y)

    return {
        "model": model,
        "space_bits": b,
        "rates": list(tries_per_sec),
        "time_years": times,
        "assumptions": {
            "rationale": rationale,
            "notes": (
                "Educational baseline only. Use reduced parameters for lab demos; "
                "real parameters are astronomically out of reach."
            ),
        },
        "guidance": {
            "lab_mode_max_bits": 32,
            "warning": "Refuse or simulate >32-bit spaces when running any brute loop.",
        },
    }
