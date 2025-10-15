from __future__ import annotations

"""Secret key bitstring analysis helpers (Hamming weight/distance).

These routines provide lightweight sanity checks over raw secret-key bytes.
The goal is to surface obvious RNG/encoding issues without ever persisting keys.
"""

from dataclasses import dataclass, field
from itertools import combinations, islice
import math
import statistics
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, TYPE_CHECKING

try:  # Local import guarded to avoid circular dependency during typing.
    from .hqc_secret_parser import HQCSecretParseResult, parse_secret_keys
except Exception:  # pragma: no cover - parser availability verified at runtime.
    HQCSecretParseResult = None  # type: ignore
    parse_secret_keys = None  # type: ignore

try:
    from .bike_secret_parser import parse_bike_secret_keys
except Exception:  # pragma: no cover - optional parser helpers
    parse_bike_secret_keys = None  # type: ignore

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except Exception:  # pragma: no cover - cryptography optional at runtime
    serialization = None  # type: ignore
    rsa = None  # type: ignore

try:
    from .lattice_secret_parser import (
        LatticeSecretParseResult,
        parse_ml_dsa_secret_keys,
        parse_ml_kem_secret_keys,
    )
except Exception:  # pragma: no cover - optional parser helpers
    LatticeSecretParseResult = None  # type: ignore
    parse_ml_dsa_secret_keys = None  # type: ignore
    parse_ml_kem_secret_keys = None  # type: ignore

_BYTE_POPCOUNT = tuple(bin(i).count("1") for i in range(256))

# Keep sampling modest so CLI runs stay responsive.
DEFAULT_SECRET_KEY_SAMPLES: int = 32
DEFAULT_PAIR_SAMPLE_LIMIT: int = 128

if TYPE_CHECKING:  # pragma: no cover - type checking aid only
    from .params import ParamHint


def _popcount_bytes(data: bytes) -> int:
    return sum(_BYTE_POPCOUNT[b] for b in data)


def _hamming_distance(a: bytes, b: bytes) -> int:
    return sum(_BYTE_POPCOUNT[x ^ y] for x, y in zip(a, b))


@dataclass
class KeyAnalysisModel:
    """Model assumptions for interpreting bit-level statistics."""

    name: str
    expected_hw_fraction: Optional[float] = None
    expected_hd_fraction: Optional[float] = None
    per_bit_reference: Optional[float] = None
    notes: List[str] = field(default_factory=list)
    extras: Dict[str, object] = field(default_factory=dict)


@dataclass
class PreparedKeyBundle:
    """Secret-key material normalised for downstream bitstring analysis."""

    keys: Sequence[bytes]
    context: Dict[str, object] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    coefficients: Optional[List[List[List[int]]]] = None


def prepare_keys_for_analysis(
    keys: Sequence[bytes],
    *,
    family: Optional[str],
    mechanism: Optional[str],
) -> PreparedKeyBundle:
    """Apply scheme-aware parsing before bit-level analysis.

    Currently only HQC requires special handling (seed-based constant-weight
    vectors). Other families return the original byte strings untouched.
    """

    bundle = PreparedKeyBundle(keys=list(keys))

    if not keys:
        return bundle

    fam = (family or "").upper()

    if fam == "HQC" and parse_secret_keys is not None:
        try:
            parsed: Optional[HQCSecretParseResult] = parse_secret_keys(
                keys, mechanism=mechanism
            )
        except Exception as exc:  # pragma: no cover - defensive guard
            bundle.warnings.append(f"HQC parser error: {exc}")
            return bundle
        if parsed:
            bundle.keys = parsed.bitstrings
            bundle.context.update(parsed.context)
            bundle.context.setdefault("parser", parsed.parser)
            bundle.warnings.extend(parsed.warnings)
            bundle.context.setdefault("parsed_components", "constant_weight_vectors")

    elif fam == "BIKE" and parse_bike_secret_keys is not None:
        from . import params

        hint = params.find(mechanism) if mechanism else None
        extras = hint.extras if hint else {}
        parsed_bike = parse_bike_secret_keys(
            keys,
            r_bits=extras.get("r_bits"),
            weight_per_vector=extras.get("weight_per_vector"),
            n0=extras.get("n0", 2),
        )
        if parsed_bike is not None:
            bundle.keys = parsed_bike.bitstrings
            bundle.context.update(parsed_bike.context)
            bundle.warnings.extend(parsed_bike.warnings)

    elif fam == "RSA" and serialization is not None and rsa is not None:
        parsed_keys: List[bytes] = []
        for idx, raw in enumerate(keys):
            try:
                sk = serialization.load_der_private_key(raw, password=None)
            except Exception as exc:
                bundle.warnings.append(f"RSA key {idx} parse error: {exc}")
                continue
            if not isinstance(sk, rsa.RSAPrivateKey):
                bundle.warnings.append(f"RSA key {idx} type mismatch ({type(sk)!r})")
                continue
            numbers = sk.private_numbers()
            modulus = numbers.public_numbers.n
            priv_exp = numbers.d
            n_bytes = (modulus.bit_length() + 7) // 8
            parsed_keys.append(priv_exp.to_bytes(n_bytes, "big"))
        if parsed_keys:
            if len(parsed_keys) > 1:
                lengths = {len(k) for k in parsed_keys}
                if len(lengths) > 1:
                    max_len = max(lengths)
                    parsed_keys = [bytes(k).rjust(max_len, b"\0") for k in parsed_keys]
                    bundle.warnings.append(
                        "RSA secrets padded to uniform length for analysis"
                    )
            bundle.keys = parsed_keys
            bundle.context.setdefault("parser", "rsa_private_exponent_v1")
            bundle.context.setdefault("parsed_components", "private_exponent")

    elif fam in {"ML-KEM", "ML-DSA"}:
        from . import params

        hint = params.find(mechanism) if mechanism else None
        extras = hint.extras if hint else {}
        parse_result: Optional["LatticeSecretParseResult"] = None

        if fam == "ML-KEM" and parse_ml_kem_secret_keys is not None:
            parse_result = parse_ml_kem_secret_keys(
                keys,
                k=extras.get("k"),
                eta1=extras.get("eta1"),
                n=extras.get("n", 256),
            )
        elif fam == "ML-DSA" and parse_ml_dsa_secret_keys is not None:
            parse_result = parse_ml_dsa_secret_keys(
                keys,
                k=extras.get("k"),
                l=extras.get("l"),
                eta=extras.get("eta"),
            )

        if parse_result is not None:
            if parse_result.coefficients:
                bundle.coefficients = parse_result.coefficients
                meta = dict(parse_result.context)
                meta.setdefault("keys_parsed", len(parse_result.coefficients))
                bundle.context["ternary_coefficients"] = meta
                bundle.context["parsed_components"] = "ternary_coefficients"
                bundle.context.setdefault("parser", parse_result.parser)
            bundle.warnings.extend(parse_result.warnings)

    return bundle


def derive_model(family: Optional[str], hint: Optional["ParamHint"]) -> KeyAnalysisModel:
    """Select an interpretation model based on family metadata."""
    if family and family.upper() == "HQC":
        extras = dict((hint.extras or {}) if hint else {})
        n = extras.get("n")
        w = extras.get("w")
        if isinstance(n, int) and isinstance(w, int) and n > 0:
            expected_hw = float(w) / float(n)
            expected_hd = (2.0 * float(w) * (1.0 - (float(w) / float(n)))) / float(n)
            notes = [
                "Constant-weight secret (binary vector of weight w).",
                "Expect exact Hamming weight w; deviations flag encoding bugs.",
            ]
            return KeyAnalysisModel(
                name="constant_weight",
                expected_hw_fraction=expected_hw,
                expected_hd_fraction=expected_hd,
                per_bit_reference=expected_hw,
                notes=notes,
                extras={"n": n, "w": w},
            )
        return KeyAnalysisModel(
            name="constant_weight",
            expected_hw_fraction=None,
            expected_hd_fraction=None,
            per_bit_reference=None,
            notes=[
                "HQC secret expected to be constant-weight, but parameter hint missing (n, w).",
                "Bit-level stats reported without theoretical expectations.",
            ],
        )

    if family and family.upper() == "BIKE":
        extras = dict((hint.extras or {}) if hint else {})
        r_bits = extras.get("r_bits")
        weight = extras.get("weight_per_vector")
        n0 = extras.get("n0", 2)
        if isinstance(r_bits, int) and isinstance(weight, int) and isinstance(n0, int) and r_bits > 0 and weight >= 0 and n0 > 0:
            total_bits = float(r_bits * n0)
            total_weight = float(weight * n0)
            p = total_weight / total_bits if total_bits else 0.0
            expected_hd = 2.0 * p * (1.0 - p) if total_bits else None
            notes = [
                f"Sparse BIKE secret (n0={n0}, r={r_bits}, weight {weight} per polynomial).",
                "Expect constant-weight binary vectors reconstructed from index lists.",
            ]
            return KeyAnalysisModel(
                name="constant_weight",
                expected_hw_fraction=p if total_bits else None,
                expected_hd_fraction=expected_hd,
                per_bit_reference=p if total_bits else None,
                notes=notes,
                extras={"r_bits": r_bits, "weight_per_vector": weight, "n0": n0},
            )
        return KeyAnalysisModel(
            name="constant_weight",
            expected_hw_fraction=None,
            expected_hd_fraction=None,
            per_bit_reference=None,
            notes=[
                "BIKE secret expected to be constant-weight, but parameter hints missing (r_bits, weight_per_vector).",
                "Bit-level stats reported without theoretical expectations.",
            ],
        )

    if family and family.upper() in {"ML-KEM", "ML-DSA", "FALCON"}:
        notes = [
            "Structured lattice secret; blob mixes seeds/compressed state.",
            "Treat bit-level HW/HD as coarse RNG sanity only.",
        ]
        return KeyAnalysisModel(
            name="structured_lattice_blob",
            expected_hw_fraction=0.5,
            expected_hd_fraction=0.5,
            per_bit_reference=0.5,
            notes=notes,
        )

    # Default: assume uniform random bits (RSA, SPHINCS, XMSS, MAYO, etc.).
    return KeyAnalysisModel(
        name="uniform_bitstring",
        expected_hw_fraction=0.5,
        expected_hd_fraction=0.5,
        per_bit_reference=0.5,
        notes=[],
    )


def _centered_binomial_distribution(eta: int) -> Dict[int, float]:
    """Return probability mass function for centered binomial with parameter eta."""
    if eta < 0:
        raise ValueError("eta must be non-negative")
    dist: Dict[int, float] = {}
    denom = float(1 << (2 * eta))
    for a in range(eta + 1):
        for b in range(eta + 1):
            value = a - b
            weight = math.comb(eta, a) * math.comb(eta, b)
            dist[value] = dist.get(value, 0.0) + weight / denom
    return dist


def summarize_secret_keys(
    keys: Sequence[bytes],
    *,
    model: KeyAnalysisModel,
    pair_sample_limit: int = DEFAULT_PAIR_SAMPLE_LIMIT,
    coefficients: Optional[Sequence[Sequence[Sequence[int]]]] = None,
    coefficient_meta: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    """Compute aggregate Hamming statistics for a collection of secret keys."""
    if not keys:
        raise ValueError("no keys provided for analysis")

    sample_count = len(keys)
    first = keys[0]
    if not isinstance(first, (bytes, bytearray)):
        raise TypeError("keys must be byte-like sequences")
    bit_len = len(first) * 8
    if bit_len == 0:
        raise ValueError("secret key length is zero bits")

    # Ensure all keys are consistent in length.
    for k in keys:
        if len(k) != len(first):
            raise ValueError("inconsistent secret key lengths across samples")

    hw_fracs: List[float] = []
    hw_counts: List[int] = []
    for k in keys:
        cnt = _popcount_bytes(k)
        hw_counts.append(cnt)
        hw_fracs.append(cnt / float(bit_len))

    hw_mean = statistics.mean(hw_fracs)
    hw_std = statistics.pstdev(hw_fracs) if sample_count > 1 else 0.0
    hw_min = min(hw_fracs)
    hw_max = max(hw_fracs)

    expected_hw = model.expected_hw_fraction
    expected_hd = model.expected_hd_fraction
    per_bit_reference = model.per_bit_reference if model.per_bit_reference is not None else expected_hw

    expected_bits_value: Optional[float]
    expected_fraction_value: Optional[float]
    if model.name == "constant_weight" and model.extras.get("w") is not None:
        expected_bits_value = float(model.extras["w"])
        expected_fraction_value = (
            expected_bits_value / float(bit_len) if bit_len > 0 else None
        )
    else:
        expected_bits_value = (expected_hw * bit_len) if expected_hw is not None else None
        expected_fraction_value = expected_hw

    byte_width = len(first)
    max_abs_byte_dev = 0.0
    mean_abs_byte_dev = 0.0
    if byte_width > 0:
        total_samples_bits = float(sample_count * 8)
        reference = per_bit_reference if per_bit_reference is not None else 0.5
        for idx in range(byte_width):
            ones = sum(_BYTE_POPCOUNT[key[idx]] for key in keys)
            frac = ones / total_samples_bits
            dev = abs(frac - reference)
            max_abs_byte_dev = max(max_abs_byte_dev, dev)
            mean_abs_byte_dev += dev
        mean_abs_byte_dev /= float(byte_width)

    hd_fracs: List[float] = []
    hd_counts: List[int] = []
    if sample_count > 1 and pair_sample_limit > 0:
        combos: Iterable[Tuple[int, int]] = combinations(range(sample_count), 2)
        for i, j in islice(combos, pair_sample_limit):
            hd = _hamming_distance(keys[i], keys[j])
            hd_counts.append(hd)
            hd_fracs.append(hd / float(bit_len))

    hd_samples = len(hd_fracs)
    if hd_samples:
        hd_mean = statistics.mean(hd_fracs)
        hd_std = statistics.pstdev(hd_fracs) if hd_samples > 1 else 0.0
        hd_min = min(hd_fracs)
        hd_max = max(hd_fracs)
    else:
        hd_mean = hd_std = hd_min = hd_max = None

    result: Dict[str, object] = {
        "method": "bitstring_hw_hd_v1",
        "model": {
            "name": model.name,
            "expected_hw_fraction": expected_hw,
            "expected_hd_fraction": expected_hd,
            "notes": list(model.notes),
            "extras": dict(model.extras),
        },
        "samples": sample_count,
        "bits_per_sample": bit_len,
        "hw": {
            "mean_fraction": hw_mean,
            "std_fraction": hw_std,
            "min_fraction": hw_min,
            "max_fraction": hw_max,
            "mean_bits": hw_mean * bit_len,
            "std_bits": hw_std * bit_len,
            "expected_fraction": expected_fraction_value,
            "expected_bits": expected_bits_value,
        },
        "hd": {
            "samples": hd_samples,
            "mean_fraction": hd_mean,
            "std_fraction": hd_std,
            "min_fraction": hd_min,
            "max_fraction": hd_max,
            "expected_fraction": expected_hd,
        },
        "byte_bias": {
            "reference_fraction": per_bit_reference,
            "max_abs_deviation": max_abs_byte_dev,
            "mean_abs_deviation": mean_abs_byte_dev,
        },
        "pair_sample_limit": pair_sample_limit,
        "warnings": [],
    }

    # Optional uniform-band checks (only meaningful for uniform model).
    if bit_len > 0 and model.name == "uniform_bitstring" and expected_hw is not None:
        sigma = 1.0 / (2.0 * math.sqrt(bit_len))
        band = (max(0.0, expected_hw - 3.0 * sigma), min(1.0, expected_hw + 3.0 * sigma))
        result["hw"]["three_sigma_band"] = band
        if sigma > 0.0:
            z_score = (hw_mean - expected_hw) / sigma
            result["hw"]["z_score_vs_uniform"] = z_score
            if abs(z_score) > 3.0:
                result["warnings"].append(
                    f"mean HW fraction {hw_mean:.4f} outside ±3σ band around {expected_hw:.3f}"
                )
    elif model.name == "constant_weight" and model.extras.get("w") is not None:
        expected_w = float(model.extras["w"])
        observed = statistics.mean(hw_counts)
        if abs(observed - expected_w) > 0.5:
            result["warnings"].append(
                f"mean HW (bits) {observed:.2f} deviates from expected weight {expected_w:.0f}"
            )

    if coefficients is not None:
        if len(coefficients) != sample_count:
            raise ValueError("coefficient samples must align with secret key samples")
        flat_samples: List[List[int]] = []
        non_zero_fracs: List[float] = []
        value_min: Optional[int] = None
        value_max: Optional[int] = None

        polynomials_per_sample: Optional[int] = None
        coeffs_per_polynomial: Optional[int] = None

        for coeff_sample in coefficients:
            if polynomials_per_sample is None:
                polynomials_per_sample = len(coeff_sample)
            elif polynomials_per_sample != len(coeff_sample):
                raise ValueError("inconsistent polynomial counts across coefficient samples")
            if coeff_sample:
                coeff_len = len(coeff_sample[0])
                if coeffs_per_polynomial is None:
                    coeffs_per_polynomial = coeff_len
                elif coeffs_per_polynomial != coeff_len:
                    raise ValueError("inconsistent coefficient lengths across samples")
            flat = _flatten_coefficients(coeff_sample)
            if not flat:
                raise ValueError("coefficient sample contains empty polynomial")
            flat_samples.append(flat)
            total = len(flat)
            nz = sum(1 for c in flat if c != 0)
            non_zero_fracs.append(nz / float(total))
            sample_min = min(flat)
            sample_max = max(flat)
            value_min = sample_min if value_min is None else min(value_min, sample_min)
            value_max = sample_max if value_max is None else max(value_max, sample_max)

        polynomials_per_sample = polynomials_per_sample or 0
        coeffs_per_polynomial = coeffs_per_polynomial or 0
        coeffs_per_sample = polynomials_per_sample * coeffs_per_polynomial

        nz_mean = statistics.mean(non_zero_fracs)
        nz_std = statistics.pstdev(non_zero_fracs) if sample_count > 1 else 0.0
        nz_min = min(non_zero_fracs)
        nz_max = max(non_zero_fracs)

        coeff_pair_fracs: List[float] = []
        if sample_count > 1 and pair_sample_limit > 0:
            combos = combinations(range(sample_count), 2)
            for i, j in islice(combos, pair_sample_limit):
                a = flat_samples[i]
                b = flat_samples[j]
                if len(a) != len(b):
                    raise ValueError("coefficient samples must have equal length per key")
                diff = sum(1 for x, y in zip(a, b) if x != y)
                coeff_pair_fracs.append(diff / float(len(a)))

        if coeff_pair_fracs:
            coeff_pair_mean = statistics.mean(coeff_pair_fracs)
            coeff_pair_std = statistics.pstdev(coeff_pair_fracs) if len(coeff_pair_fracs) > 1 else 0.0
            coeff_pair_min = min(coeff_pair_fracs)
            coeff_pair_max = max(coeff_pair_fracs)
        else:
            coeff_pair_mean = coeff_pair_std = coeff_pair_min = coeff_pair_max = None

        expected_non_zero = None
        expected_pair_diff = None
        eta_value = None
        distribution = None
        if coefficient_meta:
            eta_raw = coefficient_meta.get("eta")
            if isinstance(eta_raw, int) and eta_raw >= 0:
                eta_value = eta_raw
            distribution_raw = coefficient_meta.get("distribution")
            if isinstance(distribution_raw, str):
                distribution = distribution_raw

        if eta_value is not None:
            if distribution == "uniform_eta":
                support = 2 * eta_value + 1
                if support > 0:
                    expected_non_zero = (support - 1) / float(support)
                    expected_pair_diff = (support - 1) / float(support)
            else:
                dist = _centered_binomial_distribution(eta_value)
                expected_non_zero = 1.0 - dist.get(0, 0.0)
                expected_pair_diff = 1.0 - sum(p * p for p in dist.values())

        coeff_section: Dict[str, object] = {
            "polynomials_per_sample": polynomials_per_sample,
            "coefficients_per_polynomial": coeffs_per_polynomial,
            "coefficients_per_sample": coeffs_per_sample,
            "value_range": {
                "min": value_min,
                "max": value_max,
            },
            "non_zero": {
                "mean_fraction": nz_mean,
                "std_fraction": nz_std,
                "min_fraction": nz_min,
                "max_fraction": nz_max,
                "expected_fraction": expected_non_zero,
            },
            "pairwise_difference": {
                "samples": len(coeff_pair_fracs),
                "mean_fraction": coeff_pair_mean,
                "std_fraction": coeff_pair_std,
                "min_fraction": coeff_pair_min,
                "max_fraction": coeff_pair_max,
                "expected_fraction": expected_pair_diff,
            },
        }

        if coefficient_meta:
            coeff_section.update(
                {
                    "segments": coefficient_meta.get("segments"),
                    "eta": eta_value,
                    "keys_parsed": coefficient_meta.get("keys_parsed"),
                    "distribution": distribution,
                }
            )

        result["coefficients"] = coeff_section

        # Preserve original bitstring stats for reference before overriding.
        result["bitstring"] = {
            "bits_per_sample": bit_len,
            "hw": dict(result["hw"]),
            "hd": dict(result["hd"]),
            "byte_bias": dict(result["byte_bias"]),
        }

        # Derive a model name reflecting coefficient domain when expectations are available.
        if distribution == "uniform_eta":
            model_name = "uniform_eta_coefficients"
            model_notes = [
                "Coefficient domain treated as uniform over [-eta, eta].",
                "Secret stats derived from packed ML-DSA ternary coefficients.",
            ]
        else:
            model_name = "centered_binomial_coefficients"
            model_notes = [
                "Coefficient domain sampled via centered binomial distribution.",
                "Secret stats derived from packed ML-KEM ternary coefficients.",
            ]

        result["model"].update(
            {
                "name": model_name,
                "expected_hw_fraction": expected_non_zero,
                "expected_hd_fraction": expected_pair_diff,
                "notes": model_notes,
                "extras": {
                    **model.extras,
                    "eta": eta_value,
                    "distribution": distribution,
                    "coefficients_per_sample": coeffs_per_sample,
                },
            }
        )

        expected_bits_coeff = (
            expected_non_zero * coeffs_per_sample if expected_non_zero is not None else None
        )
        result["bits_per_sample"] = coeffs_per_sample
        result["hw"].update(
            {
                "mean_fraction": nz_mean,
                "std_fraction": nz_std,
                "min_fraction": nz_min,
                "max_fraction": nz_max,
                "mean_bits": nz_mean * coeffs_per_sample,
                "std_bits": nz_std * coeffs_per_sample,
                "expected_fraction": expected_non_zero,
                "expected_bits": expected_bits_coeff,
            }
        )

        result["hd"].update(
            {
                "samples": len(coeff_pair_fracs),
                "mean_fraction": coeff_pair_mean,
                "std_fraction": coeff_pair_std,
                "min_fraction": coeff_pair_min,
                "max_fraction": coeff_pair_max,
                "expected_fraction": expected_pair_diff,
            }
        )

        result["byte_bias"] = {
            "reference_fraction": expected_non_zero,
            "max_abs_deviation": None,
            "mean_abs_deviation": None,
        }

    return result

    # pragma: no cover - dead code guard


def _flatten_coefficients(sample: Sequence[Sequence[int]]) -> List[int]:
    flat: List[int] = []
    for poly in sample:
        flat.extend(poly)
    return flat


__all__ = [
    "DEFAULT_SECRET_KEY_SAMPLES",
    "DEFAULT_PAIR_SAMPLE_LIMIT",
    "KeyAnalysisModel",
    "PreparedKeyBundle",
    "derive_model",
    "prepare_keys_for_analysis",
    "summarize_secret_keys",
]
