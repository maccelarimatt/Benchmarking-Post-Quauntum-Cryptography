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
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except Exception:  # pragma: no cover - cryptography optional at runtime
    serialization = None  # type: ignore
    rsa = None  # type: ignore

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


def summarize_secret_keys(
    keys: Sequence[bytes],
    *,
    model: KeyAnalysisModel,
    pair_sample_limit: int = DEFAULT_PAIR_SAMPLE_LIMIT,
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

    return result


__all__ = [
    "DEFAULT_SECRET_KEY_SAMPLES",
    "DEFAULT_PAIR_SAMPLE_LIMIT",
    "KeyAnalysisModel",
    "PreparedKeyBundle",
    "derive_model",
    "prepare_keys_for_analysis",
    "summarize_secret_keys",
]
