from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path
from typing import Iterable
import sys
import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "libs" / "core" / "src"))

from pqcbench.key_analysis import (
    DEFAULT_PAIR_SAMPLE_LIMIT,
    DEFAULT_SECRET_KEY_SAMPLES,
    derive_model,
    prepare_keys_for_analysis,
    summarize_secret_keys,
)
from pqcbench.lattice_secret_parser import (
    _dilithium_polyeta_pack,
    _mlkem_ntt,
    _mlkem_poly_tobytes,
)
from pqcbench import params


def _uniform_keys(count: int, length: int) -> list[bytes]:
    # Deterministic pseudo-random bytes (linear feedback style) to keep tests stable.
    out: list[bytes] = []
    seed = 0xACE5
    for _ in range(count):
        buf = bytearray(length)
        for i in range(length):
            seed = (1103515245 * seed + 12345) & 0x7FFFFFFF
            buf[i] = seed & 0xFF
        out.append(bytes(buf))
    return out


def _constant_weight_keys(count: int, length_bits: int, weight: int) -> list[bytes]:
    """Construct simple constant-weight bitstrings for tests."""
    if weight > length_bits:
        raise ValueError("weight cannot exceed length")
    if length_bits % 8 != 0:
        raise ValueError("length_bits must be divisible by 8 for this helper")
    out: list[bytes] = []
    base_bits = [1] * weight + [0] * (length_bits - weight)
    for idx in range(count):
        shift = idx % length_bits
        rotated = base_bits[shift:] + base_bits[:shift]
        value = 0
        for bit in rotated:
            value = (value << 1) | bit
        out.append(value.to_bytes(length_bits // 8, "big"))
    return out


def test_uniform_model_has_reasonable_band():
    keys = _uniform_keys(16, 32)
    model = derive_model(family="RSA", hint=None)
    summary = summarize_secret_keys(keys, model=model, pair_sample_limit=32)
    assert summary["samples"] == 16
    assert summary["bits_per_sample"] == 32 * 8
    assert summary["model"]["name"] == "uniform_bitstring"
    assert "three_sigma_band" in summary["hw"]
    assert "warnings" in summary


def test_uniform_model_flags_bias():
    biased_key = bytes([0xFF] * 32)
    summary = summarize_secret_keys([biased_key] * 8, model=derive_model("RSA", None), pair_sample_limit=4)
    assert summary["hw"]["mean_fraction"] == 1.0
    assert summary["warnings"], "Expected warning for highly biased key bits"


def test_constant_weight_model_matches_expectations():
    length_bits = 16
    weight = 4
    keys = _constant_weight_keys(12, length_bits, weight)
    hint = SimpleNamespace(extras={"n": length_bits, "w": weight}, category_floor=128, notes="test")
    model = derive_model("HQC", hint)
    summary = summarize_secret_keys(keys, model=model, pair_sample_limit=16)
    assert summary["model"]["name"] == "constant_weight"
    expected_hw = weight / length_bits
    assert abs(summary["hw"]["mean_fraction"] - expected_hw) < 1e-6
    assert summary["warnings"] == []


def test_defaults_exported_constants():
    assert DEFAULT_SECRET_KEY_SAMPLES > 0
    assert DEFAULT_PAIR_SAMPLE_LIMIT > 0


def test_prepare_keys_for_analysis_invokes_hqc_parser():
    from pqcbench.hqc_secret_parser import resolve_variant  # local import to avoid cycles

    variant = resolve_variant("HQC-128", None)
    assert variant is not None
    seed = bytes(range(variant.seed_bytes))
    sigma = bytes(variant.sigma_bytes)
    pk = bytes(variant.public_key_bytes)
    secret_key = seed + sigma + pk
    prepared = prepare_keys_for_analysis([secret_key], family="HQC", mechanism="HQC-128")
    if prepared.context.get("parser") == "hqc_seed_constant_weight_v1":
        assert len(prepared.keys) == 1
        bitstring = prepared.keys[0]
        assert len(bitstring) >= variant.vector_byte_length
        hw = sum(bin(byte).count("1") for byte in bitstring)
        assert 0 < hw <= variant.n
    else:
        # On older Python versions the parser may be unavailable (bit_count missing).
        assert prepared.warnings


def test_prepare_keys_for_analysis_rsa_normalises_length():
    keys = []
    for bits in (2048, 2048):
        sk = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        sk_bytes = sk.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        keys.append(sk_bytes)

    prepared = prepare_keys_for_analysis(keys, family="RSA", mechanism="rsa-pss")
    assert len(prepared.keys) == 2
    assert len(prepared.keys[0]) == len(prepared.keys[1])


def test_prepare_keys_for_analysis_bike_constant_weight():
    from pqcbench.bike_secret_parser import parse_bike_secret_keys

    r_bits = 12323
    weight = 71
    n0 = 2
    r_bytes = (r_bits + 7) // 8

    # Construct synthetic BIKE secret key matching liboqs layout (wlist + h0 + h1 + pk + sigma)
    h0_indices = list(range(weight))
    h1_indices = list(range(weight, 2 * weight))
    raw = bytearray()
    for idx in h0_indices + h1_indices:
        raw.extend(idx.to_bytes(4, "little"))

    def build_sparse(indices: Iterable[int]) -> bytes:
        buf = bytearray(r_bytes)
        for position in indices:
            byte_pos = position // 8
            bit_pos = position % 8
            buf[byte_pos] |= 1 << bit_pos
        excess = (r_bytes * 8) - r_bits
        if excess:
            mask = (1 << (8 - excess)) - 1
            buf[-1] &= mask
        return bytes(buf)

    h0_bytes = build_sparse(h0_indices)
    h1_bytes = build_sparse(h1_indices)
    raw.extend(h0_bytes)
    raw.extend(h1_bytes)
    raw.extend(b"\0" * r_bytes)  # public key (unused by parser)
    raw.extend(b"\0" * 32)       # sigma seed

    parsed = parse_bike_secret_keys([bytes(raw)], r_bits=r_bits, weight_per_vector=weight, n0=n0)
    assert parsed is not None
    assert len(parsed.bitstrings) == 1
    bitstring = parsed.bitstrings[0]
    assert len(bitstring) == r_bytes * n0
    total_weight = sum(bin(b).count("1") for b in bitstring)
    assert total_weight == weight * n0

    prepared = prepare_keys_for_analysis([bytes(raw)], family="BIKE", mechanism="BIKE-L1")
    assert prepared.context.get("parser") == "bike_constant_weight_v1"
    assert sum(bin(b).count("1") for b in prepared.keys[0]) == weight * n0


def _make_mlkem_secret_bytes(mechanism: str, coeffs: list[list[int]]) -> bytes:
    hint = params.find(mechanism)
    assert hint is not None and hint.extras is not None
    extras = hint.extras
    k = extras["k"]
    secret_len = extras["sizes_bytes"]["secret_key"]
    poly_bytes = 384
    packed = bytearray()
    for poly in coeffs:
        assert len(poly) == 256
        ntt = _mlkem_ntt(poly)
        packed.extend(_mlkem_poly_tobytes(ntt))
    packed.extend(b"\0" * (secret_len - len(packed)))
    return bytes(packed)


def _make_mldsa_secret_bytes(mechanism: str, s1: list[list[int]], s2: list[list[int]]) -> bytes:
    hint = params.find(mechanism)
    assert hint is not None and hint.extras is not None
    extras = hint.extras
    k = extras["k"]
    l = extras["l"]
    eta = extras["eta"]
    secret_len = extras["sizes_bytes"]["secret_key"]
    prefix = 32 + 32 + 64
    expected_poly_count = l + k
    assert len(s1) == l and len(s2) == k
    body = bytearray()
    for vec in (s1, s2):
        for poly in vec:
            assert len(poly) == 256
            body.extend(_dilithium_polyeta_pack(poly, eta))
    total = bytearray(prefix)
    total.extend(body)
    if len(total) < secret_len:
        total.extend(b"\0" * (secret_len - len(total)))
    assert len(total) == secret_len
    assert len(s1) + len(s2) == expected_poly_count
    return bytes(total)


def test_coefficient_expectations_uniform_eta():
    keys = _uniform_keys(2, 8)
    coeffs = [
        [[-4, -3, -2, -1]],
        [[0, 1, 2, 3]],
    ]
    meta = {
        "eta": 4,
        "segments": [{"name": "s", "count": 1}],
        "keys_parsed": len(coeffs),
        "distribution": "uniform_eta",
    }
    model = derive_model("ML-DSA", SimpleNamespace(extras={}, category_floor=1, notes="test"))
    summary = summarize_secret_keys(
        keys,
        model=model,
        pair_sample_limit=1,
        coefficients=coeffs,
        coefficient_meta=meta,
    )
    coeff_section = summary["coefficients"]
    assert coeff_section["eta"] == 4
    expected = (2 * 4 + 1 - 1) / float(2 * 4 + 1)
    assert coeff_section["non_zero"]["expected_fraction"] == pytest.approx(expected)
    assert coeff_section["pairwise_difference"]["expected_fraction"] == pytest.approx(expected)
    assert summary["bits_per_sample"] == 4
    assert summary["model"]["name"] == "uniform_eta_coefficients"
    assert summary["hw"]["mean_fraction"] == pytest.approx(coeff_section["non_zero"]["mean_fraction"])


def test_prepare_keys_for_analysis_mlkem_coefficients():
    coeffs = [[0] * 256 for _ in range(3)]
    coeffs[0][0] = 1
    coeffs[1][1] = -1
    coeffs[2][2] = 2
    key_bytes = _make_mlkem_secret_bytes("ML-KEM-768", coeffs)
    bundle = prepare_keys_for_analysis(
        [key_bytes], family="ML-KEM", mechanism="ML-KEM-768"
    )
    assert bundle.coefficients is not None
    assert len(bundle.coefficients) == 1
    parsed_polys = bundle.coefficients[0]
    assert len(parsed_polys) == 3
    assert parsed_polys[0][0] == 1
    assert parsed_polys[1][1] == -1
    assert parsed_polys[2][2] == 2
    meta = bundle.context.get("ternary_coefficients")
    assert meta and meta.get("eta") == 2


def test_prepare_keys_for_analysis_mldsa_coefficients():
    s1 = [[0] * 256 for _ in range(5)]
    s2 = [[0] * 256 for _ in range(6)]
    s1[0][0] = -4
    s2[1][1] = 3
    key_bytes = _make_mldsa_secret_bytes("ML-DSA-65", s1, s2)
    bundle = prepare_keys_for_analysis(
        [key_bytes], family="ML-DSA", mechanism="ML-DSA-65"
    )
    assert bundle.coefficients is not None
    assert len(bundle.coefficients[0]) == 11
    assert bundle.coefficients[0][0][0] == -4
    assert bundle.coefficients[0][5 + 1][1] == 3
    meta = bundle.context.get("ternary_coefficients")
    assert meta and meta.get("eta") == 4


def test_summarize_secret_keys_reports_coefficient_stats():
    keys = _uniform_keys(4, 8)
    coeffs = [
        [[0, 1, 0, -1]],
        [[0, 0, 0, 0]],
        [[1, 0, 0, 0]],
        [[-1, 1, 0, 0]],
    ]
    meta = {
        "eta": 2,
        "segments": [{"name": "s", "count": 1}],
        "keys_parsed": len(coeffs),
        "distribution": "centered_binomial",
    }
    model = derive_model("ML-KEM", SimpleNamespace(extras={}, category_floor=1, notes="test"))
    summary = summarize_secret_keys(
        keys,
        model=model,
        pair_sample_limit=6,
        coefficients=coeffs,
        coefficient_meta=meta,
    )
    coeff_section = summary.get("coefficients")
    assert coeff_section is not None
    assert coeff_section["polynomials_per_sample"] == 1
    assert coeff_section["coefficients_per_polynomial"] == 4
    assert coeff_section["non_zero"]["mean_fraction"] == pytest.approx(0.3125)
    assert coeff_section["eta"] == 2
    assert coeff_section["non_zero"]["expected_fraction"] == pytest.approx(0.625)
    assert coeff_section["pairwise_difference"]["expected_fraction"] == pytest.approx(93 / 128)
    assert summary["bits_per_sample"] == 4
    assert summary["model"]["name"] == "centered_binomial_coefficients"
    assert summary["model"]["expected_hw_fraction"] == pytest.approx(0.625)
    assert summary["hw"]["mean_fraction"] == pytest.approx(0.3125)
    assert "bitstring" in summary
    assert summary["bitstring"]["bits_per_sample"] == 64
