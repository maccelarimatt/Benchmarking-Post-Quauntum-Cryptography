from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path
import sys

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
