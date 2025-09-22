from __future__ import annotations

from pqcbench.hqc_secret_parser import parse_secret_keys, resolve_variant


def _make_secret_key_bytes(variant_name: str) -> bytes:
    variant = resolve_variant(variant_name, None)
    assert variant is not None
    seed = bytes(range(variant.seed_bytes))
    sigma = bytes(variant.sigma_bytes)
    pk = bytes(variant.public_key_bytes)
    return seed + sigma + pk


def test_parse_secret_keys_recovers_constant_weight_vector():
    sk = _make_secret_key_bytes("HQC-128")
    result = parse_secret_keys([sk], mechanism="HQC-128")
    assert result is not None
    assert result.parser == "hqc_seed_constant_weight_v1"
    assert result.context.get("bit_component") == "HQC secret vector x"
    assert len(result.bitstrings) == 1
    vector = result.bitstrings[0]
    variant = resolve_variant("HQC-128", None)
    assert variant is not None
    assert len(vector) == variant.vector_byte_length
    assert sum(byte.bit_count() for byte in vector) == variant.w
    assert not result.warnings


def test_parse_secret_keys_reports_length_mismatch():
    sk_good = _make_secret_key_bytes("HQC-128")
    sk_bad = sk_good[:-1]
    result = parse_secret_keys([sk_good, sk_bad], mechanism="HQC-128")
    assert result is not None
    assert len(result.bitstrings) == 1
    assert result.warnings and "does not match expected" in result.warnings[0]


def test_parse_secret_keys_falls_back_on_length_detection():
    sk = _make_secret_key_bytes("HQC-128")
    result = parse_secret_keys([sk], mechanism=None)
    assert result is not None
    assert result.context.get("variant", "").startswith("HQC-128")
