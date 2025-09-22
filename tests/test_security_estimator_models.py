from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "libs" / "core" / "src"))
sys.path.append(str(ROOT / "apps" / "cli" / "src"))

from pqcbench_cli.runners.common import _standardize_security

from pqcbench.security_estimator import (
    _estimate_dilithium_from_name,
    _estimate_kyber_from_name,
    EstimatorOptions,
)


def test_module_lwe_cost_headline_kyber():
    metrics = _estimate_kyber_from_name("ML-KEM-512", EstimatorOptions())
    cost = metrics.extras.get("mlkem", {}).get("module_lwe_cost")
    assert cost, "expected module_lwe_cost in extras"
    headline = cost["headline"]
    assert 134.0 <= headline["classical_bits"] <= 140.0
    assert metrics.classical_bits == headline["classical_bits"]
    assert metrics.quantum_bits == headline["quantum_bits"]
    assert cost["classical_bits_range"][0] < cost["classical_bits_range"][1]
    assert metrics.extras.get("category_floor") == 128


def test_module_lwe_cost_headline_dilithium():
    metrics = _estimate_dilithium_from_name("ML-DSA-65", EstimatorOptions())
    cost = metrics.extras.get("mldsa", {}).get("module_lwe_cost")
    assert cost, "expected module_lwe_cost in extras"
    headline = cost["headline"]
    assert 165.0 <= headline["classical_bits"] <= 175.0
    assert metrics.classical_bits == headline["classical_bits"]
    assert metrics.quantum_bits == headline["quantum_bits"]
    lo, hi = cost["classical_bits_range"]
    assert lo <= headline["classical_bits"] <= hi


def test_standardize_security_includes_calculated_range():
    metrics = _estimate_kyber_from_name("ML-KEM-512", EstimatorOptions())
    sec_dict = asdict(metrics)
    sec_dict["extras"] = metrics.extras
    sec_dict["mechanism"] = "ML-KEM-512"
    summary = SimpleNamespace(algo="kyber", kind="KEM", meta={"mechanism": "ML-KEM-512"})
    formatted = _standardize_security(summary, sec_dict)
    assert "calculated" in formatted["estimates"]
    calc = formatted["estimates"]["calculated"]
    assert calc["classical_bits"] == metrics.classical_bits
    ml_model = formatted.get("assumptions", {}).get("module_lwe_model")
    assert ml_model
    assert ml_model["dimension"] == metrics.extras["mlkem"]["module_lwe_cost"]["dimension"]
    assert "module_lwe_profile_constants" in formatted.get("assumptions", {})
    assert formatted.get("details", {}).get("module_lwe_profiles")
    assert formatted.get("details", {}).get("module_lwe_attacks")
