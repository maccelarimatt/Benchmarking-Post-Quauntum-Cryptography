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
    _estimate_falcon_from_name,
    _estimate_hqc_from_name,
    _estimate_rsa_from_meta,
    _estimate_mayo_from_name,
    _estimate_sphincs_from_name,
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


def test_falcon_bkz_model_present():
    metrics = _estimate_falcon_from_name("Falcon-512", EstimatorOptions())
    falcon_extras = metrics.extras.get("falcon", {})
    model = falcon_extras.get("bkz_model")
    assert model, "expected bkz_model metadata"
    attacks = model.get("attacks") or []
    assert attacks and all(entry.get("beta_curve") for entry in attacks)
    sample_curve = attacks[0]["beta_curve"][0]
    assert "classical_bits" in sample_curve and "success_margin_bits" in sample_curve
    assert "calibrated_margin_bits" in sample_curve
    calib = attacks[0].get("calibration_reference")
    if calib:
        assert "beta" in calib


def test_standardize_security_falcon_exposes_bkz_details():
    metrics = _estimate_falcon_from_name("Falcon-512", EstimatorOptions())
    sec_dict = asdict(metrics)
    sec_dict["extras"] = metrics.extras
    sec_dict["mechanism"] = "Falcon-512"
    summary = SimpleNamespace(algo="falcon", kind="SIG", meta={"mechanism": "Falcon-512"})
    formatted = _standardize_security(summary, sec_dict)
    details = formatted.get("details", {})
    model = details.get("falcon_bkz_model")
    assert model
    curve = model.get("attacks", [])[0]["beta_curve"][0]
    assert "calibrated_margin_bits" in curve


def test_hqc_isd_models_present():
    metrics = _estimate_hqc_from_name("HQC-128", EstimatorOptions())
    isd = (metrics.extras.get("isd") or {})
    assert "stern_entropy" in isd and "bjmm" in isd
    assert isd["stern_entropy"]["time_bits_classical"] >= 0.0
    assert len(isd.get("w_sensitivity", [])) >= 3
    sec_dict = asdict(metrics)
    sec_dict["extras"] = metrics.extras
    sec_dict["mechanism"] = "HQC-128"
    summary = SimpleNamespace(algo="hqc", kind="KEM", meta={"mechanism": "HQC-128"})
    formatted = _standardize_security(summary, sec_dict)
    assert formatted.get("estimates", {}).get("hqc_isd")


def test_sphincs_sanity_and_structure():
    metrics = _estimate_sphincs_from_name("SPHINCS+-SHAKE-128s-simple")
    sx = metrics.extras["sphincs"]
    sanity = sx["sanity"]
    assert sanity["classical_floor_bits"] == float(metrics.classical_bits)
    assert sanity.get("fors_height") is not None
    structure = sx.get("structure") or {}
    assert structure.get("layers") == 7
    sec_dict = asdict(metrics)
    sec_dict["extras"] = metrics.extras
    sec_dict["mechanism"] = "SPHINCS+-SHAKE-128s-simple"
    summary = SimpleNamespace(algo="sphincsplus", kind="SIG", meta={"mechanism": "SPHINCS+-SHAKE-128s-simple"})
    formatted = _standardize_security(summary, sec_dict)
    estimates = formatted.get("estimates", {})
    assert estimates.get("sanity")


def test_mayo_checks_present():
    metrics = _estimate_mayo_from_name("MAYO-1")
    mayo = metrics.extras.get("mayo", {})
    checks = mayo.get("checks", {})
    assert "rank_attack" in checks and checks["rank_attack"].get("risk")
    assert "minrank" in checks and checks["minrank"].get("bits") is not None
    sec_dict = asdict(metrics)
    sec_dict["extras"] = metrics.extras
    sec_dict["mechanism"] = "MAYO-1"
    summary = SimpleNamespace(algo="mayo", kind="SIG", meta={"mechanism": "MAYO-1"})
    formatted = _standardize_security(summary, sec_dict)
    assert formatted.get("estimates", {}).get("checks")


def test_rsa_shor_profiles_present():
    metrics = _estimate_rsa_from_meta("SIG", {"signature_len": 256}, EstimatorOptions())
    profiles = metrics.extras.get("shor_profiles")
    assert profiles
    moduli = profiles.get("moduli", [])
    bits_list = [entry.get("modulus_bits") for entry in moduli]
    assert set([2048, 3072, 4096]).issubset(set(bits_list))
    first_entry = moduli[0]
    scenarios = first_entry.get("scenarios")
    assert scenarios and {s.get("label") for s in scenarios} == {"optimistic", "median", "conservative"}
    assert "phys_qubits_total" in scenarios[0]
