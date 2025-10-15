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
    _estimate_lattice_like_from_name,
    _estimate_bike_from_name,
    _estimate_classic_mceliece_from_name,
    EstimatorOptions,
)


def test_module_lwe_cost_headline_kyber():
    metrics = _estimate_kyber_from_name("ML-KEM-512", EstimatorOptions())
    cost = metrics.extras.get("mlkem", {}).get("module_lwe_cost")
    assert cost, "expected module_lwe_cost in extras"
    headline = cost["headline"]
    assert 146.0 <= headline["classical_bits"] <= 150.0
    assert 133.0 <= headline["quantum_bits"] <= 136.0
    assert metrics.classical_bits == headline["classical_bits"]
    assert metrics.quantum_bits == headline["quantum_bits"]
    assert metrics.extras.get("category_floor") == 128
    assert abs(cost["primal"]["beta"] - 508.0) < 0.5
    assert cost["source"] == "core-svp-spec-table"


def test_module_lwe_cost_headline_kyber_768():
    metrics = _estimate_kyber_from_name("ML-KEM-768", EstimatorOptions())
    assert metrics.classical_bits == 184.0
    cost = metrics.extras.get("mlkem", {}).get("module_lwe_cost")
    assert cost["source"] == "core-svp-spec-table"
    assert abs(cost["primal"]["beta"] - 630.0) < 0.5


def test_module_lwe_cost_headline_dilithium():
    metrics = _estimate_dilithium_from_name("ML-DSA-65", EstimatorOptions())
    cost = metrics.extras.get("mldsa", {}).get("module_lwe_cost")
    assert cost, "expected module_lwe_cost for Dilithium"
    headline = cost["headline"]
    assert 210.0 <= headline["classical_bits"] <= 225.0
    assert metrics.classical_bits == headline["classical_bits"]
    assert metrics.quantum_bits == headline["quantum_bits"]
    assert abs(cost["primal"]["beta"] - 746.0) < 0.5
    assert cost["source"] == "core-svp-spec-table"


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
    assert ml_model and isinstance(ml_model.get("params"), dict)
    core_details = formatted.get("details", {}).get("module_lwe_core_svp")
    assert core_details and core_details.get("primal")
    assert formatted.get("assumptions", {}).get("module_lwe_model", {}).get("source")
    standardization = formatted.get("standardization")
    assert standardization and standardization.get("label") == "FIPS 203"
    detail_rows = dict(formatted.get("detail_rows") or [])
    assert "Scheme parameters" in detail_rows
    assert "Headline β" in detail_rows


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
    headline = formatted.get("headline")
    assert headline["classical_bits"] == metrics.classical_bits == metrics.extras.get("category_floor")
    assert headline["quantum_bits"] == metrics.quantum_bits == metrics.extras.get("category_floor")


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
    detail_rows = dict(formatted.get("detail_rows") or [])
    assert "Hash suite" in detail_rows
    assert "Winternitz w" in detail_rows


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
    moduli = profiles.get("scenarios", [])
    bits_list = [int(entry.get("modulus_bits")) for entry in moduli]
    assert {2048, 3072, 4096}.issubset(set(bits_list))
    first_entry = moduli[0]
    scenarios = first_entry.get("scenarios")
    labels = {s.get("label") for s in scenarios}
    assert labels == {"ge-baseline", "optimistic", "conservative"}
    assert "phys_qubits_total" in scenarios[0]
    assert first_entry.get("logical", {}).get("model") == "ge2019"
    rd = scenarios[0].get("rate_details")
    assert rd and rd.get("rate_unit")
    assert any(key.startswith("factory_rate_peak_") for key in rd)
    assert "factory_utilization_target" in rd
    calib = metrics.extras.get("calibration", {})
    assert calib.get("baseline_delta_pct") is not None


def test_bike_isd_details_present():
    metrics = _estimate_bike_from_name("BIKE-L1")
    bike_extras = metrics.extras.get("bike", {})
    assert bike_extras.get("isd") is not None
    sec_dict = asdict(metrics)
    sec_dict["extras"] = metrics.extras
    sec_dict["mechanism"] = "BIKE-L1"
    summary = SimpleNamespace(algo="bike", kind="KEM", meta={"mechanism": "BIKE-L1"})
    formatted = _standardize_security(summary, sec_dict)
    detail_rows = dict(formatted.get("detail_rows") or [])
    assert "Stern time bits (classical)" in detail_rows
    assert "Grover factor" in detail_rows


def test_classic_mceliece_details_present():
    metrics = _estimate_classic_mceliece_from_name("Classic-McEliece-348864f")
    cm_extras = metrics.extras.get("classic_mceliece", {})
    assert cm_extras.get("curated_estimates") is not None
    sec_dict = asdict(metrics)
    sec_dict["extras"] = metrics.extras
    sec_dict["mechanism"] = "Classic-McEliece-348864f"
    summary = SimpleNamespace(algo="classic-mceliece", kind="KEM", meta={"mechanism": "Classic-McEliece-348864f"})
    formatted = _standardize_security(summary, sec_dict)
    detail_rows = dict(formatted.get("detail_rows") or [])
    assert "Classical attack" in detail_rows
    assert "Design classical bits" in detail_rows


def test_lattice_like_notes_when_advanced_not_supported():
    metrics = _estimate_lattice_like_from_name("sntrup761", EstimatorOptions(lattice_use_estimator=True))
    assert "Advanced estimator requested" in metrics.notes
    assert "APS modeling is not available" in metrics.notes
    extras = metrics.extras
    assert extras.get("estimator_available") is False
    assert extras.get("estimator_supported") is False
    assert metrics.classical_bits == 192.0
    sec_dict = asdict(metrics)
    sec_dict["extras"] = metrics.extras
    sec_dict["mechanism"] = "sntrup761"
    summary = SimpleNamespace(algo="ntruprime", kind="KEM", meta={"mechanism": "sntrup761"})
    formatted = _standardize_security(summary, sec_dict)
    headline = formatted["headline"]
    notes_joined = " ".join(headline.get("notes") or [])
    assert "APS modeling is not available" in notes_joined
    assert headline.get("estimator") == "floor (APS unavailable)"
