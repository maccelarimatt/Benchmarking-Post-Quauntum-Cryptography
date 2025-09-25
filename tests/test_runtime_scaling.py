from __future__ import annotations

import math

import pytest

import pqcbench.runtime_scaling as runtime_scaling
from pqcbench.runtime_scaling import (
    DeviceProfile,
    RuntimeScalingResult,
    alpha_for_algorithm,
    build_runtime_scaling,
    host_bandwidth_score,
    load_device_profiles,
    resolve_baseline_profile,
    scale_runtime,
)


@pytest.fixture(autouse=True)
def _reset_bandwidth_cache():
    runtime_scaling._HOST_BANDWIDTH_CACHE = None
    yield
    runtime_scaling._HOST_BANDWIDTH_CACHE = None


def test_scale_runtime_compute_only() -> None:
    baseline = DeviceProfile(
        name="baseline",
        compute_metric="geekbench6_single",
        compute_score=2974.0,
    )
    target = DeviceProfile(
        name="target",
        compute_metric="geekbench6_single",
        compute_score=3289.0,
    )
    predicted, compute_ratio, bw_ratio, model = scale_runtime(
        5.0,
        baseline,
        target,
        alpha=1.0,
    )
    expected = 5.0 * (2974.0 / 3289.0)
    assert math.isclose(predicted, expected, rel_tol=1e-9)
    assert math.isclose(compute_ratio, 2974.0 / 3289.0, rel_tol=1e-9)
    assert bw_ratio is None
    assert model == "compute_only"


def test_scale_runtime_two_term() -> None:
    baseline = DeviceProfile(
        name="baseline",
        compute_metric="geekbench6_single",
        compute_score=2974.0,
        bandwidth_metric="memcpy_gbps",
        bandwidth_score=90.0,
    )
    target = DeviceProfile(
        name="target",
        compute_metric="geekbench6_single",
        compute_score=3289.0,
        bandwidth_metric="memcpy_gbps",
        bandwidth_score=110.0,
    )
    predicted, compute_ratio, bw_ratio, model = scale_runtime(
        5.0,
        baseline,
        target,
        alpha=0.8,
    )
    expected_factor = 0.8 * (2974.0 / 3289.0) + 0.2 * (90.0 / 110.0)
    assert math.isclose(predicted, 5.0 * expected_factor, rel_tol=1e-9)
    assert math.isclose(compute_ratio, 2974.0 / 3289.0, rel_tol=1e-9)
    assert math.isclose(bw_ratio or 0.0, 90.0 / 110.0, rel_tol=1e-9)
    assert model == "two_term"


def test_alpha_for_algorithm_defaults() -> None:
    assert alpha_for_algorithm("kyber768") == 0.85
    assert alpha_for_algorithm("Falcon-1024") == 0.85
    assert alpha_for_algorithm("SPHINCS+ SHAKE") == 0.75
    assert alpha_for_algorithm("hqc256") == 0.65
    assert alpha_for_algorithm("mayo-1") == 0.7
    assert alpha_for_algorithm("unknown") == 0.8


def test_resolve_baseline_profile_from_cpu_model() -> None:
    profiles = load_device_profiles(None)
    baseline = resolve_baseline_profile(
        profiles,
        cpu_model="AMD Ryzen 9 7950X 16-Core Processor",
        env={},
    )
    assert baseline is not None
    assert baseline.name == "amd_ryzen_9_7950x"


def test_resolve_baseline_profile_handles_parentheses_noise() -> None:
    profiles = load_device_profiles(None)
    CPU = "Intel(R) Core(TM) i9-14900K"
    baseline = resolve_baseline_profile(profiles, cpu_model=CPU, env={})
    assert baseline is not None
    assert baseline.name == "intel_i9_14900k"


def test_resolve_baseline_profile_env_override() -> None:
    profiles = load_device_profiles(None)
    baseline = resolve_baseline_profile(
        profiles,
        cpu_model=None,
        env={
            "PQCBENCH_BASELINE_COMPUTE_SCORE": "1500",
            "PQCBENCH_BASELINE_COMPUTE_METRIC": "custom",
        },
    )
    assert baseline is not None
    assert baseline.compute_score == 1500.0
    assert baseline.compute_metric == "custom"


def test_resolve_baseline_profile_estimates_unknown_cpu() -> None:
    profiles = load_device_profiles(None)
    baseline = resolve_baseline_profile(
        profiles,
        cpu_model="Intel(R) Core(TM) i9-9880H CPU @ 2.30GHz",
        env={},
    )
    assert baseline is not None
    assert baseline.name == "macbookpro16_i9_9880h"


def test_build_runtime_scaling_with_defaults() -> None:
    profiles = load_device_profiles(None)
    scaling = build_runtime_scaling(
        mean_ms=10.0,
        algo="kyber768",
        op="keygen",
        cpu_model="AMD Ryzen 9 7950X",
        profiles=profiles,
        env={},
    )
    assert isinstance(scaling, RuntimeScalingResult)
    assert scaling.baseline_device == "amd_ryzen_9_7950x"
    assert "intel_i9_14900k" in scaling.predictions
    prediction = scaling.predictions["intel_i9_14900k"]
    assert prediction.model == "two_term"
    compute_ratio = 2974.0 / 3289.0
    bandwidth_ratio = 110.0 / 120.0
    expected_factor = 0.85 * compute_ratio + 0.15 * bandwidth_ratio
    expected = 10.0 * expected_factor
    assert math.isclose(prediction.predicted_ms, expected, rel_tol=1e-9)
    assert math.isclose(prediction.factor, expected_factor, rel_tol=1e-9)


def test_build_runtime_scaling_two_term(monkeypatch) -> None:
    profiles = load_device_profiles(None)
    monkeypatch.setattr(runtime_scaling, "host_bandwidth_score", lambda env=None: 90.0)
    scaling = build_runtime_scaling(
        mean_ms=5.0,
        algo="kyber768",
        op="keygen",
        cpu_model="Intel(R) Core(TM) i9-9980H CPU @ 2.30GHz",
        profiles=profiles,
        env={},
    )
    assert isinstance(scaling, RuntimeScalingResult)
    # Baseline should be host_estimated with bandwidth injected.
    assert scaling.baseline_device == "host_estimated"
    assert scaling.model == "two_term"
    intel_pred = scaling.predictions["intel_i9_14900k"]
    assert intel_pred.model == "two_term"
    assert intel_pred.bandwidth_ratio is not None


def test_host_bandwidth_score_prefers_override() -> None:
    score = host_bandwidth_score({"PQCBENCH_BASELINE_BANDWIDTH_SCORE": "42.5"})
    assert math.isclose(score or 0.0, 42.5, rel_tol=1e-9)


def test_host_bandwidth_score_caches_measured_value(monkeypatch) -> None:
    monkeypatch.setattr(runtime_scaling, "_measure_memcpy_bandwidth", lambda **_: 12.34)
    score = host_bandwidth_score({})
    assert math.isclose(score or 0.0, 12.34, rel_tol=1e-9)
    # Change the measurement; cached value should still be returned.
    monkeypatch.setattr(runtime_scaling, "_measure_memcpy_bandwidth", lambda **_: 99.0)
    cached = host_bandwidth_score({})
    assert math.isclose(cached or 0.0, 12.34, rel_tol=1e-9)
