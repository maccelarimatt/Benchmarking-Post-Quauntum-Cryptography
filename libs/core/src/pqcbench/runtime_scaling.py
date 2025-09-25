"""Runtime scaling helpers for projecting measured latencies to other devices."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import json
import os
import pathlib
import statistics
import time
from typing import Dict, Iterable, Mapping, MutableMapping, Optional, Tuple


@dataclass(frozen=True)
class DeviceProfile:
    name: str
    compute_metric: str
    compute_score: float
    bandwidth_metric: str | None = None
    bandwidth_score: float | None = None
    notes: str | None = None
    aliases: Tuple[str, ...] = field(default_factory=tuple)

    def normalized_aliases(self) -> Tuple[str, ...]:
        return tuple(a.lower() for a in self.aliases)


@dataclass
class RuntimeScalingPrediction:
    device: str
    predicted_ms: float
    factor: float
    compute_ratio: float
    bandwidth_ratio: float | None
    model: str


@dataclass
class RuntimeScalingResult:
    baseline_device: str
    baseline_metric: str
    baseline_score: float
    alpha: float
    model: str
    predictions: Dict[str, RuntimeScalingPrediction]
    notes: str | None = None


_DEFAULT_DEVICE_PROFILES: Dict[str, DeviceProfile] = {
    "intel_i9_14900k": DeviceProfile(
        name="intel_i9_14900k",
        compute_metric="geekbench6_single",
        compute_score=3289.0,
        bandwidth_metric="memcpy_gbps",
        bandwidth_score=120.0,
        aliases=("14900k", "i9-14900k", "intel core i9-14900k"),
        notes="Geekbench 6 single-core ≈3289; STREAM copy ≈120 GB/s (DDR5-6400)",
    ),
    "amd_ryzen_9_7950x": DeviceProfile(
        name="amd_ryzen_9_7950x",
        compute_metric="geekbench6_single",
        compute_score=2974.0,
        bandwidth_metric="memcpy_gbps",
        bandwidth_score=110.0,
        aliases=("7950x", "ryzen 9 7950x", "amd ryzen 9 7950x"),
        notes="Geekbench 6 single-core ≈2974; STREAM copy ≈110 GB/s (DDR5-6000)",
    ),
    "esp32_s3": DeviceProfile(
        name="esp32_s3",
        compute_metric="coremark",
        compute_score=665.0,
        bandwidth_metric="memcpy_gbps",
        bandwidth_score=0.8,
        aliases=("esp32-s3", "esp32 s3"),
        notes="Single-core CoreMark ≈665 at 240 MHz; SRAM memcpy ≈0.8 GB/s",
    ),
    "nrf52840": DeviceProfile(
        name="nrf52840",
        compute_metric="coremark",
        compute_score=212.0,
        bandwidth_metric="memcpy_gbps",
        bandwidth_score=0.25,
        aliases=("nrf52840", "nrf52840 mcu"),
        notes="Single-core CoreMark ≈212 at 64 MHz; SRAM memcpy ≈0.25 GB/s",
    ),
    "macbookpro16_i9_9880h": DeviceProfile(
        name="macbookpro16_i9_9880h",
        compute_metric="geekbench6_single",
        compute_score=1329.0,
        bandwidth_metric="memcpy_gbps",
        bandwidth_score=8.1,
        aliases=(
            "intel core i9-9880h",
            "i9-9880h",
            "macbookpro16,1",
            "macbook pro 16-inch 2019",
        ),
        notes=(
            "MacBook Pro 16-inch (2019) median Geekbench 6 single-core ≈1329 (n≈19); "
            "Python memcpy probe (~32 MB) ≈8.1 GB/s"
        ),
    ),
}

_HOST_BANDWIDTH_METRIC = "memcpy_gbps"
_HOST_BANDWIDTH_CACHE: float | None = None
_GEEKBENCH_PER_GHZ = 548.0  # Approximate conversion from single-core GHz to Geekbench 6 single-core


def load_device_profiles(extra_config: str | os.PathLike[str] | None = None) -> Dict[str, DeviceProfile]:
    profiles: Dict[str, DeviceProfile] = dict(_DEFAULT_DEVICE_PROFILES)
    if not extra_config:
        return profiles
    path = pathlib.Path(extra_config)
    if not path.exists():
        return profiles
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return profiles
    if not isinstance(raw, Mapping):
        return profiles
    for key, value in raw.items():
        parsed = _parse_profile_entry(key, value)
        if parsed:
            profiles[parsed.name] = parsed
    return profiles


def _parse_profile_entry(name: str, value: object) -> DeviceProfile | None:
    if not isinstance(value, Mapping):
        return None
    compute = value.get("compute_proxy")
    if not isinstance(compute, Mapping):
        return None
    metric = str(compute.get("metric", "")).strip()
    if not metric:
        return None
    score = _infer_compute_score(compute)
    if score is None or score <= 0:
        return None
    bandwidth = value.get("bandwidth_proxy")
    bandwidth_metric: str | None = None
    bandwidth_score: float | None = None
    if isinstance(bandwidth, Mapping):
        bandwidth_metric = str(bandwidth.get("metric", "")).strip() or None
        bandwidth_score = _try_float(bandwidth.get("score"))
        if bandwidth_score is not None and bandwidth_score <= 0:
            bandwidth_score = None
    aliases_raw = value.get("aliases")
    aliases: Tuple[str, ...]
    if isinstance(aliases_raw, Iterable) and not isinstance(aliases_raw, (str, bytes)):
        aliases = tuple(str(item).strip() for item in aliases_raw if str(item).strip())
    else:
        aliases = tuple()
    notes = value.get("notes")
    if isinstance(notes, str):
        note_val = notes.strip() or None
    else:
        note_val = None
    return DeviceProfile(
        name=name,
        compute_metric=metric,
        compute_score=score,
        bandwidth_metric=bandwidth_metric,
        bandwidth_score=bandwidth_score,
        notes=note_val,
        aliases=aliases,
    )


def _infer_compute_score(proxy: Mapping[str, object]) -> float | None:
    explicit = _try_float(proxy.get("score"))
    if explicit is not None:
        return explicit
    metric = str(proxy.get("metric", "")).strip().lower()
    if metric != "coremark":
        return None
    per_mhz = _try_float(proxy.get("per_mhz_per_core"))
    clock = _try_float(proxy.get("clock_mhz"))
    if per_mhz is None or clock is None:
        return None
    cores = _try_float(proxy.get("cores_used")) or 1.0
    score = per_mhz * clock * cores
    return float(score)


def _try_float(value: object) -> float | None:
    try:
        if value is None:
            return None
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _measure_memcpy_bandwidth(
    *,
    buffer_size_mb: float = 32.0,
    iterations: int = 4,
    warmup: int = 1,
) -> float | None:
    """Approximate memcpy bandwidth (GB/s) via repeated bytearray copies."""
    if buffer_size_mb <= 0 or iterations <= 0:
        return None
    try:
        size_bytes = int(buffer_size_mb * 1024 * 1024)
        src = bytearray(size_bytes)
        dst = bytearray(size_bytes)
        mv_src = memoryview(src)
        mv_dst = memoryview(dst)
    except Exception:
        return None
    timings: list[float] = []
    total_iters = warmup + iterations
    for idx in range(total_iters):
        t0 = time.perf_counter()
        mv_dst[:] = mv_src
        dt = time.perf_counter() - t0
        if idx >= warmup and dt > 0:
            timings.append(dt)
    if not timings:
        return None
    rates = [(size_bytes / t) / 1e9 for t in timings if t > 0]
    if not rates:
        return None
    try:
        return float(statistics.median(rates))
    except statistics.StatisticsError:
        return float(rates[0])


def host_bandwidth_score(
    env: Mapping[str, str] | None = None,
) -> float | None:
    """Return (and cache) the host memcpy bandwidth proxy in GB/s."""
    env_map = env if env is not None else os.environ
    override = _try_float(env_map.get("PQCBENCH_BASELINE_BANDWIDTH_SCORE"))
    if override and override > 0:
        return float(override)
    global _HOST_BANDWIDTH_CACHE
    if _HOST_BANDWIDTH_CACHE is not None:
        return _HOST_BANDWIDTH_CACHE
    measured = _measure_memcpy_bandwidth()
    if measured is None:
        return None
    _HOST_BANDWIDTH_CACHE = measured
    return measured


def alpha_for_algorithm(algo: str | None) -> float:
    if not algo:
        return 0.8
    name = algo.lower()
    if name.startswith(("kyber", "mlkem", "dilithium", "falcon")):
        return 0.85
    if name.startswith("sphincs"):
        return 0.75
    if name.startswith("hqc"):
        return 0.65
    if name.startswith("mayo"):
        return 0.7
    return 0.8


def resolve_baseline_profile(
    profiles: Mapping[str, DeviceProfile],
    *,
    cpu_model: str | None = None,
    env: Mapping[str, str] | None = None,
) -> DeviceProfile | None:
    env_map = env if env is not None else os.environ
    env_profile = env_map.get("PQCBENCH_BASELINE_PROFILE")
    if env_profile and env_profile in profiles:
        return profiles[env_profile]
    env_score = _try_float(env_map.get("PQCBENCH_BASELINE_COMPUTE_SCORE"))
    if env_score:
        metric = env_map.get("PQCBENCH_BASELINE_COMPUTE_METRIC", "user")
        return DeviceProfile(
            name="env_baseline",
            compute_metric=metric,
            compute_score=float(env_score),
        )
    if cpu_model:
        cpu_tokens = _tokenize(cpu_model)
        for profile in profiles.values():
            if profile.name == env_profile:
                return profile
            if _profile_matches_tokens(profile, cpu_tokens):
                return profile
        estimate = _estimate_profile_from_cpu_string(cpu_model)
        if estimate is not None:
            return estimate
    return None


def _tokenize(text: str) -> Tuple[str, ...]:
    filtered = "".join(ch if ch.isalnum() else " " for ch in text.lower())
    tokens = tuple(tok for tok in filtered.split() if tok)
    return tokens


def _profile_matches_tokens(profile: DeviceProfile, cpu_tokens: Tuple[str, ...]) -> bool:
    if not cpu_tokens:
        return False
    cpu_set = set(cpu_tokens)
    candidates = [profile.name.replace("_", " ")] + list(profile.aliases)
    for candidate in candidates:
        tokens = _tokenize(candidate)
        if tokens and all(token in cpu_set for token in tokens):
            return True
    return False


def _estimate_profile_from_cpu_string(cpu_model: str) -> DeviceProfile | None:
    freq = _extract_ghz(cpu_model)
    if freq is None or freq <= 0:
        return None
    score = freq * _GEEKBENCH_PER_GHZ
    name = "host_estimated"
    compute_metric = "geekbench6_single_est"
    return DeviceProfile(
        name=name,
        compute_metric=compute_metric,
        compute_score=score,
        notes=f"Estimated from {freq:.2f} GHz using {_GEEKBENCH_PER_GHZ:.0f} Geekbench6/ GHz heuristic",
    )


def _extract_ghz(cpu_model: str) -> float | None:
    text = cpu_model.lower()
    marker = "ghz"
    if marker not in text:
        return None
    head = text.split(marker, 1)[0]
    tokens = head.split()
    for token in reversed(tokens):
        try:
            return float(token)
        except ValueError:
            cleaned = token.strip("@")
            try:
                return float(cleaned)
            except ValueError:
                continue
    return None


def runtime_targets(
    profiles: Mapping[str, DeviceProfile],
    *,
    env: Mapping[str, str] | None = None,
    baseline: DeviceProfile | None = None,
) -> Dict[str, DeviceProfile]:
    env_map = env if env is not None else os.environ
    raw = env_map.get("PQCBENCH_RUNTIME_TARGETS")
    if raw:
        ordered = []
        for item in raw.split(","):
            key = item.strip()
            if key and key in profiles:
                ordered.append((key, profiles[key]))
        if ordered:
            return dict(ordered)
    out: Dict[str, DeviceProfile] = {}
    for key, profile in profiles.items():
        if baseline and profile.name == baseline.name:
            continue
        out[key] = profile
    return out


def scale_runtime(
    mean_ms: float,
    baseline: DeviceProfile,
    target: DeviceProfile,
    *,
    alpha: float,
) -> Tuple[float, float, Optional[float], str]:
    if mean_ms < 0:
        raise ValueError("mean_ms must be non-negative")
    if baseline.compute_score <= 0 or target.compute_score <= 0:
        raise ValueError("Compute scores must be positive")
    compute_ratio = baseline.compute_score / target.compute_score
    if baseline.bandwidth_score and target.bandwidth_score and 0.0 <= alpha <= 1.0:
        bw_ratio = baseline.bandwidth_score / target.bandwidth_score
        model = "two_term"
        factor = alpha * compute_ratio + (1.0 - alpha) * bw_ratio
        return mean_ms * factor, compute_ratio, bw_ratio, model
    factor = compute_ratio
    return mean_ms * factor, compute_ratio, None, "compute_only"


def build_runtime_scaling(
    *,
    mean_ms: float,
    algo: str,
    op: str,
    cpu_model: str | None,
    profiles: Mapping[str, DeviceProfile],
    env: Mapping[str, str] | None = None,
    alpha_override: float | None = None,
) -> RuntimeScalingResult | None:
    env_map = env if env is not None else os.environ
    baseline = resolve_baseline_profile(profiles, cpu_model=cpu_model, env=env)
    if baseline is None:
        return None
    if baseline.bandwidth_score is None:
        bw = host_bandwidth_score(env_map)
        if bw:
            baseline_metric = baseline.bandwidth_metric or _HOST_BANDWIDTH_METRIC
            baseline = replace(
                baseline,
                bandwidth_metric=baseline_metric,
                bandwidth_score=bw,
            )
    alpha_env = _try_float((env or os.environ).get("PQCBENCH_RUNTIME_ALPHA"))
    alpha = alpha_override if alpha_override is not None else alpha_env
    if alpha is None:
        per_op_key = f"PQCBENCH_RUNTIME_ALPHA_{op.upper()}"
        alpha = _try_float((env or os.environ).get(per_op_key))
    if alpha is None:
        alpha = alpha_for_algorithm(algo)
    alpha = max(0.0, min(float(alpha), 1.0))
    targets = runtime_targets(profiles, env=env, baseline=baseline)
    if not targets:
        return None
    predictions: Dict[str, RuntimeScalingPrediction] = {}
    model_kind = "compute_only"
    for key, target in targets.items():
        try:
            predicted, compute_ratio, bw_ratio, model = scale_runtime(
                mean_ms,
                baseline,
                target,
                alpha=alpha,
            )
        except ValueError:
            continue
        model_kind = model if model == "two_term" else model_kind
        predictions[key] = RuntimeScalingPrediction(
            device=key,
            predicted_ms=predicted,
            factor=predicted / mean_ms if mean_ms else 0.0,
            compute_ratio=compute_ratio,
            bandwidth_ratio=bw_ratio,
            model=model,
        )
    if not predictions:
        return None
    return RuntimeScalingResult(
        baseline_device=baseline.name,
        baseline_metric=baseline.compute_metric,
        baseline_score=baseline.compute_score,
        alpha=alpha,
        model=model_kind,
        predictions=predictions,
        notes=baseline.notes,
    )


def apply_runtime_scaling(
    op_stats: MutableMapping[str, object],
    *,
    algo: str,
    cpu_model: str | None,
    profiles: Mapping[str, DeviceProfile] | None = None,
    env: Mapping[str, str] | None = None,
    alpha_override: float | None = None,
) -> None:
    if profiles is None:
        profiles = load_device_profiles(os.environ.get("PQCBENCH_DEVICE_PROFILES"))
    for op_name, stats in op_stats.items():
        mean_ms = getattr(stats, "mean_ms", None)
        if mean_ms is None:
            continue
        scaling = build_runtime_scaling(
            mean_ms=float(mean_ms),
            algo=algo,
            op=op_name,
            cpu_model=cpu_model,
            profiles=profiles,
            env=env,
            alpha_override=alpha_override,
        )
        if scaling is None:
            continue
        setattr(stats, "runtime_scaling", scaling)
