#!/usr/bin/env python3
"""Forensic side-channel probe for PQCbench algorithms.

This tool exercises registered KEM/Signature adapters under multiple
scenarios, captures timing/memory/process metadata, and applies basic
statistical tests to highlight potential secret-dependent leakage or
forensic artefacts.

Usage:
    python tools/forensic_probe.py --help
"""

from __future__ import annotations

import argparse
import dataclasses
import gc
import hashlib
import inspect
import json
import math
import os
try:  # pragma: no cover - platform-specific import
    import resource
except ImportError:  # pragma: no cover - Windows fallback
    resource = None  # type: ignore
import pathlib
import platform
import importlib
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import psutil
import tracemalloc

try:
    import numpy as np
    from scipy import stats
except ImportError as exc:  # pragma: no cover - dependency resolution
    print("[forensic_probe] Missing numpy/scipy dependencies: {}".format(exc), file=sys.stderr)
    print("Install requirements-dev.txt or pip install numpy scipy", file=sys.stderr)
    raise


# ---------------------------------------------------------------------------
# Project bootstrap
# ---------------------------------------------------------------------------

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent

for rel in (
    pathlib.Path("libs/core/src"),
    pathlib.Path("libs/adapters/liboqs/src"),
    pathlib.Path("libs/adapters/native/src"),
    pathlib.Path("libs/adapters/rsa/src"),
    pathlib.Path("apps/cli/src"),
):
    candidate = PROJECT_ROOT / rel
    if candidate.exists():
        candidate_str = str(candidate)
        if candidate_str not in sys.path:
            sys.path.append(candidate_str)


# Import adapters to populate registry.
for module_name in (
    "pqcbench_liboqs",
    "pqcbench_native",
    "pqcbench_rsa",
):
    try:
        __import__(module_name)
    except ImportError:
        pass

from pqcbench import registry  # noqa: E402
from pqcbench.params import find as find_param_hint  # noqa: E402


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

DEFAULT_ALGORITHM_EXCLUDE = {"xmssmt"}

TVLA_T_THRESHOLD = 4.5
SIGNIFICANCE_ALPHA = 1e-3
MI_ALPHA = 1e-3
MI_PERMUTATIONS = 10000

_PERM_RNG = np.random.default_rng(20240907)
_SIGN_FIXED_MESSAGE = b"forensic-fixed-message"

@dataclass
class ProbeConfig:
    iterations: int = 800
    seed: int = 991239
    output_path: Optional[pathlib.Path] = None
    keep_artifacts: bool = False
    include_algorithms: Optional[List[str]] = None
    include_scenarios: Optional[List[str]] = None
    exclude_algorithms: Optional[List[str]] = None
    enable_sanity_checks: bool = True


@dataclass
class AlgorithmDescriptor:
    key: str
    factory: Callable[[], Any]
    kind: str
    parameter_name: Optional[str]
    param_hint: Optional[Any]


@dataclass
class Observation:
    algorithm: str
    algorithm_kind: str
    parameter_name: Optional[str]
    scenario: str
    iteration: int
    success: bool
    wall_time_ns: int
    cpu_time_ns: int
    rss_before: int
    rss_after: int
    rss_peak: int
    rss_delta: int
    alloc_current: int
    alloc_peak: int
    alloc_before: int
    alloc_peak_before: int
    alloc_delta: int
    alloc_peak_delta: int
    gc_counts_before: Tuple[int, int, int]
    gc_counts_after: Tuple[int, int, int]
    payload: Dict[str, Any]
    error: Optional[str] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class ScenarioDefinition:
    name: str
    description: str
    group: Optional[str]
    label: Optional[str]
    builder: Callable[[AlgorithmDescriptor, random.Random], "ScenarioExecution"]


@dataclass
class ScenarioExecution:
    prepare: Callable[[], None]
    iterate: Callable[[int], Callable[[], Dict[str, Any]]]
    finalize: Callable[[], Dict[str, Any]]


@dataclass
class ScenarioResult:
    descriptor: AlgorithmDescriptor
    definition: ScenarioDefinition
    observations: List[Observation]
    artifacts: Dict[str, Any]


@dataclass
class AnalysisResult:
    algorithm: str
    algorithm_kind: str
    parameter_name: Optional[str]
    scenario_name: str
    metrics: Dict[str, Any]


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _read_git_commit(repo_path: pathlib.Path) -> Optional[str]:
    head = repo_path / ".git" / "HEAD"
    if not head.exists():
        return None
    try:
        head_value = head.read_text(encoding="utf-8").strip()
    except Exception:
        return None
    if head_value.startswith("ref:"):
        ref = head_value.split(":", 1)[1].strip()
        ref_path = repo_path / ".git" / ref
        if ref_path.exists():
            try:
                return ref_path.read_text(encoding="utf-8").strip()
            except Exception:
                return None
        return None
    return head_value or None


def collect_host_metadata() -> Dict[str, Any]:
    process = psutil.Process()
    cpu_freq = None
    try:
        freq = psutil.cpu_freq()
        if freq:
            cpu_freq = {"current": freq.current, "min": freq.min, "max": freq.max}
    except Exception:
        cpu_freq = None

    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()

    metadata = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "host": platform.node(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": sys.version,
        },
        "cpu": {
            "model": platform.processor(),
            "cores_logical": psutil.cpu_count(),
            "cores_physical": psutil.cpu_count(logical=False),
            "freq": cpu_freq,
            "load_avg": os.getloadavg() if hasattr(os, "getloadavg") else None,
        },
        "memory": {
            "total": vm.total,
            "available": vm.available,
            "swap_total": swap.total,
        },
        "process": {
            "pid": process.pid,
            "exe": process.exe(),
            "cmdline": process.cmdline(),
            "num_threads": process.num_threads(),
        },
        "git": {
            "commit": _read_git_commit(PROJECT_ROOT),
        },
        "environment": {
            key: os.environ.get(key)
            for key in sorted(k for k in os.environ if k.startswith("PQCBENCH") or k.startswith("OQS") or k in {"OPENSSL_ia32cap", "PYTHONHASHSEED"})
        },
    }
    try:
        metadata["git"]["liboqs_commit"] = _read_git_commit(PROJECT_ROOT / "liboqs")
    except Exception:
        metadata["git"].setdefault("liboqs_commit", None)
    try:
        metadata["git"]["liboqs_python_commit"] = _read_git_commit(PROJECT_ROOT / "liboqs-python")
    except Exception:
        metadata["git"].setdefault("liboqs_python_commit", None)

    package_versions: Dict[str, str] = {}
    for package_name in ("numpy", "scipy", "psutil", "cryptography", "oqs"):
        try:
            module = importlib.import_module(package_name)
        except ImportError:
            continue
        version = getattr(module, "__version__", None) or getattr(module, "VERSION", None)
        if version is None and hasattr(module, "__about__"):
            version = getattr(module.__about__, "__version__", None)
        if version is not None:
            package_versions[package_name] = str(version)
    metadata["libraries"] = package_versions
    return metadata


def hash_bytes(data: bytes, label: str) -> Dict[str, Any]:
    digest = hashlib.blake2b(data, digest_size=16).hexdigest()
    return {f"{label}_length": len(data), f"{label}_sha3": hashlib.sha3_256(data).hexdigest(), f"{label}_blake2b": digest}


def ensure_bytes_summary(name: str, value: Optional[bytes]) -> Dict[str, Any]:
    if value is None:
        return {f"{name}_present": False}
    return {f"{name}_present": True, **hash_bytes(value, name)}


def to_jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): to_jsonable(val) for key, val in value.items()}
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [to_jsonable(item) for item in value]
    if isinstance(value, set):
        return [to_jsonable(item) for item in value]
    if isinstance(value, pathlib.Path):
        return str(value)
    if isinstance(value, np.ndarray):
        return value.tolist()
    if hasattr(value, "item") and isinstance(value, np.generic):  # numpy scalar
        return value.item()
    if isinstance(value, (np.bool_, np.integer, np.floating)):
        return value.item()
    return value


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------


def build_kem_scenarios(config: ProbeConfig) -> List[ScenarioDefinition]:
    scenarios: List[ScenarioDefinition] = []

    def keygen_builder(descriptor: AlgorithmDescriptor, rng: random.Random) -> ScenarioExecution:
        inst = descriptor.factory()

        def prepare() -> None:
            pass

        def iterate(_: int) -> Callable[[], Dict[str, Any]]:
            def run() -> Dict[str, Any]:
                pk, sk = inst.keygen()
                payload = {}
                payload.update(hash_bytes(pk, "public_key"))
                payload.update(hash_bytes(sk, "secret_key"))
                return payload
            return run

        def finalize() -> Dict[str, Any]:
            return {}

        return ScenarioExecution(prepare=prepare, iterate=iterate, finalize=finalize)

    def encapsulate_fixed_builder(descriptor: AlgorithmDescriptor, rng: random.Random) -> ScenarioExecution:
        inst = descriptor.factory()
        base_pk: Optional[bytes] = None
        base_sk: Optional[bytes] = None
        ciphertexts: List[bytes] = []
        secrets: List[bytes] = []
        ciphertext_meta: List[Dict[str, Any]] = []
        secret_meta: List[Dict[str, Any]] = []

        def prepare() -> None:
            nonlocal base_pk, base_sk
            base_pk, base_sk = inst.keygen()
            ciphertexts.clear()
            secrets.clear()
            ciphertext_meta.clear()
            secret_meta.clear()
            for _ in range(config.iterations):
                ct, ss = inst.encapsulate(base_pk)
                ciphertexts.append(ct)
                secrets.append(ss)
                ciphertext_meta.append(hash_bytes(ct, "ciphertext"))
                secret_meta.append(hash_bytes(ss, "shared_secret"))

        def iterate(index: int) -> Callable[[], Dict[str, Any]]:
            def run() -> Dict[str, Any]:
                payload: Dict[str, Any] = {}
                payload.update(ciphertext_meta[index])
                payload.update(secret_meta[index])
                return payload
            return run

        def finalize() -> Dict[str, Any]:
            secret_summary = ensure_bytes_summary("base_secret_key", base_sk)
            secret_summary.update(ensure_bytes_summary("base_public_key", base_pk))
            return secret_summary

        return ScenarioExecution(prepare=prepare, iterate=iterate, finalize=finalize)

    def decapsulate_valid_builder(descriptor: AlgorithmDescriptor, rng: random.Random) -> ScenarioExecution:
        inst = descriptor.factory()
        base_pk: Optional[bytes] = None
        base_sk: Optional[bytes] = None
        ciphertexts: List[bytes] = []
        secrets: List[bytes] = []
        ciphertext_meta: List[Dict[str, Any]] = []
        secret_meta: List[Dict[str, Any]] = []

        def prepare() -> None:
            nonlocal base_pk, base_sk
            base_pk, base_sk = inst.keygen()
            ciphertexts.clear()
            secrets.clear()
            ciphertext_meta.clear()
            secret_meta.clear()
            for _ in range(config.iterations):
                ct, ss = inst.encapsulate(base_pk)
                ciphertexts.append(ct)
                secrets.append(ss)
                ciphertext_meta.append(hash_bytes(ct, "ciphertext"))
                secret_meta.append(hash_bytes(ss, "shared_secret"))

        def iterate(index: int) -> Callable[[], Dict[str, Any]]:
            def run() -> Dict[str, Any]:
                assert base_sk is not None
                ct = ciphertexts[index]
                expected_ss = secrets[index]
                recovered = inst.decapsulate(base_sk, ct)
                payload: Dict[str, Any] = {}
                payload.update(ciphertext_meta[index])
                payload.update(secret_meta[index])
                payload.update(hash_bytes(recovered, "recovered_secret"))
                payload["match_shared_secret"] = recovered == expected_ss
                return payload
            return run

        def finalize() -> Dict[str, Any]:
            return ensure_bytes_summary("base_secret_key", base_sk)

        return ScenarioExecution(prepare=prepare, iterate=iterate, finalize=finalize)

    def decapsulate_invalid_builder(descriptor: AlgorithmDescriptor, rng: random.Random) -> ScenarioExecution:
        inst = descriptor.factory()
        base_pk: Optional[bytes] = None
        base_sk: Optional[bytes] = None
        corrupted_ciphertexts: List[bytes] = []
        ciphertext_meta: List[Dict[str, Any]] = []

        def prepare() -> None:
            nonlocal base_pk, base_sk
            base_pk, base_sk = inst.keygen()
            corrupted_ciphertexts.clear()
            ciphertext_meta.clear()
            for _ in range(config.iterations):
                ct, _ = inst.encapsulate(base_pk)
                corrupted = bytearray(ct)
                if corrupted:
                    idx = rng.randrange(len(corrupted))
                    corrupted[idx] ^= 0xFF
                corrupted_bytes = bytes(corrupted)
                corrupted_ciphertexts.append(corrupted_bytes)
                ciphertext_meta.append(hash_bytes(corrupted_bytes, "corrupted_ciphertext"))

        def iterate(index: int) -> Callable[[], Dict[str, Any]]:
            def run() -> Dict[str, Any]:
                assert base_sk is not None
                corrupted = corrupted_ciphertexts[index]
                try:
                    recovered = inst.decapsulate(base_sk, corrupted)
                    payload = hash_bytes(recovered, "recovered_secret")
                except Exception:
                    payload = hash_bytes(b"", "recovered_secret")
                payload.update(ciphertext_meta[index])
                return payload
            return run

        def finalize() -> Dict[str, Any]:
            return ensure_bytes_summary("base_secret_key", base_sk)

        return ScenarioExecution(prepare=prepare, iterate=iterate, finalize=finalize)

    scenarios.extend([
        ScenarioDefinition(
            name="keygen",
            description="Generate new key pairs",
            group=None,
            label=None,
            builder=keygen_builder,
        ),
        ScenarioDefinition(
            name="encapsulate_fixed_public",
            description="Encapsulate to a fixed public key",
            group=None,
            label=None,
            builder=encapsulate_fixed_builder,
        ),
        ScenarioDefinition(
            name="decapsulate_valid",
            description="Decapsulate valid ciphertexts with a fixed secret key",
            group="kem_tvla_decapsulation",
            label="fixed",
            builder=decapsulate_valid_builder,
        ),
        ScenarioDefinition(
            name="decapsulate_invalid",
            description="Decapsulate intentionally corrupted ciphertexts with a fixed secret key",
            group="kem_tvla_decapsulation",
            label="invalid",
            builder=decapsulate_invalid_builder,
        ),
    ])
    return scenarios


def build_signature_scenarios(config: ProbeConfig) -> List[ScenarioDefinition]:
    scenarios: List[ScenarioDefinition] = []

    def keygen_builder(descriptor: AlgorithmDescriptor, rng: random.Random) -> ScenarioExecution:
        inst = descriptor.factory()

        def prepare() -> None:
            pass

        def iterate(_: int) -> Callable[[], Dict[str, Any]]:
            def run() -> Dict[str, Any]:
                pk, sk = inst.keygen()
                payload = {}
                payload.update(hash_bytes(pk, "public_key"))
                payload.update(hash_bytes(sk, "secret_key"))
                return payload
            return run

        def finalize() -> Dict[str, Any]:
            return {}

        return ScenarioExecution(prepare=prepare, iterate=iterate, finalize=finalize)

    def sign_fixed_builder(descriptor: AlgorithmDescriptor, rng: random.Random) -> ScenarioExecution:
        inst = descriptor.factory()
        fixed_pk: Optional[bytes] = None
        fixed_sk: Optional[bytes] = None
        fixed_message = _SIGN_FIXED_MESSAGE

        def prepare() -> None:
            nonlocal fixed_pk, fixed_sk
            fixed_pk, fixed_sk = inst.keygen()

        def iterate(iteration: int) -> Callable[[], Dict[str, Any]]:
            def run() -> Dict[str, Any]:
                assert fixed_sk is not None
                signature = inst.sign(fixed_sk, fixed_message)
                payload = hash_bytes(signature, "signature")
                payload["message_length"] = len(fixed_message)
                payload["message_digest"] = hashlib.sha3_256(fixed_message).hexdigest()
                return payload
            return run

        def finalize() -> Dict[str, Any]:
            return ensure_bytes_summary("fixed_secret_key", fixed_sk)

        return ScenarioExecution(prepare=prepare, iterate=iterate, finalize=finalize)

    def sign_random_builder(descriptor: AlgorithmDescriptor, rng: random.Random) -> ScenarioExecution:
        inst = descriptor.factory()
        fixed_pk: Optional[bytes] = None
        fixed_sk: Optional[bytes] = None
        messages: List[bytes] = []
        message_meta: List[Tuple[int, str]] = []
        message_length = len(_SIGN_FIXED_MESSAGE)

        def prepare() -> None:
            nonlocal fixed_pk, fixed_sk
            fixed_pk, fixed_sk = inst.keygen()
            messages.clear()
            message_meta.clear()
            for _ in range(config.iterations):
                msg = rng.randbytes(message_length)
                messages.append(msg)
                message_meta.append((message_length, hashlib.sha3_256(msg).hexdigest()))

        def iterate(index: int) -> Callable[[], Dict[str, Any]]:
            def run() -> Dict[str, Any]:
                assert fixed_sk is not None
                msg = messages[index]
                length, digest = message_meta[index]
                signature = inst.sign(fixed_sk, msg)
                payload = hash_bytes(signature, "signature")
                payload["message_length"] = length
                payload["message_digest"] = digest
                return payload
            return run

        def finalize() -> Dict[str, Any]:
            return ensure_bytes_summary("fixed_secret_key", fixed_sk)

        return ScenarioExecution(prepare=prepare, iterate=iterate, finalize=finalize)

    def sign_fault_builder(descriptor: AlgorithmDescriptor, rng: random.Random) -> ScenarioExecution:
        inst = descriptor.factory()
        fixed_pk: Optional[bytes] = None
        fixed_sk: Optional[bytes] = None

        def prepare() -> None:
            nonlocal fixed_pk, fixed_sk
            fixed_pk, fixed_sk = inst.keygen()

        def iterate(iteration: int) -> Callable[[], Dict[str, Any]]:
            message = (f"forensic-fault-message-{iteration}").encode("utf-8")

            def run() -> Dict[str, Any]:
                assert fixed_sk is not None
                tampered = bytearray(fixed_sk)
                if tampered:
                    idx = rng.randrange(len(tampered))
                    tampered[idx] ^= 0xFF
                try:
                    signature = inst.sign(bytes(tampered), message)
                    payload = hash_bytes(signature, "signature")
                    payload["fault_status"] = "success"
                except Exception as exc:  # pragma: no cover - backend dependent
                    payload = {"fault_status": "error", "fault_error": repr(exc)}
                payload["message_length"] = len(message)
                return payload
            return run

        def finalize() -> Dict[str, Any]:
            return ensure_bytes_summary("fixed_secret_key", fixed_sk)

        return ScenarioExecution(prepare=prepare, iterate=iterate, finalize=finalize)

    def verify_invalid_builder(descriptor: AlgorithmDescriptor, rng: random.Random) -> ScenarioExecution:
        inst = descriptor.factory()
        fixed_pk: Optional[bytes] = None
        fixed_sk: Optional[bytes] = None

        def prepare() -> None:
            nonlocal fixed_pk, fixed_sk
            fixed_pk, fixed_sk = inst.keygen()

        def iterate(iteration: int) -> Callable[[], Dict[str, Any]]:
            message = (f"forensic-verify-message-{iteration}").encode("utf-8")

            def run() -> Dict[str, Any]:
                assert fixed_pk is not None and fixed_sk is not None
                signature = inst.sign(fixed_sk, message)
                corrupted = bytearray(signature)
                if corrupted:
                    idx = rng.randrange(len(corrupted))
                    corrupted[idx] ^= 0x01
                is_valid = inst.verify(fixed_pk, message, bytes(corrupted))
                return {
                    "verification_result": bool(is_valid),
                    "original_signature_digest": hashlib.sha3_256(signature).hexdigest(),
                    "corrupted_signature_digest": hashlib.sha3_256(bytes(corrupted)).hexdigest(),
                    "message_length": len(message),
                }
            return run

        def finalize() -> Dict[str, Any]:
            return ensure_bytes_summary("fixed_secret_key", fixed_sk)

        return ScenarioExecution(prepare=prepare, iterate=iterate, finalize=finalize)

    scenarios.extend([
        ScenarioDefinition(
            name="keygen",
            description="Generate new signing key pairs",
            group=None,
            label=None,
            builder=keygen_builder,
        ),
        ScenarioDefinition(
            name="sign_fixed_message",
            description="Sign a fixed message with a fixed secret key",
            group="signature_tvla_sign",
            label="fixed",
            builder=sign_fixed_builder,
        ),
        ScenarioDefinition(
            name="sign_random_message",
            description="Sign random messages with a fixed secret key",
            group="signature_tvla_sign",
            label="random",
            builder=sign_random_builder,
        ),
        ScenarioDefinition(
            name="sign_fault",
            description="Attempt signing with a fault-injected secret key",
            group=None,
            label=None,
            builder=sign_fault_builder,
        ),
        ScenarioDefinition(
            name="verify_invalid_signature",
            description="Verify corrupted signatures to observe error handling",
            group=None,
            label=None,
            builder=verify_invalid_builder,
        ),
    ])
    return scenarios


# ---------------------------------------------------------------------------
# Core execution logic
# ---------------------------------------------------------------------------


def classify_algorithm(key: str, obj: Any) -> Optional[str]:
    attrs = {"keygen": hasattr(obj, "keygen"), "encapsulate": hasattr(obj, "encapsulate"), "decapsulate": hasattr(obj, "decapsulate"), "sign": hasattr(obj, "sign"), "verify": hasattr(obj, "verify")}
    if attrs["encapsulate"] and attrs["decapsulate"]:
        return "kem"
    if attrs["sign"] and attrs["verify"]:
        return "signature"
    return None


def discover_algorithms(config: ProbeConfig) -> List[AlgorithmDescriptor]:
    discovered: List[AlgorithmDescriptor] = []
    available = registry.list()
    include_set = set(config.include_algorithms or [])
    explicit_include = bool(config.include_algorithms)
    exclude_set = {key.lower() for key in (config.exclude_algorithms or [])}
    for key, candidate in sorted(available.items()):
        key_lower = key.lower()
        if config.include_algorithms and key not in include_set:
            continue
        if key_lower in exclude_set:
            print(f"[forensic_probe] Skipping {key}: excluded via CLI", file=sys.stderr)
            continue
        if key_lower in DEFAULT_ALGORITHM_EXCLUDE and not (explicit_include and key in include_set):
            print(f"[forensic_probe] Skipping {key}: excluded by default (unstable)", file=sys.stderr)
            continue
        if inspect.isclass(candidate):
            factory: Callable[[], Any] = candidate
        elif callable(candidate):
            factory = candidate
        else:
            factory = lambda candidate=candidate: candidate
        try:
            probe_obj = factory()
        except Exception as exc:
            print(f"[forensic_probe] Skipping {key}: instantiation failed ({exc!r})", file=sys.stderr)
            continue
        kind = classify_algorithm(key, probe_obj)
        if kind is None:
            continue
        parameter_name = getattr(probe_obj, "alg", None)
        param_hint = find_param_hint(parameter_name or key)
        descriptor = AlgorithmDescriptor(
            key=key,
            factory=factory,
            kind=kind,
            parameter_name=parameter_name,
            param_hint=param_hint,
        )
        discovered.append(descriptor)
    return discovered


def snapshot_directory(path: pathlib.Path) -> Dict[str, Dict[str, Any]]:
    snapshot: Dict[str, Dict[str, Any]] = {}
    if not path.exists():
        return snapshot
    for root, _, files in os.walk(path):
        for file_name in files:
            file_path = pathlib.Path(root) / file_name
            try:
                data = file_path.read_bytes()
            except Exception:
                continue
            rel = file_path.relative_to(path).as_posix()
            snapshot[rel] = {
                "size": len(data),
                "sha3_256": hashlib.sha3_256(data).hexdigest(),
                "blake2b": hashlib.blake2b(data, digest_size=16).hexdigest(),
            }
    return snapshot


def run_scenario(config: ProbeConfig, descriptor: AlgorithmDescriptor, definition: ScenarioDefinition, rng: random.Random) -> ScenarioResult:
    temp_dir = pathlib.Path(tempfile.mkdtemp(prefix=f"forensic_{descriptor.key}_{definition.name}_", dir=None))
    original_tempdir = tempfile.gettempdir()
    os_environ_backup = {var: os.environ.get(var) for var in ("TMP", "TEMP", "TMPDIR")}
    try:
        os.environ["TMP"] = os.environ["TEMP"] = os.environ["TMPDIR"] = str(temp_dir)
        tempfile.tempdir = str(temp_dir)
        execution = definition.builder(descriptor, rng)
        execution.prepare()
        observations: List[Observation] = []
        tracemalloc.start()
        process = psutil.Process()
        for iteration in range(config.iterations):
            operation = execution.iterate(iteration)
            gc_counts_before = gc.get_count()
            rss_before = process.memory_info().rss
            alloc_current_before, alloc_peak_before = tracemalloc.get_traced_memory()
            start_wall = time.perf_counter_ns()
            start_cpu = time.process_time_ns()
            success = True
            payload: Dict[str, Any]
            error: Optional[str] = None
            notes: List[str] = []
            try:
                payload = operation()
            except Exception as exc:  # pragma: no cover - depends on backend
                success = False
                payload = {}
                error = repr(exc)
            end_wall = time.perf_counter_ns()
            end_cpu = time.process_time_ns()
            rss_after = process.memory_info().rss
            if resource is not None:
                try:
                    rss_peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                except Exception:
                    rss_peak = rss_after
            else:
                rss_peak = rss_after
            alloc_current_after, alloc_peak_after = tracemalloc.get_traced_memory()
            gc_counts_after = gc.get_count()
            observation = Observation(
                algorithm=descriptor.key,
                algorithm_kind=descriptor.kind,
                parameter_name=descriptor.parameter_name,
                scenario=definition.name,
                iteration=iteration,
                success=success,
                wall_time_ns=end_wall - start_wall,
                cpu_time_ns=end_cpu - start_cpu,
                rss_before=rss_before,
                rss_after=rss_after,
                rss_peak=rss_peak,
                rss_delta=rss_after - rss_before,
                alloc_current=alloc_current_after,
                alloc_peak=alloc_peak_after,
                alloc_before=alloc_current_before,
                alloc_peak_before=alloc_peak_before,
                alloc_delta=alloc_current_after - alloc_current_before,
                alloc_peak_delta=alloc_peak_after - alloc_peak_before,
                gc_counts_before=gc_counts_before,
                gc_counts_after=gc_counts_after,
                payload=payload,
                error=error,
                notes=notes,
            )
            observations.append(observation)
        artifacts = {
            "artifact_path": str(temp_dir),
            "files": snapshot_directory(temp_dir),
        }
        execution_artifacts = execution.finalize()
        if execution_artifacts:
            artifacts["context"] = execution_artifacts
    finally:
        tempfile.tempdir = original_tempdir
        for key, value in os_environ_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        tracemalloc.stop()
        if not config.keep_artifacts:
            shutil.rmtree(temp_dir, ignore_errors=True)
    return ScenarioResult(descriptor=descriptor, definition=definition, observations=observations, artifacts=artifacts)


def collect_results(config: ProbeConfig, descriptors: List[AlgorithmDescriptor]) -> Tuple[List[ScenarioResult], Dict[str, Any]]:
    host_metadata = collect_host_metadata()
    rng = random.Random(config.seed)
    scenario_results: List[ScenarioResult] = []
    for descriptor in descriptors:
        print(f"[forensic_probe] Running scenarios for {descriptor.key} ({descriptor.kind})")
        scenarios = build_kem_scenarios(config) if descriptor.kind == "kem" else build_signature_scenarios(config)
        for definition in scenarios:
            if config.include_scenarios and definition.name not in config.include_scenarios:
                continue
            print(f"    -> Scenario {definition.name}: {definition.description}")
            result = run_scenario(config, descriptor, definition, rng)
            scenario_results.append(result)
    return scenario_results, host_metadata


# ---------------------------------------------------------------------------
# Statistical analysis
# ---------------------------------------------------------------------------

def analyse_pairs(results: List[ScenarioResult], config: ProbeConfig) -> List[AnalysisResult]:
    grouped: Dict[Tuple[str, str, str, str], Dict[str, List[Observation]]] = defaultdict(lambda: defaultdict(list))
    for result in results:
        descriptor = result.descriptor
        definition = result.definition
        if not definition.group or not definition.label:
            continue
        key = (descriptor.key, descriptor.kind, descriptor.parameter_name or descriptor.key, definition.group)
        grouped[key][definition.label].extend(result.observations)

    analysis_results: List[AnalysisResult] = []
    sanity_rng = random.Random(config.seed ^ 0xDADBEEF)
    for (alg_key, alg_kind, param_name, group), label_map in grouped.items():
        labels = list(label_map)
        if len(labels) < 2:
            continue
        reference = label_map[labels[0]]
        for label, observations in label_map.items():
            if label == labels[0]:
                continue
            metrics = compute_statistical_tests(reference, observations)
            analysis_results.append(
                AnalysisResult(
                    algorithm=alg_key,
                    algorithm_kind=alg_kind,
                    parameter_name=param_name,
                    scenario_name=f"{group}:{labels[0]} vs {label}",
                    metrics=metrics,
                )
            )
            if config.enable_sanity_checks:
                sanity_results = generate_sanity_results(
                    alg_key=alg_key,
                    alg_kind=alg_kind,
                    param_name=param_name,
                    group=group,
                    reference=reference,
                    variant=observations,
                    rng=sanity_rng,
                )
                analysis_results.extend(sanity_results)
    return analysis_results


def generate_sanity_results(
    *,
    alg_key: str,
    alg_kind: str,
    param_name: Optional[str],
    group: str,
    reference: List[Observation],
    variant: List[Observation],
    rng: random.Random,
) -> List[AnalysisResult]:
    outputs: List[AnalysisResult] = []
    shuffle_pair = generate_shuffle_control(reference, variant, rng)
    if shuffle_pair is not None:
        metrics = compute_statistical_tests(shuffle_pair[0], shuffle_pair[1])
        outputs.append(
            AnalysisResult(
                algorithm=alg_key,
                algorithm_kind=alg_kind,
                parameter_name=param_name,
                scenario_name=f"{group}:sanity_shuffle",
                metrics=metrics,
            )
        )
    split_pair = generate_split_control(reference, rng)
    if split_pair is not None:
        metrics = compute_statistical_tests(split_pair[0], split_pair[1])
        outputs.append(
            AnalysisResult(
                algorithm=alg_key,
                algorithm_kind=alg_kind,
                parameter_name=param_name,
                scenario_name=f"{group}:sanity_fixed_split",
                metrics=metrics,
            )
        )
    variant_split = generate_split_control(variant, rng)
    if variant_split is not None:
        metrics = compute_statistical_tests(variant_split[0], variant_split[1])
        outputs.append(
            AnalysisResult(
                algorithm=alg_key,
                algorithm_kind=alg_kind,
                parameter_name=param_name,
                scenario_name=f"{group}:sanity_toggle_split",
                metrics=metrics,
            )
        )
    return outputs


def generate_shuffle_control(
    reference: List[Observation],
    variant: List[Observation],
    rng: random.Random,
) -> Optional[Tuple[List[Observation], List[Observation]]]:
    combined = list(reference) + list(variant)
    if not combined:
        return None
    rng.shuffle(combined)
    split = len(reference)
    if split == 0 or split >= len(combined):
        return None
    return combined[:split], combined[split:]


def generate_split_control(
    samples: List[Observation],
    rng: random.Random,
) -> Optional[Tuple[List[Observation], List[Observation]]]:
    if len(samples) < 4:
        return None
    shuffled = list(samples)
    rng.shuffle(shuffled)
    mid = len(shuffled) // 2
    if mid == 0 or mid == len(shuffled):
        return None
    return shuffled[:mid], shuffled[mid:]


def compute_statistical_tests(reference: List[Observation], variant: List[Observation]) -> Dict[str, Any]:
    ref_times = np.array([obs.wall_time_ns for obs in reference], dtype=np.float64)
    var_times = np.array([obs.wall_time_ns for obs in variant], dtype=np.float64)
    ref_cpu = np.array([obs.cpu_time_ns for obs in reference], dtype=np.float64)
    var_cpu = np.array([obs.cpu_time_ns for obs in variant], dtype=np.float64)
    ref_rss = np.array([obs.rss_delta for obs in reference], dtype=np.float64)
    var_rss = np.array([obs.rss_delta for obs in variant], dtype=np.float64)

    t_time = stats.ttest_ind(ref_times, var_times, equal_var=False)
    t_cpu = stats.ttest_ind(ref_cpu, var_cpu, equal_var=False)
    t_rss = stats.ttest_ind(ref_rss, var_rss, equal_var=False)

    mann_time = stats.mannwhitneyu(ref_times, var_times, alternative="two-sided")
    mann_cpu = stats.mannwhitneyu(ref_cpu, var_cpu, alternative="two-sided")
    mann_rss = stats.mannwhitneyu(ref_rss, var_rss, alternative="two-sided")
    mann_time_greater = stats.mannwhitneyu(ref_times, var_times, alternative="greater")
    mann_cpu_greater = stats.mannwhitneyu(ref_cpu, var_cpu, alternative="greater")
    mann_rss_greater = stats.mannwhitneyu(ref_rss, var_rss, alternative="greater")

    ks_time = stats.ks_2samp(ref_times, var_times)
    ks_cpu = stats.ks_2samp(ref_cpu, var_cpu)
    ks_rss = stats.ks_2samp(ref_rss, var_rss)

    ref_times_centered = ref_times - np.mean(ref_times)
    var_times_centered = var_times - np.mean(var_times)
    ref_cpu_centered = ref_cpu - np.mean(ref_cpu)
    var_cpu_centered = var_cpu - np.mean(var_cpu)
    ref_rss_centered = ref_rss - np.mean(ref_rss)
    var_rss_centered = var_rss - np.mean(var_rss)

    t2_time = stats.ttest_ind(ref_times_centered ** 2, var_times_centered ** 2, equal_var=False)
    t2_cpu = stats.ttest_ind(ref_cpu_centered ** 2, var_cpu_centered ** 2, equal_var=False)
    t2_rss = stats.ttest_ind(ref_rss_centered ** 2, var_rss_centered ** 2, equal_var=False)

    mi_time, mi_p_time = estimate_mutual_information_with_pvalue(ref_times, var_times)
    mi_cpu, mi_p_cpu = estimate_mutual_information_with_pvalue(ref_cpu, var_cpu)
    mi_rss, mi_p_rss = estimate_mutual_information_with_pvalue(ref_rss, var_rss)

    cliff_time = cliffs_delta_from_u(mann_time_greater.statistic, len(ref_times), len(var_times))
    cliff_cpu = cliffs_delta_from_u(mann_cpu_greater.statistic, len(ref_cpu), len(var_cpu))
    cliff_rss = cliffs_delta_from_u(mann_rss_greater.statistic, len(ref_rss), len(var_rss))

    time_flag, time_details = evaluate_metric(
        "time",
        t_stat=float(t_time.statistic),
        t_p=float(t_time.pvalue),
        t2_stat=float(t2_time.statistic),
        t2_p=float(t2_time.pvalue),
        mann_p=float(mann_time.pvalue),
        ks_stat=float(ks_time.statistic),
        ks_p=float(ks_time.pvalue),
        mi=mi_time,
        mi_p=mi_p_time,
    )
    cpu_flag, cpu_details = evaluate_metric(
        "cpu",
        t_stat=float(t_cpu.statistic),
        t_p=float(t_cpu.pvalue),
        t2_stat=float(t2_cpu.statistic),
        t2_p=float(t2_cpu.pvalue),
        mann_p=float(mann_cpu.pvalue),
        ks_stat=float(ks_cpu.statistic),
        ks_p=float(ks_cpu.pvalue),
        mi=mi_cpu,
        mi_p=mi_p_cpu,
    )
    rss_flag, rss_details = evaluate_metric(
        "rss",
        t_stat=float(t_rss.statistic),
        t_p=float(t_rss.pvalue),
        t2_stat=float(t2_rss.statistic),
        t2_p=float(t2_rss.pvalue),
        mann_p=float(mann_rss.pvalue),
        ks_stat=float(ks_rss.statistic),
        ks_p=float(ks_rss.pvalue),
        mi=mi_rss,
        mi_p=mi_p_rss,
    )

    metrics: Dict[str, Any] = {
        "t_stat_time": float(t_time.statistic),
        "t_pvalue_time": float(t_time.pvalue),
        "t2_stat_time": float(t2_time.statistic),
        "t2_pvalue_time": float(t2_time.pvalue),
        "t_stat_cpu": float(t_cpu.statistic),
        "t_pvalue_cpu": float(t_cpu.pvalue),
        "t2_stat_cpu": float(t2_cpu.statistic),
        "t2_pvalue_cpu": float(t2_cpu.pvalue),
        "t_stat_rss": float(t_rss.statistic),
        "t_pvalue_rss": float(t_rss.pvalue),
        "t2_stat_rss": float(t2_rss.statistic),
        "t2_pvalue_rss": float(t2_rss.pvalue),
        "mannu_time": float(mann_time.statistic),
        "mannu_pvalue_time": float(mann_time.pvalue),
        "mannu_cpu": float(mann_cpu.statistic),
        "mannu_pvalue_cpu": float(mann_cpu.pvalue),
        "mannu_rss": float(mann_rss.statistic),
        "mannu_pvalue_rss": float(mann_rss.pvalue),
        "ks_stat_time": float(ks_time.statistic),
        "ks_pvalue_time": float(ks_time.pvalue),
        "ks_stat_cpu": float(ks_cpu.statistic),
        "ks_pvalue_cpu": float(ks_cpu.pvalue),
        "ks_stat_rss": float(ks_rss.statistic),
        "ks_pvalue_rss": float(ks_rss.pvalue),
        "mi_time": mi_time,
        "mi_pvalue_time": mi_p_time,
        "mi_cpu": mi_cpu,
        "mi_pvalue_cpu": mi_p_cpu,
        "mi_rss": mi_rss,
        "mi_pvalue_rss": mi_p_rss,
        "cliffs_delta_time": cliff_time,
        "cliffs_delta_cpu": cliff_cpu,
        "cliffs_delta_rss": cliff_rss,
    }
    metrics.update(time_details)
    metrics.update(cpu_details)
    metrics.update(rss_details)
    metrics["time_leak_flag"] = time_flag
    metrics["cpu_leak_flag"] = cpu_flag
    metrics["rss_leak_flag"] = rss_flag
    return metrics


def estimate_mutual_information(reference: np.ndarray, variant: np.ndarray, bins: int = 30) -> float:
    combined = np.concatenate([reference, variant])
    labels = np.concatenate([np.zeros_like(reference), np.ones_like(variant)])
    if combined.size == 0:
        return 0.0
    hist_bins = np.histogram_bin_edges(combined, bins=bins)
    ref_hist, _ = np.histogram(reference, bins=hist_bins)
    var_hist, _ = np.histogram(variant, bins=hist_bins)
    joint = np.stack([ref_hist, var_hist], axis=0)
    joint = joint + 1e-9
    joint_prob = joint / joint.sum()
    marginal_metric = joint_prob.sum(axis=0)
    marginal_label = joint_prob.sum(axis=1)
    entropy_metric = stats.entropy(marginal_metric)
    entropy_label = stats.entropy(marginal_label)
    joint_entropy = stats.entropy(joint_prob.flatten())
    mi = entropy_metric + entropy_label - joint_entropy
    return float(max(mi, 0.0))


def estimate_mutual_information_with_pvalue(
    reference: np.ndarray,
    variant: np.ndarray,
    bins: int = 30,
    permutations: int = MI_PERMUTATIONS,
) -> Tuple[float, Optional[float]]:
    base_mi = estimate_mutual_information(reference, variant, bins=bins)
    if permutations <= 0:
        return base_mi, None
    combined = np.concatenate([reference, variant])
    labels = np.concatenate([np.zeros_like(reference, dtype=np.int8), np.ones_like(variant, dtype=np.int8)])
    greater_equal = 1
    total = permutations + 1
    for _ in range(permutations):
        shuffled = _PERM_RNG.permutation(labels)
        perm_ref = combined[shuffled == 0]
        perm_var = combined[shuffled == 1]
        perm_mi = estimate_mutual_information(perm_ref, perm_var, bins=bins)
        if perm_mi >= base_mi:
            greater_equal += 1
    pvalue = greater_equal / total
    return base_mi, pvalue


def cliffs_delta_from_u(u_value: float, m: int, n: int) -> float:
    if m == 0 or n == 0:
        return 0.0
    return float((2.0 * (u_value / (m * n))) - 1.0)


def apply_holm_bonferroni(pvalues: List[float], alpha: float) -> List[bool]:
    indexed = [(i, 1.0 if p is None else p) for i, p in enumerate(pvalues)]
    indexed.sort(key=lambda item: item[1])
    results = [False] * len(pvalues)
    remaining = len(pvalues)
    for rank, (idx, pval) in enumerate(indexed):
        threshold = alpha / (remaining - rank)
        if pval <= threshold:
            results[idx] = True
        else:
            break
    return results


def evaluate_metric(
    metric_label: str,
    *,
    t_stat: float,
    t_p: float,
    t2_stat: float,
    t2_p: float,
    mann_p: float,
    ks_stat: float,
    ks_p: float,
    mi: float,
    mi_p: Optional[float],
) -> Tuple[bool, Dict[str, Any]]:
    pvalues = [t_p, t2_p, mann_p, ks_p]
    holm_hits = apply_holm_bonferroni(pvalues, SIGNIFICANCE_ALPHA)
    holm_map = {"t": holm_hits[0], "t2": holm_hits[1], "mann": holm_hits[2], "ks": holm_hits[3]}
    tvla_hit = abs(t_stat) >= TVLA_T_THRESHOLD and t_p <= SIGNIFICANCE_ALPHA
    mi_hit = mi_p is not None and mi_p <= MI_ALPHA
    flag = tvla_hit or any(holm_hits) or mi_hit
    details = {
        f"holm_hits_{metric_label}": holm_map,
        f"tvla_hit_{metric_label}": tvla_hit,
        f"mi_significant_{metric_label}": mi_hit,
    }
    return flag, details


# ---------------------------------------------------------------------------
# Reporting utilities
# ---------------------------------------------------------------------------


def summarise_results(scenario_results: List[ScenarioResult], analysis_results: List[AnalysisResult], host_metadata: Dict[str, Any], config: ProbeConfig) -> Dict[str, Any]:
    config_dict = dataclasses.asdict(config)
    if config_dict.get("output_path") is not None:
        config_dict["output_path"] = str(config_dict["output_path"])
    if config_dict.get("include_algorithms") is not None:
        config_dict["include_algorithms"] = list(config_dict["include_algorithms"])
    if config_dict.get("include_scenarios") is not None:
        config_dict["include_scenarios"] = list(config_dict["include_scenarios"])
    if config_dict.get("exclude_algorithms") is not None:
        config_dict["exclude_algorithms"] = list(config_dict["exclude_algorithms"])
    summary = {
        "config": config_dict,
        "host": host_metadata,
        "scenarios": [],
        "analysis": [dataclasses.asdict(result) for result in analysis_results],
    }
    for result in scenario_results:
        scenario_entry = {
            "algorithm": result.descriptor.key,
            "algorithm_kind": result.descriptor.kind,
            "parameter_name": result.descriptor.parameter_name,
            "scenario": result.definition.name,
            "description": result.definition.description,
            "group": result.definition.group,
            "label": result.definition.label,
            "artifact": result.artifacts,
            "observations": [dataclasses.asdict(obs) for obs in result.observations],
        }
        summary["scenarios"].append(scenario_entry)
    return summary


def emit_summary(summary: Dict[str, Any], analysis_results: List[AnalysisResult]) -> None:
    print("\n=== Forensic Probe Summary ===")
    vantage_labels = {
        "time": "remote",
        "cpu": "co-resident",
        "rss": "co-resident",
    }
    for entry in analysis_results:
        metrics = entry.metrics
        flags = [name for name, flag in (("time", metrics.get("time_leak_flag")), ("cpu", metrics.get("cpu_leak_flag")), ("rss", metrics.get("rss_leak_flag"))) if flag]
        flag_status = ", ".join(f"{f}({vantage_labels.get(f, '?')})" for f in flags) if flags else "none"
        cliffs_time = metrics.get("cliffs_delta_time") or 0.0
        cliffs_cpu = metrics.get("cliffs_delta_cpu") or 0.0
        cliffs_rss = metrics.get("cliffs_delta_rss") or 0.0
        mi_vals = (
            metrics.get("mi_time", 0.0),
            metrics.get("mi_cpu", 0.0),
            metrics.get("mi_rss", 0.0),
        )
        print(
            f"{entry.algorithm} [{entry.parameter_name or '-'}] {entry.scenario_name}: "
            f"|t_time|={abs(metrics['t_stat_time']):.2f}, "
            f"|t_cpu|={abs(metrics['t_stat_cpu']):.2f}, "
            f"|t_rss|={abs(metrics['t_stat_rss']):.2f}, "
            f"t2_time={abs(metrics['t2_stat_time']):.2f}, "
            f"MI={mi_vals[0]:.4f}/{mi_vals[1]:.4f}/{mi_vals[2]:.4f}, "
            f"Δ={cliffs_time:.3f}/{cliffs_cpu:.3f}/{cliffs_rss:.3f} -> flags: {flag_status}"
        )
    if not analysis_results:
        print("No paired scenarios available for statistical analysis.")


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[Iterable[str]] = None) -> ProbeConfig:
    parser = argparse.ArgumentParser(description="Forensic side-channel probe for registered PQC algorithms.")
    parser.add_argument("--iterations", type=int, default=800, help="Iterations per scenario (default: 800)")
    parser.add_argument("--seed", type=int, default=991239, help="Seed for deterministic helper randomness")
    parser.add_argument("--output", type=pathlib.Path, help="Optional output JSON path")
    parser.add_argument("--keep-artifacts", action="store_true", help="Retain temporary artifacts generated during scenarios")
    parser.add_argument("--alg", nargs="*", help="Limit to specific registry keys")
    parser.add_argument("--scenario", nargs="*", help="Limit to specific scenario names")
    parser.add_argument("--exclude", nargs="*", help="Explicitly exclude registry keys")
    parser.add_argument("--no-sanity-checks", action="store_true", help="Disable shuffle/split sanity controls")
    args = parser.parse_args(argv)
    return ProbeConfig(
        iterations=args.iterations,
        seed=args.seed,
        output_path=args.output,
        keep_artifacts=args.keep_artifacts,
        include_algorithms=args.alg,
        include_scenarios=args.scenario,
        exclude_algorithms=args.exclude,
        enable_sanity_checks=not args.no_sanity_checks,
    )


def main(argv: Optional[Iterable[str]] = None) -> int:
    config = parse_args(argv)
    descriptors = discover_algorithms(config)
    if not descriptors:
        print("[forensic_probe] No algorithms discovered. Ensure adapters are available.", file=sys.stderr)
        return 1
    scenario_results, host_metadata = collect_results(config, descriptors)
    analysis_results = analyse_pairs(scenario_results, config)
    summary = summarise_results(scenario_results, analysis_results, host_metadata, config)
    emit_summary(summary, analysis_results)
    output_path = config.output_path or (PROJECT_ROOT / "results" / f"forensic_probe_{int(time.time())}.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(to_jsonable(summary), fh, indent=2)
    print(f"\n[forensic_probe] Written detailed results to {output_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
