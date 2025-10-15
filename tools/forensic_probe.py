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
import csv
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
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import shlex
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

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
FORENSIC_REPORT_SCRIPT = PROJECT_ROOT / "tools" / "forensic_report.py"

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
from pqcbench.security_levels import available_categories, resolve_security_override  # noqa: E402


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

DEFAULT_ALGORITHM_EXCLUDE = {"xmssmt"}

_ALGO_NAME_ALIASES = {
    "ml-kem": "kyber",
    "mlkem": "kyber",
    "ml_kem": "kyber",
    "ml dsa": "dilithium",
    "ml-dsa": "dilithium",
    "ml_dsa": "dilithium",
    "mldsa": "dilithium",
    "fn-dsa": "falcon",
    "fn_dsa": "falcon",
    "fndsa": "falcon",
    "sphincsplus": "sphincs+",
    "classicmceliece": "classic-mceliece",
    "classic_mceliece": "classic-mceliece",
    "frodo-kem": "frodokem",
    "frodo_kem": "frodokem",
    "ntru-prime": "ntruprime",
    "ntru_prime": "ntruprime",
    "slh_dsa": "slh-dsa",
}

_DISPLAY_NAME_OVERRIDES = {
    "kyber": "ml-kem",
    "dilithium": "ml-dsa",
    "falcon": "fn-dsa",
}


def _canonical_algorithm_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return name
    key = name.strip().lower()
    return _ALGO_NAME_ALIASES.get(key, key)


def _display_algorithm_name(canonical_name: str, explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    return _DISPLAY_NAME_OVERRIDES.get(canonical_name.lower(), canonical_name)

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
    categories: Optional[List[int]] = None
    rsa_max_category: int = 5
    render_plots: bool = False
    plot_dir: Optional[pathlib.Path] = None
    render_report: bool = False
    report_format: str = "markdown"
    report_output: Optional[pathlib.Path] = None
    report_options: str = ""
    resume_from: Optional[pathlib.Path] = None


@dataclass
class AlgorithmDescriptor:
    key: str
    factory: Callable[[], Any]
    kind: str
    parameter_name: Optional[str]
    param_hint: Optional[Any]
    security_category: Optional[int] = None
    override_note: Optional[str] = None
    override_env: Dict[str, str] = field(default_factory=dict)
    pending_scenarios: Optional[Set[str]] = None


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
    security_category: Optional[int] = None


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


@contextmanager
def temporary_env(overrides: Dict[str, str]):
    if not overrides:
        yield
        return
    original: Dict[str, Optional[str]] = {}
    try:
        for key, value in overrides.items():
            original[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def wrap_factory(factory: Callable[[], Any], overrides: Dict[str, str]) -> Callable[[], Any]:
    if not overrides:
        return factory

    def _wrapped() -> Any:
        with temporary_env(overrides):
            return factory()

    return _wrapped


def resolve_mechanism_name(candidate: Any, fallback: Optional[str] = None) -> Optional[str]:
    for attr in ("mechanism", "mech", "alg", "algorithm"):
        value = getattr(candidate, attr, None)
        if value:
            return str(value)
    return fallback


def slugify(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    return value or "entry"


def _default_report_suffix(fmt: str) -> str:
    fmt_lower = (fmt or "").lower()
    return {
        "markdown": ".md",
        "md": ".md",
        "html": ".html",
        "json": ".json",
        "rst": ".rst",
    }.get(fmt_lower, f".{fmt_lower or 'report'}")


def run_forensic_report(json_path: pathlib.Path, config: ProbeConfig) -> Optional[Dict[str, Any]]:
    script_path = FORENSIC_REPORT_SCRIPT
    if not script_path.exists():
        print(f"[forensic_probe] Report script not found at {script_path}; skipping report generation.")
        return {"status": "missing_script", "script": str(script_path)}

    report_path = config.report_output
    if report_path is None:
        suffix = _default_report_suffix(config.report_format)
        report_path = json_path.with_suffix(suffix)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, str(script_path), str(json_path)]
    if config.report_format:
        cmd.extend(["--format", config.report_format])
    cmd.extend(["--output", str(report_path)])
    extra_opts = config.report_options.strip()
    if extra_opts:
        cmd.extend(shlex.split(extra_opts))

    print(f"[forensic_probe] Running report generator: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        print(
            f"[forensic_probe] Report generation failed with status {exc.returncode}. Command: {' '.join(cmd)}"
        )
        return {
            "status": "error",
            "exit_code": exc.returncode,
            "command": cmd,
            "output": str(report_path),
        }

    return {
        "status": "ok",
        "format": config.report_format,
        "output": str(report_path),
        "command": cmd,
    }


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


def _load_completed_probe(path: Optional[pathlib.Path]) -> Dict[Tuple[str, Optional[int]], Set[str]]:
    if not path:
        return {}
    try:
        if not path.exists():
            return {}
    except OSError:
        return {}

    completed: Dict[Tuple[str, Optional[int]], Set[str]] = defaultdict(set)
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception as exc:  # noqa: BLE001 - resume helper failures should not abort probe
        print(f"[resume] Failed to load prior probe results from {path}: {exc}", file=sys.stderr)
        return {}

    for entry in data.get("scenarios", []):
        if not isinstance(entry, dict):
            continue
        algo = (entry.get("algorithm") or "").strip()
        scenario = (entry.get("scenario") or "").strip()
        if not algo or not scenario:
            continue
        category_raw = entry.get("security_category")
        category: Optional[int]
        try:
            category = int(category_raw)
        except (TypeError, ValueError):
            category = None
        completed[(algo, category)].add(scenario)
    return {key: set(values) for key, values in completed.items()}


def _merge_unique_entries(
    previous: Optional[Iterable[Dict[str, Any]]],
    new: Optional[Iterable[Dict[str, Any]]],
    key_fields: Sequence[str],
) -> List[Dict[str, Any]]:
    combined: List[Dict[str, Any]] = []
    seen: Set[Tuple[Any, ...]] = set()

    def _add(entry: Dict[str, Any]) -> None:
        key = tuple(entry.get(field) for field in key_fields)
        if key in seen:
            return
        seen.add(key)
        combined.append(entry)

    if previous:
        for entry in previous:
            if isinstance(entry, dict):
                _add(entry)
    if new:
        for entry in new:
            if isinstance(entry, dict):
                _add(entry)
    return combined


def _merge_report_artifacts(
    previous: Optional[Dict[str, Any]],
    current: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not previous and not current:
        return None
    if not previous:
        return current
    if not current:
        return previous
    merged: Dict[str, Any] = {}
    merged["csv"] = current.get("csv") or previous.get("csv")
    merged["captions"] = current.get("captions") or previous.get("captions")
    previous_plots = previous.get("plots", []) or []
    current_plots = current.get("plots", []) or []
    merged["plots"] = sorted({*previous_plots, *current_plots})
    previous_notes = previous.get("notes", []) or []
    current_notes = current.get("notes", []) or []
    merged_notes: List[str] = []
    for note in previous_notes + current_notes:
        if note not in merged_notes:
            merged_notes.append(note)
    merged["notes"] = merged_notes
    return merged


def _merge_summaries(
    previous: Dict[str, Any],
    current: Dict[str, Any],
    resume_source: Optional[pathlib.Path],
) -> Dict[str, Any]:
    merged: Dict[str, Any] = dict(previous)

    merged["scenarios"] = _merge_unique_entries(
        previous.get("scenarios"), current.get("scenarios"),
        ("algorithm", "parameter_name", "security_category", "scenario"),
    )
    merged["analysis"] = _merge_unique_entries(
        previous.get("analysis"), current.get("analysis"),
        ("algorithm", "parameter_name", "security_category", "scenario_name"),
    )

    config_history = list(previous.get("config_history", []))
    prev_config = previous.get("config")
    if isinstance(prev_config, dict):
        config_history.append(prev_config)
    merged["config_history"] = config_history
    merged["config"] = current.get("config")

    host_history = list(previous.get("host_history", []))
    prev_host = previous.get("host")
    if isinstance(prev_host, dict):
        host_history.append(prev_host)
    merged["host_history"] = host_history
    merged["host"] = current.get("host")

    merged_report = _merge_report_artifacts(previous.get("report_artifacts"), current.get("report_artifacts"))
    if merged_report:
        merged["report_artifacts"] = merged_report
    else:
        merged.pop("report_artifacts", None)

    if current.get("forensic_report"):
        merged["forensic_report"] = current["forensic_report"]
    elif previous.get("forensic_report"):
        merged["forensic_report"] = previous["forensic_report"]

    resume_sources = set(previous.get("resume_sources", []))
    if resume_source:
        resume_sources.add(str(resume_source))
    merged["resume_sources"] = sorted(resume_sources)

    return merged


def discover_algorithms(config: ProbeConfig) -> List[AlgorithmDescriptor]:
    discovered: List[AlgorithmDescriptor] = []
    available = registry.list()
    include_raw = config.include_algorithms or []
    include_set: Set[str] = set()
    include_set_lower: Set[str] = set()
    explicit_display_overrides: Dict[str, str] = {}
    for name in include_raw:
        canonical = _canonical_algorithm_name(name)
        if canonical is None:
            continue
        include_set.add(canonical)
        include_set_lower.add(canonical.lower())
        explicit_display_overrides.setdefault(canonical, name)
    explicit_include = bool(include_set)

    exclude_raw = config.exclude_algorithms or []
    exclude_set: Set[str] = set()
    exclude_set_lower: Set[str] = set()
    for name in exclude_raw:
        canonical = _canonical_algorithm_name(name)
        if canonical is None:
            continue
        exclude_set.add(canonical)
        exclude_set_lower.add(canonical.lower())

    if config.categories:
        categories = sorted({cat for cat in config.categories if cat in (1, 3, 5)})
    else:
        categories = []

    completed_scenarios = _load_completed_probe(config.resume_from)
    if config.resume_from:
        if completed_scenarios:
            scenario_total = sum(len(items) for items in completed_scenarios.values())
            print(
                f"[resume] Loaded {len(completed_scenarios)} algorithm/category entries "
                f"covering {scenario_total} scenarios from {config.resume_from}",
                flush=True,
            )
        else:
            print(
                f"[resume] No scenarios found in {config.resume_from}; running full probe.",
                flush=True,
            )

    scenario_name_cache: Dict[str, List[str]] = {
        "kem": [definition.name for definition in build_kem_scenarios(config)],
        "signature": [definition.name for definition in build_signature_scenarios(config)],
    }
    if config.include_scenarios:
        allowed = {name for name in config.include_scenarios}
        for kind in scenario_name_cache:
            scenario_name_cache[kind] = [name for name in scenario_name_cache[kind] if name in allowed]

    for key, candidate in sorted(available.items()):
        canonical_key = _canonical_algorithm_name(key) or key
        key_lower = canonical_key.lower()
        display_name = _display_algorithm_name(canonical_key, explicit_display_overrides.get(canonical_key))

        if include_set and canonical_key not in include_set and key_lower not in include_set_lower:
            continue
        if canonical_key in exclude_set or key_lower in exclude_set_lower:
            print(f"[forensic_probe] Skipping {display_name}: excluded via CLI", file=sys.stderr)
            continue
        if key_lower in DEFAULT_ALGORITHM_EXCLUDE and not (explicit_include and (canonical_key in include_set or key_lower in include_set_lower)):
            print(f"[forensic_probe] Skipping {display_name}: excluded by default (unstable)", file=sys.stderr)
            continue
        if inspect.isclass(candidate):
            base_factory: Callable[[], Any] = candidate
        elif callable(candidate):
            base_factory = candidate
        else:
            base_factory = lambda candidate=candidate: candidate

        variant_specs: List[Tuple[Dict[str, str], Optional[int], Optional[str]]] = [({}, None, None)]
        if categories:
            variant_specs = []
            available_for_algo = set(available_categories(display_name))
            for category in categories:
                if canonical_key in {"rsa-oaep", "rsa-pss"} and category > config.rsa_max_category:
                    print(
                        f"[forensic_probe] Skipping {display_name} Cat-{category}: limited by --rsa-max-category={config.rsa_max_category}",
                        file=sys.stderr,
                    )
                    continue
                if available_for_algo and category not in available_for_algo:
                    continue
                override = resolve_security_override(display_name, category)
                overrides: Dict[str, str] = {}
                note = None
                if override:
                    overrides[override.env_var] = str(override.value)
                    note = override.note
                variant_specs.append((overrides, category, note))
            if not variant_specs:
                continue

        for overrides, category, note in variant_specs:
            factory = wrap_factory(base_factory, overrides)
            try:
                probe_obj = factory()
            except Exception as exc:
                label = f"{display_name} cat-{category}" if category is not None else display_name
                print(f"[forensic_probe] Skipping {label}: instantiation failed ({exc!r})", file=sys.stderr)
                continue
            kind = classify_algorithm(key, probe_obj)
            if kind is None:
                continue
            parameter_name = resolve_mechanism_name(probe_obj)
            if parameter_name is None:
                parameter_name = getattr(probe_obj, "alg", None)
            param_hint = find_param_hint(parameter_name or canonical_key)
            descriptor = AlgorithmDescriptor(
                key=display_name,
                factory=factory,
                kind=kind,
                parameter_name=parameter_name,
                param_hint=param_hint,
                security_category=category,
                override_note=note,
                override_env=dict(overrides),
            )
            if config.resume_from:
                expected_names = scenario_name_cache.get(kind, [])
                expected = set(expected_names)
                if expected:
                    completed = completed_scenarios.get((descriptor.key, category), set())
                    missing = expected - completed
                    if not missing:
                        category_suffix = f" Cat-{category}" if category is not None else ""
                        print(
                            f"[resume] Skipping {descriptor.key}{category_suffix}: scenarios already present in {config.resume_from}",
                            flush=True,
                        )
                        del probe_obj
                        continue
                    descriptor.pending_scenarios = missing
                    if completed:
                        skipped = [name for name in expected_names if name in completed]
                        if skipped:
                            remaining_ordered = [name for name in expected_names if name in missing]
                            if not remaining_ordered:
                                remaining_ordered = sorted(missing)
                            category_suffix = f" Cat-{category}" if category is not None else ""
                            resume_note = f" from {config.resume_from}" if config.resume_from else ""
                            print(
                                f"[resume] {descriptor.key}{category_suffix}: running remaining scenarios {', '.join(remaining_ordered)}; "
                                f"skipping {', '.join(skipped)}{resume_note}",
                                flush=True,
                            )
                else:
                    descriptor.pending_scenarios = None
            discovered.append(descriptor)
            del probe_obj

    discovered.sort(
        key=lambda desc: (
            desc.key.lower(),
            -1 if desc.security_category is None else int(desc.security_category),
            (desc.parameter_name or "")
        )
    )
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
        variant_tokens: List[str] = []
        if descriptor.parameter_name and descriptor.parameter_name.lower() != descriptor.key.lower():
            variant_tokens.append(str(descriptor.parameter_name))
        if descriptor.security_category is not None:
            variant_tokens.append(f"cat-{descriptor.security_category}")
        variant_text = f" [{' | '.join(variant_tokens)}]" if variant_tokens else ""
        print(f"[forensic_probe] Running scenarios for {descriptor.key}{variant_text} ({descriptor.kind})")
        scenarios = build_kem_scenarios(config) if descriptor.kind == "kem" else build_signature_scenarios(config)
        pending_names = set(descriptor.pending_scenarios) if descriptor.pending_scenarios else None
        for definition in scenarios:
            if config.include_scenarios and definition.name not in config.include_scenarios:
                continue
            if pending_names is not None and definition.name not in pending_names:
                continue
            print(f"    -> Scenario {definition.name}: {definition.description}")
            result = run_scenario(config, descriptor, definition, rng)
            scenario_results.append(result)
    return scenario_results, host_metadata


# ---------------------------------------------------------------------------
# Statistical analysis
# ---------------------------------------------------------------------------

def analyse_pairs(results: List[ScenarioResult], config: ProbeConfig) -> List[AnalysisResult]:
    grouped: Dict[Tuple[str, str, str, Optional[int], str], Dict[str, List[Observation]]] = defaultdict(lambda: defaultdict(list))
    for result in results:
        descriptor = result.descriptor
        definition = result.definition
        if not definition.group or not definition.label:
            continue
        key = (
            descriptor.key,
            descriptor.kind,
            descriptor.parameter_name or descriptor.key,
            descriptor.security_category,
            definition.group,
        )
        grouped[key][definition.label].extend(result.observations)

    analysis_results: List[AnalysisResult] = []
    sanity_rng = random.Random(config.seed ^ 0xDADBEEF)
    for (alg_key, alg_kind, param_name, category, group), label_map in grouped.items():
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
                    security_category=category,
                )
            )
            if config.enable_sanity_checks:
                sanity_results = generate_sanity_results(
                    alg_key=alg_key,
                    alg_kind=alg_kind,
                    param_name=param_name,
                    category=category,
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
    category: Optional[int],
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
                security_category=category,
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
                security_category=category,
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
                security_category=category,
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
    if config_dict.get("resume_from") is not None:
        config_dict["resume_from"] = str(config_dict["resume_from"])
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
            "security_category": result.descriptor.security_category,
            "security_override_note": result.descriptor.override_note,
            "security_override_env": result.descriptor.override_env,
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
        category_tag = f" cat-{entry.security_category}" if entry.security_category is not None else ""
        param_label = entry.parameter_name or "-"
        print(
            f"{entry.algorithm}{category_tag} [{param_label}] {entry.scenario_name}: "
            f"|t_time|={abs(metrics['t_stat_time']):.2f}, "
            f"|t_cpu|={abs(metrics['t_stat_cpu']):.2f}, "
            f"|t_rss|={abs(metrics['t_stat_rss']):.2f}, "
            f"t2_time={abs(metrics['t2_stat_time']):.2f}, "
            f"MI={mi_vals[0]:.4f}/{mi_vals[1]:.4f}/{mi_vals[2]:.4f}, "
            f"Δ={cliffs_time:.3f}/{cliffs_cpu:.3f}/{cliffs_rss:.3f} -> flags: {flag_status}"
        )
    if not analysis_results:
        print("No paired scenarios available for statistical analysis.")


def generate_visual_report(analysis_results: List[AnalysisResult], report_dir: pathlib.Path) -> Dict[str, Any]:
    artifacts: Dict[str, Any] = {"plots": [], "csv": None, "notes": []}
    report_dir.mkdir(parents=True, exist_ok=True)

    csv_path = report_dir / "analysis_summary.csv"
    fieldnames = [
        "algorithm",
        "scenario",
        "security_category",
        "parameter",
        "is_sanity",
        "t_stat_time",
        "t_stat_cpu",
        "t_stat_rss",
        "t2_stat_time",
        "t2_stat_cpu",
        "t2_stat_rss",
        "mannu_pvalue_time",
        "mannu_pvalue_cpu",
        "mannu_pvalue_rss",
        "ks_pvalue_time",
        "ks_pvalue_cpu",
        "ks_pvalue_rss",
        "mi_time",
        "mi_pvalue_time",
        "mi_cpu",
        "mi_pvalue_cpu",
        "mi_rss",
        "mi_pvalue_rss",
        "cliffs_delta_time",
        "cliffs_delta_cpu",
        "cliffs_delta_rss",
        "time_leak_flag",
        "cpu_leak_flag",
        "rss_leak_flag",
    ]
    csv_exists = csv_path.exists()
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if csv_exists else "w"
    with csv_path.open(mode, newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        if not csv_exists or csv_file.tell() == 0:
            writer.writeheader()
        for entry in analysis_results:
            metrics = entry.metrics
            writer.writerow(
                {
                    "algorithm": entry.algorithm,
                    "scenario": entry.scenario_name,
                    "security_category": entry.security_category,
                    "parameter": entry.parameter_name,
                    "is_sanity": "sanity" in entry.scenario_name,
                    "t_stat_time": metrics.get("t_stat_time"),
                    "t_stat_cpu": metrics.get("t_stat_cpu"),
                    "t_stat_rss": metrics.get("t_stat_rss"),
                    "t2_stat_time": metrics.get("t2_stat_time"),
                    "t2_stat_cpu": metrics.get("t2_stat_cpu"),
                    "t2_stat_rss": metrics.get("t2_stat_rss"),
                    "mannu_pvalue_time": metrics.get("mannu_pvalue_time"),
                    "mannu_pvalue_cpu": metrics.get("mannu_pvalue_cpu"),
                    "mannu_pvalue_rss": metrics.get("mannu_pvalue_rss"),
                    "ks_pvalue_time": metrics.get("ks_pvalue_time"),
                    "ks_pvalue_cpu": metrics.get("ks_pvalue_cpu"),
                    "ks_pvalue_rss": metrics.get("ks_pvalue_rss"),
                    "mi_time": metrics.get("mi_time"),
                    "mi_pvalue_time": metrics.get("mi_pvalue_time"),
                    "mi_cpu": metrics.get("mi_cpu"),
                    "mi_pvalue_cpu": metrics.get("mi_pvalue_cpu"),
                    "mi_rss": metrics.get("mi_rss"),
                    "mi_pvalue_rss": metrics.get("mi_pvalue_rss"),
                    "cliffs_delta_time": metrics.get("cliffs_delta_time"),
                    "cliffs_delta_cpu": metrics.get("cliffs_delta_cpu"),
                    "cliffs_delta_rss": metrics.get("cliffs_delta_rss"),
                    "time_leak_flag": metrics.get("time_leak_flag"),
                    "cpu_leak_flag": metrics.get("cpu_leak_flag"),
                    "rss_leak_flag": metrics.get("rss_leak_flag"),
                }
            )
    artifacts["csv"] = str(csv_path)

    non_sanity = [entry for entry in analysis_results if "sanity" not in entry.scenario_name]
    if not non_sanity:
        artifacts["notes"].append("No primary scenario pairs available for plotting.")
        return artifacts

    try:
        import matplotlib.pyplot as plt  # type: ignore
    except ImportError:
        artifacts["notes"].append(
            "matplotlib not installed; skipped plot generation. Install matplotlib to enable --render-plots."
        )
        return artifacts

    class CaptionCollector:
        def __init__(self) -> None:
            self.entries: List[Tuple[pathlib.Path, str]] = []

        def add(self, path: pathlib.Path, caption: str) -> None:
            self.entries.append((path, caption))

        def write(self, root: pathlib.Path) -> Optional[pathlib.Path]:
            if not self.entries:
                return None
            root.mkdir(parents=True, exist_ok=True)
            lines = ["# Side-Channel Plots", ""]
            for path, caption in sorted(self.entries, key=lambda item: str(item[0])):
                rel = path.relative_to(root)
                lines.append(f"![{rel}]({rel})")
                lines.append("")
                lines.append(caption)
                lines.append("")
            output = root / "captions.md"
            output.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
            return output

    captions = CaptionCollector()
    palette = {"time": "#1f77b4", "cpu": "#ff7f0e", "rss": "#2ca02c"}
    metric_labels = {"time": "Wall-clock", "cpu": "CPU", "rss": "RSS Δ"}

    grouped: Dict[Tuple[str, str], Dict[int, Dict[str, float]]] = defaultdict(lambda: defaultdict(dict))
    params_by_category: Dict[Tuple[str, str, int], Optional[str]] = {}
    for entry in non_sanity:
        if entry.security_category is None:
            continue
        metrics = entry.metrics
        grouped[(entry.algorithm, entry.scenario_name)][entry.security_category] = {
            "time": abs(metrics.get("t_stat_time", 0.0) or 0.0),
            "cpu": abs(metrics.get("t_stat_cpu", 0.0) or 0.0),
            "rss": abs(metrics.get("t_stat_rss", 0.0) or 0.0),
        }
        params_by_category[(entry.algorithm, entry.scenario_name, entry.security_category)] = entry.parameter_name

    if not grouped:
        artifacts["notes"].append("No category-tagged scenarios available for plotting.")
        return artifacts

    for (algorithm, scenario_name), category_map in sorted(grouped.items()):
        categories = sorted(category_map.keys())
        if not categories:
            continue
        fig_width = max(6.0, len(categories) * 1.2)
        fig, ax = plt.subplots(figsize=(fig_width, 4.8))
        metrics_order = ["time", "cpu", "rss"]
        width = 0.75 / len(metrics_order)
        x_positions = list(range(len(categories)))

        for idx, metric in enumerate(metrics_order):
            offsets = [pos + idx * width for pos in x_positions]
            values = [category_map.get(cat, {}).get(metric, 0.0) for cat in categories]
            ax.bar(
                offsets,
                values,
                width=width,
                label=metric_labels[metric],
                color=palette.get(metric, "#555555"),
            )
            for offset, value in zip(offsets, values):
                ax.text(offset, value + 0.08, f"{value:.2f}", ha="center", va="bottom", fontsize=8)

        ax.set_xticks([pos + (len(metrics_order) - 1) * width / 2 for pos in x_positions])
        ax.set_xticklabels([f"Cat-{cat}" for cat in categories])
        ax.set_ylabel("Absolute t-statistic")
        friendly_name = scenario_name.replace(":", " — ")
        ax.set_title(f"{algorithm} — {friendly_name}")
        ax.grid(True, axis="y", linestyle="--", alpha=0.3)
        sample_values = [v for cat in categories for v in category_map.get(cat, {}).values() if v is not None]
        if sample_values:
            ymax = max(sample_values + [TVLA_T_THRESHOLD])
            ax.set_ylim(0, max(ymax * 1.15, TVLA_T_THRESHOLD * 1.1))
        else:
            ax.set_ylim(0, TVLA_T_THRESHOLD * 1.1)
        ax.axhline(
            TVLA_T_THRESHOLD,
            color="#d62728",
            linestyle="--",
            linewidth=1,
            label="TVLA |t|=4.5",
        )
        ax.legend(loc="upper right")

        param_notes = [
            params_by_category.get((algorithm, scenario_name, cat))
            for cat in categories
            if params_by_category.get((algorithm, scenario_name, cat))
        ]
        caption_parts = [
            "|t|-statistics for wall-clock (time), CPU, and RSS deltas across security categories.",
            f"Scenario: {friendly_name}",
        ]
        if param_notes:
            caption_parts.append(f"Parameters: {', '.join(sorted(set(param_notes)))}")
        caption_parts.append("Dashed line marks the TVLA threshold (|t|=4.5).")
        caption = " ".join(caption_parts)

        slug = slugify(f"{algorithm}-{scenario_name}")
        plot_path = report_dir / f"sidechannel_{slug}.png"
        fig.tight_layout(rect=(0, 0.09, 1, 1))
        fig.text(0.5, 0.02, caption, ha="center", va="center", fontsize=9)
        fig.savefig(plot_path, dpi=200)
        plt.close(fig)
        artifacts["plots"].append(str(plot_path))
        captions.add(plot_path, caption)

    captions_path = captions.write(report_dir)
    if captions_path is not None:
        artifacts["captions"] = str(captions_path)

    return artifacts


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[Iterable[str]] = None) -> ProbeConfig:
    parser = argparse.ArgumentParser(description="Forensic side-channel probe for registered PQC algorithms.")
    parser.add_argument("--iterations", type=int, default=800, help="Iterations per scenario (default: 800)")
    parser.add_argument("--seed", type=int, default=991239, help="Seed for deterministic helper randomness")
    parser.add_argument("--output", type=pathlib.Path, help="Optional output JSON path")
    parser.add_argument(
        "--resume-from",
        type=pathlib.Path,
        help="Path to an existing forensic_probe JSON file; scenarios already present there are skipped",
    )
    parser.add_argument("--keep-artifacts", action="store_true", help="Retain temporary artifacts generated during scenarios")
    parser.add_argument("--alg", nargs="*", help="Limit to specific registry keys")
    parser.add_argument("--scenario", nargs="*", help="Limit to specific scenario names")
    parser.add_argument("--exclude", nargs="*", help="Explicitly exclude registry keys")
    parser.add_argument("--no-sanity-checks", action="store_true", help="Disable shuffle/split sanity controls")
    parser.add_argument(
        "--categories",
        type=int,
        nargs="*",
        help="Security categories (subset of 1,3,5) to probe via parameter overrides",
    )
    parser.add_argument(
        "--rsa-max-category",
        type=int,
        default=5,
        help="Highest RSA category to include when probing categories (default: 5; set to 3 to skip Cat-5 RSA).",
    )
    parser.add_argument(
        "--all-categories",
        action="store_true",
        help="Shortcut for probing categories 1, 3, and 5",
    )
    parser.add_argument(
        "--render-plots",
        action="store_true",
        help="Generate simple plots and a CSV summary for analysis results (requires matplotlib)",
    )
    parser.add_argument(
        "--plot-dir",
        type=pathlib.Path,
        help="Directory for report artifacts (plots/CSV). Defaults to alongside the JSON output.",
    )
    parser.add_argument(
        "--render-report",
        action="store_true",
        help="Run tools/forensic_report.py after the probe completes.",
    )
    parser.add_argument(
        "--report-format",
        default="markdown",
        help="Output format for the generated report (default: markdown).",
    )
    parser.add_argument(
        "--report-output",
        type=pathlib.Path,
        help="Explicit path for the generated forensic report.",
    )
    parser.add_argument(
        "--report-options",
        type=str,
        default="",
        help="Additional options forwarded to tools/forensic_report.py.",
    )
    args = parser.parse_args(argv)
    categories: Optional[List[int]] = None
    if args.all_categories:
        categories = [1, 3, 5]
    elif args.categories:
        filtered = sorted({cat for cat in args.categories if cat in (1, 3, 5)})
        if filtered:
            categories = filtered
        else:
            print("[forensic_probe] Ignoring --categories with no valid values (choose from 1,3,5)", file=sys.stderr)

    render_plots = args.render_plots or bool(args.plot_dir)

    return ProbeConfig(
        iterations=args.iterations,
        seed=args.seed,
        output_path=args.output,
        keep_artifacts=args.keep_artifacts,
        include_algorithms=args.alg,
        include_scenarios=args.scenario,
        exclude_algorithms=args.exclude,
        enable_sanity_checks=not args.no_sanity_checks,
        categories=categories,
        render_plots=render_plots,
        plot_dir=args.plot_dir,
        render_report=args.render_report,
        report_format=args.report_format,
        report_output=args.report_output,
        report_options=args.report_options,
        rsa_max_category=max(1, min(args.rsa_max_category, 5)),
        resume_from=args.resume_from,
    )


def main(argv: Optional[Iterable[str]] = None) -> int:
    config = parse_args(argv)
    existing_summary: Optional[Dict[str, Any]] = None
    if config.resume_from:
        try:
            with config.resume_from.open("r", encoding="utf-8") as fh:
                existing_summary = json.load(fh)
        except FileNotFoundError:
            existing_summary = None
        except Exception as exc:
            print(f"[resume] Failed to load existing summary from {config.resume_from}: {exc}", file=sys.stderr)
            existing_summary = None
    descriptors = discover_algorithms(config)
    if not descriptors:
        print("[forensic_probe] No algorithms discovered. Ensure adapters are available.", file=sys.stderr)
        return 1
    scenario_results, host_metadata = collect_results(config, descriptors)
    analysis_results = analyse_pairs(scenario_results, config)
    summary = summarise_results(scenario_results, analysis_results, host_metadata, config)
    emit_summary(summary, analysis_results)
    output_path = config.output_path or (PROJECT_ROOT / "results" / f"forensic_probe_{int(time.time())}.json")
    report_artifacts: Optional[Dict[str, Any]] = None
    if config.render_plots:
        report_dir = config.plot_dir or (output_path.parent / f"{output_path.stem}_report")
        report_artifacts = generate_visual_report(analysis_results, report_dir)
        summary["report_artifacts"] = report_artifacts
        if report_artifacts.get("plots"):
            print(f"[forensic_probe] Generated plots in {report_dir}")
        if report_artifacts.get("csv"):
            print(f"[forensic_probe] Wrote analysis summary CSV to {report_artifacts['csv']}")
        if report_artifacts.get("captions"):
            print(f"[forensic_probe] Wrote plot captions to {report_artifacts['captions']}")
        for note in report_artifacts.get("notes", []):
            print(f"[forensic_probe] {note}")
    if existing_summary:
        summary = _merge_summaries(existing_summary, summary, config.resume_from)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    def _write_summary() -> None:
        with output_path.open("w", encoding="utf-8") as fh:
            json.dump(to_jsonable(summary), fh, indent=2)

    _write_summary()
    print(f"\n[forensic_probe] Written detailed results to {output_path}")

    if config.render_report:
        report_info = run_forensic_report(output_path, config)
        if report_info:
            summary["forensic_report"] = report_info
            _write_summary()
            if report_info.get("status") == "ok" and report_info.get("output"):
                print(f"[forensic_probe] Forensic report generated at {report_info['output']}")
            elif report_info.get("status") == "missing_script":
                print("[forensic_probe] Forensic report skipped: report script not found.")
            else:
                print("[forensic_probe] Forensic report generation completed with warnings; see JSON for details.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
