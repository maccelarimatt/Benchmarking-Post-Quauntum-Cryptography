from __future__ import annotations

import argparse
import csv
import datetime as _dt
import json
import pathlib
import shlex
import subprocess
import sys
from dataclasses import asdict, dataclass, is_dataclass
import contextlib
import os
import copy
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from pqcbench import registry
from pqcbench.params import ParamHint, find as find_param_hint
from pqcbench_cli.runners.common import (
    _collect_environment_meta,
    _load_adapters,
    reset_adapter_cache,
    run_kem,
    run_sig,
)
from pqcbench.security_estimator import estimate_for_summary
from pqcbench.security_levels import resolve_security_override, available_categories

HERE = pathlib.Path(__file__).resolve().parent
RESULTS_DIR = HERE.parent / "results"
GRAPH_SCRIPT = HERE / "render_category_floor_graphs.py"
SIDE_CHANNEL_SCRIPT = HERE.parent / "tools" / "forensic_probe.py"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
_UTC = _dt.UTC

DEFAULT_OUTPUT = RESULTS_DIR / "category_floor_benchmarks.csv"
DEFAULT_META = RESULTS_DIR / "category_floor_benchmarks.meta.json"

# Mapping from param floor (bits) to human-friendly labels and category numbers
_FLOOR_TO_CATEGORY = {
    128: ("cat-1", 1),
    192: ("cat-3", 3),
    256: ("cat-5", 5),
}
_CATEGORY_TO_FLOOR = {v[1]: k for k, v in _FLOOR_TO_CATEGORY.items()}
_CATEGORY_DEFAULT_FLOOR = {1: 128, 3: 192, 5: 256}




@dataclass
class AlgorithmSpec:
    name: str
    kind: str
    mechanism: Optional[str]
    hint: ParamHint
    category_bits: int
    category_label: str
    category_number: int


_FIELDNAMES: Sequence[str] = (
    "session_id",
    "timestamp_iso",
    "measurement_pass",
    "algo",
    "kind",
    "family",
    "mechanism",
    "category_label",
    "category_number",
    "category_floor_bits",
    "parameter_notes",
    "parameter_extras_json",
    "runs",
    "operation",
    "mean_ms",
    "median_ms",
    "stddev_ms",
    "min_ms",
    "max_ms",
    "range_ms",
    "ci95_low_ms",
    "ci95_high_ms",
    "mem_mean_kb",
    "mem_median_kb",
    "mem_stddev_kb",
    "mem_min_kb",
    "mem_max_kb",
    "mem_range_kb",
    "mem_ci95_low_kb",
    "mem_ci95_high_kb",
    "series_json",
    "mem_series_json",
    "runtime_scaling_json",
    "meta_json",
    "security_classical_bits",
    "security_quantum_bits",
    "security_shor_breakable",
    "security_notes",
    "security_mechanism",
    "security_extras_json",
    "pass_config_json",
)


def _json_default(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serialisable")


def _json_dumps(data: Any) -> str:
    if data is None:
        return ""
    try:
        return json.dumps(data, default=_json_default, sort_keys=True, separators=(",", ":"))
    except TypeError:
        return json.dumps(str(data))


def _variant_env_for_category(category: int) -> Dict[str, str]:
    overrides: Dict[str, str] = {}
    for algo_name in registry.list().keys():
        override = resolve_security_override(algo_name, category)
        if not override:
            continue
        overrides[override.env_var] = str(override.value)
    return overrides


@contextlib.contextmanager
def _temporary_env(overrides: Dict[str, str]):
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
        for key, previous in original.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous


def _detect_kind(candidate: Any) -> Optional[str]:
    if hasattr(candidate, "encapsulate") and hasattr(candidate, "decapsulate"):
        return "KEM"
    if hasattr(candidate, "sign") and hasattr(candidate, "verify"):
        return "SIG"
    return None


def _resolve_mechanism(candidate: Any, fallback_name: str) -> str | None:
    attrs = ("mech", "alg", "_mech", "algorithm")
    for attr in attrs:
        value = getattr(candidate, attr, None)
        if value:
            return str(value)
    return fallback_name


def _supports_category(algo: str, category: int, override) -> bool:
    """Return True if applying the security override selects a distinct mechanism."""

    if override is None:
        return False
    try:
        value = override.value
    except AttributeError:
        value = None
    if value is None:
        return False
    if not isinstance(value, str):
        return True  # RSA-sized overrides
    env_var = override.env_var
    desired = value.strip().lower()
    if not desired:
        return False
    with _temporary_env({env_var: str(value)}):
        reset_adapter_cache(algo)
        try:
            candidate = registry.get(algo)()
        except Exception:
            return False
    mechanism = _resolve_mechanism(candidate, algo)
    if not mechanism:
        return False
    return mechanism.strip().lower() == desired


def _clone_hint_for_category(hint: ParamHint, category: int, override_value: Any) -> ParamHint:
    extras = copy.deepcopy(hint.extras) if hint.extras else {}
    category_floor = _CATEGORY_DEFAULT_FLOOR.get(category, hint.category_floor)
    if isinstance(override_value, int):
        extras = dict(extras)
        extras["modulus_bits"] = int(override_value)
    return ParamHint(
        family=hint.family,
        mechanism=hint.mechanism,
        category_floor=category_floor,
        notes=hint.notes,
        extras=extras,
    )


def _load_completed_passes(csv_path: Optional[pathlib.Path]) -> Dict[Tuple[str, int], Set[str]]:
    if not csv_path:
        return {}
    try:
        if not csv_path.exists():
            return {}
    except OSError:
        return {}

    completed: Dict[Tuple[str, int], Set[str]] = defaultdict(set)
    try:
        with csv_path.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                algo = (row.get("algo") or "").strip()
                pass_name = (row.get("measurement_pass") or "").strip().lower()
                if not algo or not pass_name:
                    continue
                try:
                    category = int(row.get("category_number", "") or 0)
                except (TypeError, ValueError):
                    continue
                completed[(algo, category)].add(pass_name)
    except Exception as exc:  # noqa: BLE001 - resume helper errors are non-fatal
        print(f"[resume] Failed to load prior results from {csv_path}: {exc}", file=sys.stderr)
        return {}
    return {key: set(passes) for key, passes in completed.items()}


def _fallback_hint(name: str, mechanism: Optional[str], category: int, override_value: Any) -> ParamHint:
    fallback_bits = _CATEGORY_DEFAULT_FLOOR.get(category, _CATEGORY_DEFAULT_FLOOR.get(1, 0))
    mechanism_label: str = (
        str(override_value)
        if isinstance(override_value, str)
        else (mechanism or name)
    )
    extras: Dict[str, Any] | None = None
    if isinstance(override_value, int):
        extras = {"modulus_bits": int(override_value)}
    return ParamHint(
        family=name.replace("_", "-").upper(),
        mechanism=mechanism_label,
        category_floor=fallback_bits,
        notes="Fallback hint (add pqcbench.params entry for richer metadata).",
        extras=extras,
    )


def discover_algorithms(categories: Iterable[int], *, rsa_max_category: int = 5) -> List[AlgorithmSpec]:
    desired = [cat for cat in categories if cat in (1, 3, 5)]
    specs: List[AlgorithmSpec] = []
    for name, cls in registry.list().items():
        try:
            adapter = cls()
        except Exception:
            continue
        kind = _detect_kind(adapter)
        if not kind:
            continue
        mechanism = _resolve_mechanism(adapter, name)
        hint = find_param_hint(mechanism) or find_param_hint(name)
        available = set(available_categories(name))
        for category in desired:
            if available and category not in available:
                continue
            override = resolve_security_override(name, category)
            if name in {"rsa-oaep", "rsa-pss"} and int(category) > int(rsa_max_category):
                continue
            if not _supports_category(name, category, override):
                continue
            if hint:
                hint_for_cat = _clone_hint_for_category(
                    hint,
                    category,
                    override.value if override else None,
                )
            else:
                hint_for_cat = _fallback_hint(
                    name,
                    mechanism,
                    category,
                    override.value if override else None,
                )
            label = f"cat-{category}"
            specs.append(
                AlgorithmSpec(
                    name=name,
                    kind=kind,
                    mechanism=mechanism,
                    hint=hint_for_cat,
                    category_bits=hint_for_cat.category_floor,
                    category_label=label,
                    category_number=category,
                )
            )
    specs.sort(key=lambda s: (s.category_number, s.kind, s.name))
    return specs


def _timestamp_iso() -> str:
    return _dt.datetime.now(_UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _build_rows(
    summary,
    spec: AlgorithmSpec,
    measurement_pass: str,
    security: Dict[str, Any],
    pass_config: Dict[str, Any],
    session_id: str,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    security_mech = security.get("mechanism") if isinstance(security, dict) else None
    meta_mech = None
    if isinstance(summary.meta, dict):
        meta_mech = summary.meta.get("mechanism")
    resolved_mech = meta_mech or security_mech or spec.mechanism or spec.name
    family = spec.hint.family if hasattr(spec.hint, "family") else None
    category_number = int(pass_config.get("category") or spec.category_number)
    category_label = f"cat-{category_number}" if category_number else spec.category_label
    meta_json = _json_dumps(summary.meta)
    security_extras_json = _json_dumps(security.get("extras") if isinstance(security, dict) else None)
    pass_config_json = _json_dumps(pass_config)
    param_extras_json = _json_dumps(spec.hint.extras)

    for op_name, stats in summary.ops.items():
        runtime_scaling_json = _json_dumps(asdict(stats.runtime_scaling)) if stats.runtime_scaling else ""
        rows.append(
            {
                "session_id": session_id,
                "timestamp_iso": _timestamp_iso(),
                "measurement_pass": measurement_pass,
                "algo": summary.algo,
                "kind": summary.kind,
                "family": family,
                "mechanism": resolved_mech,
                "category_label": category_label,
                "category_number": category_number,
                "category_floor_bits": spec.category_bits,
                "parameter_notes": spec.hint.notes or "",
                "parameter_extras_json": param_extras_json,
                "runs": stats.runs,
                "operation": op_name,
                "mean_ms": stats.mean_ms,
                "median_ms": stats.median_ms,
                "stddev_ms": stats.stddev_ms,
                "min_ms": stats.min_ms,
                "max_ms": stats.max_ms,
                "range_ms": stats.range_ms,
                "ci95_low_ms": stats.ci95_low_ms,
                "ci95_high_ms": stats.ci95_high_ms,
                "mem_mean_kb": stats.mem_mean_kb,
                "mem_median_kb": stats.mem_median_kb,
                "mem_stddev_kb": stats.mem_stddev_kb,
                "mem_min_kb": stats.mem_min_kb,
                "mem_max_kb": stats.mem_max_kb,
                "mem_range_kb": stats.mem_range_kb,
                "mem_ci95_low_kb": stats.mem_ci95_low_kb,
                "mem_ci95_high_kb": stats.mem_ci95_high_kb,
                "series_json": _json_dumps(stats.series),
                "mem_series_json": _json_dumps(stats.mem_series_kb),
                "runtime_scaling_json": runtime_scaling_json,
                "meta_json": meta_json,
                "security_classical_bits": security.get("classical_bits") if isinstance(security, dict) else None,
                "security_quantum_bits": security.get("quantum_bits") if isinstance(security, dict) else None,
                "security_shor_breakable": security.get("shor_breakable") if isinstance(security, dict) else None,
                "security_notes": security.get("notes") if isinstance(security, dict) else None,
                "security_mechanism": resolved_mech,
                "security_extras_json": security_extras_json,
                "pass_config_json": pass_config_json,
            }
        )
    return rows


def _run_summary(
    spec: AlgorithmSpec,
    runs: int,
    message_size: int,
    *,
    capture_memory: bool,
    memory_interval: float,
    cold: bool,
):
    if spec.kind == "KEM":
        return run_kem(
            spec.name,
            runs,
            cold=cold,
            capture_memory=capture_memory,
            memory_interval=memory_interval,
        )
    return run_sig(
        spec.name,
        runs,
        message_size,
        cold=cold,
        capture_memory=capture_memory,
        memory_interval=memory_interval,
    )


def _normalize_graph_args(extra_args: Optional[List[str]]) -> List[str]:
    extra = list(extra_args) if extra_args else []
    if extra[:1] == ["--"]:
        extra = extra[1:]
    return extra


def _run_graph_renderer(script_path: pathlib.Path, extra_args: Optional[List[str]], csv_path: pathlib.Path) -> None:
    if not script_path.exists():
        print(f"Graph renderer not found at {script_path}. Skipping graph generation.")
        return

    extra = _normalize_graph_args(extra_args)
    includes_csv = any(arg == "--csv" or arg.startswith("--csv=") for arg in extra)
    cmd = [sys.executable, str(script_path)]
    if not includes_csv:
        cmd.extend(["--csv", str(csv_path)])
    cmd.extend(extra)

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        print(f"Graph renderer exited with status {exc.returncode}. Command: {' '.join(cmd)}")


def _run_side_channel(script_path: pathlib.Path, options: str) -> None:
    if not script_path.exists():
        print(f"Side-channel probe not found at {script_path}. Skipping side-channel run.")
        return

    cmd = [sys.executable, str(script_path)]
    if options:
        cmd.extend(shlex.split(options))

    print(f"Running side-channel probe: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        print(f"Side-channel probe exited with status {exc.returncode}. Command: {' '.join(cmd)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run category-floor benchmarks with split timing/memory passes.",
    )
    parser.add_argument("--runs", type=int, default=40, help="Iterations per operation for each pass (default: 40)")
    parser.add_argument(
        "--categories",
        type=int,
        nargs="*",
        default=[1, 3, 5],
        help="Category numbers to benchmark (subset of 1,3,5). Default runs all.",
    )
    parser.add_argument(
        "--message-size",
        type=int,
        default=1024,
        help="Message size (bytes) for signature benchmarks (default: 1024)",
    )
    parser.add_argument(
        "--warm",
        action="store_true",
        help="Add warm in-process passes alongside the default cold measurements.",
    )
    parser.add_argument(
        "--memory-interval",
        type=float,
        default=0.0005,
        help="Memory sampling interval in seconds for memory pass (default: 0.0005)",
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=DEFAULT_OUTPUT,
        help=f"Output CSV path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--metadata",
        type=pathlib.Path,
        default=DEFAULT_META,
        help=f"Metadata JSON path (default: {DEFAULT_META})",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to existing CSV instead of overwriting",
    )
    parser.add_argument(
        "--resume-from",
        type=pathlib.Path,
        default=None,
        help="Existing category floor CSV to reuse; skip passes already recorded there.",
    )
    parser.add_argument(
        "--no-security",
        action="store_true",
        help="Skip security estimator (speeds up large batches).",
    )
    parser.add_argument(
        "--rsa-max-category",
        type=int,
        default=5,
        help="Highest RSA category to benchmark (default 5). Use 3 to skip Cat-5 RSA.",
    )
    parser.add_argument(
        "--jsonl-output",
        type=pathlib.Path,
        default=None,
        help="Optional JSONL export path (one JSON object per line).",
    )
    parser.add_argument(
        "--parquet-output",
        type=pathlib.Path,
        default=None,
        help="Optional Parquet export path (requires pandas + pyarrow/fastparquet).",
    )
    parser.add_argument(
        "--render-graphs",
        action="store_true",
        help="Invoke the category floor graph renderer after benchmarks finish.",
    )
    parser.add_argument(
        "--graph-script",
        type=pathlib.Path,
        default=GRAPH_SCRIPT,
        help="Override the category floor graph renderer script (default: render_category_floor_graphs.py)",
    )
    parser.add_argument(
        "--graph-args",
        nargs=argparse.REMAINDER,
        default=None,
        help="Extra arguments forwarded to the graph renderer (must follow '--').",
    )
    parser.add_argument(
        "--run-side-channel",
        action="store_true",
        help="Run the forensic side-channel probe after benchmarks (and any graphs).",
    )
    parser.add_argument(
        "--side-channel-options",
        type=str,
        default="",
        help="Extra options appended to the side-channel probe command (e.g. '--all-categories --render-plots').",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    session_id = _dt.datetime.now(_UTC).strftime("%Y%m%dT%H%M%SZ")
    start_iso = _timestamp_iso()
    selected_categories = {cat for cat in args.categories if cat in _CATEGORY_TO_FLOOR}
    if not selected_categories:
        raise SystemExit("No valid categories selected; choose from 1, 3, 5.")

    _load_adapters()

    rows: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    env_meta = _collect_environment_meta()
    collected_specs: List[AlgorithmSpec] = []

    Pass = Tuple[str, bool, bool]  # (name, capture_memory, cold)
    passes: List[Pass] = [
        ("timing", False, True),
        ("memory", True, True),
    ]
    if args.warm:
        passes.extend(
            [
                ("timing-warm", False, False),
                ("memory-warm", True, False),
            ]
        )

    security_cache: Dict[Tuple[str, str], Dict[str, Any]] = {}
    category_spec_map: Dict[int, List[AlgorithmSpec]] = {}
    pending_pass_lookup: Dict[Tuple[int, str], Set[str]] = {}

    pass_names = [name for name, _, _ in passes]

    completed_passes: Dict[Tuple[str, int], Set[str]] = _load_completed_passes(args.resume_from)
    if args.resume_from:
        if completed_passes:
            completed_total = sum(len(done) for done in completed_passes.values())
            print(
                f"[resume] Loaded {len(completed_passes)} algorithm/category entries "
                f"covering {completed_total} passes from {args.resume_from}",
                flush=True,
            )
        else:
            print(
                f"[resume] No completed passes found in {args.resume_from}; running full benchmark set.",
                flush=True,
            )

    total_steps = 0
    for category in sorted(selected_categories):
        overrides = _variant_env_for_category(category)
        with _temporary_env(overrides):
            reset_adapter_cache()
            specs_for_cat = discover_algorithms({category}, rsa_max_category=args.rsa_max_category)
        filtered_specs: List[AlgorithmSpec] = []
        for spec in specs_for_cat:
            done_passes = completed_passes.get((spec.name, spec.category_number), set())
            remaining_passes = {name for name in pass_names if name not in done_passes}
            if not remaining_passes:
                if args.resume_from and done_passes:
                    print(
                        f"[resume] Skipping Cat-{category} :: {spec.name} — all passes already present in {args.resume_from}",
                        flush=True,
                    )
                continue
            if args.resume_from and done_passes:
                skip_list = [name for name in pass_names if name not in remaining_passes]
                if skip_list:
                    run_list = [name for name in pass_names if name in remaining_passes]
                    print(
                        f"[resume] Cat-{category} :: {spec.name} — running missing passes "
                        f"{', '.join(run_list)}; skipping {', '.join(skip_list)}",
                        flush=True,
                    )
            pending_pass_lookup[(spec.category_number, spec.name)] = remaining_passes
            filtered_specs.append(spec)
            total_steps += len(remaining_passes)
        category_spec_map[category] = filtered_specs
    reset_adapter_cache()
    print(
        f"[progress] Prepared {total_steps} measurement tasks "
        f"across {len(selected_categories)} categories and {len(passes)} passes.",
        flush=True,
    )
    if total_steps == 0 and args.resume_from:
        print("[resume] No pending passes to execute; skipping measurement phase.", flush=True)
    progress_done = 0

    for category in sorted(selected_categories):
        overrides = _variant_env_for_category(category)
        with _temporary_env(overrides):
            reset_adapter_cache()
            category_specs = category_spec_map.get(category, [])
            if not category_specs:
                failures.append(
                    {
                        "algo": None,
                        "kind": None,
                        "category_number": category,
                        "measurement_pass": "setup",
                        "error": f"No adapters available for category {category}.",
                    }
                )
                continue
            for spec in category_specs:
                spec_key = (spec.category_number, spec.name)
                pending_passes = pending_pass_lookup.get(spec_key, set(pass_names))
                if not pending_passes:
                    continue
                spec_started = False
                for pass_name, capture_memory, cold in passes:
                    if pass_name not in pending_passes:
                        continue
                    progress_done += 1
                    print(
                        f"[{progress_done}/{max(total_steps, 1)}] "
                        f"Cat-{category} :: {spec.name} ({spec.kind}) :: {pass_name}",
                        flush=True,
                    )
                    try:
                        if not spec_started:
                            collected_specs.append(spec)
                            spec_started = True
                        summary = _run_summary(
                            spec,
                            args.runs,
                            args.message_size,
                            capture_memory=capture_memory,
                            memory_interval=args.memory_interval,
                            cold=cold,
                        )
                        if args.no_security:
                            security: Dict[str, Any] = {}
                        else:
                            cache_key = (spec.name, spec.mechanism or spec.name)
                            if cache_key not in security_cache:
                                security_cache[cache_key] = estimate_for_summary(summary)
                            security = security_cache[cache_key]
                        pass_config = {
                            "capture_memory": capture_memory,
                            "memory_interval_seconds": args.memory_interval if capture_memory else None,
                            "runs": args.runs,
                            "cold": cold,
                            "category": category,
                            "warm_pass": not cold,
                        }
                        merged_meta = dict(summary.meta or {})
                        if env_meta and "environment" not in merged_meta:
                            merged_meta["environment"] = env_meta
                        summary.meta = merged_meta
                        rows.extend(
                            _build_rows(
                                summary,
                                spec,
                                pass_name,
                                security,
                                pass_config,
                                session_id,
                            )
                        )
                    except Exception as exc:  # noqa: BLE001 - best-effort collection
                        failures.append(
                            {
                                "algo": spec.name,
                                "kind": spec.kind,
                                "category_number": category,
                                "measurement_pass": pass_name,
                                "error": repr(exc),
                            }
                        )
                        break
                    finally:
                        reset_adapter_cache(spec.name)
            reset_adapter_cache()

    if not rows and failures:
        raise SystemExit("All benchmark passes failed; see metadata for details.")

    output_path = args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if (args.append or (args.resume_from and output_path.exists())) else "w"
    with output_path.open(mode, newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=_FIELDNAMES)
        if mode == "w":
            writer.writeheader()
        elif mode == "a" and output_path.stat().st_size == 0:
            writer.writeheader()
        rows.sort(
            key=lambda r: (
                r.get("category_number", 0),
                r.get("kind", ""),
                r.get("algo", ""),
                r.get("measurement_pass", ""),
                r.get("operation", ""),
            )
        )
        writer.writerows(rows)

    meta_payload = {
        "session_id": session_id,
        "generated_at": start_iso,
        "runs": args.runs,
        "message_size": args.message_size,
        "memory_interval_seconds": args.memory_interval,
        "includes_warm": bool(args.warm),
        "security_estimation": not args.no_security,
        "rsa_max_category": int(args.rsa_max_category),
        "categories": sorted(selected_categories),
        "algorithms": [
            {
                "name": spec.name,
                "kind": spec.kind,
                "mechanism": spec.mechanism,
                "category_floor_bits": spec.category_bits,
                "category_label": spec.category_label,
                "category_number": spec.category_number,
                "family": spec.hint.family,
                "notes": spec.hint.notes,
                "extras": spec.hint.extras,
            }
            for spec in collected_specs
        ],
        "output_csv": str(output_path),
        "row_count": len(rows),
        "failures": failures,
        "environment": env_meta,
    }

    if args.resume_from:
        meta_payload["resume_from_csv"] = str(args.resume_from)

    if args.jsonl_output:
        meta_payload["output_jsonl"] = str(args.jsonl_output)
    if args.parquet_output:
        meta_payload["output_parquet"] = str(args.parquet_output)

    meta_path = args.metadata
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    with meta_path.open("w", encoding="utf-8") as handle:
        json.dump(meta_payload, handle, indent=2, sort_keys=True, default=_json_default)

    if args.jsonl_output:
        args.jsonl_output.parent.mkdir(parents=True, exist_ok=True)
        with args.jsonl_output.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, default=_json_default, separators=(",", ":")) + "\n")

    if args.parquet_output:
        try:
            import pandas as pd  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency
            print(
                f"Parquet export skipped: pandas not available ({exc}).",
                file=sys.stderr,
            )
        else:
            args.parquet_output.parent.mkdir(parents=True, exist_ok=True)
            df = pd.DataFrame(rows)
            try:
                df.to_parquet(args.parquet_output, index=False)
            except Exception as exc:
                print(f"Failed to write Parquet file: {exc}", file=sys.stderr)

    if args.render_graphs:
        _run_graph_renderer(args.graph_script, args.graph_args, output_path)

    if args.run_side_channel:
        _run_side_channel(SIDE_CHANNEL_SCRIPT, args.side_channel_options)

    print(f"Wrote {len(rows)} rows to {output_path}")
    if failures:
        print(f"Encountered {len(failures)} failures; details recorded in {meta_path}")
    else:
        print(f"Metadata recorded at {meta_path}")


if __name__ == "__main__":
    main()
