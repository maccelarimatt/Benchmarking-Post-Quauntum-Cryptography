from __future__ import annotations

import argparse
import csv
import datetime as _dt
import json
import pathlib
import sys
from dataclasses import asdict, dataclass, is_dataclass
import contextlib
import os
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

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
from pqcbench.security_levels import resolve_security_override

HERE = pathlib.Path(__file__).resolve().parent
RESULTS_DIR = HERE.parent / "results"
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


def discover_algorithms(categories: Iterable[int]) -> List[AlgorithmSpec]:
    desired = {cat for cat in categories if cat in _CATEGORY_TO_FLOOR}
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
        if not hint:
            continue
        floor_bits = hint.category_floor
        mapping = _FLOOR_TO_CATEGORY.get(floor_bits)
        if not mapping:
            continue
        label, cat_number = mapping
        if cat_number not in desired:
            continue
        specs.append(
            AlgorithmSpec(
                name=name,
                kind=kind,
                mechanism=mechanism,
                hint=hint,
                category_bits=floor_bits,
                category_label=label,
                category_number=cat_number,
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
        "--no-security",
        action="store_true",
        help="Skip security estimator (speeds up large batches).",
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

    for category in sorted(selected_categories):
        overrides = _variant_env_for_category(category)
        with _temporary_env(overrides):
            reset_adapter_cache()
            category_specs = discover_algorithms({category})
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
                collected_specs.append(spec)
                for pass_name, capture_memory, cold in passes:
                    try:
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
    mode = "a" if args.append and output_path.exists() else "w"
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

    print(f"Wrote {len(rows)} rows to {output_path}")
    if failures:
        print(f"Encountered {len(failures)} failures; details recorded in {meta_path}")
    else:
        print(f"Metadata recorded at {meta_path}")


if __name__ == "__main__":
    main()
