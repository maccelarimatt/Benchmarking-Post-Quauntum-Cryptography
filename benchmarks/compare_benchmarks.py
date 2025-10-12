"""Utilities to compare benchmark CSVs across machines and generate comparison outputs."""

from __future__ import annotations

import argparse
import csv
import datetime
import math
import pathlib
from collections import defaultdict
from typing import Dict, List, Sequence, Tuple

import matplotlib.pyplot as plt

from benchmarks.render_category_floor_graphs import (
    CaptionLog,
    Record,
    load_records,
    plot_session_comparisons,
)

plt.style.use("seaborn-v0_8-colorblind")
plt.rcParams.update(
    {
        "axes.titlesize": 12,
        "axes.labelsize": 11,
        "axes.grid": True,
        "grid.alpha": 0.35,
        "grid.linestyle": "--",
        "legend.frameon": False,
        "legend.fontsize": 9,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
    }
)


def _parse_labeled_path(raw: str) -> Tuple[str, pathlib.Path]:
    if "=" in raw:
        label, path_str = raw.split("=", 1)
        label = label.strip()
        path = pathlib.Path(path_str).expanduser().resolve()
    else:
        path = pathlib.Path(raw).expanduser().resolve()
        # Assume layout Tested Benchmarks/<machine>/Benchmarks/file.csv
        label = path.parent.parent.name or path.stem
    return label, path


def _default_output_dir(csv_paths: Sequence[pathlib.Path]) -> pathlib.Path:
    first = csv_paths[0]
    try:
        base = first.parents[2]  # Tested Benchmarks/<machine>/Benchmarks
    except IndexError:
        base = first.parent
    return base.parent / "Comparisons"


def _write_combined_csv(
    out_path: pathlib.Path, csv_paths: Sequence[pathlib.Path]
) -> None:
    if not csv_paths:
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    header = None
    with out_path.open("w", newline="", encoding="utf-8") as fh_out:
        writer = None
        for idx, src in enumerate(csv_paths):
            with src.open("r", newline="", encoding="utf-8") as fh_in:
                reader = csv.reader(fh_in)
                try:
                    src_header = next(reader)
                except StopIteration:
                    continue
                if idx == 0:
                    header = src_header
                    writer = csv.writer(fh_out)
                    writer.writerow(header)
                elif header != src_header:
                    raise ValueError(
                        f"CSV header mismatch between {csv_paths[0]} and {src}"
                    )
                for row in reader:
                    writer.writerow(row)


def _build_metrics(records: Sequence[Record]):
    grouped: Dict[Tuple[str, str, str, int, str], Dict[str, Record]] = defaultdict(dict)
    for rec in records:
        key = (
            rec.measurement_pass,
            rec.kind,
            rec.operation,
            rec.category_number,
            rec.algo,
        )
        grouped[key][rec.session_id] = rec
    return grouped


def _write_latency_ratio_table(grouped, sessions, outfile: pathlib.Path) -> None:
    if len(sessions) < 2:
        return
    baseline = sessions[0]
    outfile.parent.mkdir(parents=True, exist_ok=True)
    with outfile.open("w", newline="", encoding="utf-8") as fh:
        fieldnames = [
            "measurement_pass",
            "kind",
            "operation",
            "category",
            "algorithm",
            "baseline_session",
            "compare_session",
            "baseline_mean_ms",
            "compare_mean_ms",
            "ratio",
            "delta_ms",
        ]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for key, recs in sorted(grouped.items()):
            base_rec = recs.get(baseline)
            if base_rec is None or base_rec.mean_ms is None:
                continue
            base_mean = base_rec.mean_ms
            for session in sessions[1:]:
                cmp_rec = recs.get(session)
                if cmp_rec is None or cmp_rec.mean_ms is None:
                    continue
                ratio = cmp_rec.mean_ms / base_mean if base_mean else math.nan
                writer.writerow(
                    {
                        "measurement_pass": key[0],
                        "kind": key[1],
                        "operation": key[2],
                        "category": key[3],
                        "algorithm": key[4],
                        "baseline_session": baseline,
                        "compare_session": session,
                        "baseline_mean_ms": f"{base_mean:.6f}",
                        "compare_mean_ms": f"{cmp_rec.mean_ms:.6f}",
                        "ratio": f"{ratio:.6f}",
                        "delta_ms": f"{cmp_rec.mean_ms - base_mean:.6f}",
                    }
                )


def _write_memory_ratio_table(grouped, sessions, outfile: pathlib.Path) -> None:
    if len(sessions) < 2:
        return
    baseline = sessions[0]
    outfile.parent.mkdir(parents=True, exist_ok=True)
    with outfile.open("w", newline="", encoding="utf-8") as fh:
        fieldnames = [
            "measurement_pass",
            "kind",
            "operation",
            "category",
            "algorithm",
            "baseline_session",
            "compare_session",
            "baseline_mem_kb",
            "compare_mem_kb",
            "ratio",
            "delta_kb",
        ]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for key, recs in sorted(grouped.items()):
            base_rec = recs.get(baseline)
            if base_rec is None or base_rec.mem_mean_kb is None:
                continue
            base_mean = base_rec.mem_mean_kb
            for session in sessions[1:]:
                cmp_rec = recs.get(session)
                if cmp_rec is None or cmp_rec.mem_mean_kb is None:
                    continue
                ratio = cmp_rec.mem_mean_kb / base_mean if base_mean else math.nan
                writer.writerow(
                    {
                        "measurement_pass": key[0],
                        "kind": key[1],
                        "operation": key[2],
                        "category": key[3],
                        "algorithm": key[4],
                        "baseline_session": baseline,
                        "compare_session": session,
                        "baseline_mem_kb": f"{base_mean:.6f}",
                        "compare_mem_kb": f"{cmp_rec.mem_mean_kb:.6f}",
                        "ratio": f"{ratio:.6f}",
                        "delta_kb": f"{cmp_rec.mem_mean_kb - base_mean:.6f}",
                    }
                )


def _aggregate_passes(records: Sequence[Record]) -> List[str]:
    return sorted({rec.measurement_pass for rec in records})


def _filter_records_by_category(
    records_by_session: Dict[str, List[Record]], category: int
) -> Dict[str, List[Record]]:
    filtered: Dict[str, List[Record]] = {}
    for session, records in records_by_session.items():
        subset = [rec for rec in records if rec.category_number == category]
        if subset:
            filtered[session] = subset
    return filtered


CATEGORY_TREND_LEVELS = (1, 3, 5)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare benchmark CSV outputs across sessions/machines.",
    )
    parser.add_argument(
        "--csv",
        nargs="+",
        required=True,
        help="Input CSV paths. Optional label=path format to override session label.",
    )
    parser.add_argument(
        "--output-dir",
        type=pathlib.Path,
        help="Directory for comparison outputs (default: sibling 'Comparisons').",
    )
    parser.add_argument(
        "--passes",
        nargs="*",
        help="Specific measurement passes to include (default: all).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    labeled_paths = [_parse_labeled_path(item) for item in args.csv]
    csv_paths = [path for _, path in labeled_paths]
    output_root = args.output_dir or _default_output_dir(csv_paths)
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    comparison_root = output_root / timestamp
    graph_root = comparison_root / "graphs"
    table_root = comparison_root / "tables"
    combined_csv = comparison_root / "combined.csv"

    records_by_session: Dict[str, List[Record]] = {}
    all_records: List[Record] = []
    for label, path in labeled_paths:
        session_records = load_records(path)
        if label:
            for rec in session_records:
                rec.session_id = label
        records_by_session[label] = session_records
        all_records.extend(session_records)

    if not all_records:
        raise SystemExit("No records loaded from the provided CSVs.")

    passes = args.passes or _aggregate_passes(all_records)

    _write_combined_csv(combined_csv, csv_paths)

    captions = CaptionLog()
    plot_session_comparisons(records_by_session, graph_root, passes, captions)
    for category in CATEGORY_TREND_LEVELS:
        filtered_sessions = _filter_records_by_category(records_by_session, category)
        if filtered_sessions:
            cat_root = graph_root / f"cat-{category}"
            plot_session_comparisons(filtered_sessions, cat_root, passes, captions)
    captions.write(graph_root)

    metrics = _build_metrics(all_records)
    sessions = list(records_by_session.keys())
    _write_latency_ratio_table(metrics, sessions, table_root / "latency_ratios.csv")
    _write_memory_ratio_table(metrics, sessions, table_root / "memory_ratios.csv")

    print(f"Comparison outputs written to {comparison_root}")


if __name__ == "__main__":
    main()
