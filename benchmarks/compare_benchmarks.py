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


def _plot_scatter(
    metrics,
    sessions,
    output_dir: pathlib.Path,
    value_getter,
    value_label: str,
    filename_suffix: str,
) -> None:
    if len(sessions) < 2:
        return
    baseline = sessions[0]
    for (pass_name, kind, operation, category, algo), recs in sorted(metrics.items()):
        base_rec = recs.get(baseline)
        if base_rec is None:
            continue
        base_val = value_getter(base_rec)
        if base_val is None:
            continue
        for session in sessions[1:]:
            cmp_rec = recs.get(session)
            if cmp_rec is None:
                continue
            cmp_val = value_getter(cmp_rec)
            if cmp_val is None:
                continue
            fig, ax = plt.subplots(figsize=(5, 5))
            ax.scatter(base_val, cmp_val, color="#1f77b4", alpha=0.85)
            ax.annotate(
                f"{algo}\nCat-{category}",
                (base_val, cmp_val),
                textcoords="offset points",
                xytext=(4, 4),
                fontsize=8,
            )
            lim_min = min(base_val, cmp_val)
            lim_max = max(base_val, cmp_val)
            pad = 0.1 * (lim_max - lim_min or 1.0)
            ax.plot(
                [lim_min - pad, lim_max + pad],
                [lim_min - pad, lim_max + pad],
                linestyle="--",
                color="#555555",
                linewidth=1,
            )
            ax.set_xlim(lim_min - pad, lim_max + pad)
            ax.set_ylim(lim_min - pad, lim_max + pad)
            ax.set_xlabel(f"{baseline} {value_label}")
            ax.set_ylabel(f"{session} {value_label}")
            ax.set_title(f"{kind} {operation} ({pass_name}, Cat-{category})")
            ax.grid(True, linestyle="--", alpha=0.3)
            safe_name = (
                f"{pass_name}_{kind}_{operation}_cat-{category}_{session}".lower()
                .replace("/", "-")
                .replace(" ", "_")
            )
            outfile = output_dir / f"scatter_{filename_suffix}_{safe_name}.png"
            outfile.parent.mkdir(parents=True, exist_ok=True)
            fig.tight_layout()
            fig.savefig(outfile, dpi=200)
            plt.close(fig)


def _aggregate_passes(records: Sequence[Record]) -> List[str]:
    return sorted({rec.measurement_pass for rec in records})


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
    captions.write(graph_root)

    metrics = _build_metrics(all_records)
    sessions = list(records_by_session.keys())
    _write_latency_ratio_table(metrics, sessions, table_root / "latency_ratios.csv")
    _write_memory_ratio_table(metrics, sessions, table_root / "memory_ratios.csv")

    _plot_scatter(
        metrics,
        sessions,
        graph_root,
        value_getter=lambda rec: rec.mean_ms,
        value_label="mean latency (ms)",
        filename_suffix="latency",
    )
    _plot_scatter(
        metrics,
        sessions,
        graph_root,
        value_getter=lambda rec: rec.mem_mean_kb,
        value_label="peak memory (KB)",
        filename_suffix="memory",
    )

    print(f"Comparison outputs written to {comparison_root}")


if __name__ == "__main__":
    main()
