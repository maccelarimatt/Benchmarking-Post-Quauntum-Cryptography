from __future__ import annotations

import argparse
import csv
import json
import math
import pathlib
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import matplotlib.pyplot as plt
except ImportError as exc:  # pragma: no cover - import guard
    raise SystemExit(
        "matplotlib is required for graph rendering. Install it via 'pip install matplotlib'."
    ) from exc

HERE = pathlib.Path(__file__).resolve().parent
RESULTS_DIR = HERE.parent / "results"
DEFAULT_CSV = RESULTS_DIR / "category_floor_benchmarks.csv"
DEFAULT_OUTPUT_DIR = RESULTS_DIR / "graphs"

KEM_OPERATIONS: Sequence[str] = ("keygen", "encapsulate", "decapsulate")
SIG_OPERATIONS: Sequence[str] = ("keygen", "sign", "verify")

NUMERIC_FIELDS = (
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
    "security_classical_bits",
    "security_quantum_bits",
)


@dataclass
class Record:
    session_id: str
    measurement_pass: str
    algo: str
    kind: str
    operation: str
    category_number: int
    mean_ms: Optional[float]
    ci95_low_ms: Optional[float]
    ci95_high_ms: Optional[float]
    mem_mean_kb: Optional[float]
    mem_ci95_low_kb: Optional[float]
    mem_ci95_high_kb: Optional[float]
    security_classical_bits: Optional[float]
    security_quantum_bits: Optional[float]
    category_label: str
    mechanism: str
    meta: Dict[str, Any]
    series: Sequence[float]
    mem_series: Sequence[float]


def _parse_float(value: str | None) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        val = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(val):
        return None
    return val


def _parse_series(raw: str | None) -> Sequence[float]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    series: List[float] = []
    for item in data:
        try:
            val = float(item)
        except (TypeError, ValueError):
            continue
        if math.isfinite(val):
            series.append(val)
    return series


def load_records(csv_path: pathlib.Path) -> List[Record]:
    if not csv_path.exists():
        raise SystemExit(f"CSV file not found: {csv_path}")
    records: List[Record] = []
    with csv_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            try:
                meta = json.loads(row.get("meta_json", "") or "{}")
                if not isinstance(meta, dict):
                    meta = {}
            except json.JSONDecodeError:
                meta = {}

            record = Record(
                session_id=row.get("session_id", ""),
                measurement_pass=(row.get("measurement_pass", "") or "timing").lower(),
                algo=row.get("algo", ""),
                kind=row.get("kind", ""),
                operation=row.get("operation", ""),
                category_number=int(row.get("category_number", "0") or 0),
                mean_ms=_parse_float(row.get("mean_ms")),
                ci95_low_ms=_parse_float(row.get("ci95_low_ms")),
                ci95_high_ms=_parse_float(row.get("ci95_high_ms")),
                mem_mean_kb=_parse_float(row.get("mem_mean_kb")),
                mem_ci95_low_kb=_parse_float(row.get("mem_ci95_low_kb")),
                mem_ci95_high_kb=_parse_float(row.get("mem_ci95_high_kb")),
                security_classical_bits=_parse_float(row.get("security_classical_bits")),
                security_quantum_bits=_parse_float(row.get("security_quantum_bits")),
                category_label=row.get("category_label", ""),
                mechanism=row.get("mechanism", ""),
                meta=meta,
                series=_parse_series(row.get("series_json")),
                mem_series=_parse_series(row.get("mem_series_json")),
            )
            records.append(record)
    if not records:
        raise SystemExit(f"No rows found in CSV: {csv_path}")
    return records


def select_session(records: Sequence[Record], session_id: Optional[str]) -> Tuple[str, List[Record]]:
    sessions = sorted({rec.session_id for rec in records if rec.session_id})
    if not sessions:
        raise SystemExit("Records do not contain session identifiers; cannot select session.")
    if session_id is None:
        selected = sessions[-1]
    else:
        if session_id not in sessions:
            raise SystemExit(f"Session '{session_id}' not present. Available: {', '.join(sessions)}")
        selected = session_id
    filtered = [rec for rec in records if rec.session_id == selected]
    if not filtered:
        raise SystemExit(f"No records found for session {selected}.")
    return selected, filtered


def _ensure_output_dir(path: pathlib.Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _operations_for_kind(kind: str, present_ops: Iterable[str]) -> List[str]:
    if kind.upper() == "KEM":
        base = list(KEM_OPERATIONS)
    elif kind.upper() == "SIG":
        base = list(SIG_OPERATIONS)
    else:
        base = sorted(set(present_ops))
    return [op for op in base if op in present_ops]


def plot_latency_bars(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str) -> None:
    by_kind: Dict[str, Dict[Tuple[str, str], Optional[float]]] = defaultdict(dict)
    algorithms_by_kind: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
    ops_by_kind: Dict[str, set] = defaultdict(set)

    for rec in records:
        if rec.measurement_pass != pass_name:
            continue
        key = (rec.algo, rec.operation)
        by_kind[rec.kind][key] = rec.mean_ms
        algorithms_by_kind[rec.kind].append((rec.category_number, rec.algo))
        ops_by_kind[rec.kind].add(rec.operation)

    for kind, means in by_kind.items():
        algorithms = [name for _, name in sorted(set(algorithms_by_kind[kind]))]
        if not algorithms:
            continue
        operations = _operations_for_kind(kind, ops_by_kind[kind])
        if not operations:
            continue

        fig, ax = plt.subplots(figsize=(max(6, len(algorithms) * 0.75), 4.5))
        width = 0.75 / max(1, len(operations))
        x_positions = list(range(len(algorithms)))

        for idx, op in enumerate(operations):
            offsets = [pos + idx * width for pos in x_positions]
            values = [means.get((algo, op)) or 0.0 for algo in algorithms]
            ax.bar(offsets, values, width=width, label=op)

        ax.set_xticks([pos + (len(operations) - 1) * width / 2 for pos in x_positions])
        ax.set_xticklabels(algorithms, rotation=45, ha="right")
        ax.set_ylabel("Mean latency (ms)")
        ax.set_title(f"{pass_name.title()} pass latency — {kind}")
        ax.legend()
        ax.grid(True, axis="y", linestyle="--", alpha=0.3)
        fig.tight_layout()
        outfile = output_dir / f"latency_{pass_name}_{kind.lower()}.png"
        fig.savefig(outfile, dpi=200)
        plt.close(fig)


def plot_memory_bars(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str) -> None:
    by_kind: Dict[str, Dict[Tuple[str, str], Optional[float]]] = defaultdict(dict)
    algorithms_by_kind: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
    ops_by_kind: Dict[str, set] = defaultdict(set)

    for rec in records:
        if rec.measurement_pass != pass_name:
            continue
        key = (rec.algo, rec.operation)
        by_kind[rec.kind][key] = rec.mem_mean_kb
        algorithms_by_kind[rec.kind].append((rec.category_number, rec.algo))
        ops_by_kind[rec.kind].add(rec.operation)

    for kind, mems in by_kind.items():
        algorithms = [name for _, name in sorted(set(algorithms_by_kind[kind]))]
        if not algorithms:
            continue
        operations = _operations_for_kind(kind, ops_by_kind[kind])
        if not operations:
            continue

        fig, ax = plt.subplots(figsize=(max(6, len(algorithms) * 0.75), 4.5))
        width = 0.75 / max(1, len(operations))
        x_positions = list(range(len(algorithms)))

        for idx, op in enumerate(operations):
            offsets = [pos + idx * width for pos in x_positions]
            values = [mems.get((algo, op)) or 0.0 for algo in algorithms]
            ax.bar(offsets, values, width=width, label=op)

        ax.set_xticks([pos + (len(operations) - 1) * width / 2 for pos in x_positions])
        ax.set_xticklabels(algorithms, rotation=45, ha="right")
        ax.set_ylabel("Peak memory (KB)")
        ax.set_title(f"{pass_name.title()} peak RSS — {kind}")
        ax.legend()
        ax.grid(True, axis="y", linestyle="--", alpha=0.3)
        fig.tight_layout()
        outfile = output_dir / f"memory_peak_{pass_name}_{kind.lower()}.png"
        fig.savefig(outfile, dpi=200)
        plt.close(fig)


def plot_security_vs_latency(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str) -> None:
    points: List[Tuple[float, float, str, str]] = []  # (classical_bits, latency, kind, algo)
    for rec in records:
        if rec.measurement_pass != pass_name:
            continue
        if rec.operation != "keygen":
            continue
        if rec.mean_ms is None or rec.security_classical_bits is None:
            continue
        points.append((rec.security_classical_bits, rec.mean_ms, rec.kind, rec.algo))

    if not points:
        return

    fig, ax = plt.subplots(figsize=(6, 4.5))
    markers = {"KEM": "o", "SIG": "^"}
    colors = {"KEM": "#1f77b4", "SIG": "#ff7f0e"}

    for classical_bits, latency, kind, algo in points:
        marker = markers.get(kind, "o")
        color = colors.get(kind, "#555555")
        ax.scatter(classical_bits, latency, marker=marker, color=color, alpha=0.8)
        ax.annotate(algo, (classical_bits, latency), textcoords="offset points", xytext=(4, 4), fontsize=7)

    ax.set_xlabel("Classical security bits")
    ax.set_ylabel("Keygen mean latency (ms)")
    ax.set_title(f"Security vs keygen latency — {pass_name.title()} pass")
    ax.grid(True, linestyle="--", alpha=0.3)
    handles = [plt.Line2D([0], [0], marker=markers[k], color="w", markerfacecolor=colors[k], markersize=8) for k in markers if any(pt[2] == k for pt in points)]
    labels = [k for k in markers if any(pt[2] == k for pt in points)]
    if handles:
        ax.legend(handles, labels, title="Kind")
    fig.tight_layout()
    outfile = output_dir / f"security_vs_latency_{pass_name}.png"
    fig.savefig(outfile, dpi=200)
    plt.close(fig)


def plot_latency_distributions(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str) -> None:
    grouped: Dict[Tuple[str, str], List[Tuple[str, Sequence[float]]]] = defaultdict(list)
    for rec in records:
        if rec.measurement_pass != pass_name or not rec.series:
            continue
        grouped[(rec.kind, rec.operation)].append((rec.algo, rec.series))

    for (kind, operation), entries in grouped.items():
        entries = sorted(entries, key=lambda item: item[0])
        data = [list(series) for _, series in entries if series]
        if not data:
            continue
        labels = [algo for algo, series in entries if series]
        positions = list(range(1, len(data) + 1))

        fig, ax = plt.subplots(figsize=(max(6, len(labels) * 0.75), 4.5))
        violins = ax.violinplot(data, positions=positions, showmeans=True, showextrema=False)
        for body in violins['bodies']:
            body.set_alpha(0.6)
        ax.boxplot(data, positions=positions, widths=0.2, patch_artist=True)
        ax.set_xticks(positions)
        ax.set_xticklabels(labels, rotation=45, ha="right")
        ax.set_ylabel("Latency (ms)")
        ax.set_title(f"{pass_name.title()} latency distribution — {kind} / {operation}")
        ax.grid(True, axis="y", linestyle="--", alpha=0.3)
        fig.tight_layout()
        outfile = output_dir / f"latency_distribution_{pass_name}_{kind.lower()}_{operation}.png"
        fig.savefig(outfile, dpi=200)
        plt.close(fig)


def plot_memory_distributions(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str) -> None:
    grouped: Dict[Tuple[str, str], List[Tuple[str, Sequence[float]]]] = defaultdict(list)
    for rec in records:
        if rec.measurement_pass != pass_name or not rec.mem_series:
            continue
        grouped[(rec.kind, rec.operation)].append((rec.algo, rec.mem_series))

    for (kind, operation), entries in grouped.items():
        entries = sorted(entries, key=lambda item: item[0])
        data = [list(series) for _, series in entries if series]
        if not data:
            continue
        labels = [algo for algo, series in entries if series]
        positions = list(range(1, len(data) + 1))

        fig, ax = plt.subplots(figsize=(max(6, len(labels) * 0.75), 4.5))
        violins = ax.violinplot(data, positions=positions, showmeans=True, showextrema=False)
        for body in violins['bodies']:
            body.set_alpha(0.6)
        ax.boxplot(data, positions=positions, widths=0.2, patch_artist=True)
        ax.set_xticks(positions)
        ax.set_xticklabels(labels, rotation=45, ha="right")
        ax.set_ylabel("Peak memory (KB)")
        ax.set_title(f"{pass_name.title()} memory distribution — {kind} / {operation}")
        ax.grid(True, axis="y", linestyle="--", alpha=0.3)
        fig.tight_layout()
        outfile = output_dir / f"memory_distribution_{pass_name}_{kind.lower()}_{operation}.png"
        fig.savefig(outfile, dpi=200)
        plt.close(fig)


def plot_latency_ecdf(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str) -> None:
    grouped: Dict[Tuple[str, str], List[Tuple[str, Sequence[float]]]] = defaultdict(list)
    for rec in records:
        if rec.measurement_pass != pass_name or not rec.series:
            continue
        grouped[(rec.kind, rec.operation)].append((rec.algo, rec.series))

    for (kind, operation), entries in grouped.items():
        entries = sorted(entries, key=lambda item: item[0])
        fig, ax = plt.subplots(figsize=(6, 4.5))
        for algo, series in entries:
            if not series:
                continue
            sorted_vals = sorted(series)
            n = len(sorted_vals)
            y_vals = [i / n for i in range(1, n + 1)]
            ax.step(sorted_vals, y_vals, where="post", label=algo)
        ax.set_title(f"{pass_name.title()} latency ECDF — {kind} / {operation}")
        ax.set_xlabel("Latency (ms)")
        ax.set_ylabel("F(x)")
        ax.grid(True, linestyle="--", alpha=0.3)
        if ax.lines:
            ax.legend()
        fig.tight_layout()
        outfile = output_dir / f"latency_ecdf_{pass_name}_{kind.lower()}_{operation}.png"
        fig.savefig(outfile, dpi=200)
        plt.close(fig)


def plot_throughput_vs_category(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str) -> None:
    grouped: Dict[Tuple[str, str], Dict[str, Dict[int, float]]] = defaultdict(lambda: defaultdict(dict))
    for rec in records:
        if rec.measurement_pass != pass_name or rec.mean_ms is None or rec.mean_ms <= 0.0:
            continue
        throughput = 1000.0 / rec.mean_ms  # operations per second
        grouped[(rec.kind, rec.operation)][rec.algo][rec.category_number] = throughput

    for (kind, operation), algo_map in grouped.items():
        categories = sorted({cat for points in algo_map.values() for cat in points.keys()})
        if not categories or len(algo_map) < 1:
            continue
        fig, ax = plt.subplots(figsize=(max(6, len(categories) * 1.2), 4.5))
        x_positions = range(len(categories))
        for algo, values in sorted(algo_map.items()):
            y_vals = [values.get(cat) for cat in categories]
            if all(v is None for v in y_vals):
                continue
            ax.plot(x_positions, y_vals, marker="o", label=algo)
        ax.set_title(f"Throughput ({pass_name}) — {kind} / {operation}")
        ax.set_ylabel("Ops per second")
        ax.set_xlabel("Security category")
        ax.set_xticks(list(x_positions))
        ax.set_xticklabels([str(cat) for cat in categories])
        ax.grid(True, linestyle="--", alpha=0.3)
        if ax.lines:
            ax.legend()
        fig.tight_layout()
        outfile = output_dir / f"throughput_{pass_name}_{kind.lower()}_{operation}.png"
        fig.savefig(outfile, dpi=200)
        plt.close(fig)


def _collect_unique_meta(records: Sequence[Record]) -> Dict[Tuple[str, str, int], Record]:
    unique: Dict[Tuple[str, str, int], Record] = {}
    for rec in records:
        key = (rec.kind, rec.algo, rec.category_number)
        if key not in unique:
            unique[key] = rec
    return unique


def plot_size_stacked_bars(records: Sequence[Record], output_dir: pathlib.Path) -> None:
    unique = _collect_unique_meta(records)
    kem_entries: List[Tuple[int, str, Dict[str, Any]]] = []
    sig_entries: List[Tuple[int, str, Dict[str, Any]]] = []
    for (kind, algo, category), rec in unique.items():
        if rec.operation.lower() != "keygen":
            continue
        entry = (category, algo, rec.meta)
        if kind.upper() == "KEM":
            kem_entries.append(entry)
        elif kind.upper() == "SIG":
            sig_entries.append(entry)

    def _plot(entries: List[Tuple[int, str, Dict[str, Any]]], kind_label: str) -> None:
        if not entries:
            return
        entries.sort()
        labels = [f"{algo}\nCat-{cat}" for cat, algo, _ in entries]
        components = []
        if kind_label == "KEM":
            components = [
                ("Public key", "public_key_len"),
                ("Secret key", "secret_key_len"),
                ("Ciphertext", "ciphertext_len"),
                ("Shared secret", "shared_secret_len"),
            ]
        else:
            components = [
                ("Public key", "public_key_len"),
                ("Secret key", "secret_key_len"),
                ("Signature", "signature_len"),
            ]

        fig, ax = plt.subplots(figsize=(max(6, len(entries) * 0.8), 4.5))
        bottoms = [0.0] * len(entries)
        for label, key in components:
            values = []
            for _, _, meta in entries:
                val = meta.get(key)
                values.append(float(val) if isinstance(val, (int, float)) else 0.0)
            ax.bar(labels, values, bottom=bottoms, label=label)
            bottoms = [b + v for b, v in zip(bottoms, values)]
        ax.set_ylabel("Bytes")
        ax.set_title(f"Key material sizes — {kind_label}")
        ax.legend()
        ax.grid(True, axis="y", linestyle="--", alpha=0.3)
        fig.tight_layout()
        outfile = output_dir / f"sizes_{kind_label.lower()}.png"
        fig.savefig(outfile, dpi=200)
        plt.close(fig)

    _plot(kem_entries, "KEM")
    _plot(sig_entries, "SIG")


def plot_expansion_scatter(records: Sequence[Record], output_dir: pathlib.Path) -> None:
    unique = _collect_unique_meta(records)
    kem_points: List[Tuple[float, int, str]] = []
    sig_points: List[Tuple[float, int, str]] = []
    for (kind, algo, category), rec in unique.items():
        meta = rec.meta
        ratio = None
        if kind.upper() == "KEM":
            ratio = meta.get("ciphertext_expansion_ratio")
            if not ratio and meta.get("ciphertext_len") and meta.get("shared_secret_len"):
                ss = meta.get("shared_secret_len") or 0
                if ss:
                    ratio = float(meta.get("ciphertext_len")) / float(ss)
            if ratio:
                kem_points.append((float(ratio), category, algo))
        elif kind.upper() == "SIG":
            ratio = meta.get("signature_expansion_ratio")
            msg_size = meta.get("message_size")
            if not ratio and meta.get("signature_len") and msg_size:
                if msg_size:
                    ratio = float(meta.get("signature_len")) / float(msg_size)
            if ratio:
                sig_points.append((float(ratio), category, algo))

    def _plot(points: List[Tuple[float, int, str]], label: str) -> None:
        if not points:
            return
        fig, ax = plt.subplots(figsize=(6, 4.5))
        for ratio, category, algo in sorted(points, key=lambda x: (x[1], x[2])):
            ax.scatter(category, ratio, label=algo)
            ax.annotate(algo, (category, ratio), textcoords="offset points", xytext=(4, 4), fontsize=7)
        ax.set_title(f"Expansion ratio vs category — {label}")
        ax.set_xlabel("Security category")
        ax.set_ylabel("Expansion ratio")
        ax.grid(True, linestyle="--", alpha=0.3)
        fig.tight_layout()
        outfile = output_dir / f"expansion_{label.lower()}.png"
        fig.savefig(outfile, dpi=200)
        plt.close(fig)

    _plot(kem_points, "KEM")
    _plot(sig_points, "SIG")


def plot_memory_error_bars(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str) -> None:
    grouped: Dict[str, Dict[str, Tuple[float, float, float]]] = defaultdict(dict)
    for rec in records:
        if rec.measurement_pass != pass_name:
            continue
        if (
            rec.mem_mean_kb is None
            or rec.mem_ci95_low_kb is None
            or rec.mem_ci95_high_kb is None
        ):
            continue
        key = f"{rec.kind} / {rec.operation}"
        grouped[key][rec.algo] = (
            rec.mem_mean_kb,
            max(0.0, rec.mem_mean_kb - rec.mem_ci95_low_kb),
            max(0.0, rec.mem_ci95_high_kb - rec.mem_mean_kb),
        )

    for label, data in grouped.items():
        if not data:
            continue
        algorithms = sorted(data.keys())
        means = [data[a][0] for a in algorithms]
        yerr = [[data[a][1] for a in algorithms], [data[a][2] for a in algorithms]]
        fig, ax = plt.subplots(figsize=(max(6, len(algorithms) * 0.75), 4.5))
        ax.bar(algorithms, means, yerr=yerr, capsize=4)
        ax.set_ylabel("Peak memory (KB)")
        ax.set_title(f"Peak RSS with 95% CI — {label} ({pass_name})")
        ax.grid(True, axis="y", linestyle="--", alpha=0.3)
        ax.tick_params(axis="x", rotation=45, ha="right")
        fig.tight_layout()
        safe_label = label.replace(" / ", "_").replace(" ", "_").lower()
        outfile = output_dir / f"memory_errorbars_{pass_name}_{safe_label}.png"
        fig.savefig(outfile, dpi=200)
        plt.close(fig)


def plot_security_cost_bars(records: Sequence[Record], output_dir: pathlib.Path) -> None:
    unique = _collect_unique_meta(records)
    entries = []
    for (kind, algo, category), rec in unique.items():
        if rec.security_classical_bits is None and rec.security_quantum_bits is None:
            continue
        label = f"{algo}\nCat-{category}"
        entries.append((label, rec.security_classical_bits or 0.0, rec.security_quantum_bits or 0.0))
    if not entries:
        return
    entries.sort()
    labels = [item[0] for item in entries]
    classical = [item[1] for item in entries]
    quantum = [item[2] for item in entries]
    x = range(len(entries))
    fig, ax = plt.subplots(figsize=(max(6, len(entries) * 0.8), 4.5))
    ax.bar(x, classical, width=0.4, label="Classical bits")
    ax.bar([i + 0.4 for i in x], quantum, width=0.4, label="Quantum bits")
    ax.set_xticks([i + 0.2 for i in x])
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_ylabel("Bits of security")
    ax.set_title("Classical vs quantum cost estimates")
    ax.legend()
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)
    fig.tight_layout()
    outfile = output_dir / "security_bits_comparison.png"
    fig.savefig(outfile, dpi=200)
    plt.close(fig)


def plot_tradeoff_frontier(records: Sequence[Record], output_dir: pathlib.Path, preferred_passes: Sequence[str]) -> None:
    available_passes = {rec.measurement_pass for rec in records}
    pass_name = next((p for p in preferred_passes if p in available_passes), None)
    if pass_name is None:
        return

    unique = _collect_unique_meta(records)
    points = []
    for (kind, algo, category), rec in unique.items():
        relevant = [
            r
            for r in records
            if r.algo == algo
            and r.kind == kind
            and r.category_number == category
            and r.measurement_pass == pass_name
            and r.operation.lower() == "keygen"
        ]
        if not relevant:
            continue
        mean_latency = next((r.mean_ms for r in relevant if r.mean_ms is not None), None)
        if mean_latency is None or rec.security_classical_bits is None:
            continue
        size = (
            rec.meta.get("public_key_len")
            or rec.meta.get("signature_len")
            or rec.meta.get("ciphertext_len")
            or 0
        )
        points.append((mean_latency, rec.security_classical_bits, size, algo, category, kind))

    if not points:
        return

    fig, ax = plt.subplots(figsize=(6, 4.5))
    for latency, sec_bits, size, algo, category, kind in sorted(points, key=lambda x: (x[5], x[0])):
        marker = "o" if kind.upper() == "KEM" else "^"
        ax.scatter(latency, sec_bits, s=max(20, size / 5), marker=marker, alpha=0.7, label=f"{algo} Cat-{category}")
        ax.annotate(f"{algo}\nCat-{category}", (latency, sec_bits), textcoords="offset points", xytext=(4, 4), fontsize=7)
    ax.set_xlabel(f"Latency (ms) — {pass_name}")
    ax.set_ylabel("Security bits (classical)")
    ax.set_title("Performance vs security trade-off")
    ax.grid(True, linestyle="--", alpha=0.3)
    handles, labels = ax.get_legend_handles_labels()
    unique_pairs = dict(zip(labels, handles))
    ax.legend(unique_pairs.values(), unique_pairs.keys(), fontsize=8)
    fig.tight_layout()
    outfile = output_dir / f"tradeoff_{pass_name}.png"
    fig.savefig(outfile, dpi=200)
    plt.close(fig)

def generate_graphs(records: Sequence[Record], output_dir: pathlib.Path, passes: Sequence[str]) -> None:
    if not records:
        return
    _ensure_output_dir(output_dir)
    available_passes = {rec.measurement_pass for rec in records}

    for pass_name in passes:
        if pass_name not in available_passes:
            continue
        plot_latency_bars(records, output_dir, pass_name)
        plot_latency_distributions(records, output_dir, pass_name)
        plot_latency_ecdf(records, output_dir, pass_name)
        plot_security_vs_latency(records, output_dir, pass_name)
        if "timing" in pass_name:
            plot_throughput_vs_category(records, output_dir, pass_name)
        if pass_name.startswith("memory"):
            plot_memory_bars(records, output_dir, pass_name)
            plot_memory_distributions(records, output_dir, pass_name)
            plot_memory_error_bars(records, output_dir, pass_name)

    # Pass-agnostic summaries
    plot_size_stacked_bars(records, output_dir)
    plot_expansion_scatter(records, output_dir)
    plot_security_cost_bars(records, output_dir)
    plot_tradeoff_frontier(records, output_dir, preferred_passes=[p for p in passes if "timing" in p] + list(passes))


def plot_session_comparisons(
    session_records: Dict[str, List[Record]],
    output_dir: pathlib.Path,
    passes: Sequence[str],
) -> None:
    if not session_records:
        return
    sessions = sorted(session_records.keys())
    available_passes = {
        rec.measurement_pass
        for records in session_records.values()
        for rec in records
    }
    pass_list = [p for p in passes if p in available_passes]
    if not pass_list:
        return
    _ensure_output_dir(output_dir)

    for pass_name in pass_list:
        latency_lines: Dict[Tuple[str, str], Dict[str, Dict[str, float]]] = defaultdict(lambda: defaultdict(dict))
        memory_lines: Dict[Tuple[str, str], Dict[str, Dict[str, float]]] = defaultdict(lambda: defaultdict(dict))
        for session_id in sessions:
            for rec in session_records[session_id]:
                if rec.measurement_pass != pass_name:
                    continue
                if rec.mean_ms is not None:
                    latency_lines[(rec.kind, rec.operation)][rec.algo][session_id] = rec.mean_ms
                if rec.mem_mean_kb is not None:
                    memory_lines[(rec.kind, rec.operation)][rec.algo][session_id] = rec.mem_mean_kb

        x_positions = list(range(len(sessions)))

        for (kind, operation), algo_map in latency_lines.items():
            fig, ax = plt.subplots(figsize=(max(6, len(sessions) * 0.75), 4.5))
            for algo, values_by_session in sorted(algo_map.items()):
                values = [values_by_session.get(sid) for sid in sessions]
                if all(v is None for v in values):
                    continue
                ax.plot(x_positions, values, marker="o", label=algo)
            ax.set_title(f"{pass_name.title()} latency trend — {kind} / {operation}")
            ax.set_ylabel("Mean latency (ms)")
            ax.set_xlabel("Session")
            ax.grid(True, linestyle="--", alpha=0.3)
            if ax.lines:
                ax.legend()
            ax.set_xticks(x_positions)
            ax.set_xticklabels(sessions, rotation=45, ha="right")
            fig.tight_layout()
            outfile = output_dir / f"trend_latency_{pass_name}_{kind.lower()}_{operation}.png"
            fig.savefig(outfile, dpi=200)
            plt.close(fig)

        if pass_name.startswith("memory"):
            for (kind, operation), algo_map in memory_lines.items():
                fig, ax = plt.subplots(figsize=(max(6, len(sessions) * 0.75), 4.5))
                for algo, values_by_session in sorted(algo_map.items()):
                    values = [values_by_session.get(sid) for sid in sessions]
                    if all(v is None for v in values):
                        continue
                    ax.plot(x_positions, values, marker="o", label=algo)
                ax.set_title(f"{pass_name.title()} peak RSS trend — {kind} / {operation}")
                ax.set_ylabel("Peak memory (KB)")
                ax.set_xlabel("Session")
                ax.grid(True, linestyle="--", alpha=0.3)
                if ax.lines:
                    ax.legend()
                ax.set_xticks(x_positions)
                ax.set_xticklabels(sessions, rotation=45, ha="right")
                fig.tight_layout()
                outfile = output_dir / f"trend_memory_{pass_name}_{kind.lower()}_{operation}.png"
                fig.savefig(outfile, dpi=200)
                plt.close(fig)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render graphs from category floor benchmark CSV outputs.",
    )
    parser.add_argument("--csv", default=DEFAULT_CSV, type=pathlib.Path, help="Input CSV (default: results/category_floor_benchmarks.csv)")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, type=pathlib.Path, help="Directory for generated graphs (default: results/graphs)")
    parser.add_argument("--session", default=None, help="Optional session_id to render (ignored if --sessions used).")
    parser.add_argument("--sessions", nargs="*", default=None, help="Render multiple sessions and produce comparison plots.")
    parser.add_argument(
        "--passes",
        nargs="*",
        help="Limit to specific measurement passes (e.g. timing memory-warm). Default uses all present in the data.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    records = load_records(args.csv)
    records_by_session: Dict[str, List[Record]] = defaultdict(list)
    for rec in records:
        if rec.session_id:
            records_by_session[rec.session_id].append(rec)

    if not records_by_session:
        raise SystemExit("No session data found in CSV.")

    if args.sessions:
        session_ids = args.sessions
        missing = [sid for sid in session_ids if sid not in records_by_session]
        if missing:
            raise SystemExit(f"Sessions not found: {', '.join(missing)}")
    else:
        if args.session:
            if args.session not in records_by_session:
                raise SystemExit(f"Session '{args.session}' not present. Available: {', '.join(sorted(records_by_session))}")
            session_ids = [args.session]
        else:
            session_ids = [sorted(records_by_session.keys())[-1]]

    passes = args.passes or sorted({rec.measurement_pass for sid in session_ids for rec in records_by_session[sid]})

    for session_id in session_ids:
        session_records = records_by_session[session_id]
        output_dir = args.output_dir / session_id
        generate_graphs(session_records, output_dir, passes)

        categories = sorted({rec.category_number for rec in session_records if rec.category_number})
        for category in categories:
            cat_records = [rec for rec in session_records if rec.category_number == category]
            if not cat_records:
                continue
            cat_dir = output_dir / f"category_{category}"
            generate_graphs(cat_records, cat_dir, passes)

    if len(session_ids) > 1:
        compare_dir = args.output_dir / "multi_session"
        plot_session_comparisons({sid: records_by_session[sid] for sid in session_ids}, compare_dir, passes)

    print(f"Graphs written to {args.output_dir}")


if __name__ == "__main__":
    main()
