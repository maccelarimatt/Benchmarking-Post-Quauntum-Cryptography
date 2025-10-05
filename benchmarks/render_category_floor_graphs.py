from __future__ import annotations

import argparse
import csv
import json
import math
import pathlib
from collections import defaultdict
from dataclasses import dataclass, field
import statistics
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
    runtime_scaling: Dict[str, Any] | None


@dataclass
class CaptionLog:
    entries: List[Tuple[pathlib.Path, str]] = field(default_factory=list)

    def add(self, path: pathlib.Path, text: str) -> None:
        self.entries.append((path, text))

    def write(self, root: pathlib.Path) -> None:
        if not self.entries:
            return
        root.mkdir(parents=True, exist_ok=True)
        entries = sorted(
            ((p.relative_to(root), h) for p, h in self.entries),
            key=lambda item: str(item[0]),
        )
        lines = ["# Graph Captions\n"]
        for rel_path, heading in entries:
            lines.append(f"![{rel_path}]({rel_path})\n")
            lines.append(f"{heading}\n")
        (root / "captions.md").write_text("\n".join(lines), encoding="utf-8")


def _save_with_caption(
    fig: plt.Figure,
    outfile: pathlib.Path,
    caption: str,
    captions: CaptionLog,
    rect: Tuple[float, float, float, float] = (0, 0.08, 1, 1),
) -> None:
    fig.tight_layout(rect=rect)
    fig.text(0.5, 0.02, caption, ha="center", va="center")
    fig.savefig(outfile, dpi=200)
    captions.add(outfile, caption)
    plt.close(fig)


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
                runtime_scaling=json.loads(row.get("runtime_scaling_json")) if row.get("runtime_scaling_json") else None,
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


def plot_latency_bars(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str, captions: CaptionLog) -> None:
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
        title = f"{pass_name.title()} pass latency — {kind}"
        ax.legend()
        ax.grid(True, axis="y", linestyle="--", alpha=0.3)
        for tick in ax.get_xticklabels():
            tick.set_horizontalalignment("right")
        outfile = output_dir / f"latency_{pass_name}_{kind.lower()}.png"
        caption = f"Mean latency per operation for {kind} ({pass_name})"
        _save_with_caption(fig, outfile, caption, captions)


def plot_memory_bars(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str, captions: CaptionLog) -> None:
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
        title = f"{pass_name.title()} peak RSS — {kind}"
        ax.legend()
        ax.grid(True, axis="y", linestyle="--", alpha=0.3)
        outfile = output_dir / f"memory_peak_{pass_name}_{kind.lower()}.png"
        caption = f"Peak RSS per operation for {kind} ({pass_name})"
        _save_with_caption(fig, outfile, caption, captions)


def plot_security_vs_latency(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str, captions: CaptionLog) -> None:
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
    ax.grid(True, linestyle="--", alpha=0.3)
    handles = [plt.Line2D([0], [0], marker=markers[k], color="w", markerfacecolor=colors[k], markersize=8) for k in markers if any(pt[2] == k for pt in points)]
    labels = [k for k in markers if any(pt[2] == k for pt in points)]
    if handles:
        ax.legend(handles, labels, title="Kind")
    outfile = output_dir / f"security_vs_latency_{pass_name}.png"
    caption = f"Keygen latency vs. classical security ({pass_name})"
    _save_with_caption(fig, outfile, caption, captions)


def plot_latency_distributions(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str, captions: CaptionLog) -> None:
    grouped: Dict[Tuple[str, str], List[Tuple[str, int, Sequence[float]]]] = defaultdict(list)
    for rec in records:
        if rec.measurement_pass != pass_name or not rec.series:
            continue
        grouped[(rec.kind, rec.operation)].append((rec.algo, rec.category_number, rec.series))

    for (kind, operation), entries in grouped.items():
        entries = sorted(entries, key=lambda item: (item[0], item[1]))
        data = [list(series) for _, _, series in entries if series]
        if not data:
            continue
        labels = [f"{algo} (Cat-{category})" for algo, category, series in entries if series]
        positions = list(range(1, len(data) + 1))

        fig, ax = plt.subplots(figsize=(max(6, len(labels) * 0.75), 4.5))
        violins = ax.violinplot(data, positions=positions, showmeans=True, showextrema=False)
        for body in violins['bodies']:
            body.set_alpha(0.6)
        ax.boxplot(data, positions=positions, widths=0.2, patch_artist=True)
        ax.set_xticks(positions)
        ax.set_xticklabels(labels, rotation=45)
        for tick in ax.get_xticklabels():
            tick.set_horizontalalignment("right")
        ax.set_ylabel("Latency (ms)")
        ax.grid(True, axis="y", linestyle="--", alpha=0.3)
        outfile = output_dir / f"latency_distribution_{pass_name}_{kind.lower()}_{operation}.png"
        caption = f"Latency distribution for {kind} {operation} ({pass_name})"
        _save_with_caption(fig, outfile, caption, captions)


def plot_memory_distributions(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str, captions: CaptionLog) -> None:
    grouped: Dict[Tuple[str, str], List[Tuple[str, int, Sequence[float]]]] = defaultdict(list)
    for rec in records:
        if rec.measurement_pass != pass_name or not rec.mem_series:
            continue
        grouped[(rec.kind, rec.operation)].append((rec.algo, rec.category_number, rec.mem_series))

    for (kind, operation), entries in grouped.items():
        entries = sorted(entries, key=lambda item: (item[0], item[1]))
        data = [list(series) for _, _, series in entries if series]
        if not data:
            continue
        labels = [f"{algo} (Cat-{category})" for algo, category, series in entries if series]
        positions = list(range(1, len(data) + 1))

        fig, ax = plt.subplots(figsize=(max(6, len(labels) * 0.75), 4.5))
        violins = ax.violinplot(data, positions=positions, showmeans=True, showextrema=False)
        for body in violins['bodies']:
            body.set_alpha(0.6)
        ax.boxplot(data, positions=positions, widths=0.2, patch_artist=True)
        ax.set_xticks(positions)
        ax.set_xticklabels(labels, rotation=45)
        for tick in ax.get_xticklabels():
            tick.set_horizontalalignment("right")
        ax.set_ylabel("Peak memory (KB)")
        ax.grid(True, axis="y", linestyle="--", alpha=0.3)
        outfile = output_dir / f"memory_distribution_{pass_name}_{kind.lower()}_{operation}.png"
        caption = f"Memory distribution for {kind} {operation} ({pass_name})"
        _save_with_caption(fig, outfile, caption, captions)


def plot_latency_ecdf(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str, captions: CaptionLog) -> None:
    grouped: Dict[Tuple[str, str], List[Tuple[str, int, Sequence[float]]]] = defaultdict(list)
    for rec in records:
        if rec.measurement_pass != pass_name or not rec.series:
            continue
        grouped[(rec.kind, rec.operation)].append((rec.algo, rec.category_number, rec.series))

    for (kind, operation), entries in grouped.items():
        entries = sorted(entries, key=lambda item: (item[0], item[1]))
        fig, ax = plt.subplots(figsize=(6, 4.5))
        for algo, category, series in entries:
            if not series:
                continue
            sorted_vals = sorted(series)
            n = len(sorted_vals)
            y_vals = [i / n for i in range(1, n + 1)]
            label = f"{algo} (Cat-{category})"
            ax.step(sorted_vals, y_vals, where="post", label=label)
        ax.set_xlabel("Latency (ms)")
        ax.set_ylabel("F(x)")
        ax.grid(True, linestyle="--", alpha=0.3)
        if ax.lines:
            ax.legend()
        outfile = output_dir / f"latency_ecdf_{pass_name}_{kind.lower()}_{operation}.png"
        caption = f"Latency ECDF for {kind} {operation} ({pass_name})"
        _save_with_caption(fig, outfile, caption, captions)


def plot_throughput_vs_category(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str, captions: CaptionLog) -> None:
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
        ax.set_ylabel("Ops per second")
        ax.set_xlabel("Security category")
        ax.set_xticks(list(x_positions))
        ax.set_xticklabels([str(cat) for cat in categories])
        ax.grid(True, linestyle="--", alpha=0.3)
        if ax.lines:
            ax.legend()
        outfile = output_dir / f"throughput_{pass_name}_{kind.lower()}_{operation}.png"
        caption = f"Throughput across categories for {kind} {operation} ({pass_name})"
        _save_with_caption(fig, outfile, caption, captions)


def _collect_unique_meta(records: Sequence[Record]) -> Dict[Tuple[str, str, int], Record]:
    unique: Dict[Tuple[str, str, int], Record] = {}
    for rec in records:
        key = (rec.kind, rec.algo, rec.category_number)
        if key not in unique:
            unique[key] = rec
    return unique


def plot_size_stacked_bars(records: Sequence[Record], output_dir: pathlib.Path, captions: CaptionLog) -> None:
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
        title = f"Key material sizes — {kind_label}"
        ax.legend()
        ax.grid(True, axis="y", linestyle="--", alpha=0.3)
        outfile = output_dir / f"sizes_{kind_label.lower()}.png"
        caption = f"Key material sizes ({kind_label})"
        _save_with_caption(fig, outfile, caption, captions)

    _plot(kem_entries, "KEM")
    _plot(sig_entries, "SIG")


def plot_expansion_scatter(records: Sequence[Record], output_dir: pathlib.Path, captions: CaptionLog) -> None:
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
            algo_label = f"{algo} (Cat-{category})"
            ax.scatter(category, ratio, label=algo_label)
            ax.annotate(algo_label, (category, ratio), textcoords="offset points", xytext=(4, 4), fontsize=7)
        ax.set_xlabel("Security category")
        ax.set_ylabel("Expansion ratio")
        ax.grid(True, linestyle="--", alpha=0.3)
        outfile = output_dir / f"expansion_{label.lower()}.png"
        caption = f"Expansion ratio vs category ({label})"
        _save_with_caption(fig, outfile, caption, captions)

    _plot(kem_points, "KEM")
    _plot(sig_points, "SIG")


def _render_bar_chart(
    items: List[Tuple[str, float, float]],
    outfile: pathlib.Path,
    ylabel: str,
    title: str,
    captions: CaptionLog,
) -> None:
    if not items:
        return
    labels = [label for label, _, _ in items]
    values = [max(0.0, val) for _, val, _ in items]
    errors = [max(0.0, err) for _, _, err in items]
    fig, ax = plt.subplots(figsize=(max(6, len(items) * 0.75), 4.5))
    lower = [min(err, val) for err, val in zip(errors, values)]
    yerr = [lower, errors]
    ax.bar(labels, values, yerr=yerr, capsize=4)
    ax.set_ylabel(ylabel)
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)
    ax.tick_params(axis="x", rotation=45)
    for tick in ax.get_xticklabels():
        tick.set_horizontalalignment("right")
    ax.set_ylim(bottom=0)
    _save_with_caption(fig, outfile, title, captions)


def plot_hamming_metrics(records: Sequence[Record], output_dir: pathlib.Path, captions: CaptionLog) -> None:
    unique = _collect_unique_meta(records)
    entries: List[Dict[str, Any]] = []
    for (kind, algo, category), rec in unique.items():
        analysis = rec.meta.get("secret_key_analysis")
        if not isinstance(analysis, dict):
            continue
        hw = analysis.get("hw") or {}
        hd = analysis.get("hd") or {}
        hw_mean = hw.get("mean_fraction")
        hd_mean = hd.get("mean_fraction")
        if hw_mean is None and hd_mean is None:
            continue
        entry = {
            "algo": algo,
            "kind": kind,
            "category": category,
            "hw_mean": hw_mean,
            "hw_std": hw.get("std_fraction") or 0.0,
            "hd_mean": hd_mean,
            "hd_std": hd.get("std_fraction") or 0.0,
        }
        entries.append(entry)
    if not entries:
        return

    by_category: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        by_category[entry["category"]].append(entry)

    # Overall charts using algo + category label
    overall_hw_items: List[Tuple[str, float, float]] = []
    overall_hd_items: List[Tuple[str, float, float]] = []
    for entry in sorted(entries, key=lambda e: (e["category"], e["algo"])):
        label = f"{entry['algo']} (Cat-{entry['category']})"
        if entry["hw_mean"] is not None:
            overall_hw_items.append((label, entry["hw_mean"] * 100.0, entry["hw_std"] * 100.0))
        if entry["hd_mean"] is not None:
            overall_hd_items.append((label, entry["hd_mean"] * 100.0, entry["hd_std"] * 100.0))

    _render_bar_chart(
        overall_hw_items,
        output_dir / "hamming_weight_all.png",
        "Mean HW fraction (%)",
        "Hamming weight per algorithm/category",
        captions,
    )
    _render_bar_chart(
        overall_hd_items,
        output_dir / "hamming_distance_all.png",
        "Mean HD fraction (%)",
        "Hamming distance per algorithm/category",
        captions,
    )

    # Per-category charts
    for category, items in sorted(by_category.items()):
        hw_items: List[Tuple[str, float, float]] = []
        hd_items: List[Tuple[str, float, float]] = []
        for entry in sorted(items, key=lambda e: e["algo"]):
            label = entry["algo"]
            if entry["hw_mean"] is not None:
                hw_items.append((label, entry["hw_mean"] * 100.0, entry["hw_std"] * 100.0))
            if entry["hd_mean"] is not None:
                hd_items.append((label, entry["hd_mean"] * 100.0, entry["hd_std"] * 100.0))
        _render_bar_chart(
            hw_items,
            output_dir / f"hamming_weight_cat-{category}.png",
            "Mean HW fraction (%)",
            f"Hamming weight — Category {category}",
            captions,
        )
        _render_bar_chart(
            hd_items,
            output_dir / f"hamming_distance_cat-{category}.png",
            "Mean HD fraction (%)",
            f"Hamming distance — Category {category}",
            captions,
        )


def plot_memory_error_bars(records: Sequence[Record], output_dir: pathlib.Path, pass_name: str, captions: CaptionLog) -> None:
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
        label_name = f"{rec.algo} (Cat-{rec.category_number})"
        grouped[key][label_name] = (
            rec.mem_mean_kb,
            max(0.0, rec.mem_mean_kb - rec.mem_ci95_low_kb),
            max(0.0, rec.mem_ci95_high_kb - rec.mem_mean_kb),
        )

    for label, data in grouped.items():
        if not data:
            continue
        entries = sorted(data.items(), key=lambda item: item[0])
        labels = [name for name, _ in entries]
        means = [vals[0] for _, vals in entries]
        yerr = [[vals[1] for _, vals in entries], [vals[2] for _, vals in entries]]
        fig, ax = plt.subplots(figsize=(max(6, len(entries) * 0.75), 4.5))
        ax.bar(labels, means, yerr=yerr, capsize=4)
        ax.set_ylabel("Peak memory (KB)")
        ax.grid(True, axis="y", linestyle="--", alpha=0.3)
        ax.tick_params(axis="x", rotation=45)
        for tick in ax.get_xticklabels():
            tick.set_horizontalalignment("right")
        ax.set_ylim(bottom=0)
        safe_label = label.replace(" / ", "_").replace(" ", "_").lower()
        outfile = output_dir / f"memory_errorbars_{pass_name}_{safe_label}.png"
        caption = f"Peak memory with 95% CI — {label} ({pass_name})"
        _save_with_caption(fig, outfile, caption, captions)


def plot_security_cost_bars(records: Sequence[Record], output_dir: pathlib.Path, captions: CaptionLog) -> None:
    unique = _collect_unique_meta(records)
    entries = []
    for (kind, algo, category), rec in unique.items():
        if rec.security_classical_bits is None and rec.security_quantum_bits is None:
            continue
        label = f"{algo}\nCat-{category}"
        entries.append((label, rec.security_classical_bits or 0.0, rec.security_quantum_bits or 0.0))
    if not entries:
        return
    entries.sort(key=lambda item: (item[0].split("\n")[-1], item[0]))
    labels = [item[0] for item in entries]
    classical = [item[1] for item in entries]
    quantum = [item[2] for item in entries]
    x = range(len(entries))
    fig, ax = plt.subplots(figsize=(max(6, len(entries) * 0.8), 4.5))
    ax.bar(x, classical, width=0.4, label="Classical bits")
    ax.bar([i + 0.4 for i in x], quantum, width=0.4, label="Quantum bits")
    ax.set_xticks([i + 0.2 for i in x])
    ax.set_xticklabels(labels, rotation=45)
    for tick in ax.get_xticklabels():
        tick.set_horizontalalignment("right")
    ax.set_ylabel("Bits of security")
    ax.legend()
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)
    outfile = output_dir / "security_bits_comparison.png"
    caption = "Classical vs quantum security estimates"
    _save_with_caption(fig, outfile, caption, captions)


def plot_tradeoff_frontier(records: Sequence[Record], output_dir: pathlib.Path, preferred_passes: Sequence[str], captions: CaptionLog) -> None:
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
    ax.grid(True, linestyle="--", alpha=0.3)
    handles, labels = ax.get_legend_handles_labels()
    unique_pairs = dict(zip(labels, handles))
    ax.legend(unique_pairs.values(), unique_pairs.keys(), fontsize=8)
    outfile = output_dir / f"tradeoff_{pass_name}.png"
    caption = "Performance vs security trade-off"
    _save_with_caption(fig, outfile, caption, captions)

def _aggregate_scaling(values: Dict[str, Dict[str, Any]]) -> List[Tuple[str, float, float]]:
    items: List[Tuple[str, float, float]] = []
    for label, info in values.items():
        samples = info.get('values', [])
        if not samples:
            continue
        mean_val = sum(samples) / len(samples)
        std_val = statistics.pstdev(samples) if len(samples) > 1 else 0.0
        display_label = label + (' (baseline)' if info.get('baseline') else '')
        items.append((display_label, mean_val, std_val))
    items.sort(key=lambda item: (0 if item[0].endswith('(baseline)') else 1, item[0]))
    return items


def plot_runtime_scaling(records: Sequence[Record], output_dir: pathlib.Path, captions: CaptionLog) -> None:
    per_algo_cat: Dict[Tuple[str, int], Dict[str, Dict[str, Any]]] = defaultdict(dict)
    per_algo: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    per_category: Dict[int, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    overall: Dict[str, Dict[str, Any]] = {}

    for rec in records:
        scaling = rec.runtime_scaling
        if not scaling or rec.mean_ms is None:
            continue
        preds = scaling.get('predictions') or {}
        baseline_device = scaling.get('baseline_device') or 'baseline'

        key = (rec.algo, rec.category_number)
        target = per_algo_cat.setdefault(key, {})
        algo_target = per_algo.setdefault(rec.algo, {})
        cat_target = per_category.setdefault(rec.category_number, {})

        for container in (target, algo_target, cat_target, overall):
            entry = container.setdefault(baseline_device, {'values': [], 'baseline': True})
            entry['values'].append(rec.mean_ms)

        for device, info in preds.items():
            predicted = info.get('predicted_ms')
            if predicted is None:
                continue
            for container in (target, algo_target, cat_target, overall):
                entry = container.setdefault(device, {'values': [], 'baseline': False})
                entry['values'].append(float(predicted))

    def _plot_group(container: Dict[str, Dict[str, Any]], title: str, filename: pathlib.Path) -> None:
        items = _aggregate_scaling(container)
        _render_bar_chart(items, filename, 'Predicted latency (ms)', title, captions)

    for (algo, category), container in per_algo_cat.items():
        if not container:
            continue
        safe_algo = algo.replace('/', '_').replace(' ', '_')
        outfile = output_dir / f'runtime_scaling_{safe_algo}_cat-{category}.png'
        title = f'Runtime scaling — {algo} (Cat-{category})'
        _plot_group(container, title, outfile)

    for algo, container in per_algo.items():
        if not container:
            continue
        safe_algo = algo.replace('/', '_').replace(' ', '_')
        outfile = output_dir / f'runtime_scaling_{safe_algo}_overall.png'
        title = f'Runtime scaling — {algo} (all categories)'
        _plot_group(container, title, outfile)

    for category, container in per_category.items():
        if not container:
            continue
        outfile = output_dir / f'runtime_scaling_category_cat-{category}.png'
        title = f'Runtime scaling — Category {category}'
        _plot_group(container, title, outfile)

    if overall:
        outfile = output_dir / 'runtime_scaling_overall.png'
        title = 'Runtime scaling — overall'
        _plot_group(overall, title, outfile)



def generate_graphs(records: Sequence[Record], output_dir: pathlib.Path, passes: Sequence[str], captions: CaptionLog) -> None:
    if not records:
        return
    _ensure_output_dir(output_dir)
    available_passes = {rec.measurement_pass for rec in records}

    for pass_name in passes:
        if pass_name not in available_passes:
            continue
        plot_latency_bars(records, output_dir, pass_name, captions)
        plot_latency_distributions(records, output_dir, pass_name, captions)
        plot_latency_ecdf(records, output_dir, pass_name, captions)
        plot_security_vs_latency(records, output_dir, pass_name, captions)
        if "timing" in pass_name:
            plot_throughput_vs_category(records, output_dir, pass_name, captions)
        if pass_name.startswith("memory"):
            plot_memory_bars(records, output_dir, pass_name, captions)
            plot_memory_distributions(records, output_dir, pass_name, captions)
            plot_memory_error_bars(records, output_dir, pass_name, captions)

    plot_size_stacked_bars(records, output_dir, captions)
    plot_expansion_scatter(records, output_dir, captions)
    plot_security_cost_bars(records, output_dir, captions)
    plot_tradeoff_frontier(records, output_dir, preferred_passes=[p for p in passes if "timing" in p] + list(passes), captions=captions)
    plot_hamming_metrics(records, output_dir, captions)
    plot_runtime_scaling(records, output_dir, captions)


def plot_session_comparisons(
    session_records: Dict[str, List[Record]],
    output_dir: pathlib.Path,
    passes: Sequence[str],
    captions: CaptionLog,
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
                ax.set_ylabel("Mean latency (ms)")
            ax.set_xlabel("Session")
            ax.grid(True, linestyle="--", alpha=0.3)
            if ax.lines:
                ax.legend()
            ax.set_xticks(x_positions)
            ax.set_xticklabels(sessions, rotation=45)
            for tick in ax.get_xticklabels():
                tick.set_horizontalalignment("right")
            fig.tight_layout()
            outfile = output_dir / f"trend_latency_{pass_name}_{kind.lower()}_{operation}.png"
            fig.savefig(outfile, dpi=200)
            captions.add(outfile, f"Latency trend across sessions — {kind} {operation} ({pass_name})")
            plt.close(fig)

        if pass_name.startswith("memory"):
            for (kind, operation), algo_map in memory_lines.items():
                fig, ax = plt.subplots(figsize=(max(6, len(sessions) * 0.75), 4.5))
                for algo, values_by_session in sorted(algo_map.items()):
                    values = [values_by_session.get(sid) for sid in sessions]
                    if all(v is None for v in values):
                        continue
                    ax.plot(x_positions, values, marker="o", label=algo)                
                    ax.set_ylabel("Peak memory (KB)")
                ax.set_xlabel("Session")
                ax.grid(True, linestyle="--", alpha=0.3)
                if ax.lines:
                    ax.legend()
                ax.set_xticks(x_positions)
                ax.set_xticklabels(sessions, rotation=45)
            for tick in ax.get_xticklabels():
                tick.set_horizontalalignment("right")
                fig.tight_layout()
                outfile = output_dir / f"trend_memory_{pass_name}_{kind.lower()}_{operation}.png"
                fig.savefig(outfile, dpi=200)
                captions.add(outfile, f"Peak memory trend across sessions — {kind} {operation} ({pass_name})")
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
    captions = CaptionLog()
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
        generate_graphs(session_records, output_dir, passes, captions)

        categories = sorted({rec.category_number for rec in session_records if rec.category_number})
        for category in categories:
            cat_records = [rec for rec in session_records if rec.category_number == category]
            if not cat_records:
                continue
            cat_dir = output_dir / f"category_{category}"
            generate_graphs(cat_records, cat_dir, passes, captions)

    if len(session_ids) > 1:
        compare_dir = args.output_dir / "multi_session"
        plot_session_comparisons({sid: records_by_session[sid] for sid in session_ids}, compare_dir, passes, captions)

    captions.write(args.output_dir)
    print(f"Graphs written to {args.output_dir}")


if __name__ == "__main__":
    main()
