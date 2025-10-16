#!/usr/bin/env python3
"""Render poster-friendly graphs from benchmark CSV data."""

from __future__ import annotations

import argparse
import csv
import json
import math
import pathlib
import io, contextlib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import matplotlib.pyplot as plt
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "matplotlib is required for poster graph rendering. Install it via 'pip install matplotlib'."
    ) from exc

import matplotlib.lines as mlines

try:
    from adjustText import adjust_text  # pip install adjustText
except Exception:
    adjust_text = None





# Poster styling: larger fonts, consistent grid visibility
plt.rcParams.update(
    {
        "axes.titlesize": 22,
        "axes.labelsize": 18,
        "axes.grid": True,
        "grid.alpha": 0.3,
        "grid.linestyle": "--",
        "legend.frameon": False,
        "legend.fontsize": 16,
        "xtick.labelsize": 16,
        "ytick.labelsize": 16,
    }
)

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
DEFAULT_CSV = REPO_ROOT / "Tested Benchmarks" / "i9 9880h" / "Benchmarks" / "category_floor_benchmarks.csv"
DEFAULT_OUTPUT = REPO_ROOT / "Tested Benchmarks" / "i9 9880h" / "Benchmarks"

KEM_OPERATIONS: Sequence[str] = ("keygen", "encapsulate", "decapsulate")
SIG_OPERATIONS: Sequence[str] = ("keygen", "sign", "verify")


@dataclass
class Record:
    session_id: str
    measurement_pass: str
    algo: str
    kind: str
    operation: str
    category_number: int
    mean_ms: Optional[float]
    mem_mean_kb: Optional[float]
    security_classical_bits: Optional[float]
    security_quantum_bits: Optional[float]
    security_shor_breakable: Optional[bool]
    security_extras: Dict[str, Any]
    meta: Dict[str, Any]


def _parse_float(value: str | None) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(parsed):
        return None
    return parsed


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
            try:
                security_extras = json.loads(row.get("security_extras_json", "") or "{}")
                if not isinstance(security_extras, dict):
                    security_extras = {}
            except json.JSONDecodeError:
                security_extras = {}

            security_shor = row.get("security_shor_breakable")
            if security_shor is not None:
                security_shor_breakable = security_shor.lower() in {"true", "1", "t"}
            else:
                security_shor_breakable = None

            records.append(
                Record(
                    session_id=row.get("session_id", ""),
                    measurement_pass=(row.get("measurement_pass", "") or "timing").lower(),
                    algo=row.get("algo", ""),
                    kind=row.get("kind", ""),
                    operation=(row.get("operation") or "").lower(),
                    category_number=int(row.get("category_number", "0") or 0),
                    mean_ms=_parse_float(row.get("mean_ms")),
                    mem_mean_kb=_parse_float(row.get("mem_mean_kb")),
                    security_classical_bits=_parse_float(row.get("security_classical_bits")),
                    security_quantum_bits=_parse_float(row.get("security_quantum_bits")),
                    security_shor_breakable=security_shor_breakable,
                    security_extras=security_extras,
                    meta=meta,
                )
            )
    if not records:
        raise SystemExit(f"No rows found in CSV: {csv_path}")
    return records


def _friendly_label(name: str) -> str:
    cleaned = name.replace("_", " ").replace("-", " ").strip()
    if not cleaned:
        return name
    if "+" in cleaned:
        parts = [part.strip() for part in cleaned.split("+") if part.strip()]
        if parts:
            return "+".join(part.upper() for part in parts)
    return cleaned.title()


def _ensure_dir(path: pathlib.Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _save_figure(fig: plt.Figure, name: str, png_dir: pathlib.Path, pdf_dir: pathlib.Path) -> None:
    _ensure_dir(png_dir)
    _ensure_dir(pdf_dir)
    fig.savefig(png_dir / f"{name}.png", dpi=300, bbox_inches="tight")
    fig.savefig(pdf_dir / f"{name}.pdf", bbox_inches="tight")
    plt.close(fig)


def _select_top_algos(records: Iterable[Record], kind: str, count: int, pass_name: str, operation: str = "keygen") -> List[str]:
    filtered = [
        rec
        for rec in records
        if rec.kind.upper() == kind
        and rec.measurement_pass == pass_name
        and rec.operation == operation
        and rec.mean_ms is not None
    ]
    filtered.sort(key=lambda r: r.mean_ms)
    result: List[str] = []
    for rec in filtered:
        if rec.algo not in result:
            result.append(rec.algo)
        if len(result) >= count:
            break
    return result


def plot_latency_combined(records: Sequence[Record], png_dir: pathlib.Path, pdf_dir: pathlib.Path) -> None:
    pass_name = "timing"
    # Change this value if you want more or fewer algorithms plotted.
    top_n = 5

    aggregated: Dict[str, Dict[str, Any]] = {}
    for rec in records:
        if rec.measurement_pass != pass_name or rec.mean_ms is None:
            continue
        key = (rec.kind.upper(), rec.algo, rec.category_number)
        bucket = aggregated.setdefault(key, {"sums": 0.0, "count": 0, "entries": []})
        bucket["sums"] += rec.mean_ms
        bucket["count"] += 1
        bucket["entries"].append(rec)

    averaged: List[Tuple[str, str, int, float, List[Record]]] = []
    for (kind, algo, category), info in aggregated.items():
        if info["count"]:
            averaged.append((kind, algo, category, info["sums"] / info["count"], info["entries"]))

    averaged.sort(key=lambda item: item[3])
    top_algos = averaged[:top_n]
    if not top_algos:
        return

    kem_palette = ["#1f77b4", "#14796d", "#33539e", "#209fb5", "#14a44d"]
    sig_palette = ["#d62839", "#f77f00", "#b56576", "#6d597a", "#ef6351"]

    fig, ax = plt.subplots(figsize=(13, 8))
    #ax.set_title("Latency (Timing) — Top PQC Algorithms (Mean Over Operations)")

    bars: List[Tuple[str, float, str]] = []
    for idx, (kind, algo, category, _, entries) in enumerate(top_algos):
        color_palette = kem_palette if kind == "KEM" else sig_palette
        base_color = color_palette[idx % len(color_palette)]
        algorithm_label = _friendly_label(algo)
        for entry in entries:
            op_label = entry.operation[:4].upper()
            bars.append((f"{algorithm_label} {op_label} ({category})", entry.mean_ms, base_color))

    labels = [label for label, _, _ in bars]
    values = [value for _, value, _ in bars]
    colors = [color for _, _, color in bars]

    ax.bar(labels, values, color=colors)
    ax.set_ylabel("Mean latency (ms)")
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)
    ax.tick_params(axis="x", rotation=45)
    for tick in ax.get_xticklabels():
        tick.set_horizontalalignment("right")

    _save_figure(fig, "poster_latency_timing_top", png_dir, pdf_dir)


def _format_scientific(value: Optional[float]) -> str:
    if value is None or value <= 0:
        return "N/A"
    return f"{value:.2e}"


def plot_shor_runtime(records: Sequence[Record], png_dir: pathlib.Path, pdf_dir: pathlib.Path) -> None:
    entries: List[Tuple[int, float, Optional[float]]] = []  # (modulus_bits, runtime_seconds, classical_core_years)
    for rec in records:
        if rec.algo.lower() != "rsa-oaep" or rec.security_extras is None:
            continue
        profiles = rec.security_extras.get("shor_profiles")
        if not isinstance(profiles, dict):
            continue
        for group in profiles.get("scenarios", []):
            if not isinstance(group, dict):
                continue
            modulus_bits = group.get("modulus_bits")
            for scenario in group.get("scenarios", []) or []:
                if not isinstance(scenario, dict):
                    continue
                calibrated = (scenario.get("calibrated_against") or "").lower()
                if "ge" not in calibrated:
                    continue
                runtime = scenario.get("runtime_seconds")
                if runtime is None or modulus_bits is None:
                    continue
                try:
                    bits = int(float(modulus_bits))
                    rt = float(runtime)
                except (TypeError, ValueError):
                    continue
                classical = None
                bruteforce = rec.security_extras.get("bruteforce")
                if isinstance(bruteforce, dict):
                    core_years = bruteforce.get("core_years")
                    if isinstance(core_years, (int, float)):
                        classical = float(core_years)
                entries.append((bits, rt, classical))

    if not entries:
        return

    entries.sort(key=lambda x: x[0])

    labels = [str(bits) for bits, _, _ in entries]
    runtime_days = [rt / 86400.0 for _, rt, _ in entries]

    fig, ax = plt.subplots(figsize=(11, 7))
    bars = ax.bar(labels, runtime_days, color="#6c5ce7")
    ax.set_xlabel("RSA modulus (bits)")
    ax.set_ylabel("Runtime to factor (days)")
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)
    ax.tick_params(axis="x", rotation=0)

    for (bar, days, (_, _, classical)) in zip(bars, runtime_days, entries):
        hours = days * 24.0
        ax.text(
            bar.get_x() + bar.get_width() / 2.0,
            bar.get_height(),
            f"Shor: {hours:.1f} h",
            ha="center",
            va="bottom",
            fontsize=14,
            color="black",
            clip_on=True,
        )
        if classical:
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                bar.get_height() + max(days * 0.1, 0.6),
                f"Classical: {_format_scientific(classical)} core-years",
                ha="center",
                va="bottom",
                fontsize=12,
                color="red",
                clip_on=True,
            )

    legend_handles = [
        mlines.Line2D([], [], color="black", marker="|", linestyle="None", markersize=12, label="Shor runtime (text in black)"),
        mlines.Line2D([], [], color="red", marker="|", linestyle="None", markersize=12, label="Classical GNFS estimate (red text)"),
    ]
    ax.legend(handles=legend_handles, loc="upper left")

    _save_figure(fig, "poster_shor_runtime_rsa_ge", png_dir, pdf_dir)




def _place_labels(
    ax: plt.Axes,
    specs: Sequence[Tuple[float, float, str, str]],
) -> None:
    offsets = [
        (20, 20),
        (-20, 20),
        (20, -20),
        (-20, -20),
        (0, 25),
        (0, -25),
        (28, 0),
        (-28, 0),
    ]
    for idx, (x, y, label, color) in enumerate(specs):
        dx, dy = offsets[idx % len(offsets)]
        ax.annotate(
            label,
            (x, y),
            textcoords="offset points",
            xytext=(dx, dy),
            ha="center",
            fontsize=14,
            bbox=dict(boxstyle="round,pad=0.3", fc="white", alpha=0.0, lw=0.0),
            arrowprops=dict(arrowstyle="-", color=color, lw=0.8, alpha=0.7),
        )


def plot_security_vs_latency(records: Sequence[Record], png_dir: pathlib.Path, pdf_dir: pathlib.Path) -> None:
    points: List[Tuple[float, float, str, str, Optional[int]]] = []
    for rec in records:
        if rec.measurement_pass != "timing" or rec.operation != "keygen":
            continue
        if rec.mean_ms is None or rec.security_quantum_bits is None:
            continue
        points.append(
            (rec.security_quantum_bits, rec.mean_ms, rec.kind.upper(), _friendly_label(rec.algo), rec.category_number)
        )
    if not points:
        return

    kem_palette = ["#264653", "#2a9d8f", "#1d3557", "#457b9d", "#0a9396"]
    sig_palette = ["#e63946", "#f77f00", "#a01a58", "#b56576", "#ef6351"]

    fig, ax = plt.subplots(figsize=(12, 8))
    #ax.set_title("Quantum Security vs Latency (Key Generation)")

    label_specs: List[Tuple[float, float, str, str]] = []
    kem_idx = sig_idx = 0
    for qbits, latency, kind, label, category in points:
        if kind == "KEM":
            color = kem_palette[kem_idx % len(kem_palette)]
            kem_idx += 1
            marker = "o"
        else:
            color = sig_palette[sig_idx % len(sig_palette)]
            sig_idx += 1
            marker = "^"

        ax.scatter(
            qbits, latency,
            color=color, marker=marker, s=110,
            edgecolors="#222222", linewidths=0.6, zorder=3,
        )
        label_specs.append((qbits, latency, f"{label} ({category})", color))

    # Give a touch of margin so labels have space to move
    ax.margins(x=0.05, y=0.12)
    _place_labels_smart(ax, label_specs, base_offset=34, max_iter=370, max_distance_px=110.0)

    ax.set_xlabel("Quantum security bits")
    ax.set_ylabel("Key generation mean latency (ms)")
    ax.grid(True, linestyle="--", alpha=0.3, zorder=0)

    kem_marker = plt.Line2D([], [], marker="o", color="w", markerfacecolor="#264653", markeredgecolor="#222222", markersize=10, label="KEM")
    sig_marker = plt.Line2D([], [], marker="^", color="w", markerfacecolor="#e63946", markeredgecolor="#222222", markersize=10, label="Signature")
    ax.legend(handles=[kem_marker, sig_marker], loc="upper left")

    _save_figure(fig, "poster_security_vs_latency", png_dir, pdf_dir)


def plot_security_vs_latency_by_category(
    records: Sequence[Record],
    png_dir: pathlib.Path,
    pdf_dir: pathlib.Path,
    csv_dir: pathlib.Path,
) -> None:
    aggregator: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
    for rec in records:
        if rec.measurement_pass != "timing" or rec.mean_ms is None:
            continue
        key = (rec.kind.upper(), rec.algo, rec.category_number)
        info = aggregator.setdefault(key, {"ops": {}, "quantum": rec.security_quantum_bits})
        info["ops"][rec.operation] = rec.mean_ms
        if info.get("quantum") is None and rec.security_quantum_bits is not None:
            info["quantum"] = rec.security_quantum_bits

    categories: Dict[int, List[Tuple[str, str, int, float, float, Dict[str, float]]]] = {1: [], 3: [], 5: []}
    for (kind, algo, category), info in aggregator.items():
        if category not in categories:
            continue
        if info.get("quantum") is None:
            continue
        required_ops = KEM_OPERATIONS if kind == "KEM" else SIG_OPERATIONS
        ops = info["ops"]
        if any(op not in ops for op in required_ops):
            continue
        total_latency = sum(ops[op] for op in required_ops if ops[op] is not None)
        categories[category].append((kind, algo, category, info["quantum"], total_latency, ops))

    _ensure_dir(csv_dir)
    for category, entries in sorted(categories.items()):
        if not entries:
            continue
        kem_palette = ["#264653", "#2a9d8f", "#1d3557", "#457b9d", "#0a9396"]
        sig_palette = ["#e63946", "#f77f00", "#a01a58", "#b56576", "#ef6351"]

        fig, ax = plt.subplots(figsize=(12, 8))
        ax.set_title(f"Quantum Security vs Total Latency — Cat {category}")

        label_specs: List[Tuple[float, float, str, str]] = []
        kem_idx = sig_idx = 0
        for kind, algo, _, quantum, total_latency, ops in entries:
            if kind == "KEM":
                color = kem_palette[kem_idx % len(kem_palette)]
                kem_idx += 1
                marker = "o"
            else:
                color = sig_palette[sig_idx % len(sig_palette)]
                sig_idx += 1
                marker = "^"
            ax.scatter(
                quantum,
                total_latency,
                color=color,
                marker=marker,
                s=110,
                edgecolors="#222222",
                linewidths=0.6,
                zorder=3,
            )
            label_specs.append((quantum, total_latency, _friendly_label(algo), color))

        ax.margins(x=0.05, y=0.12)
        _place_labels_smart(ax, label_specs, base_offset=32, max_iter=340, max_distance_px=110.0)
        ax.set_xlabel("Quantum security bits")
        ax.set_ylabel("Total mean latency (ms)")
        ax.grid(True, linestyle="--", alpha=0.3, zorder=0)
        kem_marker = plt.Line2D([], [], marker="o", color="w", markerfacecolor="#264653", markeredgecolor="#222222", markersize=10, label="KEM")
        sig_marker = plt.Line2D([], [], marker="^", color="w", markerfacecolor="#e63946", markeredgecolor="#222222", markersize=10, label="Signature")
        ax.legend(handles=[kem_marker, sig_marker], loc="upper left")
        _save_figure(fig, f"poster_security_vs_latency_cat{category}", png_dir, pdf_dir)

        csv_path = csv_dir / f"poster_security_vs_latency_cat{category}.csv"
        fieldnames = [
            "algorithm",
            "kind",
            "category",
            "quantum_bits",
            "total_latency_ms",
            "keygen_ms",
            "encapsulate_ms",
            "decapsulate_ms",
            "sign_ms",
            "verify_ms",
        ]
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for kind, algo, _, quantum, total_latency, ops in entries:
                writer.writerow(
                    {
                        "algorithm": _friendly_label(algo),
                        "kind": kind,
                        "category": category,
                        "quantum_bits": quantum,
                        "total_latency_ms": total_latency,
                        "keygen_ms": ops.get("keygen"),
                        "encapsulate_ms": ops.get("encapsulate"),
                        "decapsulate_ms": ops.get("decapsulate"),
                        "sign_ms": ops.get("sign"),
                        "verify_ms": ops.get("verify"),
                    }
                )



def plot_security_bits(records: Sequence[Record], png_dir: pathlib.Path, pdf_dir: pathlib.Path) -> None:
    uniques: Dict[Tuple[str, int], Record] = {}
    for rec in records:
        key = (rec.algo, rec.category_number)
        if key not in uniques and rec.security_classical_bits is not None:
            uniques[key] = rec
    if not uniques:
        return

    entries = sorted(
        uniques.values(),
        key=lambda r: (r.category_number, r.kind.upper(), r.algo),
    )
    labels = [
        f"{_friendly_label(r.algo)}\nCat-{r.category_number}" for r in entries
    ]
    classical = [r.security_classical_bits or 0.0 for r in entries]
    quantum = [r.security_quantum_bits or 0.0 for r in entries]

    fig, ax = plt.subplots(figsize=(13, 8))
    #ax.set_title("Security Bits — Classical vs Quantum (All Algorithms)")
    positions = range(len(entries))
    ax.bar([p - 0.225 for p in positions], classical, width=0.35, label="Classical bits", color="#1f77b4")
    ax.bar([p + 0.225 for p in positions], quantum, width=0.35, label="Quantum bits", color="#d62728")
    ax.set_xticks(list(positions))
    ax.set_xticklabels(labels, rotation=45)
    for tick in ax.get_xticklabels():
        tick.set_horizontalalignment("right")
    ax.set_ylabel("Bits of security")
    ax.legend()
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)

    _save_figure(fig, "poster_security_bits", png_dir, pdf_dir)


def plot_memory_combined(records: Sequence[Record], png_dir: pathlib.Path, pdf_dir: pathlib.Path) -> None:
    pass_name = "memory"
    top_n = 5

    aggregated: Dict[str, Dict[str, Any]] = {}
    for rec in records:
        if rec.measurement_pass != pass_name or rec.mem_mean_kb is None:
            continue
        key = (rec.kind.upper(), rec.algo, rec.category_number)
        bucket = aggregated.setdefault(key, {"sums": 0.0, "count": 0, "entries": []})
        bucket["sums"] += rec.mem_mean_kb
        bucket["count"] += 1
        bucket["entries"].append(rec)

    averaged: List[Tuple[str, str, int, float, List[Record]]] = []
    for (kind, algo, category), info in aggregated.items():
        if info["count"]:
            averaged.append((kind, algo, category, info["sums"] / info["count"], info["entries"]))

    averaged.sort(key=lambda item: item[3])
    top_algos = averaged[:top_n]
    if not top_algos:
        return

    kem_palette = ["#14213d", "#1b4965", "#264653", "#186276", "#0d3b66"]
    sig_palette = ["#ff7f51", "#ff9f1c", "#f4a261", "#e76f51", "#bc6c25"]

    fig, ax = plt.subplots(figsize=(13, 8))
    #ax.set_title("Peak Memory — Top PQC Algorithms (Mean Over Operations)")

    bars: List[Tuple[str, float, str]] = []
    for idx, (kind, algo, category, _, entries) in enumerate(top_algos):
        palette = kem_palette if kind == "KEM" else sig_palette
        base_color = palette[idx % len(palette)]
        algo_label = _friendly_label(algo)
        for entry in entries:
            op_label = entry.operation[:4].upper()
            bars.append((f"{algo_label} {op_label} ({category})", entry.mem_mean_kb, base_color))

    labels = [label for label, _, _ in bars]
    values = [value for _, value, _ in bars]
    colors = [color for _, _, color in bars]

    ax.bar(labels, values, color=colors)
    ax.set_ylabel("Peak memory (KB)")
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)
    ax.tick_params(axis="x", rotation=45)
    for tick in ax.get_xticklabels():
        tick.set_horizontalalignment("right")

    _save_figure(fig, "poster_memory_peak_top", png_dir, pdf_dir)


def plot_size_by_scheme(records: Sequence[Record], png_dir: pathlib.Path, pdf_dir: pathlib.Path) -> None:
    uniques: Dict[Tuple[str, int], Record] = {}
    for rec in records:
        key = (rec.algo, rec.category_number)
        if key not in uniques and rec.meta:
            uniques[key] = rec
    if not uniques:
        return

    entries = sorted(
        uniques.values(), key=lambda r: (r.category_number, r.kind.upper(), r.algo)
    )
    labels = [
        f"{_friendly_label(r.algo)}\nCat-{r.category_number}" for r in entries
    ]

    fig, ax = plt.subplots(figsize=(13, 8))
    ax.set_title("Key Material Sizes by Scheme")

    pk = []
    sk = []
    ct = []
    sig = []
    for rec in entries:
        pk.append(float(rec.meta.get("public_key_len") or 0.0))
        sk.append(float(rec.meta.get("secret_key_len") or 0.0))
        if rec.kind.upper() == "KEM":
            ct.append(float(rec.meta.get("ciphertext_len") or 0.0))
            sig.append(0.0)
        else:
            ct.append(0.0)
            sig.append(float(rec.meta.get("signature_len") or 0.0))

    bottoms = [0.0] * len(entries)
    for label, values in [
        ("Public Key", pk),
        ("Secret Key", sk),
        ("Ciphertext", ct),
        ("Signature", sig),
    ]:
        if not any(values):
            continue
        ax.bar(labels, values, bottom=bottoms, label=label)
        bottoms = [b + v for b, v in zip(bottoms, values)]

    ax.set_ylabel("Bytes")
    ax.legend()
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)
    ax.tick_params(axis="x", rotation=45)
    for tick in ax.get_xticklabels():
        tick.set_horizontalalignment("right")

    _save_figure(fig, "poster_size_by_scheme", png_dir, pdf_dir)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render poster graphs.")
    parser.add_argument(
        "--csv",
        default=DEFAULT_CSV,
        type=pathlib.Path,
        help="Input CSV path (default: Tested Benchmarks/.../category_floor_benchmarks.csv)",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT,
        type=pathlib.Path,
        help="Poster output directory base (default: Tested Benchmarks/i9 9880h/Benchmarks)",
    )
    return parser.parse_args()


def _place_labels_smart(
    ax: plt.Axes,
    specs: Sequence[Tuple[float, float, str, str]],
    base_offset: int = 24,
    max_iter: int = 300,
    max_distance_px: float = 90.0,
) -> None:
    ring = [
        ( base_offset,  base_offset),
        (-base_offset,  base_offset),
        ( base_offset, -base_offset),
        (-base_offset, -base_offset),
        (0,  int(base_offset * 1.4)),
        (0, -int(base_offset * 1.4)),
        ( int(base_offset * 1.7), 0),
        (-int(base_offset * 1.7), 0),
    ]

    trans = ax.transData
    inv = trans.inverted()
    texts: List[plt.Text] = []
    points: List[Tuple[float, float]] = []
    colors: List[str] = []

    for idx, (x, y, label, color) in enumerate(specs):
        dx, dy = ring[idx % len(ring)]
        disp = trans.transform((x, y)) + (dx, dy)
        data_pos = inv.transform(disp)
        txt = ax.text(
            data_pos[0],
            data_pos[1],
            label,
            fontsize=13,
            ha="center",
            va="center",
            zorder=5,
        )
        texts.append(txt)
        points.append((x, y))
        colors.append(color)

    xs = [x for x, _ in points]
    ys = [y for _, y in points]

    if adjust_text is not None:
        with contextlib.redirect_stdout(io.StringIO()):
            adjust_text(
                texts,
                x=xs,
                y=ys,
                ax=ax,
                only_move={'points': 'y', 'text': 'xy'},
                expand_points=(1.25, 1.35),
                expand_text=(1.15, 1.25),
                force_points=0.25,
                force_text=0.45,
                ensure_inside_axes=True,
                precision=0.02,
            )
    else:
        fig = ax.figure
        for _ in range(max_iter):
            fig.canvas.draw()
            renderer = fig.canvas.get_renderer()
            bbs = [text.get_window_extent(renderer=renderer).expanded(1.05, 1.08) for text in texts]
            moved = False
            for i in range(len(texts)):
                for j in range(i + 1, len(texts)):
                    if bbs[i].overlaps(bbs[j]):
                        moved = True
                        for idx_text, direction in ((i, 1), (j, -1)):
                            tx, ty = texts[idx_text].get_position()
                            disp = trans.transform((tx, ty))
                            disp = (disp[0], disp[1] + direction * base_offset * 0.6)
                            texts[idx_text].set_position(inv.transform(disp))
            if not moved:
                break

    max_px = max_distance_px
    lines: List[mlines.Line2D] = []
    for text, (x, y), color in zip(texts, points, colors):
        tx, ty = text.get_position()
        point_disp = trans.transform((x, y))
        text_disp = trans.transform((tx, ty))
        dx = text_disp[0] - point_disp[0]
        dy = text_disp[1] - point_disp[1]
        dist = math.hypot(dx, dy)
        if dist > max_px:
            scale = max_px / dist
            limited = (point_disp[0] + dx * scale, point_disp[1] + dy * scale)
            new_pos = inv.transform(limited)
            text.set_position(new_pos)
            tx, ty = new_pos
            dist = max_px

        if dist > 6.0:
            line = mlines.Line2D(
                [x, tx],
                [y, ty],
                color=color,
                lw=0.8,
                alpha=0.6,
                zorder=3,
            )
            lines.append(line)
            ax.add_line(line)


def main() -> None:
    args = parse_args()
    records = load_records(args.csv)
    poster_root = args.output_dir / "PosterGraphs"
    png_dir = poster_root / "png"
    pdf_dir = poster_root / "pdf"
    csv_dir = poster_root / "csv"

    plot_latency_combined(records, png_dir, pdf_dir)
    plot_shor_runtime(records, png_dir, pdf_dir)
    plot_security_vs_latency(records, png_dir, pdf_dir)
    plot_security_vs_latency_by_category(records, png_dir, pdf_dir, csv_dir)
    plot_security_bits(records, png_dir, pdf_dir)
    plot_memory_combined(records, png_dir, pdf_dir)
    plot_size_by_scheme(records, png_dir, pdf_dir)

    print(f"Poster graphs written to {poster_root}")


if __name__ == "__main__":
    main()
