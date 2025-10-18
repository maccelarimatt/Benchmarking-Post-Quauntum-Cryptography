#!/usr/bin/env python3
"""Render poster-friendly graphs from benchmark CSV data."""

from __future__ import annotations

import argparse
import csv
import json
import math
import pathlib
# near your imports
import matplotlib.patheffects as pe
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
from matplotlib.patches import Patch

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
    # Aggregate one entry per modulus_bits; prefer per-bit classical values if available.
    agg: Dict[int, Dict[str, Optional[float]]] = {}  # bits -> {'runtime_s': float, 'classical_core_years': float}
    global_classical_values: List[float] = []  # in case only a single (global) classical was provided

    for rec in records:
        if rec.algo.lower() != "rsa-oaep" or not isinstance(rec.security_extras, dict):
            continue

        # Try to find a dictionary of per-bit classical values in common locations
        per_bit_maps = []
        for key in ("classical_by_bits", "gnfs_by_bits", "rsa_classical", "gnfs", "classical"):
            m = rec.security_extras.get(key)
            if isinstance(m, dict):
                # support keys as str or int
                per_bit_maps.append(m)

        profiles = rec.security_extras.get("shor_profiles")
        if not isinstance(profiles, dict):
            continue

        for group in profiles.get("scenarios", []) or []:
            if not isinstance(group, dict):
                continue
            bits_raw = group.get("modulus_bits")
            try:
                bits = int(float(bits_raw))
            except (TypeError, ValueError):
                continue

            # Fastest GE-baseline runtime for this bit size
            best_runtime = None
            for scenario in group.get("scenarios", []) or []:
                if not isinstance(scenario, dict):
                    continue
                if "ge" not in str(scenario.get("calibrated_against", "")).lower():
                    continue
                rt = scenario.get("runtime_seconds")
                if rt is None:
                    continue
                rt = float(rt)
                best_runtime = rt if best_runtime is None else min(best_runtime, rt)
            if best_runtime is None:
                continue

            # Per-bit classical (if present)
            classical: Optional[float] = None
            # (a) group-level classical (occasionally available)
            for k in ("classical_core_years",):
                v = group.get(k)
                if isinstance(v, (int, float)) and v > 0:
                    classical = float(v)
                    break
            # (b) any collected per-bit maps (keys may be '2048' or 2048)
            if classical is None:
                for m in per_bit_maps:
                    if str(bits) in m and isinstance(m[str(bits)], (int, float)) and m[str(bits)] > 0:
                        classical = float(m[str(bits)])
                        break
                    if bits in m and isinstance(m[bits], (int, float)) and m[bits] > 0:
                        classical = float(m[bits])
                        break

            # (c) if only a single global 'bruteforce.core_years' exists, store for GNFS scaling later
            bruteforce = rec.security_extras.get("bruteforce")
            if classical is None and isinstance(bruteforce, dict):
                cy = bruteforce.get("core_years")
                if isinstance(cy, (int, float)) and cy > 0:
                    global_classical_values.append(float(cy))

            entry = agg.setdefault(bits, {"runtime_s": None, "classical_core_years": None})
            if entry["runtime_s"] is None or best_runtime < (entry["runtime_s"] or float("inf")):
                entry["runtime_s"] = best_runtime
            if classical is not None:
                entry["classical_core_years"] = classical

    if not agg:
        return

    # If any bit sizes lack classical values, and we only have a single global classical number,
    # scale it per-bit using GNFS relative to a reference size we DO have (prefer the largest bit-size).
    missing_bits = [b for b, d in agg.items() if d["classical_core_years"] is None]
    if missing_bits and global_classical_values:
        # Pick a reference: if any bit-size already has a classical value, use that pair;
        # else use the largest bit-size with the global number as the reference.
        bits_sorted = sorted(agg)
        ref_bits = None
        ref_core_years = None
        for b in bits_sorted[::-1]:
            if agg[b]["classical_core_years"] is not None:
                ref_bits = b
                ref_core_years = agg[b]["classical_core_years"]
                break
        if ref_bits is None:
            ref_bits = bits_sorted[-1]  # largest available
            ref_core_years = max(global_classical_values)  # conservative
        # Fill in missing per-bit classical via GNFS scaling
        for b in missing_bits:
            agg[b]["classical_core_years"] = _gnfs_scale_core_years(b, ref_bits, ref_core_years)

    bits_sorted = sorted(agg)
    labels = [str(b) for b in bits_sorted]
    runtime_days = [(agg[b]["runtime_s"] or 0.0) / 86400.0 for b in bits_sorted]
    classical_vals = [agg[b]["classical_core_years"] for b in bits_sorted]

    fig, ax = plt.subplots(figsize=(11, 7))
    bars = ax.bar(labels, runtime_days, color="#6c5ce7")
    ax.set_xlabel("RSA modulus (bits)")
    ax.set_ylabel("Runtime to factor (days)")
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)
    ax.tick_params(axis="x", rotation=0)

    # Headroom so labels never clip
    ymax = max(runtime_days) if runtime_days else 1.0
    ax.set_ylim(0, ymax * 1.28)

    outline = [pe.withStroke(linewidth=3, foreground="white")]

    # Extra separation between Shor and Classical labels
    gap = max(0.04 * ymax, 0.45)         # base gap above the bar for Shor
    extra_classical_gap = max(0.06 * ymax, 0.70)  # extra gap above Shor for classical (when above)

    for bar, days, bits, classical in zip(bars, runtime_days, bits_sorted, classical_vals):
        x = bar.get_x() + bar.get_width() / 2.0
        h = bar.get_height()

        # Shor label (black) just above the bar
        shor_y = h + gap
        ax.text(
            x, shor_y, f"Shor: {days*24.0:.1f} h",
            ha="center", va="bottom", fontsize=14, color="black", clip_on=False, zorder=5
        )

        if classical and classical > 0:
            txt = f"Classical:\n{_format_scientific(classical)}\ncore-years"

            very_tall = h > 0.8 * ymax or bits >= 7680
            if very_tall:
                # Inside tall bars: place slightly below top, ensure it stays below Shor label
                inside_offset = max(0.06 * h, 0.7)
                classical_y = h - inside_offset
                if classical_y >= shor_y - gap * 0.5:
                    classical_y = shor_y - gap * 0.5
                ax.text(
                    x, classical_y, txt,
                    ha="center", va="top", fontsize=14, color="#d00000",
                    linespacing=1.10, clip_on=False, zorder=6, path_effects=outline
                )
            else:
                # Above short bars: sit comfortably above Shor label
                classical_y = shor_y + extra_classical_gap
                ax.text(
                    x, classical_y, txt,
                    ha="center", va="bottom", fontsize=14, color="#d00000",
                    linespacing=1.10, clip_on=False, zorder=6, path_effects=outline
                )

    legend_handles = [
        mlines.Line2D([], [], color="black", linestyle="None", markersize=8,
                      label="Shor (quantum) runtime"),
        mlines.Line2D([], [], color="#d00000", linestyle="None", markersize=8,
                      label="Classical GNFS runtime"),
    ]
    ax.legend(
    handles=legend_handles,
    loc="upper left", bbox_to_anchor=(0, 1),
    frameon=True, framealpha=0.85, fancybox=True,
    handlelength=0, handletextpad=0, borderaxespad=0.5, labelspacing=0.6,
    alignment="left",  # needs Matplotlib ≥ 3.7; remove if on older version
    )

    _save_figure(fig, "poster_shor_runtime_rsa_ge", png_dir, pdf_dir)

def _gnfs_scale_core_years(bits_target: int, ref_bits: int, ref_core_years: float) -> float:
    """
    Scale a reference GNFS core-years from ref_bits -> bits_target using the
    L_n[1/3, c] complexity with c = (64/9)^(1/3) ≈ 1.923.
    Absolute constants are unknown; we preserve the reference value exactly
    and scale other sizes relative to it.
    """
    c = (64.0 / 9.0) ** (1.0 / 3.0)
    # n ≈ 2^bits  => ln n = bits * ln 2
    def L(bits: int) -> float:
        ln_n = bits * math.log(2.0)
        return math.exp(c * (ln_n ** (1.0 / 3.0)) * (math.log(ln_n) ** (2.0 / 3.0)))
    L_ref = L(ref_bits)
    L_tgt = L(bits_target)
    return ref_core_years * (L_tgt / L_ref)




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
    # ax.set_title("Quantum Security vs Latency (Key Generation)")

    label_specs: List[Tuple[float, float, str, str]] = []
    kem_idx = sig_idx = 0
    latencies: List[float] = []

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
        if latency is not None:
            latencies.append(latency)

    # --- Log scale on Y (guard against non-positive values) ---
    eps = 1e-3
    if latencies:
        ymin = max(eps, min(l for l in latencies if l is not None) * 0.8)
    else:
        ymin = eps
    ax.set_yscale("log")
    ax.set_ylim(bottom=ymin)

    # Give a touch of margin so labels have space to move (works fine with log scale)
    ax.margins(x=0.05, y=0.12)
    _place_labels_smart(ax, label_specs, base_offset=34, max_iter=370, max_distance_px=110.0)

    ax.set_xlabel("Quantum security bits")
    ax.set_ylabel("Key generation mean latency (ms, log scale)")
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
        #ax.set_title(f"Quantum Security vs Total Latency — Cat {category}")

        label_specs: List[Tuple[float, float, str, str]] = []
        kem_idx = sig_idx = 0
        latencies: List[float] = []

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
            if total_latency is not None:
                latencies.append(total_latency)

        # --- Log scale on Y per category (guard against non-positive values) ---
        eps = 1e-3
        if latencies:
            ymin = max(eps, min(l for l in latencies if l is not None) * 0.8)
        else:
            ymin = eps
        ax.set_yscale("log")
        ax.set_ylim(bottom=ymin)

        ax.margins(x=0.05, y=0.12)
        _place_labels_smart(ax, label_specs, base_offset=32, max_iter=340, max_distance_px=110.0)
        ax.set_xlabel("Quantum security bits")
        ax.set_ylabel("Total mean latency (ms, log scale)")
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


def plot_category_top_metric(
    records: Sequence[Record],
    png_dir: pathlib.Path,
    pdf_dir: pathlib.Path,
    top_n: int,
    metric: str,
) -> None:
    top_n = max(int(top_n or 0), 0)
    if top_n <= 0:
        return
    metric = metric.lower()
    if metric not in {"latency", "memory"}:
        raise ValueError("metric must be 'latency' or 'memory'")

    pass_name = "timing" if metric == "latency" else "memory"
    attr_name = "mean_ms" if metric == "latency" else "mem_mean_kb"
    ylabel = "Mean latency (ms)" if metric == "latency" else "Mean peak memory (KB)"
    file_stub = "latency" if metric == "latency" else "memory"
    title_label = "Latency" if metric == "latency" else "Memory"

    palette_kem = ["#1f77b4", "#14796d", "#33539e", "#209fb5", "#14a44d"]
    palette_sig = ["#d62839", "#f77f00", "#b56576", "#6d597a", "#ef6351"]

    aggregates: Dict[Tuple[str, str, int], List[float]] = {}
    for rec in records:
        if rec.measurement_pass != pass_name:
            continue
        if rec.category_number not in (1, 3, 5):
            continue
        value = getattr(rec, attr_name, None)
        if value is None:
            continue
        key = (rec.kind.upper(), rec.algo, rec.category_number)
        aggregates.setdefault(key, []).append(float(value))

    for kind in ("KEM", "SIG"):
        palette = palette_kem if kind == "KEM" else palette_sig
        for category in (1, 3, 5):
            entries: List[Tuple[str, float]] = []
            for (agg_kind, algo, cat), values in aggregates.items():
                if agg_kind != kind or cat != category:
                    continue
                if not values:
                    continue
                avg = sum(values) / len(values)
                entries.append((algo, avg))
            if not entries:
                continue

            entries.sort(key=lambda item: item[1])
            top_entries = entries[:min(top_n, len(entries))]

            fig, ax = plt.subplots(figsize=(11, 7))
            ax.set_title(f"{title_label} — Cat {category} Top {len(top_entries)} {kind}s")

            labels = [f"{_friendly_label(algo)}" for algo, _ in top_entries]
            values = [value for _, value in top_entries]
            colors = [palette[idx % len(palette)] for idx in range(len(top_entries))]

            ax.bar(labels, values, color=colors)
            ax.set_ylabel(ylabel)
            ax.grid(True, axis="y", linestyle="--", alpha=0.3)
            ax.tick_params(axis="x", rotation=45)
            for tick in ax.get_xticklabels():
                tick.set_horizontalalignment("right")

            output_name = f"poster_{file_stub}_cat{category}_{kind.lower()}_top"
            _save_figure(fig, output_name, png_dir, pdf_dir)


def plot_category_operation_breakdown(
    records: Sequence[Record],
    png_dir: pathlib.Path,
    pdf_dir: pathlib.Path,
    top_n: int,
    pass_name: str = "timing",
) -> None:
    top_n = max(int(top_n or 0), 0)
    if top_n <= 0:
        return

    pass_key = pass_name.lower()
    if pass_key not in {"timing", "memory"}:
        raise ValueError("pass_name must be 'timing' or 'memory'")

    attr_name = "mean_ms" if pass_key == "timing" else "mem_mean_kb"
    ylabel = "Mean latency (ms)" if pass_key == "timing" else "Mean peak memory (KB)"
    file_stub = "latency_ops" if pass_key == "timing" else "memory_ops"

    op_map = {
        "KEM": list(KEM_OPERATIONS),
        "SIG": list(SIG_OPERATIONS),
    }
    op_labels = {
        "keygen": "Keygen",
        "encapsulate": "Encap",
        "decapsulate": "Decap",
        "sign": "Sign",
        "verify": "Verify",
    }
    op_colors = {
        "keygen": "#1f77b4",
        "encapsulate": "#2ca02c",
        "decapsulate": "#d62728",
        "sign": "#ff7f0e",
        "verify": "#9467bd",
    }

    aggregates: Dict[Tuple[str, str, int], Dict[str, float]] = {}
    for rec in records:
        if rec.measurement_pass != pass_key:
            continue
        if rec.category_number not in (1, 3, 5):
            continue
        value = getattr(rec, attr_name, None)
        if value is None:
            continue
        key = (rec.kind.upper(), rec.algo, rec.category_number)
        bucket = aggregates.setdefault(key, {})
        bucket[rec.operation] = float(value)

    for kind in ("KEM", "SIG"):
        required_ops = op_map[kind]
        for category in (1, 3, 5):
            entries: List[Tuple[str, float, Dict[str, float]]] = []
            for (agg_kind, algo, cat), ops in aggregates.items():
                if agg_kind != kind or cat != category:
                    continue
                if any(op not in ops for op in required_ops):
                    continue
                total = sum(ops[op] for op in required_ops)
                entries.append((algo, total, ops))
            if not entries:
                continue

            entries.sort(key=lambda item: item[1])
            top_entries = entries[:min(top_n, len(entries))]
            if not top_entries:
                continue

            num_ops = len(required_ops)
            width = 0.18 if num_ops >= 3 else 0.25
            indices = list(range(len(top_entries)))

            fig, ax = plt.subplots(figsize=(11, 7))
            ax.set_title(f"{ylabel.split(' (')[0]} by Operation — Cat {category} {kind}s")

            for idx_op, op in enumerate(required_ops):
                offsets = [i + (idx_op - (num_ops - 1) / 2) * width for i in indices]
                values = [ops[op] for _, _, ops in top_entries]
                ax.bar(
                    offsets,
                    values,
                    width=width * 0.92,
                    color=op_colors.get(op, "#888888"),
                    label=None,
                )

            if required_ops:
                legend_handles = [
                    Patch(facecolor=op_colors.get(op, "#888888"), label=op_labels.get(op, op.title()))
                    for op in required_ops
                ]
                ax.legend(handles=legend_handles, loc="upper left")

            ax.set_ylabel(ylabel)
            ax.set_xticks(indices)
            ax.set_xticklabels([_friendly_label(algo) for algo, _, _ in top_entries], rotation=45, ha="right")
            ax.grid(True, axis="y", linestyle="--", alpha=0.3)

            output_name = f"poster_{file_stub}_cat{category}_{kind.lower()}_ops"
            _save_figure(fig, output_name, png_dir, pdf_dir)


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
    parser.add_argument(
        "--top-n",
        type=int,
        default=4,
        help="Number of top algorithms to display in category-specific charts (default: 4).",
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
    plot_category_top_metric(records, png_dir, pdf_dir, args.top_n, "latency")
    plot_category_top_metric(records, png_dir, pdf_dir, args.top_n, "memory")
    plot_category_operation_breakdown(records, png_dir, pdf_dir, args.top_n, pass_name="timing")
    plot_category_operation_breakdown(records, png_dir, pdf_dir, args.top_n, pass_name="memory")
    plot_size_by_scheme(records, png_dir, pdf_dir)

    print(f"Poster graphs written to {poster_root}")


if __name__ == "__main__":
    main()
