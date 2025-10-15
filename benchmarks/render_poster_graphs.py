#!/usr/bin/env python3
"""Render poster-friendly graphs from benchmark CSV data."""

from __future__ import annotations

import argparse
import csv
import json
import math
import pathlib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import matplotlib.pyplot as plt
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "matplotlib is required for poster graph rendering. Install it via 'pip install matplotlib'."
    ) from exc


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
    top_kems = _select_top_algos(records, "KEM", 5, pass_name)
    top_sigs = _select_top_algos(records, "SIG", 5, pass_name)
    if not top_kems and not top_sigs:
        return

    kem_palette = ["#1f77b4", "#14796d", "#33539e", "#209fb5", "#14a44d"]
    sig_palette = ["#d62839", "#f77f00", "#b56576", "#6d597a", "#ef6351"]

    fig, ax = plt.subplots(figsize=(13, 8))
    ax.set_title("Latency (Timing) — Top PQC KEMs and Signatures")

    bars: List[Tuple[str, float, str]] = []
    for rec in records:
        if rec.measurement_pass != pass_name or rec.mean_ms is None:
            continue
        if rec.kind.upper() == "KEM" and rec.algo in top_kems:
            color = kem_palette[top_kems.index(rec.algo) % len(kem_palette)]
            bars.append((f"{rec.operation[:4].upper()} (Cat-{rec.category_number})", rec.mean_ms, color))
        elif rec.kind.upper() == "SIG" and rec.algo in top_sigs:
            color = sig_palette[top_sigs.index(rec.algo) % len(sig_palette)]
            bars.append((f"{rec.operation[:4].upper()} (Cat-{rec.category_number})", rec.mean_ms, color))

    if not bars:
        return

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


def plot_shor_runtime(records: Sequence[Record], png_dir: pathlib.Path, pdf_dir: pathlib.Path) -> None:
    entries: List[Tuple[str, float]] = []
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
                calibrated = scenario.get("calibrated_against") or ""
                if "ge" not in calibrated.lower():
                    continue
                runtime = scenario.get("runtime_seconds")
                if runtime is None:
                    continue
                label = scenario.get("label") or f"{calibrated}"
                if modulus_bits:
                    label = f"{label} ({modulus_bits}-bit)"
                entries.append((label, float(runtime)))

    if not entries:
        return

    labels = [label for label, _ in entries]
    runtime_days = [value / 86400.0 for _, value in entries]

    fig, ax = plt.subplots(figsize=(11, 7))
    ax.set_title("Shor Runtime (Ge Baseline) — RSA OAEP")
    ax.bar(labels, runtime_days, color="#6c5ce7")
    ax.set_ylabel("Runtime to factor (days)")
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)
    ax.tick_params(axis="x", rotation=45)
    for tick in ax.get_xticklabels():
        tick.set_horizontalalignment("right")

    for xpos, value in enumerate(runtime_days):
        hours = value * 24.0
        ax.text(
            xpos,
            value,
            f"{hours:.1f} h",
            ha="center",
            va="bottom",
            fontsize=14,
        )

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
        if rec.measurement_pass != "timing":
            continue
        if rec.operation != "keygen":
            continue
        if rec.mean_ms is None or rec.security_quantum_bits is None:
            continue
        points.append(
            (
                rec.security_quantum_bits,
                rec.mean_ms,
                rec.kind.upper(),
                _friendly_label(rec.algo),
                rec.category_number,
            )
        )
    if not points:
        return

    kem_palette = ["#264653", "#2a9d8f", "#1d3557", "#457b9d", "#0a9396"]
    sig_palette = ["#e63946", "#f77f00", "#a01a58", "#b56576", "#ef6351"]

    fig, ax = plt.subplots(figsize=(12, 8))
    ax.set_title("Quantum Security vs Latency (Key Generation)")

    label_specs: List[Tuple[float, float, str, str]] = []
    kem_idx = sig_idx = 0
    for security_bits, latency, kind, label, category in points:
        if kind == "KEM":
            color = kem_palette[kem_idx % len(kem_palette)]
            kem_idx += 1
            marker = "o"
        else:
            color = sig_palette[sig_idx % len(sig_palette)]
            sig_idx += 1
            marker = "^"
        ax.scatter(
            security_bits,
            latency,
            color=color,
            marker=marker,
            s=110,
            edgecolors="#222222",
            linewidths=0.6,
        )
        label_specs.append((security_bits, latency, f"{label} ({category})", color))

    _place_labels(ax, label_specs)

    ax.set_xlabel("Quantum security bits")
    ax.set_ylabel("Key generation mean latency (ms)")
    ax.grid(True, linestyle="--", alpha=0.3)

    _save_figure(fig, "poster_security_vs_latency", png_dir, pdf_dir)


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
    ax.set_title("Security Bits — Classical vs Quantum (All Algorithms)")
    positions = range(len(entries))
    ax.bar(positions, classical, width=0.4, label="Classical bits", color="#1f77b4")
    ax.bar([p + 0.4 for p in positions], quantum, width=0.4, label="Quantum bits", color="#d62728")
    ax.set_xticks([p + 0.2 for p in positions])
    ax.set_xticklabels(labels, rotation=45)
    for tick in ax.get_xticklabels():
        tick.set_horizontalalignment("right")
    ax.set_ylabel("Bits of security")
    ax.legend()
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)

    _save_figure(fig, "poster_security_bits", png_dir, pdf_dir)


def plot_memory_combined(records: Sequence[Record], png_dir: pathlib.Path, pdf_dir: pathlib.Path) -> None:
    pass_name = "memory"
    top_kems = _select_top_algos(records, "KEM", 5, pass_name, operation="decapsulate")
    top_sigs = _select_top_algos(records, "SIG", 5, pass_name, operation="sign")
    if not top_kems and not top_sigs:
        return

    kem_palette = ["#14213d", "#1b4965", "#264653", "#186276", "#0d3b66"]
    sig_palette = ["#ff7f51", "#ff9f1c", "#f4a261", "#e76f51", "#bc6c25"]

    fig, ax = plt.subplots(figsize=(13, 8))
    ax.set_title("Peak Memory — Top PQC KEMs and Signatures")

    bars: List[Tuple[str, float, str]] = []
    for rec in records:
        if rec.measurement_pass != pass_name or rec.mem_mean_kb is None:
            continue
        if rec.kind.upper() == "KEM" and rec.algo in top_kems:
            color = kem_palette[top_kems.index(rec.algo) % len(kem_palette)]
            bars.append((f"{_friendly_label(rec.algo)}\n{rec.operation.title()}", rec.mem_mean_kb, color))
        elif rec.kind.upper() == "SIG" and rec.algo in top_sigs:
            color = sig_palette[top_sigs.index(rec.algo) % len(sig_palette)]
            bars.append((f"{_friendly_label(rec.algo)}\n{rec.operation.title()}", rec.mem_mean_kb, color))

    if not bars:
        return

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


def main() -> None:
    args = parse_args()
    records = load_records(args.csv)
    poster_root = args.output_dir / "PosterGraphs"
    png_dir = poster_root / "png"
    pdf_dir = poster_root / "pdf"

    plot_latency_combined(records, png_dir, pdf_dir)
    plot_shor_runtime(records, png_dir, pdf_dir)
    plot_security_vs_latency(records, png_dir, pdf_dir)
    plot_security_bits(records, png_dir, pdf_dir)
    plot_memory_combined(records, png_dir, pdf_dir)
    plot_size_by_scheme(records, png_dir, pdf_dir)

    print(f"Poster graphs written to {poster_root}")


if __name__ == "__main__":
    main()
