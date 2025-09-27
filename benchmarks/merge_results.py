from __future__ import annotations
"""Merge JSON result files under results/ into a single CSV.

Outputs results/security_metrics.csv with key performance and security columns.
"""
import json
import csv
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
OUT = RESULTS / "security_metrics.csv"


def flatten(d: dict, prefix: str = "") -> dict:
    flat = {}
    for k, v in d.items():
        key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
        if isinstance(v, dict):
            flat.update(flatten(v, key))
        else:
            flat[key] = v
    return flat


def collect_rows():
    rows = []
    for path in RESULTS.glob("*.json"):
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        base = {
            "file": path.name,
            "algo": data.get("algo"),
            "kind": data.get("kind"),
        }
        meta = data.get("meta", {})
        sec = data.get("security", {})

        # derive margins when possible
        floor = None
        if isinstance(sec.get("extras"), dict):
            floor = sec["extras"].get("category_floor")
            params = sec["extras"].get("params") or {}
        else:
            params = {}

        classical_bits = sec.get("classical_bits")
        quantum_bits = sec.get("quantum_bits")
        if classical_bits is not None and floor is not None:
            classical_margin = float(classical_bits) - float(floor)
        else:
            classical_margin = None
        if quantum_bits is not None and floor is not None:
            quantum_margin = float(quantum_bits) - float(floor)
        else:
            quantum_margin = None

        row = {
            **base,
            **{f"meta.{k}": v for k, v in meta.items()},
            **{
                "security.shor_breakable": sec.get("shor_breakable"),
                "security.classical_bits": classical_bits,
                "security.quantum_bits": quantum_bits,
                "security.notes": sec.get("notes"),
                "security.params.family": params.get("family"),
                "security.params.mechanism": params.get("mechanism"),
                "security.params.category_floor": params.get("category_floor"),
                "security.floor": floor,
                "security.classical_margin": classical_margin,
                "security.quantum_margin": quantum_margin,
            },
        }
        # Attach RSA resources and surface if present
        extras = sec.get("extras", {}) if isinstance(sec.get("extras"), dict) else {}
        logical = extras.get("logical", {}) if isinstance(extras.get("logical"), dict) else {}
        for key in ("logical_qubits", "toffoli", "meas_depth"):
            if key in logical:
                row[f"security.{key}"] = logical[key]
        if "rsa_model" in extras:
            row["security.rsa_model"] = extras["rsa_model"]
        if "log2_n_bits" in extras:
            row["security.log2_n_bits"] = extras["log2_n_bits"]
        surface = extras.get("surface", {}) if isinstance(extras.get("surface"), dict) else {}
        for key in ("code_distance", "phys_qubits_total", "runtime_seconds"):
            if key in surface:
                row[f"security.surface.{key}"] = surface[key]

        rows.append(row)
    return rows


def write_csv(rows):
    if not rows:
        print("No result JSON files found in results/.")
        return
    # Collect all fieldnames across rows for a stable header
    fieldnames = sorted({k for r in rows for k in r.keys()})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"Wrote {OUT}")


def main():
    rows = collect_rows()
    write_csv(rows)


if __name__ == "__main__":
    main()
