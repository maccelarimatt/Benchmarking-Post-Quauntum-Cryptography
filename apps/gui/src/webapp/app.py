
from __future__ import annotations
from flask import Flask, render_template, request, redirect, url_for
from pqcbench import registry
from typing import Dict, Any

# Reuse the CLI runner logic to keep one source of truth for measurements
try:
    from pqcbench_cli.runners.common import (
        _load_adapters,
        run_kem,
        run_sig,
        export_json,
        export_trace_kem,
        export_trace_sig,
    )
except Exception:
    # If CLI package isn't installed, try best-effort import of adapters directly
    _load_adapters = None
    run_kem = run_sig = export_json = None  # type: ignore

app = Flask(__name__, template_folder="../templates", static_folder="../static")


def _ensure_adapters_loaded() -> None:
    # Prefer the CLI helper which imports adapter packages and registers them
    if _load_adapters is not None:
        _load_adapters()
    else:
        # Fallback: import adapter packages directly so registry is populated
        try:
            __import__("pqcbench_rsa")
        except Exception:
            pass
        try:
            __import__("pqcbench_liboqs")
        except Exception:
            pass


def _algo_kinds() -> Dict[str, str]:
    kinds: Dict[str, str] = {}
    for name in registry.list().keys():
        cls = registry.get(name)
        if hasattr(cls, "encapsulate"):
            kinds[name] = "KEM"
        elif hasattr(cls, "sign"):
            kinds[name] = "SIG"
        else:
            kinds[name] = "OTHER"
    return kinds


ALGO_INFO = {
    "kyber": {
        "kind": "KEM",
        "label": "Kyber",
        "about": "ML-KEM (Kyber): NIST-selected post-quantum key encapsulation mechanism for secure key exchange.",
    },
    "hqc": {
        "kind": "KEM",
        "label": "HQC",
        "about": "HQC: Code-based KEM offering quantum-resistant key establishment.",
    },
    "rsa-oaep": {
        "kind": "KEM",
        "label": "RSA-OAEP",
        "about": "RSA-OAEP: Classical RSA encryption in a KEM-style wrapper for comparison.",
    },
    "dilithium": {
        "kind": "SIG",
        "label": "Dilithium",
        "about": "ML-DSA (Dilithium): NIST-selected post-quantum digital signature scheme.",
    },
    "falcon": {
        "kind": "SIG",
        "label": "Falcon",
        "about": "Falcon: Lattice-based post-quantum signature focusing on compact signatures.",
    },
    "sphincs+": {
        "kind": "SIG",
        "label": "SPHINCS+",
        "about": "SPHINCS+: Stateless hash-based signature scheme; conservative and flexible.",
    },
    "xmssmt": {
        "kind": "SIG",
        "label": "XMSSMT",
        "about": "XMSS/XMSSMT: Stateful hash-based signatures (one-time/limited-use keys).",
    },
    "rsa-pss": {
        "kind": "SIG",
        "label": "RSA-PSS",
        "about": "RSA-PSS: Classical RSA signatures baseline for benchmarking.",
    },
}


@app.route("/")
def index():
    _ensure_adapters_loaded()
    algos = list(registry.list().keys())
    kinds = _algo_kinds()
    display_names = {name: (ALGO_INFO.get(name, {}).get("label") or name.replace("-", "-").replace("sphincs+", "SPHINCS+").title()) for name in algos}
    # Home/setup screen
    return render_template(
        "home.html",
        algos=algos,
        kinds=kinds,
        algo_info=ALGO_INFO,
        display_names=display_names,
        default_runs=10,
        default_message_size=1024,
    )


@app.route("/run", methods=["POST"])
def run():
    _ensure_adapters_loaded()
    algos = list(registry.list().keys())
    kinds = _algo_kinds()

    name = request.form.get("algo", "")
    try:
        runs = int(request.form.get("runs", "10"))
    except Exception:
        runs = 10
    try:
        message_size = int(request.form.get("message_size", "1024"))
    except Exception:
        message_size = 1024
    export_path = request.form.get("export_path", "")
    do_export = request.form.get("do_export") == "on"
    do_export_trace = request.form.get("do_export_trace") == "on"
    export_trace_path = request.form.get("export_trace_path", "")

    result: Dict[str, Any] | None = None
    error: str | None = None
    last_export: str | None = None

    try:
        kind = kinds.get(name) or ""
        if kind == "KEM":
            summary = run_kem(name, runs)  # type: ignore[misc]
        elif kind == "SIG":
            summary = run_sig(name, runs, message_size)  # type: ignore[misc]
        else:
            raise RuntimeError(f"Unknown or unsupported algorithm: {name}")

        if do_export:
            # Default to results/<algo>.json if no path provided
            out_path = export_path.strip() or f"results/{name.replace('+','plus')}.json"
            export_json(summary, out_path)  # type: ignore[misc]
            last_export = out_path

        if do_export_trace:
            raw_path = export_trace_path.strip() or f"results/{name.replace('+','plus')}_trace.json"
            if kind == "KEM":
                export_trace_kem(name, raw_path)  # type: ignore[misc]
            else:
                export_trace_sig(name, message_size, raw_path)  # type: ignore[misc]

        # Shape result like CLI JSON output for consistency
        result = {
            "algo": summary.algo,
            "kind": summary.kind,
            "ops": {k: vars(v) for k, v in summary.ops.items()},
            "meta": summary.meta,
        }
    except Exception as e:
        error = str(e)

    display_names = {name: (ALGO_INFO.get(name, {}).get("label") or name.replace("-", "-").replace("sphincs+", "SPHINCS+").title()) for name in algos}
    return render_template(
        "base.html",
        algos=algos,
        kinds=kinds,
        display_names=display_names,
        last_export=last_export,
        result_json=result,
        error=error,
        default_runs=runs,
        default_message_size=message_size,
        selected_algo=name,
    )


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(debug=True)
