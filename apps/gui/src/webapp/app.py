
from __future__ import annotations
from flask import Flask, render_template, request, redirect, url_for
from pqcbench import registry
from typing import Dict, Any

# Reuse the CLI runner logic to keep one source of truth for measurements
try:
    from pqcbench_cli.runners.common import _load_adapters, run_kem, run_sig, export_json
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


@app.route("/")
def index():
    _ensure_adapters_loaded()
    algos = list(registry.list().keys())
    kinds = _algo_kinds()
    return render_template(
        "base.html",
        algos=algos,
        kinds=kinds,
        last_export=None,
        result_json=None,
        error=None,
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

        # Shape result like CLI JSON output for consistency
        result = {
            "algo": summary.algo,
            "kind": summary.kind,
            "ops": {k: vars(v) for k, v in summary.ops.items()},
            "meta": summary.meta,
        }
    except Exception as e:
        error = str(e)

    return render_template(
        "base.html",
        algos=algos,
        kinds=kinds,
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
