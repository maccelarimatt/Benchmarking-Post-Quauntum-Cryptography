
from __future__ import annotations
"""Flask web app wrapping CLI benchmarking utilities.

Uses the same adapter registry as the CLI to ensure consistent behavior.
Provides simple single-run traces and JSON summaries in the browser.
"""
import sys
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from jinja2 import TemplateNotFound
from dataclasses import asdict
import base64
from typing import Dict, Any, Mapping


_HERE = Path(__file__).resolve()
try:
    _PROJECT_ROOT = next(p for p in _HERE.parents if (p / "libs").exists())
except StopIteration:
    _PROJECT_ROOT = _HERE.parents[0]

for rel in (
    Path("libs/core/src"),
    Path("libs/adapters/native/src"),
    Path("libs/adapters/liboqs/src"),
    Path("libs/adapters/rsa/src"),
    Path("apps/cli/src"),
):
    candidate = _PROJECT_ROOT / rel
    if candidate.exists():
        candidate_str = str(candidate)
        if candidate_str not in sys.path:
            sys.path.append(candidate_str)

from pqcbench import registry

# Reuse the CLI runner logic to keep one source of truth for measurements
try:
    from pqcbench_cli.runners.common import (
        _load_adapters,
        run_kem,
        run_sig,
        export_json,
        export_trace_kem,
        export_trace_sig,
        _build_export_payload,
    )
except Exception:
    # If CLI package isn't installed, try best-effort import of adapters directly
    _load_adapters = None
    run_kem = run_sig = export_json = None  # type: ignore
    export_trace_kem = export_trace_sig = None  # type: ignore
    _build_export_payload = None  # type: ignore

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
        try:
            __import__("pqcbench_native")
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


def _display_names(names: list[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for n in names:
        label = ALGO_INFO.get(n, {}).get("label")
        if not label:
            if n.lower() == "sphincs+":
                label = "SPHINCS+"
            else:
                label = n.replace("-", "-").title()
        out[n] = label
    return out


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
    "mayo": {
        "kind": "SIG",
        "label": "MAYO",
        "about": "MAYO: Multivariate post-quantum signature (selects MAYO-1/2/3/5 if available).",
    },
}

SECURITY_PROFILE_CHOICES = ["floor", "classical", "quantum"]
QUANTUM_ARCH_CHOICES = [
    ("", "None"),
    ("superconducting-2025", "Superconducting 2025"),
    ("iontrap-2025", "Ion Trap 2025"),
]
RSA_MODEL_CHOICES = ["ge2019", "ge2025", "fast2025"]
DEFAULT_SECURITY_FORM = {
    "sec_adv": False,
    "sec_rsa_phys": False,
    "sec_phys_error_rate": 1e-3,
    "sec_cycle_time_ns": 1000.0,
    "sec_fail_prob": 1e-2,
    "sec_profile": "floor",
    "quantum_arch": "",
    "rsa_model": "ge2019",
}

def _security_defaults() -> dict[str, Any]:
    return dict(DEFAULT_SECURITY_FORM)

def _coerce_float(value: object, default: float) -> float:
    if value is None:
        return float(default)
    try:
        if isinstance(value, str):
            value = value.strip()
        if value == "":
            return float(default)
        return float(value)  # type: ignore[arg-type]
    except Exception:
        return float(default)

def _normalize_choice(value: object, choices: list[str], default: str) -> str:
    if value is None:
        return default
    text = str(value).strip().lower()
    for choice in choices:
        if text == choice.lower():
            return choice
    return default

def _parse_security_form(form: Mapping[str, object]) -> tuple[dict[str, Any], dict[str, Any]]:
    values = _security_defaults()
    raw_adv = form.get("sec_adv")
    values["sec_adv"] = str(raw_adv).lower() in ("on", "true", "1", "yes") if raw_adv is not None else False
    raw_rsa_surface = form.get("sec_rsa_phys")
    values["sec_rsa_phys"] = str(raw_rsa_surface).lower() in ("on", "true", "1", "yes") if raw_rsa_surface is not None else False
    values["sec_phys_error_rate"] = _coerce_float(form.get("sec_phys_error_rate"), DEFAULT_SECURITY_FORM["sec_phys_error_rate"])
    values["sec_cycle_time_ns"] = _coerce_float(form.get("sec_cycle_time_ns"), DEFAULT_SECURITY_FORM["sec_cycle_time_ns"])
    values["sec_fail_prob"] = _coerce_float(form.get("sec_fail_prob"), DEFAULT_SECURITY_FORM["sec_fail_prob"])
    values["sec_profile"] = _normalize_choice(form.get("sec_profile"), SECURITY_PROFILE_CHOICES, DEFAULT_SECURITY_FORM["sec_profile"])
    raw_arch = form.get("quantum_arch")
    if raw_arch is None:
        values["quantum_arch"] = DEFAULT_SECURITY_FORM["quantum_arch"]
    else:
        values["quantum_arch"] = str(raw_arch).strip()
    values["rsa_model"] = _normalize_choice(form.get("rsa_model"), RSA_MODEL_CHOICES, DEFAULT_SECURITY_FORM["rsa_model"])
    security_opts = {
        "lattice_use_estimator": bool(values["sec_adv"]),
        "lattice_profile": values["sec_profile"],
        "rsa_surface": bool(values["sec_rsa_phys"]),
        "phys_error_rate": float(values["sec_phys_error_rate"]),
        "cycle_time_s": float(values["sec_cycle_time_ns"]) * 1e-9,
        "target_total_fail_prob": float(values["sec_fail_prob"]),
        "quantum_arch": values["quantum_arch"] or None,
    }
    if values["rsa_model"]:
        security_opts["rsa_model"] = values["rsa_model"]
    return values, security_opts



def _handle_run_submission(form: Mapping[str, Any]):
    _ensure_adapters_loaded()
    algos = list(registry.list().keys())
    kinds = _algo_kinds()

    name = (form.get("algo", "") or "").strip()
    try:
        runs = int(form.get("runs", "10"))
    except Exception:
        runs = 10
    try:
        message_size = int(form.get("message_size", "1024"))
    except Exception:
        message_size = 1024
    security_form, security_opts = _parse_security_form(form)
    export_path = (form.get("export_path", "") or "")
    do_export = str(form.get("do_export") or "").lower() in ("on", "true", "1", "yes")
    do_export_trace = str(form.get("do_export_trace") or "").lower() in ("on", "true", "1", "yes")
    export_trace_path = (form.get("export_trace_path", "") or "")

    result: Dict[str, Any] | None = None
    trace_sections: list[dict[str, Any]] | None = None
    error: str | None = None
    last_export: str | None = None
    backend_label: str | None = None

    try:
        kind = kinds.get(name) or ""
        raw_cold = form.get("cold")
        cold = str(raw_cold).lower() in ("on", "true", "1", "yes")
        if kind == "KEM":
            summary = run_kem(name, runs, cold=cold)  # type: ignore[misc]
        elif kind == "SIG":
            summary = run_sig(name, runs, message_size, cold=cold)  # type: ignore[misc]
        else:
            raise RuntimeError(f"Unknown or unsupported algorithm: {name}")

        if do_export:
            out_path = export_path.strip() or f"results/{name.replace('+','plus')}.json"
            export_json(summary, out_path, security_opts=security_opts)  # type: ignore[misc]
            last_export = out_path

        if do_export_trace:
            raw_path = export_trace_path.strip() or f"results/{name.replace('+','plus')}_trace.json"
            if kind == "KEM":
                export_trace_kem(name, raw_path)  # type: ignore[misc]
            else:
                export_trace_sig(name, message_size, raw_path)  # type: ignore[misc]

        # Build base result payload
        if _build_export_payload is not None:
            result = _build_export_payload(summary, security_opts=security_opts)
        else:
            result = {
                "algo": summary.algo,
                "kind": summary.kind,
                "ops": {k: vars(v) for k, v in summary.ops.items()},
                "meta": summary.meta,
            }
            result["security"] = {"error": "security estimator unavailable"}

        # Enrich with backend/mechanism details for display
        try:
            cls = registry.get(name)
            algo_tmp = cls()
            module = getattr(cls, "__module__", "")
            if module.startswith("pqcbench_native"):
                backend = "native"
            elif module.startswith("pqcbench_liboqs"):
                backend = "liboqs"
            elif module.startswith("pqcbench_rsa"):
                backend = "rsa"
            else:
                backend = module or "python"
            mech = (
                getattr(algo_tmp, "algorithm", None)
                or getattr(algo_tmp, "alg", None)
                or getattr(algo_tmp, "mech", None)
                or getattr(algo_tmp, "_mech", None)
            )
            # Update meta so it also shows up in the Metadata table
            if isinstance(result.get("meta"), dict):
                result["meta"].setdefault("backend", backend)
                if mech and not result["meta"].get("mechanism"):
                    result["meta"]["mechanism"] = mech
            # Compose a compact label for the header
            if mech:
                backend_label = f"Backend: {backend} (mechanism: {mech})"
            else:
                backend_label = f"Backend: {backend}"
        except Exception:
            backend_label = None

        try:
            cls = registry.get(name)
            algo = cls()
            if kind == "KEM":
                pk, sk = algo.keygen()
                ct, ss = algo.encapsulate(pk)
                ss_dec = algo.decapsulate(sk, ct)
                trace_sections = [
                    {
                        "title": "Keygen",
                        "items": [
                            {"label": "public_key", "len": len(pk), "b64": base64.b64encode(pk).decode("ascii")},
                            {"label": "secret_key", "len": len(sk), "b64": base64.b64encode(sk).decode("ascii")},
                        ],
                    },
                    {
                        "title": "Encapsulate",
                        "items": [
                            {"label": "ciphertext", "len": len(ct), "b64": base64.b64encode(ct).decode("ascii")},
                            {"label": "shared_secret", "len": len(ss), "b64": base64.b64encode(ss).decode("ascii")},
                        ],
                    },
                    {
                        "title": "Decapsulate",
                        "items": [
                            {"label": "shared_secret", "len": len(ss_dec), "b64": base64.b64encode(ss_dec).decode("ascii")},
                            {"label": "matches", "len": None, "text": "true" if ss == ss_dec else "false"},
                        ],
                    },
                ]
            else:
                pk, sk = algo.keygen()
                msg = b"x" * int(message_size)
                sig = algo.sign(sk, msg)
                ok = algo.verify(pk, msg, sig)
                trace_sections = [
                    {
                        "title": "Keygen",
                        "items": [
                            {"label": "public_key", "len": len(pk), "b64": base64.b64encode(pk).decode("ascii")},
                            {"label": "secret_key", "len": len(sk), "b64": base64.b64encode(sk).decode("ascii")},
                        ],
                    },
                    {
                        "title": "Sign",
                        "items": [
                            {"label": "message", "len": len(msg), "b64": base64.b64encode(msg).decode("ascii")},
                            {"label": "signature", "len": len(sig), "b64": base64.b64encode(sig).decode("ascii")},
                        ],
                    },
                    {
                        "title": "Verify",
                        "items": [
                            {"label": "ok", "len": None, "text": "true" if ok else "false"},
                        ],
                    },
                ]
        except Exception:
            trace_sections = None
    except Exception as exc:
        error = str(exc)

    display_names = {algo_name: (ALGO_INFO.get(algo_name, {}).get("label") or algo_name.replace("-", "-").replace("sphincs+", "SPHINCS+").title()) for algo_name in algos}
    return render_template(
        "base.html",
        algos=algos,
        kinds=kinds,
        display_names=display_names,
        last_export=last_export,
        result_json=result,
        backend_label=backend_label,
        error=error,
        default_runs=runs,
        default_message_size=message_size,
        selected_algo=name,
        trace_sections=trace_sections,
        security_form=security_form,
        security_profile_choices=SECURITY_PROFILE_CHOICES,
        quantum_arch_choices=QUANTUM_ARCH_CHOICES,
        rsa_model_choices=RSA_MODEL_CHOICES,
        selected_operation="single",
    )


def _handle_compare_submission(form: Mapping[str, Any]):
    _ensure_adapters_loaded()
    kinds = _algo_kinds()
    all_names = list(kinds.keys())

    kind = str(form.get("kind", "KEM") or "KEM").upper()
    try:
        runs = int(form.get("runs", "10"))
    except Exception:
        runs = 10
    try:
        message_size = int(form.get("message_size", "1024"))
    except Exception:
        message_size = 1024

    def _getlist(key: str) -> list[str]:
        getter = getattr(form, "getlist", None)
        if callable(getter):
            return list(getter(key))
        value = form.get(key)
        if isinstance(value, (list, tuple)):
            return [v for v in value if v]
        if value:
            return [value]
        return []

    # New flow: selected algorithms come from checkbox list named 'algos'
    selected = [n for n in _getlist("algos") if n and kinds.get(n) == kind]
    # Backward compatibility fallback to old fields if none selected
    if not selected:
        mode = str(form.get("mode", "pair") or "pair").lower()
        if mode == "all":
            selected = [n for n in all_names if kinds.get(n) == kind]
        else:
            def pick_for_kind(key: str) -> str:
                vals = _getlist(key)
                seq = vals if kind == "KEM" else list(reversed(vals))
                for v in seq:
                    if v and v.strip():
                        return v
                return ""

            a = pick_for_kind("algo_a")
            b = pick_for_kind("algo_b")
            selected = [x for x in [a, b] if x and kinds.get(x) == kind and x.strip()]
            seen = set()
            selected = [x for x in selected if not (x in seen or seen.add(x))]

    if not selected:
        return redirect(url_for("index"))

    raw_cold = form.get("cold")
    cold = str(raw_cold).lower() in ("on", "true", "1", "yes")
    results = []
    errors: Dict[str, str] = {}
    for algo_name in selected:
        try:
            if kind == "KEM":
                summary = run_kem(algo_name, runs, cold=cold)  # type: ignore[misc]
            else:
                summary = run_sig(algo_name, runs, message_size, cold=cold)  # type: ignore[misc]
            # Export per-algorithm JSON + one-run trace for quick access on the compare page
            try:
                json_path = f"results/{algo_name.replace('+','plus')}_{kind.lower()}_compare.json"
                export_json(summary, json_path)  # type: ignore[misc]
            except Exception:
                json_path = None  # type: ignore[assignment]
            try:
                trace_path = f"results/{algo_name.replace('+','plus')}_{kind.lower()}_compare_trace.json"
                if kind == "KEM":
                    export_trace_kem(algo_name, trace_path)  # type: ignore[misc]
                else:
                    export_trace_sig(algo_name, message_size, trace_path)  # type: ignore[misc]
            except Exception:
                trace_path = None  # type: ignore[assignment]
            # Attach export hints to meta for template convenience
            if isinstance(summary.meta, dict):
                summary.meta.setdefault("exports", {})
                if json_path:
                    summary.meta["exports"]["json"] = json_path
                if trace_path:
                    summary.meta["exports"]["trace"] = trace_path
            results.append(summary)
        except Exception as exc:
            errors[algo_name] = str(exc)

    display_names = _display_names(selected)
    compare = {
        "kind": kind,
        "runs": runs,
        "message_size": message_size,
        "mode": ("cold" if cold else "warm"),
        "algos": [
            {
                "name": summary.algo,
                "label": display_names.get(summary.algo, summary.algo),
                "ops": {k: asdict(v) for k, v in summary.ops.items()},
                "meta": summary.meta,
                "exports": (summary.meta.get("exports") if isinstance(summary.meta, dict) else {}),
            }
            for summary in results
        ],
    }
    return render_template("compare_results.html", compare=compare, errors=errors)





@app.route("/")
def index():
    _ensure_adapters_loaded()
    algos = list(registry.list().keys())
    kinds = _algo_kinds()
    display_names = _display_names(algos)
    # Home/setup screen
    return render_template(
        "home.html",
        algos=algos,
        kinds=kinds,
        algo_info=ALGO_INFO,
        display_names=display_names,
        default_runs=10,
        default_message_size=1024,
        security_form=_security_defaults(),
        security_profile_choices=SECURITY_PROFILE_CHOICES,
        quantum_arch_choices=QUANTUM_ARCH_CHOICES,
        rsa_model_choices=RSA_MODEL_CHOICES,
        selected_operation="single",
        selected_algo=None,
        last_export=None,
        compare_kind="KEM",
        compare_mode="pair",
    )


@app.route("/run", methods=["POST"])
def run():
    return _handle_run_submission(request.form)

@app.route("/execute", methods=["POST"])
def execute():
    mode = str(request.form.get("operation", "single") or "single").lower()
    if mode == "compare":
        return _handle_compare_submission(request.form)
    return _handle_run_submission(request.form)




# Inline compare UI lives on the home page; no standalone compare form route.


@app.route("/compare/run", methods=["POST"])
def compare_run():
    return _handle_compare_submission(request.form)

@app.route("/algo/<name>")
def algo_detail(name: str):
    _ensure_adapters_loaded()
    algos = list(registry.list().keys())
    kinds = _algo_kinds()
    label = (ALGO_INFO.get(name, {}).get("label") or ("SPHINCS+" if name.lower()=="sphincs+" else name.replace("-","-").title()))
    kind = kinds.get(name, ALGO_INFO.get(name, {}).get("kind", ""))
    about = ALGO_INFO.get(name, {}).get("about", "")
    # Prefer a template named after the algorithm if it exists
    tmpl = f"{name.lower()}.html"
    try:
        return render_template(tmpl, name=name, label=label, kind=kind, about=about)
    except TemplateNotFound:
        # Fallback to a generic detail page if available
        try:
            return render_template("algo_detail.html", name=name, label=label, kind=kind, about=about)
        except TemplateNotFound:
            # Final fallback: return home to avoid a 500 if generic template is missing
            display_names = _display_names(algos)
            return render_template(
                "home.html",
                algos=algos,
                kinds=kinds,
                algo_info=ALGO_INFO,
                display_names=display_names,
                default_runs=10,
                default_message_size=1024,
                security_form=_security_defaults(),
                security_profile_choices=SECURITY_PROFILE_CHOICES,
                quantum_arch_choices=QUANTUM_ARCH_CHOICES,
                rsa_model_choices=RSA_MODEL_CHOICES,
                selected_operation="single",
                selected_algo=None,
                last_export=None,
                compare_kind="KEM",
                compare_mode="pair",
            )


@app.route("/results/<path:filename>")
def serve_results_file(filename: str):
    directory = _PROJECT_ROOT / "results"
    return send_from_directory(directory, filename, as_attachment=False)


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(debug=True)

