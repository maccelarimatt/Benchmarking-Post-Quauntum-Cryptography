
from __future__ import annotations
"""Flask web app wrapping CLI benchmarking utilities.

Uses the same adapter registry as the CLI to ensure consistent behavior.
Provides simple single-run traces and JSON summaries in the browser.
"""
import sys
import logging
import importlib.util
from types import ModuleType
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify, Response
from jinja2 import TemplateNotFound
from dataclasses import asdict
import base64
from typing import Dict, Any, Mapping
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import struct
import math
import threading
import time
import uuid


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

# Ensure this webapp directory itself is importable so sibling modules (e.g., llm.py) resolve
_WEBAPP_DIR = _HERE.parent
_WEBAPP_DIR_STR = str(_WEBAPP_DIR)
if _WEBAPP_DIR_STR in sys.path:
    # Move to front to prefer local modules over similarly named site packages
    sys.path.remove(_WEBAPP_DIR_STR)
sys.path.insert(0, _WEBAPP_DIR_STR)

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
        run_acvp_validation,
    )
except Exception:
    # If CLI package isn't installed, try best-effort import of adapters directly
    _load_adapters = None
    run_kem = run_sig = export_json = None  # type: ignore
    export_trace_kem = export_trace_sig = None  # type: ignore
    _build_export_payload = None  # type: ignore
    run_acvp_validation = None  # type: ignore

app = Flask(__name__, template_folder="../templates", static_folder="../static")

log = logging.getLogger(__name__)


# ---------------- Progress/job management (SSE) ----------------

Jobs: Dict[str, Dict[str, Any]] = {}
JobsLock = threading.Lock()


def _new_job() -> str:
    jid = uuid.uuid4().hex
    with JobsLock:
        Jobs[jid] = {
            "status": "pending",
            "percent": 0,
            "stage": "",
            "detail": "",
            "created": time.time(),
            "view": None,  # 'compare' | 'single'
            "payload": None,  # context for template
            "errors": None,
        }
    return jid


def _update_job(jid: str, *, percent: int | None = None, stage: str | None = None, detail: str | None = None, status: str | None = None) -> None:
    with JobsLock:
        job = Jobs.get(jid)
        if not job:
            return
        if percent is not None:
            # Ensure monotonic non-decreasing percentage
            newp = max(0, min(100, int(percent)))
            job["percent"] = max(int(job.get("percent", 0) or 0), newp)
        if stage is not None:
            job["stage"] = stage
        if detail is not None:
            job["detail"] = detail
        if status is not None:
            job["status"] = status


def _sse_from_job(jid: str):
    # Stream current job status every 300ms until completion
    last_payload = None
    while True:
        with JobsLock:
            job = Jobs.get(jid)
            if not job:
                payload = {"ok": False, "error": "job not found"}
                done = True
            else:
                payload = {
                    "ok": True,
                    "status": job.get("status"),
                    "percent": job.get("percent", 0),
                    "stage": job.get("stage", ""),
                    "detail": job.get("detail", ""),
                }
                done = job.get("status") in ("done", "error")
        import json as _json
        data = _json.dumps(payload)
        if data != last_payload:
            yield f"event: progress\n"
            yield f"data: {data}\n\n"
            last_payload = data
        if done:
            break
        time.sleep(0.3)


@app.route("/progress/<jid>")
def progress_stream(jid: str):
    return Response(_sse_from_job(jid), mimetype="text/event-stream")


def _import_llm() -> ModuleType | None:
    # Prefer normal import
    try:
        import llm as _llm  # type: ignore
        return _llm
    except Exception as e:
        log.debug("import llm failed: %s", e)
    # Try relative import (if running as a package)
    try:
        from . import llm as _llm  # type: ignore
        return _llm
    except Exception as e:
        log.debug("relative import .llm failed: %s", e)
    # Last resort: load by path
    try:
        llm_path = _WEBAPP_DIR / "llm.py"
        if llm_path.exists():
            spec = importlib.util.spec_from_file_location("llm", str(llm_path))
            if spec and spec.loader:
                _llm = importlib.util.module_from_spec(spec)
                sys.modules["llm"] = _llm
                spec.loader.exec_module(_llm)
                return _llm
    except Exception as e:
        log.error("loading llm from path failed: %s", e)
    return None


# Optional LLM helper (modular, safe fallback if unavailable)
llm = _import_llm()


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
    # Optional ACVP tests toggle
    do_tests = str(form.get("tests") or "").lower() in ("on", "true", "1", "yes")

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

        validation = None
        if do_tests and run_acvp_validation is not None:
            try:
                validation, _logs = run_acvp_validation(summary)  # type: ignore[misc]
                # Also attach into meta so it shows in compare inline JSON if needed
                if isinstance(summary.meta, dict):
                    summary.meta.setdefault("validation", validation)
            except Exception:
                validation = None

        if do_export:
            out_path = export_path.strip() or f"results/{name.replace('+','plus')}.json"
            export_json(summary, out_path, security_opts=security_opts, validation=validation)  # type: ignore[misc]
            last_export = out_path

        if do_export_trace:
            raw_path = export_trace_path.strip() or f"results/{name.replace('+','plus')}_trace.json"
            if kind == "KEM":
                export_trace_kem(name, raw_path)  # type: ignore[misc]
            else:
                export_trace_sig(name, message_size, raw_path)  # type: ignore[misc]

        # Build base result payload
        if _build_export_payload is not None:
            result = _build_export_payload(summary, security_opts=security_opts, validation=validation)
        else:
            result = {
                "algo": summary.algo,
                "kind": summary.kind,
                "ops": {k: vars(v) for k, v in summary.ops.items()},
                "meta": summary.meta,
            }
            result["security"] = {"error": "security estimator unavailable"}
            if validation is not None:
                result["validation"] = validation

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

    # Security + tests options
    security_form, security_opts = _parse_security_form(form)
    do_tests = str(form.get("tests") or "").lower() in ("on", "true", "1", "yes")

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
                validation = None
                if do_tests and run_acvp_validation is not None:
                    try:
                        validation, _logs = run_acvp_validation(summary)  # type: ignore[misc]
                    except Exception:
                        validation = None
                # Attach validation to meta for inline visibility
                if validation is not None and isinstance(summary.meta, dict):
                    summary.meta.setdefault("validation", validation)
                export_json(summary, json_path, security_opts=security_opts, validation=validation)  # type: ignore[misc]
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
    algos_out = []
    for summary in results:
        try:
            sec = _build_export_payload(summary, security_opts=security_opts).get("security") if _build_export_payload else None
        except Exception:
            sec = None
        algos_out.append({
            "name": summary.algo,
            "label": display_names.get(summary.algo, summary.algo),
            "ops": {k: asdict(v) for k, v in summary.ops.items()},
            "meta": summary.meta,
            "security": sec,
            "exports": (summary.meta.get("exports") if isinstance(summary.meta, dict) else {}),
        })
    compare = {
        "kind": kind,
        "runs": runs,
        "message_size": message_size,
        "mode": ("cold" if cold else "warm"),
        "algos": algos_out,
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


@app.route("/execute_async", methods=["POST"])
def execute_async():
    """Start a benchmark job asynchronously and return a job id.

    Frontend should listen to /progress/<job_id> (SSE) and then navigate to
    /job/<job_id>/view when status==done.
    """
    form = request.form
    mode = str(form.get("operation", "single") or "single").lower()
    jid = _new_job()

    def _worker_compare(jid: str, form: Mapping[str, Any]) -> None:
        try:
            _update_job(jid, status="running", stage="Preparing", detail="", percent=1)
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
            # Parse security + tests
            _security_form, security_opts = _parse_security_form(form)
            do_tests = str(form.get("tests") or "").lower() in ("on", "true", "1", "yes")

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

            selected = [n for n in _getlist("algos") if n and kinds.get(n) == kind]
            if not selected:
                mode_fallback = str(form.get("mode", "pair") or "pair").lower()
                if mode_fallback == "all":
                    selected = [n for n in all_names if kinds.get(n) == kind]
                else:
                    # mimic legacy pair selection
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
                _update_job(jid, status="error", stage="No algorithms selected", detail="", percent=100)
                return

            raw_cold = form.get("cold")
            cold = str(raw_cold).lower() in ("on", "true", "1", "yes")
            total_tasks = max(1, len(selected) * runs * 3)
            stage_offset = (
                {"keygen": 0, "encapsulate": 1, "decapsulate": 2}
                if kind == "KEM"
                else {"keygen": 0, "sign": 1, "verify": 2}
            )

            results = []
            errors: Dict[str, str] = {}
            for algo_index, algo_name in enumerate(selected):
                _update_job(jid, stage="Preparing", detail=algo_name)
                def _progress(stage: str, algo: str, i: int, total: int) -> None:
                    # Global, monotonic progress across all algorithms and stages
                    # Map stage to offset, then compute global tasks done
                    base = algo_index * runs * 3
                    so = int(stage_offset.get(stage, 0))
                    # Clamp i within [1, runs]
                    ii = i if i >= 1 else 1
                    if ii > runs:
                        ii = runs
                    global_done = base + so * runs + ii
                    pct = int((global_done / float(total_tasks)) * 100)
                    label = {
                        "keygen": "Keygen",
                        "encapsulate": "Encapsulate",
                        "decapsulate": "Decapsulate",
                        "sign": "Sign",
                        "verify": "Verify",
                    }.get(stage, stage.title())
                    _update_job(jid, stage=f"{label} — Trial {ii}/{runs}", detail=algo, percent=pct)
                try:
                    if kind == "KEM":
                        summary = run_kem(algo_name, runs, cold=cold, progress=_progress)  # type: ignore[misc]
                    else:
                        summary = run_sig(algo_name, runs, message_size, cold=cold, progress=_progress)  # type: ignore[misc]
                    # Optional ACVP validation
                    validation = None
                    if do_tests and run_acvp_validation is not None:
                        try:
                            validation, _logs = run_acvp_validation(summary)  # type: ignore[misc]
                        except Exception:
                            validation = None
                    if validation is not None and isinstance(summary.meta, dict):
                        summary.meta.setdefault("validation", validation)
                    # Export artifacts for parity with sync compare
                    try:
                        json_path = f"results/{algo_name.replace('+','plus')}_{kind.lower()}_compare.json"
                        export_json(summary, json_path, security_opts=security_opts, validation=validation)  # type: ignore[misc]
                        summary.meta.setdefault("exports", {})["json"] = json_path
                    except Exception:
                        pass
                    try:
                        trace_path = f"results/{algo_name.replace('+','plus')}_{kind.lower()}_compare_trace.json"
                        if kind == "KEM":
                            export_trace_kem(algo_name, trace_path)  # type: ignore[misc]
                        else:
                            export_trace_sig(algo_name, message_size, trace_path)  # type: ignore[misc]
                        summary.meta.setdefault("exports", {})["trace"] = trace_path
                    except Exception:
                        pass
                    results.append(summary)
                except Exception as exc:
                    errors[algo_name] = str(exc)

            _update_job(jid, stage="Compiling Results", detail="", percent=99)
            display_names = _display_names([s.algo for s in results])
            algos_out = []
            for summary in results:
                try:
                    sec = _build_export_payload(summary, security_opts=security_opts).get("security") if _build_export_payload else None
                except Exception:
                    sec = None
                algos_out.append({
                    "name": summary.algo,
                    "label": display_names.get(summary.algo, summary.algo),
                    "ops": {k: asdict(v) for k, v in summary.ops.items()},
                    "meta": summary.meta,
                    "security": sec,
                    "exports": (summary.meta.get("exports") if isinstance(summary.meta, dict) else {}),
                })
            compare = {
                "kind": kind,
                "runs": runs,
                "message_size": message_size,
                "mode": ("cold" if cold else "warm"),
                "algos": algos_out,
            }
            with JobsLock:
                job = Jobs.get(jid)
                if job is not None:
                    job["view"] = "compare"
                    job["payload"] = {"compare": compare, "errors": errors}
            _update_job(jid, status="done", stage="Complete", detail="", percent=100)
        except Exception as exc:
            _update_job(jid, status="error", stage="Error", detail=str(exc), percent=100)

    def _worker_single(jid: str, form: Mapping[str, Any]) -> None:
        try:
            _update_job(jid, status="running", stage="Preparing", detail="", percent=1)
            payload_response = _handle_run_submission(form)
            # We cannot render Response to HTML easily without request context duplication.
            # Instead, recompute the context similarly to _handle_run_submission here.
            # Minimal approach: re-run the same logic (duplicated subset) to build context.
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
            do_tests = str(form.get("tests") or "").lower() in ("on", "true", "1", "yes")

            result: Dict[str, Any] | None = None
            trace_sections: list[dict[str, Any]] | None = None
            last_export: str | None = None
            backend_label: str | None = None
            error: str | None = None

            total_tasks = max(1, runs * 3)
            stage_offset = (
                {"keygen": 0, "encapsulate": 1, "decapsulate": 2}
                if kind == "KEM"
                else {"keygen": 0, "sign": 1, "verify": 2}
            )
            def _progress(stage: str, algo: str, i: int, total: int) -> None:
                label = {
                    "keygen": "Keygen",
                    "encapsulate": "Encapsulate",
                    "decapsulate": "Decapsulate",
                    "sign": "Sign",
                    "verify": "Verify",
                }.get(stage, stage.title())
                so = int(stage_offset.get(stage, 0))
                # clamp i within [1, runs]
                ii = i if i >= 1 else 1
                if ii > runs:
                    ii = runs
                global_done = so * runs + ii
                pct = int((global_done / float(total_tasks)) * 100)
                _update_job(jid, stage=f"{label} — Trial {ii}/{runs}", detail=name, percent=pct)

            kind = kinds.get(name) or ""
            raw_cold = form.get("cold")
            cold = str(raw_cold).lower() in ("on", "true", "1", "yes")
            if kind == "KEM":
                summary = run_kem(name, runs, cold=cold, progress=_progress)  # type: ignore[misc]
            elif kind == "SIG":
                summary = run_sig(name, runs, message_size, cold=cold, progress=_progress)  # type: ignore[misc]
            else:
                raise RuntimeError(f"Unknown or unsupported algorithm: {name}")
            validation = None
            if do_tests and run_acvp_validation is not None:
                try:
                    validation, _logs = run_acvp_validation(summary)  # type: ignore[misc]
                except Exception:
                    validation = None
            if validation is not None and isinstance(summary.meta, dict):
                summary.meta.setdefault("validation", validation)

            _update_job(jid, stage="Compiling Results", detail="", percent=99)
            if do_export:
                out_path = export_path.strip() or f"results/{name.replace('+','plus')}.json"
                export_json(summary, out_path, security_opts=security_opts, validation=validation)  # type: ignore[misc]
                last_export = out_path

            if do_export_trace:
                raw_path = export_trace_path.strip() or f"results/{name.replace('+','plus')}_trace.json"
                if kind == "KEM":
                    export_trace_kem(name, raw_path)  # type: ignore[misc]
                else:
                    export_trace_sig(name, message_size, raw_path)  # type: ignore[misc]

            if _build_export_payload is not None:
                result = _build_export_payload(summary, security_opts=security_opts, validation=validation)
            else:
                result = {
                    "algo": summary.algo,
                    "kind": summary.kind,
                    "ops": {k: vars(v) for k, v in summary.ops.items()},
                    "meta": summary.meta,
                }
                result["security"] = {"error": "security estimator unavailable"}
                if validation is not None:
                    result["validation"] = validation

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

            display_names = {algo_name: (ALGO_INFO.get(algo_name, {}).get("label") or algo_name.replace("-", "-").replace("sphincs+", "SPHINCS+").title()) for algo_name in algos}
            context = {
                "algos": algos,
                "kinds": kinds,
                "display_names": display_names,
                "last_export": last_export,
                "result_json": result,
                "backend_label": backend_label,
                "error": error,
                "default_runs": runs,
                "default_message_size": message_size,
                "selected_algo": name,
                "trace_sections": trace_sections,
                "security_form": security_form,
                "security_profile_choices": SECURITY_PROFILE_CHOICES,
                "quantum_arch_choices": QUANTUM_ARCH_CHOICES,
                "rsa_model_choices": RSA_MODEL_CHOICES,
                "selected_operation": "single",
            }
            with JobsLock:
                job = Jobs.get(jid)
                if job is not None:
                    job["view"] = "single"
                    job["payload"] = context
            _update_job(jid, status="done", stage="Complete", detail="", percent=100)
        except Exception as exc:
            _update_job(jid, status="error", stage="Error", detail=str(exc), percent=100)

    t = threading.Thread(target=_worker_compare if mode == "compare" else _worker_single, args=(jid, request.form.copy()), daemon=True)
    t.start()
    return jsonify({"ok": True, "job_id": jid})


@app.route("/job/<jid>/view")
def job_view(jid: str):
    with JobsLock:
        job = Jobs.get(jid)
        if not job:
            return "Job not found", 404
        if job.get("status") != "done":
            return "Job not complete", 400
        view = job.get("view")
        payload = job.get("payload") or {}
    if view == "compare":
        return render_template("compare_results.html", **payload)
    elif view == "single":
        return render_template("base.html", **payload)
    return "Invalid job view", 400




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


@app.route("/api/analysis", methods=["POST"])
def api_analysis():
    """Analyze compare payload via modular LLM provider.

    The provider is configured via environment variables (see llm.LLMConfig).
    Falls back to a local heuristic summary if no provider is configured.
    """
    data = request.get_json(silent=True) or {}
    compare = data.get("compare")
    if not isinstance(compare, dict):
        return jsonify({"ok": False, "error": "invalid or missing 'compare' payload"}), 400
    # If llm helper is missing, fall back to a heuristic summary so UI remains useful
    if llm is None:
        log.warning("LLM module unavailable; using heuristic fallback")
        text = _heuristic_analysis(compare)
        return jsonify({
            "ok": True,
            "provider": "none",
            "model": "heuristic(local)",
            "analysis": text,
            "used_fallback": True,
            "error": "LLM module unavailable",
        })
    try:
        result = llm.analyze_compare_results(compare)  # type: ignore[attr-defined]
        return jsonify(result)
    except Exception as exc:
        log.exception("LLM analysis failed; using heuristic fallback")
        text = _heuristic_analysis(compare)
        return jsonify({
            "ok": True,
            "provider": getattr(llm, "LLMConfig", lambda: None)().__dict__.get("provider", "unknown") if hasattr(llm, "LLMConfig") else "unknown",
            "model": "heuristic(local)",
            "analysis": text,
            "used_fallback": True,
            "error": str(exc),
        })


def _heuristic_analysis(compare: dict) -> str:
    """Simple local summary when LLM is not available."""
    kind = compare.get("kind")
    ops = ["keygen", "encapsulate", "decapsulate"] if kind == "KEM" else ["keygen", "sign", "verify"]

    def best_for(op: str):
        best = None
        for a in compare.get("algos", []):
            s = (a.get("ops") or {}).get(op) or {}
            m = s.get("mean_ms")
            if isinstance(m, (int, float)):
                best = (a.get("label") or a.get("name") or "?", float(m)) if best is None or m < best[1] else best
        return best

    lines = ["Automatic analysis (local fallback):"]
    for op in ops:
        b = best_for(op)
        if b:
            lines.append(f"- Fastest {op}: {b[0]} (≈{b[1]:.3f} ms mean)")
    for op in ops:
        best_mem = None
        for a in compare.get("algos", []):
            s = (a.get("ops") or {}).get(op) or {}
            mm = s.get("mem_mean_kb")
            if isinstance(mm, (int, float)):
                best_mem = (a.get("label") or a.get("name") or "?", float(mm)) if best_mem is None or mm < best_mem[1] else best_mem
        if best_mem:
            lines.append(f"- Lowest memory {op}: {best_mem[0]} (≈{best_mem[1]:.2f} KB)")
    for a in compare.get("algos", []):
        md = a.get("meta") or {}
        sizes = []
        for k, label in (("public_key_len", "pk"), ("secret_key_len", "sk"), ("ciphertext_len", "ct"), ("signature_len", "sig")):
            v = md.get(k)
            if isinstance(v, (int, float)):
                sizes.append(f"{label}:{int(v)}B")
        if sizes:
            lines.append(f"- {a.get('label') or a.get('name')}: " + ", ".join(sizes))
    lines.append("- Note: Configure an LLM provider for richer interpretation.")
    return "\n".join(lines)


# ---------------- Image encryption demo (KEM → AES-GCM) ----------------

def _bytes_to_bmp(data: bytes, *, width: int | None = None) -> bytes:
    """Encode arbitrary bytes into a 24-bit BMP (grayscale) without external deps.

    - Each input byte becomes one pixel; value is replicated to R=G=B.
    - Image width defaults to min(512, len(data)) to keep a reasonable aspect.
    - Rows are padded to 4-byte boundaries per BMP spec.
    """
    n = len(data)
    if n == 0:
        # Minimal 1x1 black pixel BMP
        data = b"\x00"
        n = 1
    if width is None:
        width = min(512, max(1, n))
    width = max(1, int(width))
    height = int(math.ceil(n / float(width)))

    # Row sizes
    row_raw = width * 3  # 24bpp
    row_padded = (row_raw + 3) & ~3
    padding = row_padded - row_raw

    # Build pixel buffer (bottom-up)
    pixels = bytearray(row_padded * height)
    idx = 0
    for y in range(height):
        row_index = height - 1 - y  # bottom-up
        base = row_index * row_padded
        # Fill row
        for x in range(width):
            if idx < n:
                v = data[idx]
                # BMP stores B,G,R
                off = base + x * 3
                pixels[off + 0] = v
                pixels[off + 1] = v
                pixels[off + 2] = v
                idx += 1
            else:
                # remaining pixels default to black (zeros)
                break
        # padding bytes are already zero

    img_size = len(pixels)

    # File header (14 bytes) + DIB header BITMAPINFOHEADER (40 bytes)
    bfType = b"BM"
    bfOffBits = 14 + 40
    bfSize = bfOffBits + img_size
    bfReserved1 = 0
    bfReserved2 = 0
    file_header = struct.pack(
        "<2sIHHI", bfType, bfSize, bfReserved1, bfReserved2, bfOffBits
    )

    biSize = 40
    biWidth = width
    biHeight = height
    biPlanes = 1
    biBitCount = 24
    biCompression = 0
    biSizeImage = img_size
    biXPelsPerMeter = 2835
    biYPelsPerMeter = 2835
    biClrUsed = 0
    biClrImportant = 0
    dib_header = struct.pack(
        "<IIIHHIIIIII",
        biSize,
        biWidth,
        biHeight,
        biPlanes,
        biBitCount,
        biCompression,
        biSizeImage,
        biXPelsPerMeter,
        biYPelsPerMeter,
        biClrUsed,
        biClrImportant,
    )

    return file_header + dib_header + bytes(pixels)

def _kem_algorithms() -> list[str]:
    _ensure_adapters_loaded()
    kinds = _algo_kinds()
    algos = list(registry.list().keys())
    return [n for n in algos if kinds.get(n) == "KEM"]


@app.route("/image-encrypt", methods=["GET"])
def image_encrypt_page():
    try:
        kem_algos = _kem_algorithms()
    except Exception:
        kem_algos = []
    display_names = _display_names(kem_algos) if kem_algos else {}
    return render_template(
        "image_encrypt.html",
        kem_algos=kem_algos,
        display_names=display_names,
        error=None,
        result=None,
    )


@app.route("/image-encrypt/run", methods=["POST"])
def image_encrypt_run():
    _ensure_adapters_loaded()
    kinds = _algo_kinds()
    all_algos = list(registry.list().keys())
    kem_algos = [n for n in all_algos if kinds.get(n) == "KEM"]
    display_names = _display_names(kem_algos)

    file = request.files.get("image")
    algo_name = (request.form.get("algo") or "").strip()

    if not algo_name or algo_name not in kem_algos:
        return render_template(
            "image_encrypt.html",
            kem_algos=kem_algos,
            display_names=display_names,
            error="Please select a valid KEM algorithm.",
            result=None,
        )

    if not file or not getattr(file, "filename", ""):
        return render_template(
            "image_encrypt.html",
            kem_algos=kem_algos,
            display_names=display_names,
            error="Please choose an image file to encrypt.",
            result=None,
        )

    try:
        image_bytes = file.read()
        if not image_bytes:
            raise ValueError("Empty file")
        # Optional safety: limit input size to ~25MB
        if len(image_bytes) > 25 * 1024 * 1024:
            raise ValueError("Image too large (limit ~25MB)")
    except Exception as exc:
        return render_template(
            "image_encrypt.html",
            kem_algos=kem_algos,
            display_names=display_names,
            error=f"Failed to read image: {exc}",
            result=None,
        )

    # Perform KEM flow and symmetric encryption
    try:
        cls = registry.get(algo_name)
        algo = cls()

        # 1) KEM keygen
        pk, sk = algo.keygen()

        # 2) KEM encapsulate → shared secret
        kem_ct, ss = algo.encapsulate(pk)

        # 3) Derive 256-bit AES-GCM key from shared secret
        aes_key = hashlib.sha256(ss).digest()
        aesgcm = AESGCM(aes_key)

        # 4) Symmetric encrypt the image bytes
        nonce = os.urandom(12)  # GCM nonce
        cipher_img = aesgcm.encrypt(nonce, image_bytes, None)

        # 5) Decapsulate + decrypt for verification
        ss_dec = algo.decapsulate(sk, kem_ct)
        aes_key_dec = hashlib.sha256(ss_dec).digest()
        ok = False
        try:
            img_dec = AESGCM(aes_key_dec).decrypt(nonce, cipher_img, None)
            ok = (img_dec == image_bytes)
        except Exception:
            ok = False

        # Persist artifacts under results/ for download
        run_id = uuid.uuid4().hex
        out_dir = _PROJECT_ROOT / "results" / "image_encrypt" / run_id
        out_dir.mkdir(parents=True, exist_ok=True)

        (out_dir / "cipher.bin").write_bytes(cipher_img)
        (out_dir / "kem_ct.bin").write_bytes(kem_ct)
        (out_dir / "nonce.bin").write_bytes(nonce)

        # Also produce visualizations as BMP images (grayscale byte maps)
        try:
            cipher_bmp = _bytes_to_bmp(cipher_img)
            kemct_bmp = _bytes_to_bmp(kem_ct)
            # For very small nonce, use narrow width to keep a compact image
            nonce_bmp = _bytes_to_bmp(nonce, width=min(64, max(1, len(nonce))))
            (out_dir / "cipher.bmp").write_bytes(cipher_bmp)
            (out_dir / "kem_ct.bmp").write_bytes(kemct_bmp)
            (out_dir / "nonce.bmp").write_bytes(nonce_bmp)
        except Exception:
            pass

        # Prepare template payload
        import mimetypes, base64 as _b64
        mime = file.mimetype or mimetypes.guess_type(file.filename or "")[0] or "application/octet-stream"
        orig_b64 = _b64.b64encode(image_bytes).decode("ascii")
        dec_b64 = _b64.b64encode(img_dec if ok else b"").decode("ascii") if ok else None

        # For display, include truncated versions of big fields
        def b64_trunc(b: bytes, limit: int = 88) -> str:
            s = _b64.b64encode(b).decode("ascii")
            return s if len(s) <= limit else (s[:limit] + "…")

        result = {
            "algo": algo_name,
            "algo_label": display_names.get(algo_name, algo_name),
            "pk_len": len(pk),
            "sk_len": len(sk),
            "kem_ct_len": len(kem_ct),
            "cipher_len": len(cipher_img),
            "nonce_hex": nonce.hex(),
            "aes_key_hex": aes_key.hex(),
            "success": ok,
            "downloads": {
                "cipher": f"image_encrypt/{run_id}/cipher.bin",
                "kem_ct": f"image_encrypt/{run_id}/kem_ct.bin",
                "nonce": f"image_encrypt/{run_id}/nonce.bin",
                "cipher_img": f"image_encrypt/{run_id}/cipher.bmp",
                "kem_ct_img": f"image_encrypt/{run_id}/kem_ct.bmp",
                "nonce_img": f"image_encrypt/{run_id}/nonce.bmp",
            },
            "previews": {
                "mime": mime,
                "original_data_url": f"data:{mime};base64,{orig_b64}",
                "decrypted_data_url": f"data:{mime};base64,{dec_b64}" if ok else None,
            },
            "inspect": {
                "pk_b64": b64_trunc(pk),
                "sk_b64": b64_trunc(sk),
                "kem_ct_b64": b64_trunc(kem_ct),
            },
        }

        return render_template(
            "image_encrypt.html",
            kem_algos=kem_algos,
            display_names=display_names,
            error=None,
            result=result,
        )
    except Exception as exc:
        log.exception("Image encryption failed")
        return render_template(
            "image_encrypt.html",
            kem_algos=kem_algos,
            display_names=display_names,
            error=str(exc),
            result=None,
        )


# ---------------- Image signing demo (SIG → Sign/Verify) ----------------

def _sig_algorithms() -> list[str]:
    _ensure_adapters_loaded()
    kinds = _algo_kinds()
    algos = list(registry.list().keys())
    return [n for n in algos if kinds.get(n) == "SIG"]


@app.route("/image-sign", methods=["GET"])
def image_sign_page():
    try:
        sig_algos = _sig_algorithms()
    except Exception:
        sig_algos = []
    display_names = _display_names(sig_algos) if sig_algos else {}
    return render_template(
        "image_sign.html",
        sig_algos=sig_algos,
        display_names=display_names,
        error=None,
        result=None,
    )


@app.route("/image-sign/run", methods=["POST"])
def image_sign_run():
    _ensure_adapters_loaded()
    kinds = _algo_kinds()
    all_algos = list(registry.list().keys())
    sig_algos = [n for n in all_algos if kinds.get(n) == "SIG"]
    display_names = _display_names(sig_algos)

    file = request.files.get("image")
    algo_name = (request.form.get("algo") or "").strip()

    if not algo_name or algo_name not in sig_algos:
        return render_template(
            "image_sign.html",
            sig_algos=sig_algos,
            display_names=display_names,
            error="Please select a valid signature algorithm.",
            result=None,
        )

    if not file or not getattr(file, "filename", ""):
        return render_template(
            "image_sign.html",
            sig_algos=sig_algos,
            display_names=display_names,
            error="Please choose an image file to sign.",
            result=None,
        )

    try:
        image_bytes = file.read()
        if not image_bytes:
            raise ValueError("Empty file")
        if len(image_bytes) > 25 * 1024 * 1024:
            raise ValueError("Image too large (limit ~25MB)")
    except Exception as exc:
        return render_template(
            "image_sign.html",
            sig_algos=sig_algos,
            display_names=display_names,
            error=f"Failed to read image: {exc}",
            result=None,
        )

    try:
        cls = registry.get(algo_name)
        algo = cls()

        # 1) Keygen
        pk, sk = algo.keygen()

        # 2) Sign image bytes
        sig = algo.sign(sk, image_bytes)

        # 3) Verify
        ok = algo.verify(pk, image_bytes, sig)

        # Persist artifacts
        run_id = uuid.uuid4().hex
        out_dir = _PROJECT_ROOT / "results" / "image_sign" / run_id
        out_dir.mkdir(parents=True, exist_ok=True)

        (out_dir / "signature.bin").write_bytes(sig)
        (out_dir / "public_key.bin").write_bytes(pk)
        # Optional: keep original for reference
        # (out_dir / (Path(file.filename).name or "image.bin")).write_bytes(image_bytes)

        # Visualizations
        try:
            sig_bmp = _bytes_to_bmp(sig)
            pk_bmp = _bytes_to_bmp(pk)
            (out_dir / "signature.bmp").write_bytes(sig_bmp)
            (out_dir / "public_key.bmp").write_bytes(pk_bmp)
        except Exception:
            pass

        # Simple envelope for distribution
        import json as _json, base64 as _b64, mimetypes
        mime = file.mimetype or mimetypes.guess_type(file.filename or "")[0] or "application/octet-stream"
        envelope = {
            "algo": algo_name,
            "image_mime": mime,
            "image_filename": getattr(file, "filename", None),
            "signature_b64": _b64.b64encode(sig).decode("ascii"),
            "public_key_b64": _b64.b64encode(pk).decode("ascii"),
            "verify": bool(ok),
        }
        (out_dir / "signed.json").write_text(_json.dumps(envelope, indent=2))

        # Prepare result payload
        import base64 as _b64_2

        def b64_trunc(b: bytes, limit: int = 88) -> str:
            s = _b64_2.b64encode(b).decode("ascii")
            return s if len(s) <= limit else (s[:limit] + "…")

        orig_b64 = _b64_2.b64encode(image_bytes).decode("ascii")
        result = {
            "algo": algo_name,
            "algo_label": display_names.get(algo_name, algo_name),
            "pk_len": len(pk),
            "sk_len": len(sk),
            "sig_len": len(sig),
            "success": bool(ok),
            "downloads": {
                "signature": f"image_sign/{run_id}/signature.bin",
                "public_key": f"image_sign/{run_id}/public_key.bin",
                "signature_img": f"image_sign/{run_id}/signature.bmp",
                "public_key_img": f"image_sign/{run_id}/public_key.bmp",
                "envelope": f"image_sign/{run_id}/signed.json",
            },
            "previews": {
                "mime": mime,
                "original_data_url": f"data:{mime};base64,{orig_b64}",
            },
            "inspect": {
                "pk_b64": b64_trunc(pk),
                "sig_b64": b64_trunc(sig),
            },
        }

        return render_template(
            "image_sign.html",
            sig_algos=sig_algos,
            display_names=display_names,
            error=None,
            result=result,
        )
    except Exception as exc:
        log.exception("Image signing failed")
        return render_template(
            "image_sign.html",
            sig_algos=sig_algos,
            display_names=display_names,
            error=str(exc),
            result=None,
        )

if __name__ == "__main__":
    app.run(debug=True)

