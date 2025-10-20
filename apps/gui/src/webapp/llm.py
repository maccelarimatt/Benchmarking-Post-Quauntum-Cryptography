from __future__ import annotations

import json
import os
from numbers import Number
from typing import Any, Dict, List, Optional, Tuple
import time

try:
    import requests as _requests  # type: ignore
except Exception:  # requests is optional; only needed for external providers
    _requests = None  # type: ignore


# --- Configuration helpers

def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if (v is not None and str(v).strip() != "") else default


class LLMConfig:
    """Container for LLM provider configuration.

    Provider options:
      - 'openai_compatible': calls a v1/chat/completions endpoint (LM Studio, vLLM, OpenRouter-compatible, etc.)
      - 'huggingface': calls the HF Inference API for text-generation
      - 'none': no external calls; use deterministic local heuristic fallback
    """

    def __init__(self) -> None:
        # Providers: 'openai_compatible' | 'huggingface' | 'ollama' | 'none'
        # Accept common synonyms (e.g., 'openai', 'openai-compatible', 'auto').
        prov_raw = _env("LLM_PROVIDER", None) or _env("OPENAI_PROVIDER", None) or "none"
        prov = (prov_raw or "none").strip().lower().replace("-", "_")
        if prov in ("openai", "openai_compat", "openai_compatible", "openaicompatible"):
            prov = "openai_compatible"
        elif prov in ("hf", "hugging_face", "huggingface"):
            prov = "huggingface"
        elif prov in ("ollama",):
            prov = "ollama"
        elif prov in ("auto",):
            # 'auto' will be resolved after env inspection below
            pass
        self.provider: str = prov
        self.model: str = _env("LLM_MODEL", _env("OPENAI_MODEL", "llama3.1:8b"))
        # For OpenAI-compatible servers (OpenAI, Groq, LM Studio, vLLM)
        # Default to host root (without /v1). We'll add /v1/chat/completions if needed.
        self.base_url: str = _env("LLM_BASE_URL", _env("OPENAI_BASE_URL", "http://localhost:1234"))
        # For HF Inference API
        # Default to a widely-available, open-weight instruct model on HF.
        # Change via HF_MODEL env var as needed.
        self.hf_model: str = _env("HF_MODEL", "HuggingFaceH4/zephyr-7b-beta")
        # OpenAI-compatible API keys (support common env names)
        self.api_key: Optional[str] = _env("LLM_API_KEY", _env("OPENAI_API_KEY", None))
        self.hf_api_key: Optional[str] = _env("HF_API_KEY", _env("HUGGINGFACEHUB_API_TOKEN", None))
        # For Ollama local server
        self.ollama_url: str = _env("OLLAMA_HOST", _env("LLM_OLLAMA_URL", "http://localhost:11434"))
        # Generation settings
        self.max_tokens: int = int(_env("LLM_MAX_TOKENS", "1200") or 1200)
        self.temperature: float = float(_env("LLM_TEMPERATURE", "0.2") or 0.2)

        # Resolve 'auto' provider if requested
        if self.provider == "auto":
            if self.hf_api_key:
                self.provider = "huggingface"
            elif self.api_key or self.base_url:
                self.provider = "openai_compatible"
            elif self.ollama_url:
                self.provider = "ollama"
            else:
                self.provider = "none"


# --- Prompt construction

SYSTEM_PROMPT = (
    os.getenv(
        "LLM_SYSTEM_PROMPT",
        "You are an expert analyst for post-quantum cryptography (PQC) benchmarking. "
        "Write clear, structured reports that highlight performance, memory, and size trade-offs. "
        "Provide security considerations (standardization status, side-channel posture, implementation caveats) without making cryptanalytic guarantees or safety claims. "
        "Be factual and cautious; avoid recommendations beyond performance/footprint guidance."
    )
) + (
    "\n\nGeneral rules:" \
    "\n- Output clean HTML only (no scripts)." \
    "\n- Use semantic headings and short paragraphs." \
    "\n- Prefer small tables for comparisons." \
    "\n- When it improves clarity, include a single <figure data-chart='...'> visualization (JSON keys: type, title, labels, datasets[{label,data}]) with a matching <figcaption>; use single quotes around the attribute and keep each dataset to five points or fewer." \
    "\n- The JSON embedded in data-chart must be strict (double quotes only, no trailing commas) and each dataset needs at least one finite number; use null for missing values and skip the chart entirely if nothing numeric is available." \
    "\n- Use consistent units: ms for time, KB for memory, B for sizes." \
    "\n- If a field is missing, write 'n/a' rather than inventing values." \
    "\n- Treat measured metrics as 'baseline desktop'; when projecting to other devices, mark projections as rough and state assumptions."
)

def _output_template(kind: Optional[str]) -> str:
    ops = "keygen, encapsulate, decapsulate" if (kind or "") == "KEM" else "keygen, sign, verify"
    return (
        "You must follow this HTML structure exactly (omit any empty sections). After the Relative Performance table, add a <figure data-chart='...'> visualization when at least two algorithms are present; omit that figure only if the data is insufficient:\n"
        "<section>\n"
        "  <h2>Summary</h2>\n"
        "  <p>1–2 sentences on overall trends.</p>\n"
        "  <ul>\n"
        f"    <li>Fastest operations: identify leaders per operation ({ops}).</li>\n"
        "    <li>Notable memory or size extremes.</li>\n"
        "  </ul>\n"
        "  <h3>Relative Performance</h3>\n"
        "  <table>\n"
        "    <thead><tr><th>Algorithm</th><th>Op</th><th>Mean (ms)</th><th>Memory (KB)</th></tr></thead>\n"
        "    <tbody><!-- one row per algorithm-op with known mean --></tbody>\n"
        "  </table>\n"
        "  <h3>Artifact Sizes</h3>\n"
        "  <table>\n"
        "    <thead><tr><th>Algorithm</th><th>pk (B)</th><th>sk (B)</th><th>ct/sig (B)</th></tr></thead>\n"
        "    <tbody><!-- use 'ct' for KEM, 'sig' for SIG; use n/a if missing --></tbody>\n"
        "  </table>\n"
        "  <h3>Device Projections (rough)</h3>\n"
        "  <p>Baseline is measured environment. Multiply mean times by: Desktop x1; Laptop x1.2–1.5; Mobile/ARM x3–5; Microcontroller x20–100. Projections are approximate.</p>\n"
        "  <ul>\n"
        "    <li>Throughput (server/desktop): call out fastest ops.</li>\n"
        "    <li>Constrained (mobile/embedded): call out smallest sizes and lowest memory.</li>\n"
        "  </ul>\n"
        "  <h3>Security Considerations</h3>\n"
        "  <ul>\n"
        "    <li>Standardization status or typical usage if known (e.g., NIST selections).</li>\n"
        "    <li>Implementation posture: side-channel hardening needs, parameter sensitivity.</li>\n"
        "    <li>Scope: no cryptanalytic guarantees; treat as considerations only.</li>\n"
        "  </ul>\n"
        "  <h3>Notes & Caveats</h3>\n"
        "  <ul>\n"
        "    <li>Variance or outliers that may affect reliability.</li>\n"
        "    <li>Any missing data explicitly marked as n/a.</li>\n"
        "  </ul>\n"
        "</section>\n"
    )


def _build_user_prompt_v2(summary: Dict[str, Any], user_request: Optional[str] = None, *, prefer_html: bool = True) -> str:
    """New prompt builder with a consistent HTML template and expanded guidance."""
    lines: List[str] = []
    lines.append("Context: Post-quantum crypto benchmarking results.")
    lines.append(f"Kind: {summary.get('kind')} | Runs: {summary.get('runs')} | Mode: {summary.get('mode')}")
    if summary.get("message_size") is not None:
        lines.append(f"Message size (B): {summary.get('message_size')}")
    lines.append("")
    lines.append("Algorithms (per-op stats, time in ms, mem in KB):")
    for a in summary.get("algos", []):
        name = a.get('label') or a.get('name') or '?'
        lines.append(f"- {name}")
        md = a.get("meta", {}) or {}
        sizes: List[str] = []
        for k, label in (("public_key_len", "pk"), ("secret_key_len", "sk"), ("ciphertext_len", "ct"), ("signature_len", "sig")):
            v = md.get(k)
            if isinstance(v, (int, float)):
                sizes.append(f"{label}:{int(v)}B")
        if sizes:
            lines.append("  sizes: " + ", ".join(sizes))
        for op in a.get("ops_order", []):
            s = (a.get("ops", {}) or {}).get(op, {}) or {}
            mean = s.get("mean_ms"); median = s.get("median_ms"); mem = s.get("mem_mean_kb")
            mean_txt = f"{float(mean):.3f}" if isinstance(mean, (int, float)) else "n/a"
            med_txt = f"{float(median):.3f}" if isinstance(median, (int, float)) else "n/a"
            mem_txt = f"{float(mem):.2f}" if isinstance(mem, (int, float)) else "n/a"
            lines.append(f"  {op}: mean_ms={mean_txt}, median_ms={med_txt}, mem_kb={mem_txt}")
        sec = a.get("security") or {}
        head = sec.get("headline") or {}
        if head:
            bit_parts: List[str] = []
            cb = head.get("classical_bits")
            qb = head.get("quantum_bits")
            if isinstance(cb, (int, float)):
                bit_parts.append(f"classical_bits={float(cb):.2f}")
            if isinstance(qb, (int, float)):
                bit_parts.append(f"quantum_bits={float(qb):.2f}")
            est = head.get("estimator")
            if est:
                bit_parts.append(f"estimator={est}")
            attack = head.get("attack")
            if attack:
                bit_parts.append(f"attack={attack}")
            model = head.get("model")
            if model:
                bit_parts.append(f"model={model}")
            if head.get("notes"):
                notes = head["notes"] if isinstance(head["notes"], list) else [head["notes"]]
                note_preview = "; ".join(str(n) for n in notes[:2])
                if note_preview:
                    bit_parts.append(f"notes={note_preview}")
            if bit_parts:
                lines.append("  security_bits: " + "; ".join(bit_parts))
        est_meta = sec.get("estimator") or {}
        if est_meta and isinstance(est_meta, dict):
            meta_parts = []
            if est_meta.get("profile"):
                meta_parts.append(f"profile={est_meta['profile']}")
            if est_meta.get("available") is not None:
                meta_parts.append(f"available={est_meta['available']}")
            if est_meta.get("reference"):
                meta_parts.append(f"reference={est_meta['reference']}")
            if meta_parts:
                meta_txt = "; ".join(str(p) for p in meta_parts)
                lines.append(f"  estimator_meta: {meta_txt}")
        detail_rows = sec.get("detail_rows") or []
        if isinstance(detail_rows, list) and detail_rows:
            preview = []
            for row in detail_rows[:2]:
                if isinstance(row, dict):
                    label = row.get("label") or ""
                    detail = row.get("detail") or ""
                else:
                    label = ""
                    detail = ""
                label = str(label).strip()
                detail = str(detail).strip()
                if label or detail:
                    preview.append(f"{label}: {detail}" if label else detail)
            if preview:
                lines.append("  security_details: " + " | ".join(preview))
        if sec.get("notes"):
            sec_notes = "; ".join(str(n) for n in sec["notes"][:2]) if isinstance(sec["notes"], list) else str(sec["notes"])
            if sec_notes:
                lines.append(f"  security_notes: {sec_notes}")
        brute = sec.get("bruteforce") or {}
        if brute and isinstance(brute, dict):
            bf_parts = []
            if brute.get("space_bits") is not None:
                bf_parts.append(f"space_bits={brute['space_bits']}")
            if brute.get("rate_unit"):
                bf_parts.append(f"rate_unit={brute['rate_unit']}")
            if brute.get("rates"):
                bf_parts.append("sample_rates=" + ", ".join(str(r) for r in brute["rates"][:3]))
            time_map = brute.get("time_years") or {}
            if isinstance(time_map, dict) and time_map:
                sample_items = []
                for rate_key, row in list(time_map.items())[:2]:
                    if isinstance(row, dict):
                        entry = row.get("sci") or row.get("log10")
                    else:
                        entry = None
                    if entry:
                        sample_items.append(f"{rate_key}:{entry}")
                if sample_items:
                    bf_parts.append("time_years=" + ", ".join(sample_items))
            if brute.get("rationale"):
                bf_parts.append(f"rationale={brute['rationale']}")
            if bf_parts:
                lines.append("  bruteforce: " + "; ".join(bf_parts))
        secret_keys = a.get("secret_keys") or {}
        if isinstance(secret_keys, dict):
            hd = secret_keys.get("hd")
            if isinstance(hd, dict) and hd:
                hd_parts = []
                if hd.get("mean_fraction") is not None:
                    try:
                        hd_parts.append(f"mean={float(hd['mean_fraction']):.4f}")
                    except Exception:
                        hd_parts.append(f"mean={hd['mean_fraction']}")
                if hd.get("expected_fraction") is not None:
                    try:
                        hd_parts.append(f"expected={float(hd['expected_fraction']):.4f}")
                    except Exception:
                        hd_parts.append(f"expected={hd['expected_fraction']}")
                if hd.get("samples") is not None:
                    hd_parts.append(f"samples={hd['samples']}")
                if hd_parts:
                    lines.append("  hamming_distance: " + "; ".join(hd_parts))
            hw = secret_keys.get("hw")
            if isinstance(hw, dict) and hw:
                hw_parts = []
                if hw.get("mean_fraction") is not None:
                    try:
                        hw_parts.append(f"mean={float(hw['mean_fraction']):.4f}")
                    except Exception:
                        hw_parts.append(f"mean={hw['mean_fraction']}")
                if hw.get("expected_fraction") is not None:
                    try:
                        hw_parts.append(f"expected={float(hw['expected_fraction']):.4f}")
                    except Exception:
                        hw_parts.append(f"expected={hw['expected_fraction']}")
                if hw.get("samples") is not None:
                    hw_parts.append(f"samples={hw['samples']}")
                if hw_parts:
                    lines.append("  hamming_weight: " + "; ".join(hw_parts))
    lines.append("")
    req = (str(user_request).strip() if user_request is not None else "")
    if len(req) > 4000:
        req = req[:4000] + "..."
    lines.append("User request: " + (req or "(none)"))
    lines.append("Incorporate the request where relevant; keep structure consistent; avoid cryptanalytic guarantees.")
    lines.append("In the Summary section, add one sentence that explicitly references the user's request focus if provided.")
    lines.append("")
    lines.append("Task: Provide an expansive analysis with the sections below. Highlight:")
    lines.append("You must include at least one <figure data-chart='...'> that pulls numeric values from these stats (for example mean runtime per algorithm or security bits). Use at most five labels per dataset, prefer type 'bar' or 'line', and skip the chart entirely if there are fewer than two algorithms or no finite numbers to plot.")
    lines.append("Ensure the data-chart payload is valid JSON: double quotes for keys/strings, no trailing commas, and every dataset must include at least one finite numeric value (use null for missing entries, never NaN/Infinity).")
    lines.append("- fastest algorithms per operation with approximate margins")
    lines.append("- memory trade-offs plus key/ciphertext/signature size implications")
    lines.append("- interpretation of secret-key Hamming distance and weight against expected baselines")
    lines.append("- security estimator outputs: headline bits, estimator name/profile, dominant attacks, and notable security notes")
    lines.append("- brute-force baselines (search space, assumed rates, illustrative time-to-break numbers)")
    lines.append("- rough device projections (desktop/server vs mobile/embedded)")
    lines.append("- variance, outliers, or missing data caveats")
    lines.append("")
    lines.append(_output_template(summary.get("kind")))
    lines.append("Append a <h3>Conclusion</h3> section at the end with 2–3 sentences or bullets summarizing key trade-offs and when each algorithm is preferable (no security guarantees).")
    return "\n".join(lines)


def _build_user_prompt(summary: Dict[str, Any], user_request: Optional[str] = None, *, prefer_html: bool = False) -> str:
    """Render a compact, structured prompt from the condensed summary.

    If ``user_request`` is provided, it is included to steer the analysis
    toward the viewer's specific interests.
    """
    lines: List[str] = []
    lines.append("Context: Post-quantum crypto benchmarking results.")
    lines.append(f"Kind: {summary.get('kind')}  • Runs: {summary.get('runs')}  • Mode: {summary.get('mode')}")
    if summary.get("message_size") is not None:
        lines.append(f"Message size (B): {summary.get('message_size')}")
    lines.append("")
    lines.append("Algorithms (per-op stats, time in ms, mem in KB):")
    for a in summary.get("algos", []):
        lines.append(f"- {a['label']} [{a['name']}]")
        # sizes/metadata snapshot
        md = a.get("meta", {}) or {}
        sizes: List[str] = []
        for k, label in (
            ("public_key_len", "pk"),
            ("secret_key_len", "sk"),
            ("ciphertext_len", "ct"),
            ("signature_len", "sig"),
        ):
            v = md.get(k)
            if isinstance(v, (int, float)):
                sizes.append(f"{label}:{int(v)}B")
        if sizes:
            lines.append("  sizes: " + ", ".join(sizes))
        # ops
        for op in a.get("ops_order", []):
            s = a.get("ops", {}).get(op, {})
            mean = s.get("mean_ms")
            std = s.get("stddev_ms")
            med = s.get("median_ms")
            mm = s.get("mem_mean_kb")
            lines.append(
                f"  {op}: mean={mean:.3f} ms, std={std:.3f} ms, med={med:.3f} ms, mem≈{mm if mm is not None else '-'} KB"
                if (mean is not None and std is not None and med is not None)
                else f"  {op}: (insufficient stats)"
            )
    lines.append("")
    if user_request and str(user_request).strip():
        # Custom user steering
        req = str(user_request).strip()
        # Cap extremely long inputs to keep prompts manageable
        if len(req) > 4000:
            req = req[:4000] + "..."
        lines.append("User request: " + req)
        lines.append("Respond concisely and focus on the requested aspects.")
        lines.append("Avoid security claims or recommendations beyond performance/footprint observations.")
    else:
        # Default guidance
        lines.append("Task: In 6-9 concise bullets, explain:")
        lines.append("- which algorithms are fastest per operation (and by how much, roughly)")
        lines.append("- memory trade-offs and any large differences")
        lines.append("- key/ciphertext/signature size implications")
        lines.append("- suitability for constrained devices vs. throughput use")
        lines.append("- note if high variance/outliers might affect reliability")
        lines.append("Avoid security claims or recommendations beyond performance/footprint observations.")
    # Always request clean HTML formatting
    lines.append(
        "Format the response as clean HTML (no scripts), using semantic headings, lists, and tables where helpful."
    )
    return "\n".join(lines)


# --- Providers

def _compose_openai_url(base_url: str) -> str:
    b = (base_url or "").strip().rstrip("/")
    # If caller provided the full path already, respect it
    if b.endswith("/chat/completions"):
        return b
    # If base ends with /v1 or /openai/v1, append chat/completions
    if b.endswith("/v1"):
        return f"{b}/chat/completions"
    # Common provider roots (e.g., https://api.groq.com/openai -> expect .../v1/chat/completions)
    return f"{b}/v1/chat/completions"


def _call_openai_compatible(cfg: LLMConfig, user_prompt: str) -> Tuple[str, Dict[str, Any]]:
    if _requests is None:
        raise RuntimeError("python-requests is not installed; run 'pip install requests'")
    url = _compose_openai_url(cfg.base_url)
    headers = {"Content-Type": "application/json"}
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    payload = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": cfg.temperature,
        "max_tokens": cfg.max_tokens,
        "stream": False,
    }
    r = _requests.post(url, headers=headers, data=json.dumps(payload), timeout=60)
    r.raise_for_status()
    data = r.json()
    # Try to extract the assistant content
    text = (
        data.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
        or ""
    )
    if not text:
        text = json.dumps(data)  # last resort for debugging
    return text, {"endpoint": url}


def _call_huggingface_inference(cfg: LLMConfig, user_prompt: str) -> Tuple[str, Dict[str, Any]]:
    if _requests is None:
        raise RuntimeError("python-requests is not installed; run 'pip install requests'")
    if not cfg.hf_api_key:
        raise RuntimeError("HF_API_KEY not set")
    url = f"https://api-inference.huggingface.co/models/{cfg.hf_model}?wait_for_model=true"
    headers = {"Authorization": f"Bearer {cfg.hf_api_key}", "Content-Type": "application/json"}
    payload = {
        "inputs": f"{SYSTEM_PROMPT}\n\n{user_prompt}",
        "parameters": {
            "max_new_tokens": cfg.max_tokens,
            "temperature": cfg.temperature,
            "return_full_text": False,
        },
    }

    # Retry for transient statuses (503 model loading, 429 rate limit)
    attempts = 6
    backoff = 2.0
    last_err: Optional[str] = None
    for i in range(attempts):
        try:
            r = _requests.post(url, headers=headers, data=json.dumps(payload), timeout=120)
        except Exception as e:
            last_err = str(e)
            if i == attempts - 1:
                raise
            time.sleep(min(5.0 + i, 15.0))
            continue

        if r.status_code == 503:
            # Model loading; respect estimated_time if present
            try:
                j = r.json()
            except Exception:
                j = {}
            wait = float(j.get("estimated_time", 5.0)) if isinstance(j, dict) else 5.0
            time.sleep(max(2.0, min(wait + 0.5, 20.0)))
            continue

        if r.status_code == 429:
            # Rate limited
            time.sleep(min(backoff * (i + 1), 20.0))
            continue

        if r.status_code == 404:
            raise RuntimeError(
                f"Model not available on HF Inference API (404): {cfg.hf_model}. "
                "Pick a serverless-enabled model (e.g., google/flan-t5-large, google/flan-t5-base, bigscience/bloomz-560m) "
                "or use an OpenAI-compatible endpoint."
            )

        if r.status_code in (401, 403):
            raise RuntimeError("Hugging Face auth failed (401/403). Check HF_API_KEY and model access/terms.")

        # Other errors -> raise now
        r.raise_for_status()

        data = r.json()
        # HF Inference can return different shapes. Try common ones.
        text = ""
        if isinstance(data, list) and data and isinstance(data[0], dict):
            # Text-generation returns a list of objects
            text = (
                data[0].get("generated_text")
                or data[0].get("generated_texts")
                or data[0].get("summary_text")
                or ""
            )
        if not text and isinstance(data, dict):
            text = data.get("generated_text") or data.get("summary_text") or ""
        if not text:
            # Last resort: surface raw payload for debugging
            text = json.dumps(data)
        return text, {"endpoint": url}

    raise RuntimeError(f"HF inference failed after retries: {last_err or 'unknown error'}")


# Ollama local server provider
def _call_ollama(cfg: LLMConfig, user_prompt: str) -> Tuple[str, Dict[str, Any]]:
    if _requests is None:
        raise RuntimeError("python-requests is not installed; run 'pip install requests'")
    url = f"{cfg.ollama_url.rstrip('/')}/api/chat"
    model = cfg.model or "llama3.1:8b"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "options": {
            "temperature": cfg.temperature,
            "num_predict": cfg.max_tokens,
        },
    }
    r = _requests.post(url, headers={"Content-Type": "application/json"}, data=json.dumps(payload), timeout=120)
    r.raise_for_status()
    data = r.json()
    msg = (data or {}).get("message", {})
    text = msg.get("content") or data.get("response") or ""
    if not text:
        text = json.dumps(data)
    return text, {"endpoint": url}


# --- Heuristic fallback (no external calls)

def _heuristic_summary(summary: Dict[str, Any]) -> str:
    kind = summary.get("kind")
    ops_order = ["keygen", "encapsulate", "decapsulate"] if kind == "KEM" else ["keygen", "sign", "verify"]

    def best_for_op(op: str) -> Optional[Tuple[str, float]]:
        best: Optional[Tuple[str, float]] = None
        for a in summary.get("algos", []):
            s = a.get("ops", {}).get(op, {})
            mean = s.get("mean_ms")
            if isinstance(mean, (int, float)):
                if best is None or mean < best[1]:
                    best = (a.get("label") or a.get("name") or "?", float(mean))
        return best

    lines: List[str] = []
    lines.append("Automatic analysis (fallback – no external LLM configured):")
    for op in ops_order:
        best = best_for_op(op)
        if best:
            lines.append(f"- Fastest {op}: {best[0]} (≈{best[1]:.3f} ms mean)")
    # Memory deltas
    for op in ops_order:
        best_mem: Optional[Tuple[str, float]] = None
        for a in summary.get("algos", []):
            s = a.get("ops", {}).get(op, {})
            mm = s.get("mem_mean_kb")
            if isinstance(mm, (int, float)):
                if best_mem is None or mm < best_mem[1]:
                    best_mem = (a.get("label") or a.get("name") or "?", float(mm))
        if best_mem:
            lines.append(f"- Lowest memory {op}: {best_mem[0]} (≈{best_mem[1]:.2f} KB)")
    # Sizes
    for a in summary.get("algos", []):
        md = a.get("meta", {}) or {}
        sizes = []
        for k, label in (("public_key_len", "pk"), ("secret_key_len", "sk"), ("ciphertext_len", "ct"), ("signature_len", "sig")):
            v = md.get(k)
            if isinstance(v, (int, float)):
                sizes.append(f"{label}:{int(v)}B")
        if sizes:
            lines.append(f"- {a.get('label') or a.get('name')}: " + ", ".join(sizes))
    lines.append("- Note: This is a heuristic summary. For nuanced interpretation, enable an LLM provider.")
    return "\n".join(lines)


def _heuristic_summary_html(summary: Dict[str, Any]) -> str:
    kind = summary.get("kind")
    ops_order = ["keygen", "encapsulate", "decapsulate"] if kind == "KEM" else ["keygen", "sign", "verify"]

    def best_for_op(op: str) -> Optional[Tuple[str, float]]:
        best: Optional[Tuple[str, float]] = None
        for a in summary.get("algos", []):
            s = a.get("ops", {}).get(op, {})
            mean = s.get("mean_ms")
            if isinstance(mean, (int, float)):
                if best is None or mean < best[1]:
                    best = (a.get("label") or a.get("name") or "?", float(mean))
        return best

    html: List[str] = []
    html.append("<section>")
    html.append("<h2>Automatic Analysis</h2>")
    html.append("<p>This is a local fallback summary (no external LLM configured or provider failed).</p>")
    html.append("<h3>Fastest Operations</h3>")
    html.append("<ul>")
    for op in ops_order:
        best = best_for_op(op)
        if best:
            html.append(f"<li>Fastest {op}: <strong>{best[0]}</strong> (~{best[1]:.3f} ms mean)</li>")
    html.append("</ul>")
    html.append("<h3>Lowest Memory Usage</h3>")
    html.append("<ul>")
    for op in ops_order:
        best_mem: Optional[Tuple[str, float]] = None
        for a in summary.get("algos", []):
            s = a.get("ops", {}).get(op, {})
            mm = s.get("mem_mean_kb")
            if isinstance(mm, (int, float)):
                if best_mem is None or mm < best_mem[1]:
                    best_mem = (a.get("label") or a.get("name") or "?", float(mm))
        if best_mem:
            html.append(f"<li>Lowest memory {op}: <strong>{best_mem[0]}</strong> (~{best_mem[1]:.2f} KB)</li>")
    html.append("</ul>")
    html.append("<h3>Key and Artifact Sizes</h3>")
    html.append("<ul>")
    for a in summary.get("algos", []):
        md = a.get("meta", {}) or {}
        sizes: List[str] = []
        for k, label in (("public_key_len", "pk"), ("secret_key_len", "sk"), ("ciphertext_len", "ct"), ("signature_len", "sig")):
            v = md.get(k)
            if isinstance(v, (int, float)):
                sizes.append(f"{label}:{int(v)}B")
        if sizes:
            name = a.get('label') or a.get('name') or '?'
            html.append(f"<li><strong>{name}</strong>: {', '.join(sizes)}</li>")
    html.append("</ul>")
    html.append("<p><em>Note:</em> For nuanced interpretation, enable an LLM provider.</p>")
    html.append("</section>")
    return "".join(html)


# --- Public API

def _to_plain_dict(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "_asdict"):
        try:
            return dict(value._asdict())
        except Exception:
            return {}
    if hasattr(value, "__dict__"):
        try:
            return {k: v for k, v in vars(value).items() if not k.startswith("_")}
        except Exception:
            return {}
    return {}


def _clean_number(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, Number):
        try:
            return float(value)
        except Exception:
            return value
    return value


def condense_compare(compare: Dict[str, Any]) -> Dict[str, Any]:
    """Reduce the compare payload to essentials to keep prompts compact and stable."""
    kind = compare.get("kind")
    ops_order = ["keygen", "encapsulate", "decapsulate"] if kind == "KEM" else ["keygen", "sign", "verify"]
    algos_out: List[Dict[str, Any]] = []
    for a in compare.get("algos", []):
        ops_in = a.get("ops", {}) or {}
        ops_out: Dict[str, Dict[str, Any]] = {}
        for op in ops_order:
            s = ops_in.get(op)
            if not isinstance(s, dict):
                continue
            ops_out[op] = {
                "mean_ms": s.get("mean_ms"),
                "stddev_ms": s.get("stddev_ms"),
                "median_ms": s.get("median_ms"),
                "mem_mean_kb": s.get("mem_mean_kb"),
                # omit full series to keep prompt small
            }
        meta = a.get("meta", {}) or {}
        # Only keep commonly-used size fields
        meta_keep = {
            k: meta.get(k)
            for k in (
                "public_key_len",
                "secret_key_len",
                "ciphertext_len" if kind == "KEM" else "signature_len",
                "message_size",
                "mechanism",
                "algorithm",
                "alg",
                "mech",
            )
            if k in meta
        }
        algo_entry: Dict[str, Any] = {
            "name": a.get("name"),
            "label": a.get("label", a.get("name")),
            "ops_order": ops_order,
            "ops": ops_out,
            "meta": meta_keep,
        }
        secret_stats: Dict[str, Any] = {}
        secret_analysis = meta.get("secret_key_analysis")
        if secret_analysis:
            ana_dict = _to_plain_dict(secret_analysis)
            for key in ("hd", "hw"):
                stats = _to_plain_dict(ana_dict.get(key))
                if not stats:
                    continue
                entry: Dict[str, Any] = {}
                for field in ("samples", "mean_fraction", "std_fraction", "min_fraction", "max_fraction", "expected_fraction"):
                    if field in stats and stats[field] is not None:
                        entry[field] = _clean_number(stats[field])
                if entry:
                    secret_stats[key] = entry
        if secret_stats:
            algo_entry["secret_keys"] = secret_stats
        security_src = a.get("security") or {}
        sec_dict = _to_plain_dict(security_src)
        security_out: Dict[str, Any] = {}
        for field in ("nist_category", "category_floor", "shor_breakable"):
            if field in sec_dict and sec_dict[field] is not None:
                security_out[field] = sec_dict[field]
        headline_dict = _to_plain_dict(sec_dict.get("headline"))
        if headline_dict:
            headline_out: Dict[str, Any] = {}
            for field in ("classical_bits", "quantum_bits", "estimator", "attack", "model"):
                if field in headline_dict and headline_dict[field] is not None:
                    headline_out[field] = _clean_number(headline_dict[field])
            for field in ("classical_bits_range", "quantum_bits_range"):
                rng = headline_dict.get(field)
                if isinstance(rng, (list, tuple)) and len(rng) == 2:
                    headline_out[field] = [_clean_number(rng[0]), _clean_number(rng[1])]
            notes = headline_dict.get("notes")
            if isinstance(notes, (list, tuple)):
                cleaned_notes = [str(n) for n in notes if n]
                if cleaned_notes:
                    headline_out["notes"] = cleaned_notes[:4]
            if headline_out:
                security_out["headline"] = headline_out
        estimator_dict = _to_plain_dict(sec_dict.get("estimator"))
        if estimator_dict:
            estimator_out: Dict[str, Any] = {}
            for field in ("name", "profile", "available", "requested", "supported", "reference"):
                if field in estimator_dict and estimator_dict[field] is not None:
                    estimator_out[field] = estimator_dict[field]
            if estimator_out:
                security_out["estimator"] = estimator_out
        notes = sec_dict.get("notes")
        if isinstance(notes, (list, tuple)):
            cleaned = [str(n) for n in notes if n]
            if cleaned:
                security_out["notes"] = cleaned[:4]
        detail_rows = sec_dict.get("detail_rows")
        if isinstance(detail_rows, (list, tuple)):
            rows_out: List[Dict[str, Any]] = []
            for row in detail_rows[:6]:
                label = ""
                detail = ""
                if isinstance(row, dict):
                    label = str(row.get("label") or row.get("title") or "")
                    detail = str(row.get("detail") or row.get("value") or "")
                elif isinstance(row, (list, tuple)):
                    if row:
                        label = str(row[0])
                    if len(row) > 1:
                        detail = str(row[1])
                else:
                    label = str(row)
                label = label.strip()
                detail = detail.strip()
                if label or detail:
                    rows_out.append({"label": label, "detail": detail})
            if rows_out:
                security_out["detail_rows"] = rows_out
        bruteforce_dict = _to_plain_dict(sec_dict.get("bruteforce"))
        if bruteforce_dict:
            brute_out: Dict[str, Any] = {}
            if bruteforce_dict.get("model") is not None:
                brute_out["model"] = bruteforce_dict.get("model")
            if bruteforce_dict.get("rate_unit") is not None:
                brute_out["rate_unit"] = bruteforce_dict.get("rate_unit")
            if bruteforce_dict.get("space_bits") is not None:
                brute_out["space_bits"] = _clean_number(bruteforce_dict.get("space_bits"))
            rates = bruteforce_dict.get("rates")
            if isinstance(rates, (list, tuple)):
                brute_out["rates"] = [_clean_number(r) for r in rates[:4]]
            time_years = bruteforce_dict.get("time_years")
            if isinstance(time_years, dict):
                time_out: Dict[str, Any] = {}
                for key, value in list(time_years.items())[:4]:
                    entry = _to_plain_dict(value)
                    row_out: Dict[str, Any] = {}
                    if entry.get("sci") is not None:
                        row_out["sci"] = entry.get("sci")
                    if entry.get("log10") is not None:
                        row_out["log10"] = _clean_number(entry.get("log10"))
                    if row_out:
                        time_out[str(key)] = row_out
                if time_out:
                    brute_out["time_years"] = time_out
            assumptions = _to_plain_dict(bruteforce_dict.get("assumptions"))
            if assumptions.get("rationale"):
                brute_out["rationale"] = str(assumptions.get("rationale"))
            if brute_out:
                security_out["bruteforce"] = brute_out
        if security_out:
            algo_entry["security"] = security_out
        algos_out.append(algo_entry)
    return {
        "kind": kind,
        "runs": compare.get("runs"),
        "mode": compare.get("mode"),
        "message_size": compare.get("message_size"),
        "algos": algos_out,
    }


def analyze_compare_results(compare: Dict[str, Any], user_request: Optional[str] = None, *, prefer_html: Optional[bool] = None) -> Dict[str, Any]:
    """Produce an analysis string for a compare payload using the configured LLM.

    Returns a dict: { ok, provider, model, analysis, error?, used_fallback? }
    """
    cfg = LLMConfig()
    condensed = condense_compare(compare)
    # Always prefer HTML output
    want_html = True
    prompt = _build_user_prompt_v2(condensed, user_request=user_request, prefer_html=True)

    # Provider selection
    provider = (cfg.provider or "none").strip().lower()
    try:
        if provider == "openai_compatible":
            text, meta = _call_openai_compatible(cfg, prompt)
            return {
                "ok": True,
                "provider": provider,
                "model": cfg.model,
                "analysis": text.strip(),
                "meta": {**meta, "format": "html"},
            }
        elif provider == "huggingface":
            text, meta = _call_huggingface_inference(cfg, prompt)
            return {
                "ok": True,
                "provider": provider,
                "model": cfg.hf_model,
                "analysis": text.strip(),
                "meta": {**meta, "format": "html"},
            }
        elif provider == "ollama":
            text, meta = _call_ollama(cfg, prompt)
            return {
                "ok": True,
                "provider": provider,
                "model": cfg.model,
                "analysis": text.strip(),
                "meta": {**meta, "format": "html"},
            }
        else:
            # No external provider: use heuristic
            text = _heuristic_summary_html(condensed)
            return {
                "ok": True,
                "provider": "none",
                "model": "heuristic",
                "analysis": text.strip(),
                "used_fallback": True,
                "meta": {"format": "html"},
            }
    except Exception as exc:
        # Error while calling provider: fallback to heuristic, include error and endpoint
        text = _heuristic_summary_html(condensed)
        endpoint = None
        try:
            if provider == "openai_compatible":
                endpoint = f"{cfg.base_url.rstrip('/')}/v1/chat/completions"
            elif provider == "huggingface":
                endpoint = f"https://api-inference.huggingface.co/models/{cfg.hf_model}?wait_for_model=true"
            elif provider == "ollama":
                endpoint = f"{cfg.ollama_url.rstrip('/')}/api/chat"
        except Exception:
            endpoint = None
        return {
            "ok": True,
            "provider": provider,
            "model": (
                cfg.model if provider in ("openai_compatible", "ollama") else cfg.hf_model
            ),
            "analysis": text.strip(),
            "used_fallback": True,
            "error": str(exc),
            "meta": ({"endpoint": endpoint, "format": "html"} if endpoint else {"format": "html"}),
        }
