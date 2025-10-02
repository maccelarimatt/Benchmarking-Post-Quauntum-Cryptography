from __future__ import annotations

import json
import os
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
    "\n- Use consistent units: ms for time, KB for memory, B for sizes." \
    "\n- If a field is missing, write 'n/a' rather than inventing values." \
    "\n- Treat measured metrics as 'baseline desktop'; when projecting to other devices, mark projections as rough and state assumptions."
)

def _output_template(kind: Optional[str]) -> str:
    ops = "keygen, encapsulate, decapsulate" if (kind or "") == "KEM" else "keygen, sign, verify"
    return (
        "You must follow this HTML structure exactly (omit any empty sections):\n"
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
    lines.append("")
    req = (str(user_request).strip() if user_request is not None else "")
    if len(req) > 4000:
        req = req[:4000] + "…"
    lines.append("User request: " + (req or "(none)"))
    lines.append("Incorporate the request where relevant; keep structure consistent; avoid cryptanalytic guarantees.")
    lines.append("In the Summary section, add one sentence that explicitly references the user's request focus if provided.")
    lines.append("")
    lines.append("Task: Provide an expansive analysis with the sections below. Highlight:")
    lines.append("- fastest algorithms per operation and approximate margins")
    lines.append("- memory trade-offs and key/ciphertext/signature size implications")
    lines.append("- rough device projections (desktop/server vs mobile/embedded)")
    lines.append("- security considerations (standardization status, side-channel posture)")
    lines.append("- variance/outliers and caveats")
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
            req = req[:4000] + "…"
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
        algos_out.append({
            "name": a.get("name"),
            "label": a.get("label", a.get("name")),
            "ops_order": ops_order,
            "ops": ops_out,
            "meta": meta_keep,
        })
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
