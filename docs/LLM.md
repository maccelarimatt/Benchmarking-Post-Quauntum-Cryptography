# LLM Integration Guide (GUI)

This guide explains how the PQC Benchmarks GUI integrates a Large Language Model (LLM) to generate concise, practical summaries of benchmark results, and how to configure it on Windows and macOS/Linux.

The LLM feature lives entirely in the GUI backend and can be enabled with environment variables. If no provider is configured, or if a call fails, the GUI falls back to a deterministic local summary so the panel always produces something useful.

---

## How It Works

- Trigger
  - In the Compare view, after a successful run, the page auto-posts the condensed results to the backend endpoint `POST /api/analysis`.
  - Frontend code is in `apps/gui/src/templates/compare_results.html` (the “AI‑Assisted Analysis” panel).
  - Rendering: LLM analysis output is rendered as Markdown and sanitized client‑side.
- Backend path
  - Route: `apps/gui/src/webapp/app.py:/api/analysis`
  - Calls `llm.analyze_compare_results(compare, user_request?)` from `apps/gui/src/webapp/llm.py`.
- Summarization flow (`apps/gui/src/webapp/llm.py`)
  - `condense_compare(...)`: reduces the payload to the essentials to keep prompts compact and stable.
  - `_build_user_prompt(summary, user_request?)`: renders a structured prompt describing algorithms, timings, memory, and sizes, and optionally includes a viewer‑provided request to steer analysis.
  - Provider call (based on env config):
    - OpenAI‑compatible: `_call_openai_compatible(...)`
    - Hugging Face Inference API: `_call_huggingface_inference(...)`
    - Ollama (local): `_call_ollama(...)`
    - None: `_heuristic_summary(...)` (no network)
  - Returns JSON: `{ ok, provider, model, analysis, used_fallback?, error?, meta? }`.
- Fallback behavior
  - Any error (e.g., auth, network, rate limit) → return a local heuristic summary with `used_fallback: true` and an inline error banner in the UI.

---

## Providers and Environment Variables

Set these before starting Flask. The GUI reads them on each analysis request.

Common variables
- `LLM_PROVIDER`: one of `openai_compatible`, `huggingface`, `ollama`, `none`. Synonyms accepted:
  - `openai`, `openai-compatible` → `openai_compatible`
  - `hf`, `hugging_face` → `huggingface`
  - `auto` → picks an available provider by inspecting other env vars
- `LLM_MODEL`: model name (or `OPENAI_MODEL` alias)
- `LLM_MAX_TOKENS` (default 600), `LLM_TEMPERATURE` (default 0.2)
- `LLM_SYSTEM_PROMPT` (advanced; overrides the built‑in system prompt)

OpenAI‑compatible (OpenAI, Groq, OpenRouter, LM Studio, vLLM, etc.)
- `LLM_BASE_URL` (or `OPENAI_BASE_URL`): base endpoint root.
  - Examples: `https://api.openai.com/v1`, `https://api.groq.com/openai`, `http://localhost:1234` (LM Studio), `http://127.0.0.1:8000` (vLLM)
  - The backend intelligently appends the right path (`/v1/chat/completions`) if you only provide the root. If you already include `/v1` it won’t double it.
- `LLM_API_KEY` (or `OPENAI_API_KEY`): secret key.
- `LLM_MODEL` (or `OPENAI_MODEL`): model identifier.

Hugging Face Inference API (serverless)
- `HF_API_KEY` (or `HUGGINGFACEHUB_API_TOKEN`)
- `HF_MODEL` (default: `HuggingFaceH4/zephyr-7b-beta`)
  - If you see 404, the model likely isn’t enabled for serverless inference; try
    `google/flan-t5-large`, `google/flan-t5-base`, or `bigscience/bloomz-560m`.

Ollama (local)
- `OLLAMA_HOST` (or `LLM_OLLAMA_URL`): e.g., `http://localhost:11434`
- `LLM_MODEL`: e.g., `llama3.1:8b`

Auto‑select
- `LLM_PROVIDER=auto` picks in order: `huggingface` (if `HF_API_KEY`), else `openai_compatible` (if `LLM_API_KEY`/`OPENAI_API_KEY` or `LLM_BASE_URL`), else `ollama` (if `OLLAMA_HOST`), else `none`.

---

## Quick Start (macOS/Linux)

1) Create/activate venv and install deps
```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

2) Choose a provider and export env vars
- Groq (OpenAI‑compatible example):
```
export LLM_PROVIDER=openai_compatible
export LLM_API_KEY=YOUR_GROQ_KEY
export LLM_BASE_URL=https://api.groq.com/openai
export LLM_MODEL=llama-3.1-8b-instant
```
- Hugging Face Inference API:
```
export LLM_PROVIDER=huggingface
export HF_API_KEY=hf_xxx
# optional if default 404s:
export HF_MODEL=google/flan-t5-large
```
- LM Studio (local):
```
export LLM_PROVIDER=openai_compatible
export LLM_BASE_URL=http://localhost:1234
export LLM_MODEL=lmstudio-community/llama-3.1-8b-instruct
```
- Ollama (local):
```
export LLM_PROVIDER=ollama
export OLLAMA_HOST=http://localhost:11434
export LLM_MODEL=llama3.1:8b
```

3) Run the GUI
```
export FLASK_APP=apps/gui/src/webapp/app.py
flask run
```

4) In the browser
- Go to the Compare view, run a set of benchmarks, and watch the AI‑Assisted Analysis panel populate. The “Provider” hint shows which backend and model were used; it adds “(fallback)” only when a safe local summary was used due to an error or missing configuration.

---

## Quick Start (Windows PowerShell)

1) Create/activate venv and install deps
```
python -m venv .venv
. .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

2) Set provider env vars
- Groq (OpenAI‑compatible example):
```
$env:LLM_PROVIDER = 'openai_compatible'
$env:LLM_API_KEY  = 'YOUR_GROQ_KEY'
$env:LLM_BASE_URL = 'https://api.groq.com/openai'
$env:LLM_MODEL    = 'llama-3.1-8b-instant'
```
- Hugging Face Inference API:
```
$env:LLM_PROVIDER = 'huggingface'
$env:HF_API_KEY   = 'hf_xxx'
# optional if default 404s:
$env:HF_MODEL     = 'google/flan-t5-large'
```
- LM Studio (local):
```
$env:LLM_PROVIDER = 'openai_compatible'
$env:LLM_BASE_URL = 'http://localhost:1234'
$env:LLM_MODEL    = 'lmstudio-community/llama-3.1-8b-instruct'
```
- Ollama (local):
```
$env:LLM_PROVIDER = 'ollama'
$env:OLLAMA_HOST  = 'http://localhost:11434'
$env:LLM_MODEL    = 'llama3.1:8b'
```

3) Run the GUI
```
$env:FLASK_APP = 'apps/gui/src/webapp/app.py'
flask run
```

4) Use the Compare view as above; the analysis panel generates automatically.

---

## Verifying & Troubleshooting

- Provider hint
  - The panel shows `Provider: <name> • <model>`; it appends `(fallback)` when it used the local heuristic.
- Errors inline
  - If a provider call fails, a red inline banner shows `Provider error: ...` and the endpoint URL. Common cases:
    - 401/403 → invalid/expired API key or missing access.
    - 404 (HF) → model lacks serverless inference; switch to `google/flan-t5-large` or similar.
    - 429 → rate limited; try again or use a different provider/model.
    - 503 (HF) → model loading; the backend retries with backoff.
- Logs
  - Flask logs also record provider failures and fallbacks.
- Network & deps
  - Ensure `requests` is installed (included in `requirements-dev.txt`).
  - Verify local endpoints (LM Studio, vLLM, Ollama) are running and reachable.
- Base URL tips
  - You can set either the full `/v1` root or just the host root; the backend safely composes the final `/v1/chat/completions` path without double‑adding `/v1`.

---

## Customization

- Prompt
  - Set `LLM_SYSTEM_PROMPT` to customize the system message. Keep it short and focused on performance insights (avoid security claims).
- Output length & style
  - `LLM_MAX_TOKENS` and `LLM_TEMPERATURE` control response length and variability.
- Disabling the feature
  - Set `LLM_PROVIDER=none` or unset provider/key envs; the panel will display a deterministic local analysis without any network calls.

---

## Custom Requests (User‑Driven Prompts)

- In the Compare view’s “AI‑Assisted Analysis” panel, there’s now a “Custom request (optional)” text box.
  - Enter anything you want the analysis to focus on (e.g., “Highlight verify latency outliers and memory spikes; recommend choices for microcontrollers”).
  - Click “Generate Analysis” or “Regenerate” to run with your custom request.
- API
  - POST `/api/analysis` accepts an optional string field `request` (aliases: `prompt`, `question`).
  - The backend passes this to `llm.analyze_compare_results(compare, user_request)` so the provider can tailor its response.
- Fallback behavior
  - When no provider is configured or a provider fails, the deterministic local heuristic summary is used and may ignore the custom request.
  - The UI shows “(fallback)” next to the provider hint when this occurs.

UI notes
- The “Custom request” input is fixed‑size within the analysis card and cannot be resized.
- The analysis block supports Markdown (lists, code, emphasis); unsafe HTML is sanitized in the browser.

---

## Code References

- Backend module: `apps/gui/src/webapp/llm.py`
  - `LLMConfig`: reads env vars and selects the provider.
  - `condense_compare(...)`: compresses the results for prompting.
  - `_build_user_prompt(...)`: renders the user prompt.
  - Providers: `_call_openai_compatible(...)`, `_call_huggingface_inference(...)`, `_call_ollama(...)`.
  - Fallback: `_heuristic_summary(...)`.
- HTTP endpoint: `apps/gui/src/webapp/app.py:/api/analysis`
- Frontend trigger: `apps/gui/src/templates/compare_results.html` (auto‑invokes the analysis once results are visible).

---

## Privacy

Only the compact, necessary stats are sent to external providers. Avoid including sensitive or proprietary data in benchmark labels/metadata when using hosted models.
