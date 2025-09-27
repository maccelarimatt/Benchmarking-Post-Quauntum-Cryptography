# pqcbench-gui

Flask-based GUI to run the PQC micro-benchmarks and view results.

Quick start
- Ensure the repo venv is active and dependencies installed:
  - macOS/Linux: `python -m venv .venv && source .venv/bin/activate`
  - Windows (PowerShell): `python -m venv .venv && . .venv\Scripts\Activate.ps1`
  - Then: `pip install -r requirements-dev.txt`
- Launch the GUI:
  - macOS/Linux: `FLASK_APP=apps/gui/src/webapp/app.py flask run`
  - Windows (PowerShell): `$env:FLASK_APP = 'apps/gui/src/webapp/app.py'; flask run`

Usage
- Open the page in your browser (Flask prints the URL, typically http://127.0.0.1:5000/).
- Select an algorithm, set `runs` and (for signatures) `message size`.
- Optionally tick Export and set a results path (defaults to `results/<algo>.json`).
- Click Run to execute and display a JSON summary (same structure as CLI runners).

AI-assisted analysis (free open-source LLM)
- The Compare view includes an “AI-Assisted Analysis” panel that summarizes results.
- No local model is required. Use a hosted open‑weight model via one of these options:
  - Hugging Face Inference API (free tier; rate-limited):
    - Create a (free) HF account and a token at https://huggingface.co/settings/tokens
    - Set environment variables before launching Flask:
      - macOS/Linux:
        - `export LLM_PROVIDER=huggingface`
        - `export HF_API_KEY=hf_xxx` (your token)
        - optional: `export HF_MODEL=HuggingFaceH4/zephyr-7b-beta` (default). If you get 404 from the API, the model likely doesn’t have Serverless Inference enabled — try a serverless‑ready model such as `google/flan-t5-large`, `google/flan-t5-base`, or `bigscience/bloomz-560m`.
      - Windows (PowerShell):
        - `$env:LLM_PROVIDER = 'huggingface'`
        - `$env:HF_API_KEY = 'hf_xxx'`
        - optional: `$env:HF_MODEL = 'HuggingFaceH4/zephyr-7b-beta'`
          - If you see a 404 in the analysis panel, switch to a serverless‑ready model:
            - `$env:HF_MODEL = 'google/flan-t5-large'`
            - or `$env:HF_MODEL = 'google/flan-t5-base'`
            - or `$env:HF_MODEL = 'bigscience/bloomz-560m'`
  - OpenAI-compatible endpoint serving open models (e.g., Groq free tier):
    - Create an API key with your chosen provider.
    - Set environment variables before launching Flask:
      - macOS/Linux:
        - `export LLM_PROVIDER=openai_compatible`
        - `export LLM_API_KEY=your_key`
        - `export LLM_BASE_URL=https://api.groq.com/openai`
        - `export LLM_MODEL=llama-3.1-8b-instant`
      - Windows (PowerShell):
        - `$env:LLM_PROVIDER = 'openai_compatible'`
        - `$env:LLM_API_KEY = 'your_key'`
        - `$env:LLM_BASE_URL = 'https://api.groq.com/openai'`
        - `$env:LLM_MODEL = 'llama-3.1-8b-instant'`

Notes
- If no provider is configured or a call fails, the GUI falls back to a deterministic local heuristic summary (no network).
- The LLM prompt is compact and privacy‑aware; avoid sending sensitive data to third‑party providers unless approved.
- `requests` must be available for external providers. It is included in `requirements-dev.txt`.

Notes
- Algorithms derive from the same registry and runner logic as the CLI. If an
  algorithm is not supported by your local liboqs build (e.g., XMSSMT), you’ll
  see an error message in the Status panel.
- Mechanism selection honors the same env vars as the CLI (e.g., `PQCBENCH_KYBER_ALG`).
