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

Notes
- Algorithms derive from the same registry and runner logic as the CLI. If an
  algorithm is not supported by your local liboqs build (e.g., XMSSMT), you’ll
  see an error message in the Status panel.
- Mechanism selection honors the same env vars as the CLI (e.g., `PQCBENCH_KYBER_ALG`).
