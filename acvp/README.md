
# ACVP harness

- Put large JSON vector files under `acvp/vectors/` (tracked with Git LFS).
- Add small parsing/validation scripts under `acvp/harness/`.
- Keep cacheable artefacts out of git (`.acvp_cache/` is gitignored).

Quick demo
- Run placeholder harness: `python acvp/harness/run_acvp_demo.py`
- Extend with algorithm-specific validators comparing implementation outputs to vectors.
