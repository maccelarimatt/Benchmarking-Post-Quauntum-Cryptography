Side-channel checks (dudect/TVLA) – skeleton
===========================================

This folder outlines how to add black-box side-channel leakage checks using
`dudect` alongside your benchmarks. The goal is to produce a JSON artifact with
max |t|-scores that you can merge into your main results for each primitive.

Suggested layout
----------------

- `Makefile` – builds test harnesses and runs dudect with fixed/random classes.
- `src/` – tiny C harnesses that wrap the target decapsulation or signature API.
- `artifacts/` – JSON outputs written by dudect.

Example dudect invocation
-------------------------

```
dudect -- target ./build/decapsulate_mlkem_768 \
  --iterations 200000 --classes fixed,random \
  --out artifacts/dudect_mlkem768.json
```

Integrating with results
------------------------

Add a small parser to read the generated JSON and inject fields into your
benchmark results (e.g., `leak_tscore`, `sidechannel_pass`). A future step can
wire a CLI flag to read from `tools/sidechannel/artifacts/*.json` and merge into
the per-algorithm `security.extras` before export.

Notes
-----

- dudect provides statistical evidence of constant-time behavior but is not a
  formal proof. Use it for regression checks and CI.
- For Kyber/ML-KEM, keep an eye on KyberSlash-style timing risks; re-run dudect
  on decapsulation after dependency updates.

