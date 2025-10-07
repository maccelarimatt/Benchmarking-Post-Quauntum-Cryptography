# Validation Coverage

This repository can attach lightweight conformance checks to every CLI runner
when `--tests` is supplied. The checks are consolidated into the `validation`
block of the exported JSON and printed to the terminal (prefixed with
`[ACVP]` or `[KAT]`). This document describes how to enable the infrastructure
and which algorithms currently carry vector coverage.

## 1. Building the validation helpers

The Kyber/Dilithium/SPHINCS+/Falcon helpers rely on liboqs test binaries. Build
them once after cloning:

```bash
cmake -S native -B native/build -DPQCBENCH_ENABLE_LIBOQS_TESTS=ON
cmake --build native/build --target vectors_kem vectors_sig kat_sig
```

Fetch the ACVP vector bundles that are tracked via Git LFS:

```bash
git lfs pull liboqs/tests/ACVP_Vectors
```

The RSA checks are self-contained and do not require liboqs.

## 2. Running a runner with validation

Every runner accepts a `--tests` flag. Example:

```bash
run-kyber --runs 2 --tests --export results/kyber.json
run-rsa-pss --tests --runs 2 --message-size 2048 \
  --export results/rsa_pss_sec.json
```

The CLI prints a short status line and the exported JSON contains a
`validation` object:

```json
"validation": {
  "source": "acvp",
  "vectorset": "ML-KEM:FIPS203",
  "mechanism": "ML-KEM-768",
  "cases": 180,
  "passes": 180,
  "fails": 0,
  "status": "ok",
  "git_sha": "…"
}
```

## 3. Coverage by algorithm

| Algorithm / Runner | Validation Source | Vectorset / Check | Notes |
| --- | --- | --- | --- |
| Kyber / `run-kyber` | ACVP (`source: acvp`) | `ML-KEM:FIPS203` keyGen/encap/decap | Uses liboqs `vectors_kem`; honours mechanism selection. |
| HQC / `run-hqc` | *Skipped* | — | No public ACVP vectors yet; `validation.status=skipped` explains this. |
| RSA-OAEP / `run-rsa-oaep` | Built-in static KAT (`source: builtin_kat`) | `rsa-oaep:static-v1` | Decapsulates a fixed OAEP ciphertext with the deterministic 2048-bit key. |
| Dilithium / `run-dilithium` | ACVP | `ML-DSA:FIPS204` keyGen/sigGen/sigVer | Requires liboqs `vectors_sig`. |
| Falcon / `run-falcon` | liboqs deterministic KAT (`source: liboqs_kat`) | `kat_sig:Falcon-{512,1024}` | Executes `kat_sig --all` and hashes the transcript—reported as one case. |
| SPHINCS+ / `run-sphincsplus` | ACVP | `SLH-DSA:FIPS205` | Covered for the `*-simple` variants that map to ACVP parameter names; other presets are skipped. |
| XMSS^MT / `run-xmssmt` | *Skipped* | — | No standard vectors; message clarifies the gap. |
| RSA-PSS / `run-rsa-pss` | Built-in static KAT | `rsa-pss:static-v1` | Verifies a pre-computed PSS signature with the fixed key. |
| MAYO / `run-mayo` | *Skipped* | — | No vector suites available. |

All other runners (e.g. `run-mayo`, `run-hqc`) report a descriptive skipped
status so dashboards remain consistent.

## 4. JSON semantics

The validation block is consistent across algorithms:

* `source` – where the vectors came from (`acvp`, `liboqs_kat`, or
  `builtin_kat`).
* `vectorset` – human-readable identifier (FIPS vectorset or the name of the
  deterministic check).
* `mechanism` – concrete mechanism string resolved at runtime.
* `cases`, `passes`, `fails` – aggregate counts (Falcon/RSA KATs run as a single
  coarse case).
* `status` – `ok`, `failed`, `no_cases`, or `skipped`.
* `reason` – present only when skipped/missing.
* `fail_examples` – up to three snippets from stderr/stdout when a failure
  occurs.
* `git_sha` – HEAD revision of the `liboqs` checkout when vectors originate
  there.

## 5. Troubleshooting

* `missing_binary` or `missing_vectors` – rebuild liboqs with
  `PQCBENCH_ENABLE_LIBOQS_TESTS=ON` and ensure Git LFS assets are present.
* `unsupported` – the runner currently lacks vector coverage (see table above).
* Deterministic KAT failures – re-run after cleaning the virtualenv; if the
  static vectors fail, investigate the RSA adapter for behavioural changes.

Keeping the tests lightweight ensures the CLI remains snappy while still
providing reproducible evidence of functional correctness for supported
algorithms.
