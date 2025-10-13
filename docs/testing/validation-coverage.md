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

> **Dilithium note.** Recent liboqs snapshots (e.g., commit `f629296e`) ship a
> deterministic `vectors_sig` binary that diverges from the ACVP fixtures tracked
> in this repo, producing `signature doesn't match` errors even when the adapter
> succeeds. See `docs/issues/dilithium-validation-known-issue.md` for mitigation
> options (pin to a matching liboqs tag, rebuild with
> `-DOQS_USE_OPENSSL_SHA3=OFF`, or skip Dilithium validation until the upstream
> fix lands).

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
| BIKE / `run-bike` | liboqs deterministic KAT (`source: liboqs_kat`) | `kat_kem:BIKE-L*` | Executes `kat_kem --all`; covers whichever BIKE level the adapter resolved. |
| Classic McEliece / `run-classic-mceliece` | liboqs_kat | `kat_kem:Classic-McEliece-*` | Runs `kat_kem --all` for the concrete Classic McEliece parameter set. |
| FrodoKEM / `run-frodokem` | liboqs_kat | `kat_kem:FrodoKEM-*` | Uses liboqs `kat_kem --all`; AES and SHAKE variants are honoured. |
| NTRU / `run-ntru` | liboqs_kat | `kat_kem:NTRU-*` | Deterministic `kat_kem` check for the chosen NTRU flavour. |
| NTRU Prime / `run-ntruprime` | liboqs_kat | `kat_kem:sntrup761` | Current liboqs snapshot ships sntrup761 KATs; other variants report `unsupported`. |
| HQC / `run-hqc` | liboqs_kat | `kat_kem:HQC-*` | Falls back to `kat_kem --all`; works for both core and `*-1-CCA2` aliases. |
| RSA-OAEP / `run-rsa-oaep` | Built-in static KAT (`source: builtin_kat`) | `rsa-oaep:static-v1` | Decapsulates a fixed OAEP ciphertext with the deterministic 2048-bit key. |
| Dilithium / `run-dilithium` | ACVP | `ML-DSA:FIPS204` keyGen/sigGen/sigVer | Requires liboqs `vectors_sig`. |
| Falcon / `run-falcon` | liboqs deterministic KAT (`source: liboqs_kat`) | `kat_sig:Falcon-{512,1024}` | Executes `kat_sig --all` and hashes the transcript—reported as one case. |
| SPHINCS+ / `run-sphincsplus` | ACVP / liboqs KAT fallback | `SLH-DSA:FIPS205` or `kat_sig:*` | ACVP covers the `*-simple` presets; other variants fall back to `kat_sig --all`. |
| SLH-DSA / `run-slh-dsa` | ACVP / liboqs KAT fallback | `SLH-DSA:FIPS205` or `kat_sig:*` | Pure profiles use ACVP vectors when available; remaining presets use deterministic KATs. |
| CROSS / `run-cross` | liboqs_kat | `kat_sig:cross-*` | Covers all CROSS RSDP/RSDPG variants via `kat_sig --all`. |
| MAYO / `run-mayo` | liboqs_kat | `kat_sig:MAYO-*` | Deterministic `kat_sig` run for the selected MAYO parameter set. |
| SNOVA / `run-snova` | liboqs_kat | `kat_sig:SNOVA_*` | Uses `kat_sig --all`; includes the eight SNOVA candidates exposed by the adapter. |
| UOV / `run-uov` | liboqs_kat | `kat_sig:OV-*` | Deterministic `kat_sig` coverage for OV and pkc/pkc+skc variants. |
| XMSS^MT / `run-xmssmt` | liboqs_kat | `kat_sig_stfl:XMSSMT-*` | Uses the stateful liboqs deterministic harness (`kat_sig_stfl --all`). |
| RSA-PSS / `run-rsa-pss` | Built-in static KAT | `rsa-pss:static-v1` | Verifies a pre-computed PSS signature with the fixed key. |

Remaining unsupported runners (currently only algorithms not exposed through adapters) report a descriptive skipped status so dashboards remain consistent.

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
