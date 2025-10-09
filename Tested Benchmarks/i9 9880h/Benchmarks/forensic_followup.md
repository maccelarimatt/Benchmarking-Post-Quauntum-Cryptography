# Forensic Probe Follow-up Notes

This document captures the current leakage flags (based on `results/forensic_probe_1759068820.json`)
and the next checks recommended per algorithm.

## Kyber (ML-KEM)
- **Finding:** `kem_tvla_decapsulation fixed vs invalid` flags time & CPU (|t| ≫ 4.5).
- **Context:** Matches KyberSlash-style timing leakage when invalid decapsulation shortcuts.
- **Next checks:**
  - Ensure timing window isolates the C decapsulation routine (no Python exception overhead). *(Handled via precomputed ciphertexts outside the timed region.)*
  - Re-run on a build that includes the constant-time division patches and compare results. *(Manual: rebuild Kyber with patches and execute `python tools/forensic_probe.py --alg kyber --output results/kyber_patched.json`, then `python tools/forensic_report.py results/kyber_patched.json --baseline results/forensic_probe_1759068820.json`.)*
  - Collect hardware counters (cycles, branches) under `perf stat` to confirm division-related drift. *(Manual: e.g. `perf stat -x, -e cycles,instructions,branch-misses python tools/forensic_probe.py --alg kyber --iterations 500`).*

## HQC
- **Finding:** `kem_tvla_decapsulation fixed vs invalid` critical time/CPU leak.
- **Context:** Consistent with recent HQC timing attacks leveraging variable-time decoding.
- **Next checks:**
  - Repeat on a patched implementation; confirm mitigations collapse |t| statistics. *(Manual rebuild/testing.)*
  - Keep invalid-path Python handling uniform (constant-sized error objects). *(Handled.)*

## RSA-OAEP
- **Finding:** `kem_tvla_decapsulation fixed vs invalid` leak.
- **Context:** Likely from wrapper-visible error handling rather than OAEP core.
- **Next checks:**
  - Adjust the adapter to return a uniform failure object (no exceptions/strings). *(Handled.)*
  - Re-measure with identical Python control flow for success/failure. *(Manual: rerun `python tools/forensic_probe.py --alg rsa-oaep --output results/rsa_oaep_uniform.json` and compare with `--baseline`.)*

## Dilithium (ML-DSA)
- **Finding:** `signature_tvla_sign fixed vs random` leak.
- **Context:** Accept/reject sampling and message hashing can produce timing variance.
- **Next checks:**
  - Verify we are timing only the C signer with pre-hashed messages. *(Manual instrumentation still required; consider wrapping the signer via dudect.)*
  - Re-run on an implementation advertised as constant-time; compare effect sizes. *(Manual swap-and-rerun.)*

## Falcon
- **Finding:** `signature_tvla_sign fixed vs random` leak.
- **Context:** Gaussian sampling is notoriously difficult to implement constant-time.
- **Next checks:**
  - Evaluate an implementation using a constant-time sampler (e.g., Rossi et al.). *(Manual rebuild.)*
  - Inspect whether randomness setup (PRNG) is contributing to timing spread. *(Partially addressed: constant message length; further profiling required.)*

## MAYO
- **Finding:** `signature_tvla_sign fixed vs random` leak.
- **Context:** Timing leakage not widely reported yet—treat as implementation-specific.
- **Next checks:**
  - Replicate on a second device and alternate implementation (if available).
  - Isolate which step (linear algebra, rejection sampling) varies.

## RSA-PSS
- **Finding:** `signature_tvla_sign fixed vs random` leak.
- **Context:** Unexpected at fixed message length; may stem from wrapper hashing/salt handling.
- **Next checks:**
  - Confirm hashing/salt generation happens outside the timed section. *(Manual inspection/instrumentation required.)*
  - Repeat with pre-hashed input and constant-length salt to see if |t| collapses. *(Partial—messages fixed length; further adapter work needed to use `Prehashed`/deterministic salt for testing.)*

## SPHINCS+
- **Finding:** No leak detected in `signature_tvla_sign` pair.
- **Context:** Matches literature expectations for stateless hash-based signatures.
- **Next checks:**
  - Keep as regression baseline; re-run after any adapter or compiler change.

## General actions
- Re-run the probe on an independent session/host to confirm failures reproduce. *(Manual: vary `--seed` or use another machine.)*
- Use the new out-of-sample comparison (`tools/forensic_report.py --baseline old.json`). *(Manual command after collecting a new dataset.)*
- Record backend/library versions to correlate leaks with upstream fixes. *(Handled automatically in metadata; include in reports.)*
