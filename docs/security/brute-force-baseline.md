# Brute-Force Baseline (No Strategy)

This document explains the “no-strategy brute force” baseline added to pqcbench’s
security section. The goal is educational context and a sanity-check line in
results — not a practical attack path on real parameters.

The key idea: brute force means enumerating a search space of size 2^b until
something works. We choose a “space_bits” value per algorithm family and report
expected runtime at optimistic throughputs.

## Reporting Fields
- **model** – brute-force flavour (`trial_division_factorization`,
  `guess_shared_secret`, or `random_forgery`).
- **space_bits** – b such that the search space contains 2^b candidates.
- **time_years** – runtime in years at 10^6 / 10^9 / 10^12 trials per second
  (exact value, scientific notation, and log10).
- **assumptions** – rationale for b plus a safety reminder.
- **guidance** – lab-mode guardrails for toy demos.

## Family Mapping and Assumptions
- **RSA-OAEP / RSA-PSS**
  - model: `trial_division_factorization`
  - space_bits: ≈ modulus_bits / 2 (trial divide up to √n)
  - note: purely illustrative; real 2048-bit RSA would require 2^1024 trials.
    RSA has realistic sub-exponential (NFS) and quantum (Shor) attacks instead.
- **KEMs (ML-KEM/Kyber, HQC, BIKE, Classic McEliece, FrodoKEM, NTRU, NTRU Prime)**
  - model: `guess_shared_secret`
  - space_bits: category floor (Cat 1/3/5 → 128/192/256 bits)
  - rationale: brute-force shared secrets until confirmation succeeds; reduces
    to a 2^b search.
- **Signatures (ML-DSA/Dilithium, Falcon, SPHINCS+/XMSS-MT, SLH-DSA, CROSS, MAYO, SNOVA, UOV)**
  - model: `random_forgery`
  - space_bits: category floor
  - rationale: submit random signatures until the verifier accepts; acceptance
    probability is ≈2^-b, so expect 2^b attempts.

## Throughput Examples
- Assuming 10^12 trials per second (already generous):
  - 128-bit: 2^128 ≈ 3.40 × 10^38 trials → ~1.08 × 10^19 years.
  - 192-bit: 2^192 ≈ 6.28 × 10^57 trials → ~1.99 × 10^38 years.
  - 256-bit: 2^256 ≈ 1.16 × 10^77 trials → ~3.67 × 10^57 years.

Brute force is therefore a teaching tool; real parameters remain out of reach.

## Safety Notes
- Do not run brute-force loops on real parameters. Keep demos to toy spaces
  (≤ 2^24).
- pqcbench reports times only; it never executes brute-force loops. The JSON
  surface includes `guidance.lab_mode_max_bits = 32` as a hint for lab scripts.

## Implementation Hooks
- `libs/core/src/pqcbench/bruteforce.py`
  - `expected_years_to_bruteforce(b, rate)` returns the runtime for 2^b trials.
  - `bruteforce_summary(...)` picks the model/space bits and returns the report.
- `libs/core/src/pqcbench/security_estimator.py`
  - attaches `extras.bruteforce` to each security block after estimation.
- `apps/cli/src/pqcbench_cli/runners/common.py`
  - copies `extras.bruteforce` into `security.bruteforce` in CLI/JSON exports.

## Limitations
- “space_bits” intentionally mirrors conservative floors. RSA uses √n; other
  schemes reuse the category floor or curated mids.
- For real cryptanalysis, use appropriate estimators (e.g., APS lattice
  estimator) and literature-backed models. The brute-force baseline does not
  replace them.
