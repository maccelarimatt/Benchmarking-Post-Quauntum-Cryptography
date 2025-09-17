# Brute-Force Baseline (No Strategy)

This document explains the “no-strategy brute force” baseline added to pqcbench’s security section. The goal is educational context and a sanity-check line in results — not a practical attack path on real parameters.

Key idea: brute force means enumerating a search space of size 2^b until something works. We pick an appropriate “space_bits” b per algorithm family and report the expected time at a few optimistic throughputs.

What we report (per algorithm run):
- model: the brute-force flavor (trial_division_factorization | guess_shared_secret | random_forgery)
- space_bits: b such that the search space is 2^b
- time_years: years to cover 2^b at 1e6 / 1e9 / 1e12 tries/s (value, sci, log10)
- assumptions: short rationale for b and a safety note
- guidance: lab-mode guardrails for toy demos

Family mapping and assumptions
- RSA-OAEP / RSA-PSS:
  - model: trial_division_factorization
  - space_bits: ≈ modulus_bits/2 (trial divide up to sqrt(n))
  - Note: this is purely illustrative; for real 2048-bit RSA, 2^(1024) trials is meaningless. RSA has a sub-exponential attack (NFS) and a polynomial-time quantum attack (Shor).
- KEMs (Kyber, HQC):
  - model: guess_shared_secret
  - space_bits: classical_bits floor (Category 1/3/5 → 128/192/256)
  - Rationale: a “no-strategy” brute force is to try shared secrets until the decapsulation confirmation matches; this reduces to a 2^b search.
- Signatures (Dilithium, Falcon, SPHINCS+/XMSS-MT, MAYO):
  - model: random_forgery
  - space_bits: classical_bits floor
  - Rationale: propose random signatures until the verifier accepts. A secure b-bit scheme accepts a random forgery with probability ≈2^-b per attempt → expect 2^b tries.

Throughput-to-time math (worked examples)
- Assumption: 1e12 tries/s (already generous)
- 128-bit: 2^128 ≈ 3.40e38 trials → ~1.08e19 years
- 192-bit: 2^192 ≈ 6.28e57 trials → ~1.99e38 years
- 256-bit: 2^256 ≈ 1.16e77 trials → ~3.67e57 years
Conclusion: brute force is a teaching tool. On real parameters it is not a viable attack.

Safety and lab guidance
- Never run actual brute-force loops on real parameters. Keep demos to toy spaces (≤ 2^24).
- pqcbench reports times only; it does not run brute-force loops. The JSON includes guidance.lab_mode_max_bits=32 as a hint for test harnesses.

Implementation details
- Module: libs/core/src/pqcbench/bruteforce.py
  - expected_years_to_bruteforce(b, rate): returns years for 2^b trials.
  - bruteforce_summary(...): selects a model and space_bits for the algorithm, then returns a small dict with times at 1e6/1e9/1e12 tries/s and the assumptions.
- Integration point: libs/core/src/pqcbench/security_estimator.py
  - After computing the per-algorithm security metrics, the estimator attaches extras.bruteforce to the security block.
- Export: apps/cli/src/pqcbench_cli/runners/common.py
  - The standardizer copies extras.bruteforce into security.bruteforce in result JSON.

Limitations
- “space_bits” is intentionally simple and conservative. For RSA we use sqrt(n); for lattice/code/hash-based schemes we use the security floor (or curated mid) to define the 2^b baseline.
- For real cryptanalysis, use appropriate estimators (e.g., APS lattice estimator) and literature-backed models. The brute-force baseline is not meant to replace them.

