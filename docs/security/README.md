# Security Estimators for Various Cryptographic Algorithms

This document summarizes the security models and estimators used by pqcbench. The goal is transparent, practical measurements aligned with standards and state‑of‑the‑art cryptanalysis. Outputs are expressed as “bits of security” (log2 of the best‑known attack cost), plus algorithm‑specific resource notes where appropriate.

## Notes
- Unless a stronger model is available, we report conservative floors based on NIST security categories (128/192/256) or standard mappings. When advanced estimators are unavailable in your environment, results clearly indicate floor usage.
- Where quantum attacks fundamentally break the scheme (e.g., RSA), we report 0 bits for quantum security and include resource estimates to quantify feasibility.
- Detailed Shor factoring documentation (logical model, surface-code assumptions, GNFS baseline) lives in [Shor Estimator Playbook](SHOR.md).
- Secret-key Hamming statistics accompany every benchmark (see [Secret-Key Hamming Analysis](#secret-key-hamming-analysis)) so obvious RNG or encoding regressions are surfaced alongside timing metrics.

## Timing Methodology

Benchmark timings isolate the cryptographic primitive under test (keygen, encapsulate, decapsulate, sign, verify) while holding everything else constant.

- **Adapter setup outside the timer.** Adapters are instantiated and cached before timing begins. For factory-based stages we prepare fresh inputs (keys, messages, ciphertexts) inside the child process and only start the stopwatch when the zero-argument operation runs. Environment probing, mechanism selection, and data marshalling are therefore excluded.
- **Process isolation for fairness.** By default (`cold` runs) every iteration executes in a new child process spawned via Python’s `multiprocessing` with the `spawn` context. This resets allocator state, RNG pools, and CPU caches so each run observes the same starting conditions. Passing `--no-cold` switches to a single long-lived process for users evaluating warm-cache behaviour.
- **High-resolution timing + memory.** `_single_run_metrics` samples `perf_counter()` around the operation, collects peak unique-set size (USS) deltas at 1.5 ms cadence, and merges Python heap peaks from `tracemalloc`. Baselines are captured after factories finish so only allocations performed by the timed call contribute.
- **Consistent statistics.** `measure`/`measure_factory` aggregate per-run series with mean, median, min/max, standard deviation, and a 95% confidence interval using the Student t approximation. Memory statistics mirror these summaries when sampling is available.
- **Failure visibility.** Each worker returns status and optional traceback through a pipe; failures abort the run with a clear message rather than silently skewing aggregates.

This architecture ensures that per-run variance stems from the primitive itself (and environmental noise such as OS scheduling), not from setup code that is irrelevant in deployed contexts.

## Secret-Key Hamming Analysis

### What it measures
Every benchmark pass samples a batch of fresh secret keys (32 by default) and
computes lightweight bitstring statistics before anything is persisted:
- **Hamming weight (HW)** – fraction of `1` bits per secret.
- **Hamming distance (HD)** – fraction of differing bits between random key pairs
  (up to 128 sampled pairs).
- **Byte-wise bias** – maximum and mean deviation per byte from the expected
  `1` fraction, catching fixed padding or mis-serialised fields.
Results live under `meta.secret_key_analysis` in exported JSON/CLI output. No raw
keys or per-sample HW/HD values are written to disk; only aggregates are exposed.

### Interpretation models
The analyser selects expectations using mechanism hints (`libs/core/src/pqcbench/params.py`):
| Model | Applies to | Expected HW/HD behaviour |
| --- | --- | --- |
| `uniform_bitstring` | RSA, SPHINCS+, XMSSMT, MAYO, uniform seed blobs | HW ≈ 0.5, HD ≈ 0.5; a ±3σ band (`1/(2√N)`) is reported and warnings fire if the mean drifts outside. |
| `constant_weight` | HQC fixed-weight secrets | HW should equal the published weight `w`; HD expectation uses `2w(1 - w/n) / n`. Any significant deviation triggers a warning. |
| `structured_lattice_blob` | Kyber/ML-KEM, Dilithium/ML-DSA, Falcon | Secrets mix seeds/compressed state. HW/HD are treated as coarse RNG checks without strict warning bands.

If hints are missing (e.g., a new liboqs mechanism string), the analyser still
reports the raw aggregates so reviewers can judge them manually.

### Why it matters
- **RNG sanity:** Drift from the expected HW band flags broken entropy sources or
  truncated reads before deeper analysis occurs.
- **Spec conformance:** Constant-weight schemes rely on the exact number of ones;
  the HW check immediately catches adapter bugs or upstream changes.
- **Regression guardrail:** Because the analysis runs with every benchmark, any
  library upgrade that alters key structure is visible before comparing metrics.
- **Side-channel awareness:** Many leakage models correlate power/EM traces with
  HW/HD. Recording these aggregates helps frame constant-weight countermeasures.

### Tuning and limitations
- Default sampling (`DEFAULT_SECRET_KEY_SAMPLES = 32`, `DEFAULT_PAIR_SAMPLE_LIMIT = 128`) keeps CLI
  runs responsive. Scripts may raise these constants for tighter confidence.
- Lattice coefficient distributions are outside the scope of this helper. Extend
  `pqcbench.key_analysis` if you need coefficient-domain statistics.
- Secrets must be byte-like objects of consistent length; adapters returning other
  structures should continue to expose raw `bytes` to stay compatible.

## Table of Contents
- [RSA (Rivest–Shamir–Adleman)](#rsa-rivestshamiradleman)
- [ML‑KEM (Kyber)](#mlkem-kyber)
- [ML‑DSA (Dilithium)](#mldsa-dilithium)
- [Falcon (FN‑DSA; NTRU lattice)](#falcon-fndsa-ntru-lattice)
- [HQC (code‑based KEM)](#hqc-codebased-kem)
- [SPHINCS+ (stateless hash‑based)](#sphincs-stateless-hashbased)
- [XMSS / XMSS^MT (stateful hash‑based)](#xmss--xmssmt-stateful-hashbased)
- [MAYO (multivariate MQ signatures)](#mayo-multivariate-mq-signatures)
- [Brute-force baseline](#brute-force-baseline)
- [Implementation status](#implementation-status)

## RSA (Rivest–Shamir–Adleman)

### Hardness assumption
Integer factorization. The best classical attack is the General Number Field Sieve (GNFS/NFS) with sub‑exponential complexity L_N[1/3] = exp((c+o(1)) (ln N)^(1/3) (ln ln N)^(2/3)).

### Classical estimation (NFS → symmetric‑equivalent bits)
We follow NIST SP 800‑57 Part 1’s conservative mapping from RSA modulus size (bits) to symmetric strength (bits): 2048→112, 3072→128, 7680→192, 15360→256. For non‑standard sizes, we round down to the nearest threshold. This avoids fragile fitting of asymptotics and matches widely deployed guidance.

### Quantum estimation (Shor + resources)
Shor’s algorithm factors integers in polynomial time. We therefore set quantum_bits = 0 for RSA and complement this with resource‑level estimates to compare feasibility:
- Logical qubits Q ≈ c_q · n (default c_q ≈ 3)
- Toffoli count ≈ c_T · n^3 (default c_T ≈ 0.3)
- Measured depth ≈ c_D · n^2 · log2 n (c_D chosen to yield plausible depths near 2048‑bit)
- Optional surface‑code overhead: given a physical error rate and cycle time, we estimate code distance, total physical qubits, and runtime (very coarse, for comparison only).

### Implementation in pqcbench
The RSA estimator applies SP 800‑57 mapping for classical_bits, sets quantum_bits to 0, and reports Q/Toffoli/T/depth with optional surface-code overhead. In addition, we publish three Shor surface-code scenarios (optimistic/median/conservative) across 2048/3072/4096-bit moduli, listing code distance, physical qubits, and runtime for each. Constants can be switched with a model flag (e.g., “ge2019”, “ge2025”). See `libs/core/src/pqcbench/security_estimator.py`.

### Limitations & notes
These resource estimates are illustrative, not prescriptive. Actual implementations vary significantly with circuit design, error correction, and target architecture. Always consult current literature for precise budgets.

## ML‑KEM (Kyber)

### Hardness assumption
Kyber is a module‑LWE KEM. Security rests on the hardness of LWE over module lattices: given A·s + e = b with small error e, recover s. Parameters (ring dimension n=256, module rank k, modulus q=3329, error distribution with η1/η2) determine difficulty.

### Estimation approach
Lattice security is commonly estimated with the Albrecht–Player–Scott (APS) Lattice Estimator, which evaluates primal/dual/decoding attacks coupled with BKZ reduction and reports the minimal log2 work factor. For Kyber‑512 (k=2 → n_LWE = 512, q=3329, η≈3), public analyses cluster around 2^150–2^160 classical operations with ≈10–15% quantum improvements from Core‑SVP constants (0.292 → 0.26x). We treat the NIST category (Cat‑1 = 128) as a conservative floor but also compute headline estimates from an internal module‑LWE→LWE reduction: convert (n,k,q,η) into an LWE instance, scan BKZ block sizes for primal/dual/hybrid guessing attacks, and translate β with Core‑SVP constants. The result is exposed as a “calculated” classical/quantum range alongside the category floor.

### Quantum considerations
There is no Shor‑style break for LWE. Quantum speedups mostly affect sieving constants (Core‑SVP exponent ~0.292 → Q‑Core‑SVP ~0.265), shaving ≈10–15% from the exponent. We report both classical and “QRAM‑assisted” numbers when the estimator is available; otherwise we include a curated quantum range as context.

### Implementation in pqcbench
`_estimate_kyber_from_name` now performs a module‑LWE→LWE mapping, runs a lightweight BKZ/β cost model (primal, dual, hybrid guessing), and reports the best classical/quantum ranges derived from Core‑SVP constants (0.285–0.300 classical, 0.250–0.270 quantum). The midpoint of the aggressive profile becomes the headline `classical_bits`/`quantum_bits`; the NIST category floor remains available in `extras.category_floor`. Curated literature ranges are still attached for context, and APS outputs continue to override when explicitly requested with `--sec-adv`.

## ML‑DSA (Dilithium)

### Hardness assumption
Dilithium signatures rely on problems in module lattices (Module‑LWE/LWR and Module‑SIS). Forgery reduces to finding short vectors (SIS) or solving an LWE‑type instance. Parameters (n=256, ranks k,l, modulus q=8380417, noise bounds) are chosen so the underlying problems meet target security.

### Estimation approach
Dilithium’s security analysis also relies on core‑SVP. Choose a BKZ blocksize β so an SVP oracle hits the target norm, then convert β into a runtime exponent. Widely used constants: classical ≈0.292·β, quantum ≈0.262·β, with small variations depending on memory/circuit assumptions. pqcbench mirrors this by mapping the module parameters (n,k,q,η) into an LWE instance, scanning primal/dual/hybrid attack families with tuned exponent factors, and returning the best classical/quantum ranges over plausible Core‑SVP constants.

### Public estimates (context)
For common sets, public reports suggest (ballpark):
- ML‑DSA‑44 (Dilithium2): low‑120s classical bits; quantum lower via 0.262/0.292 scaling
- ML‑DSA‑65 (Dilithium3): ≈ mid‑140s classical bits
- ML‑DSA‑87 (Dilithium5): ≈ ~200–220 classical bits
NIST assigns categories to provide conservative floors. pqcbench reports category floors by default and attaches curated ranges for context.

### Implementation in pqcbench
`_estimate_dilithium_from_name` shares the Kyber cost infrastructure: a module‑LWE→LWE reduction with BKZ blocksize search across primal/dual/hybrid guesses. The aggressive profile midpoint becomes the headline `classical_bits`/`quantum_bits`; category floors and curated literature ranges remain in extras for comparison. APS outputs, when available via `--sec-adv`, still override these calculations. See `libs/core/src/pqcbench/security_estimator.py` for details.

## Falcon (FN‑DSA; NTRU lattice)

### Hardness assumption
Falcon signatures reduce to finding short vectors in q‑ary NTRU lattices (dimension ≈ 2n for n=512/1024). The public key encodes an NTRU relation; a forgery/secret‑recovery corresponds to a short vector (f,g) in the underlying lattice.

### Estimation approach
Falcon analyses follow core‑SVP. Choose a BKZ blocksize b and use sieve models to map to runtime exponents: classical ≈ 0.292·b; quantum ≈ 0.262·b (per Falcon docs). Using these, public reports place Falcon‑512 around 110–140 classical bits (often quoted ≈128) and Falcon‑1024 around 200–225 classical bits; quantum figures scale by 0.262/0.292.

### Implementation in pqcbench
We report NIST category floors at top level and attach NTRU parameters (n,q) plus curated mid/range estimates to extras. The Falcon path now also publishes a heuristic BKZ curve for primal and dual NTRU attacks: for β ∈ [100,≈560] we chart classical/quantum exponents (0.292·β / 0.262·β) alongside raw and calibrated success margins (log₂ gap between BKZ output length and the target short-vector norm, σ≈1.17·√(2n)). Calibration anchors the curve to published blocksize estimates (β≈360/400 for Falcon‑512, β≈520/560 for Falcon‑1024), so the calibrated margin crosses zero near those points. These curves surface under `extras.falcon.bkz_model` and in CLI exports to document the model gap until a full estimator is integrated. APS outputs, when available via `--sec-adv`, still override the floors. See `libs/core/src/pqcbench/security_estimator.py` (`_estimate_falcon_from_name`).

## HQC (code‑based KEM)

### Hardness assumption
HQC is a quasi‑cyclic code‑based KEM whose security reduces to decoding random linear codes (syndrome decoding). Given a parity‑check matrix H and a noisy codeword with error weight w, recover the error/message. Best classical attacks are information‑set decoding (ISD) and improvements (Prange, Stern, Dumer, BJMM, May–Ozerov), with sub‑exponential costs depending on (n, k, w).

### Estimation approach
The HQC submission selects parameters so that the minimum ISD workfactor across state-of-the-art algorithms exceeds the target security (2^128/2^192/2^256). pqcbench now contrasts two heuristics: a Stern-style entropy approximation (expected trials ≈ C(n,w)/C(k,⌊w/2⌋)) and a simple BJMM-style meet-in-the-middle approximation. Both report classical time/memory exponents, Grover-style (√) reductions, and a “conservative” 10% reduction to illustrate partial quantum improvements. We also display how the exponents shift as the error weight varies slightly (Δw ∈ {−2,…,+2}). Modern ISD refinements (e.g., Esser et al., PKC 2022) typically lower these numbers further; integrating those tools would tighten the bounds.

### Quantum considerations
There is no Shor‑style polynomial‑time decoder. Quantum speedups mainly apply to search components (e.g., Grover), which can reduce the dominant loop by ≈√; in practice, reductions are often modelled as modest (a handful of bits) for recommended parameters. We report classical floors and attach Grover‑limited/conservative exponents when parameters are available.

### Implementation in pqcbench
The HQC path reports category floors in classical_bits/quantum_bits. When (n,k,w) are available via params, we attach both Stern and BJMM-style heuristics, including classical/quantum/memory exponents and the w-sensitivity samples, under `extras.isd` (surfaced in CLI exports). See `libs/core/src/pqcbench/security_estimator.py` (`_estimate_hqc_from_name`).

## SPHINCS+ (stateless hash‑based)

### Hardness assumption
SPHINCS+ relies only on the security of underlying hash functions (collision and preimage resistance). Forgery boils down to attacks on FORS/WOTS+/Merkle components and thus to hash outputs of length n bits.

### Estimation approach
Designers targeted ≈128/192/256 classical bits for standard parameter sets. We therefore report the NIST category floor at top level and attach variant-specific curated mid/range estimates: e.g., 128s ~133, 128f ~128; 192s ~196, 192f ~194; 256s ~255, 256f ~254 (classical). Quantum attacks do not break hashes, but Grover-type search halves exponents; we therefore present quantum ≈ classical/2 for context.

### Implementation in pqcbench
The SPHINCS+ path parses the mechanism string (family SHA2/SHAKE; variant s/f; 128/192/256) and attaches hash output size, indicative preimage/collision costs, curated estimates, and a small sanity table (`classical_floor`, `quantum_floor`, hash output bits) under `extras.sphincs`. When the mechanism encodes structure (hypertree height/layers, Winternitz w, FORS t), these are surfaced as well. Top-level classical_bits = floor; quantum_bits = floor/2 for comparability. See `libs/core/src/pqcbench/security_estimator.py` (`_estimate_sphincs_from_name`).

## XMSS / XMSS^MT (stateful hash‑based)

### Hardness assumption
Relies solely on hash collision/preimage resistance across WOTS+/Merkle components. XMSS is stateful; reusing a one‑time key voids security.

### Estimation approach
Forgery cost is governed by the smaller of preimage (~2^n) and collision (~2^{n/2}) for n‑bit hashes; collision typically dominates. We therefore estimate classical security ≈ n/2 bits. Quantum algorithms do not break hashes but reduce collision/preimage costs (BHT/Grover), giving indicative quantum ≈ n/3 bits (collision) and n/2 (preimage).

### Implementation in pqcbench
We parse the mechanism string to recover hash output size n and (for XMSSMT) tree height/layers. Top‑level classical_bits = min(category_floor, n/2); quantum_bits ≈ n/3. Extras include structure and hash‑cost context. See `libs/core/src/pqcbench/security_estimator.py` (`_estimate_xmss_from_name`).

## MAYO (multivariate MQ signatures)

### Hardness assumption
MAYO follows the multivariate (MQ) paradigm, related to UOV‑style schemes. Forgery reduces to solving systems of quadratic equations over GF(q). Best‑known attacks include Gröbner basis (F4/F5), relinearization/XL family, and structure‑specific strategies. Hardness depends on variables n, equations m, field size q, and oil/vinegar partition; random systems are hardest near m≈n.

### Estimation approach
Designers choose parameters to meet NIST levels. Without an integrated MQ estimator, pqcbench reports the category floor and attaches heuristic checks when parameters are available: (i) underdefined thresholds (Kipnis–Shamir n≥m(m+1), Miura n≥m(m+3)/2), (ii) naive oil‑guess cost q^o expressed in bits, (iii) qualitative rank-attack indicators (bits + low/medium/high flags), and (iv) MinRank/F4 heuristics (approximate bit costs and degree-of-regularity warnings). These do not replace full MQ cryptanalysis but highlight obviously risky inputs even though MAYO’s “whipping” structure aims to blunt simple attacks.

### Implementation in pqcbench
Top‑level classical_bits and quantum_bits equal the category floor for MAYO levels. Extras include any provided parameters and the full qualitative flag table (extras.mayo.checks). See `libs/core/src/pqcbench/security_estimator.py` (`_estimate_mayo_from_name`).

## Implementation status

RSA is implemented as above and used by the CLI/JSON exports. Other families are integrated at varying levels with clear floor/assumption notes. As advanced estimators and parameters are integrated, the respective sections will be populated with details and references.

## Brute-force baseline

We include an educational brute-force baseline in each security block, labeled by a simple model and a search space size 2^b. For RSA this is "trial_division_factorization" with b≈modulus_bits/2; for KEMs it is "guess_shared_secret" with b≈category floor; for signatures it is "random_forgery" with b≈category floor. Exports report expected time in years at 1e6/1e9/1e12 tries/s. See docs/security/BRUTEFORCE.md for details and assumptions.
