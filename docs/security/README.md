# Security Estimators for Various Cryptographic Algorithms

This document summarizes the security models and estimators used by pqcbench. The goal is transparent, practical measurements aligned with standards and state‑of‑the‑art cryptanalysis. Outputs are expressed as “bits of security” (log2 of the best‑known attack cost), plus algorithm‑specific resource notes where appropriate.

## Notes
- Unless a stronger model is available, we report conservative floors based on NIST security categories (128/192/256) or standard mappings. When advanced estimators are unavailable in your environment, results clearly indicate floor usage.
- Where quantum attacks fundamentally break the scheme (e.g., RSA), we report 0 bits for quantum security and include resource estimates to quantify feasibility.

## Table of Contents
- [RSA (Rivest–Shamir–Adleman)](#rsa-rivestshamiradleman)
- [ML‑KEM (Kyber)](#mlkem-kyber)
- [ML‑DSA (Dilithium)](#mldsa-dilithium)
- [Falcon (FN‑DSA; NTRU lattice)](#falcon-fndsa-ntru-lattice)
- [HQC (code‑based KEM)](#hqc-codebased-kem)
- [SPHINCS+ (stateless hash‑based)](#sphincs-stateless-hashbased)
- [XMSS / XMSS^MT (stateful hash‑based)](#xmss--xmssmt-stateful-hashbased)
- [MAYO (multivariate MQ signatures)](#mayo-multivariate-mq-signatures)
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
The RSA estimator applies SP 800‑57 mapping for classical_bits, sets quantum_bits to 0, and reports Q/Toffoli/T/depth with optional surface‑code overhead. Constants can be switched with a model flag (e.g., “ge2019”, “ge2025”). See `libs/core/src/pqcbench/security_estimator.py`.

### Limitations & notes
These resource estimates are illustrative, not prescriptive. Actual implementations vary significantly with circuit design, error correction, and target architecture. Always consult current literature for precise budgets.

## ML‑KEM (Kyber)

### Hardness assumption
Kyber is a module‑LWE KEM. Security rests on the hardness of LWE over module lattices: given A·s + e = b with small error e, recover s. Parameters (ring dimension n=256, module rank k, modulus q=3329, error distribution with η1/η2) determine difficulty.

### Estimation approach
Lattice security is typically estimated with the Albrecht–Player–Scott (APS) Lattice Estimator (Python/Sage), which evaluates primal/dual/decoding attacks coupled with BKZ reduction and returns the minimal cost as log2 operations (bits). For Kyber‑512 (k=2 → n_LWE = 512, q=3329, η≈3), NIST’s analysis suggests ≈2^160 operations with plausible uncertainty 2^140–2^180; the Kyber team reported ≈2^151 in a RAM model; independent APS runs often lie in the 2^140–2^150 band. We therefore treat the NIST category (Cat‑1 = 128) as a floor and attach a curated classical range for context.

### Quantum considerations
There is no Shor‑style break for LWE. Quantum speedups mostly affect sieving constants (Core‑SVP exponent ~0.292 → Q‑Core‑SVP ~0.265), shaving ≈10–15% from the exponent. We report both classical and “QRAM‑assisted” numbers when the estimator is available; otherwise we include a curated quantum range as context.

### Implementation in pqcbench
The Kyber path uses category floors for classical_bits and quantum_bits to keep baselines consistent. When available, APS outputs (bits, β, model) replace the floors. Regardless, we attach Kyber parameters (n,k,q,η1,η2) and curated ranges for Kyber‑512 to extras for context. See `libs/core/src/pqcbench/security_estimator.py` (`_estimate_kyber_from_name`).

## ML‑DSA (Dilithium)

### Hardness assumption
Dilithium signatures rely on problems in module lattices (Module‑LWE/LWR and Module‑SIS). Forgery reduces to finding short vectors (SIS) or solving an LWE‑type instance. Parameters (n=256, ranks k,l, modulus q=8380417, noise bounds) are chosen so the underlying problems meet target security.

### Estimation approach
The Dilithium spec follows the "core‑SVP" methodology: choose a BKZ blocksize b so that an SVP oracle succeeds against the target norm, then translate b into a runtime exponent with sieve cost models. Widely used constants are:
- Classical sieve exponent ≈ 0.292 · b
- Quantum sieve exponent ≈ 0.262 · b
These constants are indicative; precise values depend on memory/circuit accounting and the chosen model. Lattice estimator tools (APS) can model both MLWE and MSIS paths and return the minimum cost.

### Public estimates (context)
For common sets, public reports suggest (ballpark):
- ML‑DSA‑44 (Dilithium2): low‑120s classical bits; quantum lower via 0.262/0.292 scaling
- ML‑DSA‑65 (Dilithium3): ≈ mid‑140s classical bits
- ML‑DSA‑87 (Dilithium5): ≈ ~200–220 classical bits
NIST assigns categories to provide conservative floors. pqcbench reports category floors by default and attaches curated ranges for context.

### Implementation in pqcbench
The Dilithium path reports category floors for classical_bits/quantum_bits (baseline comparability), and attaches parameters (n,k,l,q) and curated ranges to extras. When an APS estimator is available (`--sec-adv`), the lattice path can override floors and report β and bits; otherwise we clearly note that the estimator is unavailable. See `libs/core/src/pqcbench/security_estimator.py` (`_estimate_dilithium_from_name`).

## Falcon (FN‑DSA; NTRU lattice)

### Hardness assumption
Falcon signatures reduce to finding short vectors in q‑ary NTRU lattices (dimension ≈ 2n for n=512/1024). The public key encodes an NTRU relation; a forgery/secret‑recovery corresponds to a short vector (f,g) in the underlying lattice.

### Estimation approach
Falcon analyses follow core‑SVP. Choose a BKZ blocksize b and use sieve models to map to runtime exponents: classical ≈ 0.292·b; quantum ≈ 0.262·b (per Falcon docs). Using these, public reports place Falcon‑512 around 110–140 classical bits (often quoted ≈128) and Falcon‑1024 around 200–225 classical bits; quantum figures scale by 0.262/0.292.

### Implementation in pqcbench
We report NIST category floors at top level and attach NTRU parameters (n,q) plus curated mid/range estimates to extras. If an APS estimator is available and `--sec-adv` is used, its outputs (β and bits) override floors. See `libs/core/src/pqcbench/security_estimator.py` (`_estimate_falcon_from_name`).

## HQC (code‑based KEM)

### Hardness assumption
HQC is a quasi‑cyclic code‑based KEM whose security reduces to decoding random linear codes (syndrome decoding). Given a parity‑check matrix H and a noisy codeword with error weight w, recover the error/message. Best classical attacks are information‑set decoding (ISD) and improvements (Prange, Stern, Dumer, BJMM, May–Ozerov), with sub‑exponential costs depending on (n, k, w).

### Estimation approach
The HQC submission selects parameters so that the minimum ISD workfactor across state‑of‑the‑art algorithms exceeds the target security (2^128/2^192/2^256). For rough estimation without external tools, a Stern‑style entropy approximation can be used: expected trials ≈ C(n, w) / C(k, ⌊w/2⌋); taking log2 yields a coarse time exponent. Modern ISD (BJMM/May–Ozerov) typically reduces this exponent; integrating a dedicated estimator (e.g., Esser et al., PKC 2022) gives more accurate figures.

### Quantum considerations
There is no Shor‑style polynomial‑time decoder. Quantum speedups mainly apply to search components (e.g., Grover), which can reduce the dominant loop by ≈√; in practice, reductions are often modelled as modest (a handful of bits) for recommended parameters. We report classical floors and attach Grover‑limited/conservative exponents when parameters are available.

### Implementation in pqcbench
The HQC path reports category floors in classical_bits/quantum_bits. When (n,k,w) are available via params, we attach coarse ISD exponents (log2 time/memory) and two quantum illustrations (Grover‑limited and conservative partial speedup). See `libs/core/src/pqcbench/security_estimator.py` (`_estimate_hqc_from_name`).

## SPHINCS+ (stateless hash‑based)

### Hardness assumption
SPHINCS+ relies only on the security of underlying hash functions (collision and preimage resistance). Forgery boils down to attacks on FORS/WOTS+/Merkle components and thus to hash outputs of length n bits.

### Estimation approach
Designers targeted ≈128/192/256 classical bits for standard parameter sets. We therefore report the NIST category floor at top level and attach variant‑specific curated mid/range estimates: e.g., 128s ~133, 128f ~128; 192s ~196, 192f ~194; 256s ~255, 256f ~254 (classical). Quantum attacks do not break hashes, but Grover‑type search halves exponents; we therefore present quantum ≈ classical/2 for context.

### Implementation in pqcbench
The SPHINCS+ path parses the mechanism string (family SHA2/SHAKE; variant s/f; 128/192/256) and attaches hash output size, indicative preimage/collision costs, and curated estimates under extras.sphincs. Top‑level classical_bits = floor; quantum_bits = floor/2 for comparability. See `libs/core/src/pqcbench/security_estimator.py` (`_estimate_sphincs_from_name`).

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
Designers choose parameters to meet NIST levels. Without an integrated MQ estimator, pqcbench reports the category floor and attaches heuristic checks when parameters are available: (i) underdefined thresholds (Kipnis–Shamir n≥m(m+1), Miura n≥m(m+3)/2), and (ii) naive oil‑guess cost q^o expressed in bits (informational only; MAYO’s “whipping” aims to invalidate simple oil guessing). If any underdefined threshold is met, treat as a red flag for insecurity.

### Implementation in pqcbench
Top‑level classical_bits and quantum_bits equal the category floor for MAYO levels. Extras include any provided parameters and the results of the above checks under extras.mayo. See `libs/core/src/pqcbench/security_estimator.py` (`_estimate_mayo_from_name`).

## Implementation status

RSA is implemented as above and used by the CLI/JSON exports. Other families are integrated at varying levels with clear floor/assumption notes. As advanced estimators and parameters are integrated, the respective sections will be populated with details and references.

