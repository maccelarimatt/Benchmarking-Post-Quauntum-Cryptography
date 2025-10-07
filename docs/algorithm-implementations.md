# Algorithm Implementations and Benchmark Notes

This document explains how the classical and post‑quantum algorithms are implemented in this repo, what each benchmark stage actually measures, and why you see large differences between “classical” RSA and PQC schemes (especially on key generation).

## Backends at a Glance

- PQC (Kyber/ML‑KEM, HQC, Dilithium/ML‑DSA, Falcon, SPHINCS+, XMSSMT, MAYO)
  - Primary: liboqs C implementations exposed via `python-oqs` adapters.
  - Optional: native C wrapper (`pqcbench_native`) that calls liboqs directly (no Python in hot path).
- Classical RSA baselines
  - Python: `cryptography` (OpenSSL) for RSA‑OAEP and RSA‑PSS.
  - Native C: `pqcbench_native` with RSA implemented by either OpenSSL or GNU Nettle+GMP (auto‑selected at build time).
- Security categories (GUI/CLI “Category 1/3/5”) map RSA modulus sizes to 3072/7680/15360 bits and the PQC parameters to their NIST level equivalents. The GUI sets `PQCBENCH_RSA_BITS` so both Python and native RSA respect the selected category.

## Benchmarking Methodology (Fairness)

- Each timing sample runs the core operation in a fresh process (“cold” mode), so imports, allocator pools, or warmed caches don’t skew results.
- For multi‑stage ops we split out the “core” work:
  - KEM: `keygen`, then `encapsulate` (with a prepared public key), then `decapsulate` (with prepared keys and ciphertext).
  - SIG: `keygen`, then `sign` (with prepared key/message), then `verify` (with prepared key/message/signature).
- Memory is the per‑run peak unique RSS delta (plus Python heap peak) sampled ~every 1.5 ms; it reflects transient working‑set growth during the measured operation, not just output sizes.

## Why RSA KeyGen Looks “Heavy”

- RSA key generation samples random large integers and runs primality/probable‑prime tests until finding suitable primes `p` and `q`, followed by CRT parameter derivation (`d`, `qInv`, etc.).
- OpenSSL / Nettle allocate and juggle large big‑integer buffers (BN, GMP mpz), Montgomery reduction contexts, and temporary workspaces during this process.
- Typical magnitude at 2048–3072 bits on a modern desktop CPU:
  - Tens of milliseconds for keygen latency.
  - Around 0.7–0.8 MB peak RSS delta during keygen.

> RSA keygen does primality testing and CRT parameter derivation; OpenSSL allocates large big‑integer buffers. Tens of ms and ~0.7–0.8 MB transient RSS delta are normal at 2048–3072 bits.

### RSA in this repo

- KEM baseline (RSA‑OAEP): not a real KEM — we sample a random 32‑byte shared secret and encrypt it with RSA‑OAEP (SHA‑256, MGF1, empty label) to produce a comparable “encapsulate/decapsulate” pair.
- Signature baseline (RSA‑PSS): SHA‑256 with PSS salt length equal to the hash size; MGF1(sha256).
- Backends:
  - Python `cryptography` → OpenSSL.
  - Native `pqcbench_native` → OpenSSL, or GNU Nettle+GMP when OpenSSL isn’t available. The GUI labels which flavor was used.

## Why PQC KeyGen Is “Light” (By Comparison)

> PQC keygens are matrix/vector sampling and NTT/poly arithmetic in constant‑time C; they’re typically sub‑millisecond to low‑millisecond with modest memory.

### KEMs

- Kyber / ML‑KEM (lattice, module‑LWE)
  - KeyGen: sample small‑norm polynomials, compute public key via NTT‑based polynomial arithmetic.
  - Ops are fast, cache‑friendly, and implemented in optimized C; typical keygen ≈ 0.5–1.5 ms on desktop CPUs, memory tens of KB.

- HQC (code‑based)
  - KeyGen: generate secret vectors and public parity‑check structure; dense linear algebra over GF(2).
  - More variable transient memory due to buffer sizes, still far below RSA keygen.

### Signatures

- Dilithium / ML‑DSA (module‑lattice)
  - KeyGen and signing rely on sampling small vectors and NTT polynomial multiplication; low‑ms latency typical.

- Falcon (NTRU lattice)
  - KeyGen involves discrete Gaussian sampling and floating‑point lattice techniques; modestly heavier than Dilithium, but still far below RSA keygen.

- SPHINCS+ (hash‑based)
  - Stateless, tree‑based construction; keygen is very light, signing/verify can be heavier depending on parameter set (s/f variants). Memory dominated by hash stacks/buffers.

- XMSSMT (stateful hash‑based)
  - Designed for stateful keys (one‑time signatures per leaf); our micro‑bench always uses fresh keys per run for fairness.

- MAYO (multivariate)
  - Multivariate signature scheme; operations are matrix/polynomial over finite fields. Performance sits between Dilithium and SPHINCS+ depending on parameter set and implementation.

## Interpreting the Charts

- RSA `keygen` bars being much higher (time and KB) than PQC is expected; this is not an artifact of the harness.
- RSA `encapsulate`/`decapsulate` (OAEP) and `verify` are relatively lean compared to `keygen`, but still reflect big‑integer modular exponentiations and buffer churn.
- PQC operations are implemented in optimized constant‑time C; even at higher categories they avoid the large big‑integer memory churn seen in RSA keygen.

## Implementation Specifics (per adapter)

- liboqs adapters (PQC)
  - Choose concrete mechanisms through environment variables: `PQCBENCH_KYBER_ALG`, `PQCBENCH_HQC_ALG`, `PQCBENCH_DILITHIUM_ALG`, `PQCBENCH_FALCON_ALG`, `PQCBENCH_SPHINCS_ALG`, `PQCBENCH_XMSSMT_ALG`, `PQCBENCH_MAYO_ALG`.
  - If unset, we pick reasonable defaults (e.g., ML‑KEM‑768, ML‑DSA‑65).

- RSA adapters (classical)
  - Security categories set `PQCBENCH_RSA_BITS` (3072/7680/15360). Both Python and native RSA adapters honor this.
  - Python adapter: `cryptography` (OpenSSL) for RSA‑OAEP and RSA‑PSS.
  - Native adapter: OpenSSL or Nettle+GMP (auto‑selected at build); GUI shows which backend was used.

## Measurement Details

- Cold runs: each sample runs in a child process; operation setup happens before the timer starts so only the core step is measured.
- Memory: peak unique RSS (and Python heap peak if available), measured during the core step only.
- We export per‑op series, mean/median/min/max/stddev, and 95% CI. GUI “Compare” aggregates these across selected algorithms.

## Caveats and Notes

- The RSA‑OAEP KEM wrapper is a comparison baseline only; actual PQ KEMs have different security models.
- Different liboqs versions can have slightly different buffer usage or parameter defaults; we record liboqs commit/build flags in the metadata.
- If `python-oqs`/liboqs is missing, the PQC adapters fallback to placeholders (not used for comparisons); the GUI and CLI label the backend so accidental placeholder runs are easy to spot.

