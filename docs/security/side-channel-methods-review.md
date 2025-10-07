# Side-Channel Probe: Methods Review and Literature Mapping

Scope: thorough review of `tools/forensic_probe.py`, with cross-references to `docs/security/side-channel-playbook.md` and `docs/security/forensic-probe-reference.md`, to assess whether the implemented methodology aligns with established side‑channel leakage assessment practices in the literature.

Summary verdict:

- The probe implements a TVLA-style non‑specific leakage assessment (fixed vs toggle classes) with Welch’s t, second‑order TVLA, and complementary non‑parametric tests, plus a mutual information estimator with permutation‑based significance. This matches standard practice described by Goodwill et al. (TVLA) and follow‑on academic work (MIA/Standaert).
- Scenarios for KEMs (valid vs invalid decapsulation) and signatures (fixed vs random messages) are consistent with contemporary timing‑leak case studies such as KyberSlash and with general TVLA methodology.
- The vantage points (remote: wall time; co‑resident: CPU time, memory deltas) are clearly stated and instrumented. Per‑scenario temp isolation and artefact hashing provide a basic forensic surface for spill detection.
- Limitations are clearly documented: Python-level timing, environmental sensitivity, and missing physical power/EM capture. Recommendations are provided for perf/hardware counters and dudect-based C harnesses as a complement.

Overall, the script conforms with the literature for a black‑box, software‑level leakage screen. See “Gaps and Suggestions” for incremental improvements.

## Implemented Methods

The following is a concrete description of what the tool captures, how scenarios are constructed, and which statistical tests and thresholds are applied.

- Bootstrap and registry discovery
  - Adds project paths and imports adapters to populate the PQC registry (`pqcbench.registry`). tools/forensic_probe.py:57
  - Excludes unstable algorithms by default (`xmssmt`) unless explicitly included. tools/forensic_probe.py:92

- Configuration and reproducibility
  - ProbeConfig with defaults: `iterations=800`, deterministic `seed`, optional JSON `--output`, `--keep-artifacts`, explicit filters for `--alg`/`--scenario`, and sanity checks toggles. tools/forensic_probe.py:102
  - TVLA thresholds and test levels: `TVLA_T_THRESHOLD=4.5`, `SIGNIFICANCE_ALPHA=1e-3`, `MI_ALPHA=1e-3`, `MI_PERMUTATIONS=10000`. tools/forensic_probe.py:94

- Vantage points and signals recorded per iteration
  - Wall‑clock time (`perf_counter_ns`) and process CPU time (`process_time_ns`).
  - Memory metrics (RSS before/after/delta, ru_maxrss if available), Python heap via `tracemalloc` (current/peak, deltas), GC counters.
  - Operation payload: hashed outputs (SHA3‑256 + BLAKE2b‑128 digests and lengths) for keys/ciphertexts/secrets/signatures; success/verification flags; error text if any.
  - Host/environment metadata: OS/CPU/freq/cores/memory, git commit(s), relevant env vars; library versions (numpy/scipy/psutil/cryptography/oqs). tools/forensic_probe.py:200

- Isolation and artefacts
  - Every scenario runs in its own temporary directory with `TMP`/`TEMP`/`TMPDIR` overridden; a snapshot of file hashes/size is captured for forensic review and then removed unless `--keep-artifacts` is passed. tools/forensic_probe.py:846

- Scenario catalogue
  - KEM scenarios (TVLA‑aligned decapsulation pair):
    - `keygen` baseline.
    - `encapsulate_fixed_public` for sanity/correlation baselines.
    - `decapsulate_valid` (fixed class): valid ciphertexts for a fixed secret key. tools/forensic_probe.py:317
    - `decapsulate_invalid` (toggle class): corrupted ciphertexts under the same secret key, to exercise error‑handling paths. tools/forensic_probe.py:317
  - Signature scenarios (TVLA pair + negative tests):
    - `keygen` baseline.
    - `sign_fixed_message` (fixed class): sign a single fixed message with a fixed secret key. tools/forensic_probe.py:493
    - `sign_random_message` (toggle class): sign random messages of the same length with the same key. tools/forensic_probe.py:493
    - `sign_fault`: attempt signing with a fault‑tampered secret key to examine error/fault branches (not part of the TVLA pair, but useful for forensic coverage). tools/forensic_probe.py:493
    - `verify_invalid_signature`: verify a corrupted signature on a valid message to exercise verification error paths. tools/forensic_probe.py:493

- Paired analysis and sanity controls
  - Pairs are formed by scenario groups/labels: `kem_tvla_decapsulation: fixed vs invalid` and `signature_tvla_sign: fixed vs random`. tools/forensic_probe.py:989
  - Sanity checks per pair: label‑shuffle (expect no leakage), fixed‑vs‑fixed split (expect no leakage), and toggle‑vs‑toggle split (noise self‑check). tools/forensic_probe.py:989

- Statistical tests and flags
  - For each metric (time, CPU, RSS delta):
    - Welch’s t‑test (non‑equal variance) with TVLA threshold |t| ≥ 4.5 and α = 1e‑3.
    - Second‑order TVLA: Welch’s t on centred‑square samples to detect masked/variance‑based leakage.
    - Non‑parametrics: Mann–Whitney U (two‑sided) and Kolmogorov–Smirnov.
    - Mutual Information: histogram estimator with permutation‑test p‑value (default 10k permutations, α = 1e‑3).
    - Cliff’s delta effect size (derived from one‑sided U statistic).
    - Multiple‑test control: Holm–Bonferroni across {t, t2, Mann‑Whitney, KS} per metric; a leakage flag is set if TVLA threshold passes or any corrected test or MI permutation is significant. tools/forensic_probe.py:989

- Reporting and artefacts
  - In‑terminal recap per analysed pair with |t|, t2, MI, effect sizes, and which vantage(s) flagged (time/CPU/RSS). tools/forensic_probe.py:1240
  - JSON output contains config, host metadata, scenario observations + artefacts, and analysis blocks. tools/forensic_probe.py:1208
  - CLI supports filtering by algorithms/scenarios and controlling iteration count; defaults aim for stability while keeping runtime reasonable. tools/forensic_probe.py:1277

## Alignment With Literature

- TVLA methodology (non‑specific test)
  - Two classes that should be indistinguishable under leak‑free implementations (fixed vs random/invalid), assessed with Welch’s t and conventional pass/fail thresholds. This mirrors Goodwill et al. and ISO/IEC 17825 guidance. docs/security/side-channel-playbook.md:1
  - Second‑order t‑tests are included for masked/variance leakage, which is a common TVLA extension. docs/security/side-channel-playbook.md:1

- Scenario choices
  - KEM decapsulation: valid vs corrupted ciphertext under a fixed secret key directly exercises acceptance vs rejection paths known to differ in cost when not constant‑time. This is consistent with timing‑leak case studies such as KyberSlash.
  - Signature signing: fixed vs random messages with fixed key is the canonical TVLA pattern for signers (exposes message‑dependent control flow or sampling skew).
  - Verification and fault scenarios provide additional negative‑path coverage, aligning with implementation‑level hardening guidance even if not part of strict TVLA pairs.

- Information‑theoretic tests
  - Mutual Information Analysis (MIA) is a standard leakage dependence metric; the script uses a histogram estimator and permutation test to control Type‑I error in a distribution‑agnostic way. docs/security/side-channel-playbook.md:1

- Multiple testing and significance
  - Holm–Bonferroni correction across parametric and non‑parametric tests is a reasonable and conservative approach for combining evidence. The TVLA absolute |t| ≥ 4.5 threshold is widely adopted for pass/fail screening. tools/forensic_probe.py:94

- Threat model and vantage points
  - Distinguishes remote (wall‑clock) and local/co‑resident (CPU time, RSS deltas, optional hardware counters via external tooling). This follows common attacker models in timing/cache studies and is documented in the accompanying methodology. docs/security/side-channel-playbook.md:1

Conclusion: the methodology, scenarios, thresholds, and corrections align with established leakage assessment practices for software‑only screening.

## Parameters and Defaults

- Iterations: default 800 per scenario (TVLA practice often recommends ≥1000 traces per class; consider raising iterations for final assessments).
- Alpha levels: 1e‑3 for t/second‑order/Mann–Whitney/KS; 1e‑3 for MI permutation. These are appropriately strict for screening.
- MI permutations: 10,000 shuffles by default; adequate for low p‑values at the chosen alpha.
- Binning: histogram‑based MI with automatic bin edges; simple and robust, though alternative estimators may be more sensitive (see suggestions).

## Limitations and Risks

- Python‑level instrumentation
  - Wall/CPU timing includes dispatch overhead and GC effects. GC/alloc counters are captured to contextualize, but microarchitectural detail is not visible.
  - Per‑iteration work runs within one process, which is realistic for API timing but limits isolation. Outliers are not trimmed; background scheduling may add variance.

- Environmental sensitivity
  - CPU frequency scaling, thermal throttling, and host load will impact noise. The script captures environment metadata but does not pin cores or fix frequency.

- Metrics scope
  - Memory deltas (RSS) are coarse for leakage; useful to observe egregious error‑path differences but less sensitive than timing.
  - No direct integration of hardware counters; recommended via `perf stat` wrapper is documented but not automatically ingested.

- Estimators and corrections
  - MI estimator uses histograms; more advanced estimators (KNN/KDE) might detect subtle non‑linear effects but raise complexity.
  - Multiple‑test policy is per‑metric; this is reasonable, but global correction across all metrics could be considered to control family‑wise error.

- Coverage
  - KEM encapsulation is not part of a TVLA pair here (only a fixed‑public baseline). This is acceptable since decapsulation is the canonical risky operation; encapsulation TVLA can be added if desired for completeness.

## Suggestions and Enhancements

- Sampling and control
  - Increase iterations to ≥1000 per class for TVLA‑grade runs; run ≥2 independent sessions and compare with the baseline mode described in the docs.
  - Pin CPU affinity and consider disabling Turbo Boost to reduce variance; document commands (`taskset`, `cpupower`) alongside results.

- Estimators and statistics
  - Add effect‑size thresholds (e.g., interpret Cliff’s delta magnitude categories) to contextualize practical significance.
  - Optionally add KNN‑MI/KDE‑MI estimators to complement histogram MI on noisy hosts.
  - Consider adding third‑order TVLA for masked implementations (already listed in roadmap).

- Coverage and counters
  - Integrate `perf stat` collection (cycles, instructions, cache misses) directly into the payload for optional local/co-resident analysis.
  - Add a TVLA pair for KEM encapsulation if there’s concern about encapsulate-side variability.
  - Use the new `--categories`/`--all-categories` flags to sweep Cat-1/3/5 variants without manual environment overrides.
  - Generate publication-ready visuals via `--render-plots`; bar charts of |t| statistics and the CSV export plug neatly into reports.

- CI and native harness
  - Complement with `dudect` runs using a C harness for critical operations (especially KEM decapsulation) to obtain high‑fidelity timing with minimal runtime noise. tools/sidechannel/README.md:1
  - Merge dudect JSON artefacts into the main results to surface max |t| in dashboards.

## How to Validate Correctness in Your Environment

- Quick run to ensure pipeline health
  - `python tools/forensic_probe.py --iterations 10 --output results/forensic_quick.json`
  - Then summarise: `python tools/forensic_report.py results/forensic_quick.json --format markdown --output results/forensic_summary.md`

- TVLA‑style assessment
  - Increase to ≥1000 iterations; run twice with different `--seed` values; compare runs with `--baseline` to ensure flagged leaks persist.
  - For decapsulation timing (Kyber/ML‑KEM), ensure `kem_tvla_decapsulation: fixed vs invalid` shows stable statistics across runs.

- Noise control
  - Use CPU pinning and frequency controls; close background tasks; consider running on an otherwise idle machine.

## Code References (pointers)

- Thresholds and defaults: tools/forensic_probe.py:94
- Config dataclass: tools/forensic_probe.py:102
- KEM scenarios: tools/forensic_probe.py:317
- Signature scenarios: tools/forensic_probe.py:493
- Pairing and analysis: tools/forensic_probe.py:989
- Summary/emit and JSON layout: tools/forensic_probe.py:1208
- CLI: tools/forensic_probe.py:1277
- Methodology docs: docs/security/side-channel-playbook.md:1
- Quick reference: docs/security/forensic-probe-reference.md:1
- Dudect skeleton: tools/sidechannel/README.md:1

## References (as cited in repo docs)

- Goodwill, Jun, Jaffe, Rohatgi. TVLA methodology (ISO/IEC 17825:2016)
- Standaert, Malkin, Yung. Unified framework for side‑channel analysis; Mutual Information Analysis.
- Kocher. Timing attacks on cryptographic implementations.
- Dobraunig/Eichlseder/Panny/Pessl. KyberSlash: decapsulation timing vulnerabilities.
- Halderman et al. Cold‑boot attacks; Kwong et al. RAMBleed.

## Final Assessment

The probe’s design, scenarios, statistics, and thresholds correspond well to the literature for non‑invasive, software‑level side‑channel leakage assessments. Treat results as evidence of dependence, not key‑recovery per se, and use them to guide deeper, implementation‑specific hardening and investigation. For high‑confidence findings on critical paths (e.g., KEM decapsulation), complement with native dudect harnesses and, where appropriate, hardware counter collection or physical measurements.
