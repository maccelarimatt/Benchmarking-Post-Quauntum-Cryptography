# Forensic Probe Quick Reference

For a narrative, reader-friendly explainer of the side-channel methodology,
see `docs/security/side_channel.md`. This document serves as a concise quick
reference for the probe’s usage.

## Motivation and research baseline

- **Leakage validation.** The probe follows the Test Vector Leakage Assessment
  (TVLA) methodology (Goodwill et al., 2011; ISO/IEC 17825:2016) by comparing
  "fixed" versus "variable" secret executions with Welch's *t*-tests and
  complementary non-parametric checks. KyberSlash-style timing leaks (Dobraunig
  et al., 2023) and Dilithium timing artefacts illustrated that simple timing
  measurements still expose exploitable side channels.
- **Forensic artefacts.** Cold-boot memory attacks (Halderman et al., 2008)
  demonstrate that post-execution residues can survive power cycles, while
  RAMBleed (Kwong et al., 2020) exemplifies active Rowhammer-style reads that
  leak neighbouring keys. The probe snapshots dedicated temp directories per
  scenario so secret-dependent file activity is observable without persisting
  raw secrets.
- **Academically grounded analysis.** Beyond Welch's *t*-test, the tool reports
  Mann–Whitney U statistics (for distribution-free confirmation) and mutual
  information estimates (Standaert et al., 2011) to flag non-linear
  correlations.

## What the probe captures

| Capture class | Details |
| --- | --- |
| Timing | High-resolution wall-clock (`perf_counter_ns`) and CPU time per iteration. |
| Memory | RSS before/after, RSS deltas, optional `ru_maxrss` peak, Python heap deltas via `tracemalloc`. |
| GC / allocation | Python GC counters and allocation deltas per iteration. |
| Cryptographic outputs | Only hashed metadata (SHA3-256 + BLAKE2b-128 digests, lengths) for keys, ciphertexts, signatures. No raw material is retained. |
| Success/Failure | Exceptions captured verbatim for forensic review; success flags for secret/share comparisons. |
| Host metadata | OS/CPU profile, frequency, thread count, load, total memory, git commit, relevant env vars (`PQCBENCH_*`, `OQS_*`, `OPENSSL_ia32cap`, `PYTHONHASHSEED`). |
| Artefacts | Dedicated temp directory snapshot (file hashes/size). Directory is deleted unless `--keep-artifacts` is used, but metadata survives in the JSON report. |

### Scenario catalogue

The script enumerates algorithms via `pqcbench.registry` and instantiates a
fresh adapter per scenario. Available scenarios differ by kind:

- **KEMs**: `keygen`, `encapsulate_fixed_public`, `decapsulate_valid`
  *(TVLA fixed class: valid ciphertexts under a fixed secret key)*,
  `decapsulate_invalid` *(TVLA toggle class: deliberately faulted ciphertexts
  under the same secret key).* 
- **Signatures**: `keygen`, `sign_fixed_message` *(TVLA fixed class: fixed
  message under a fixed secret key)*, `sign_random_message` *(TVLA toggle class:
  random messages under the same secret key)*, `sign_fault` *(tampered key)*,
  `verify_invalid_signature` *(error-handling traces).* 

Each scenario runs in a private temp directory with environment overrides
(`TMP`, `TEMP`, `TMPDIR`) so any spillovers are isolated.

### Statistical analysis

For every group with at least two labels (e.g.,
`kem_tvla_decapsulation: fixed` vs `invalid`), the probe computes:

- Welch's *t*-statistic (timing, CPU, RSS delta). A |*t*| ≥ 4.5, combined with a
  Holm–Bonferroni corrected *p* ≤ 10⁻³, mirrors the TVLA "fail" threshold.
- Second-order TVLA (Welch’s *t* on centred-square samples) to surface masked
  or variance-based leakage.
- Mann–Whitney U and Kolmogorov–Smirnov two-sample tests to capture
  distribution shifts without normality assumptions (corrected with the same
  Holm–Bonferroni policy).
- Mutual information between class label and metric using a histogram estimator
  plus a permutation-based *p*-value (default 10 000 shuffles, α = 10⁻³).
- Cliff's delta accompanies each metric as an effect-size indicator so practical
  impact is visible alongside p-values.
- Automatic sanity checks run after each pair: label-shuffle (expect pass) and
  fixed-vs-fixed split (expect pass). Failures here indicate excessive noise or
  insufficient sampling.

Leakage flags are raised when any of these corrected tests or the MI
permutation test reports significance. Each scenario should be run with two
independent sample sets (≥1 000 traces per class recommended in TVLA practice)
to validate stability.

## Installation and prerequisites

1. Ensure project dependencies are set up. At minimum:
   ```bash
   pip install -r requirements-dev.txt
   ```
   (`numpy`, `scipy`, `psutil` are required for the probe.)
2. Optional: install `python-oqs`/liboqs so that real adapters are available. If
   absent, placeholder adapters still execute but with dummy values.
3. Optional hardware counters: run the script under `perf stat` or similar tools
   to collect microarchitectural counters. Example:
   ```bash
   perf stat -x, -e cycles,instructions,cache-misses \
     python tools/forensic_probe.py --iterations 200 --alg kyber
   ```

## Running the probe

- Default run (800 iterations per scenario, all algorithms):
  ```bash
  python tools/forensic_probe.py
  ```
- The probe skips `xmssmt` by default because the adapter is currently unstable.
  Explicitly target it with `--alg xmssmt` to override the safeguard.
- Restricting work:
  ```bash
  # Only Kyber + Dilithium, keep raw artefacts for manual inspection
  python tools/forensic_probe.py --alg kyber dilithium --keep-artifacts
  ```
- Quick smoke test:
  ```bash
  python tools/forensic_probe.py --iterations 10 --output results/forensic_quick.json
  ```

After collecting data, distil TVLA-style findings into an executive summary:
```bash
python tools/forensic_report.py results/forensic_quick.json --format markdown --output results/forensic_summary.md
```
This highlights which algorithms/scenarios breached timing, CPU, or RSS thresholds and records the supporting statistics.

Supply `--baseline other_run.json` to compare a new dataset against an older
collection and inspect deltas in |t| and MI across machines or sessions.

The CLI options:

| Option | Meaning |
| --- | --- |
| `--iterations` | Samples per scenario (default 800). High values stabilise statistics. |
| `--seed` | Deterministic seed for helper randomness (messages, fault injection). |
| `--alg` | Filter registry keys (e.g., `kyber`, `dilithium`). |
| `--scenario` | Run a subset of scenarios by name. |
| `--exclude` | Exclude specific registry keys (adds to the default skip list). |
| `--no-sanity-checks` | Skip shuffle/split controls (not recommended except for debugging). |
| `--keep-artifacts` | Leave per-scenario temp directories in place. |
| `--output` | Custom output path (defaults to `results/forensic_probe_<epoch>.json`). |

## Output format

The JSON artefact contains three top-level blocks:

- `config`: the effective CLI configuration.
- `host`: environment metadata.
- `scenarios`: per-scenario records with observations and temp file hashes.
- `analysis`: statistical summaries with leakage flags.

Each `observation` entry stores metrics for a single iteration:

```json
{
  "algorithm": "kyber",
  "scenario": "decapsulate_valid",
  "iteration": 12,
  "wall_time_ns": 823456,
  "cpu_time_ns": 812345,
  "rss_delta": 4096,
  "alloc_delta": 512,
  "payload": {
    "ciphertext_length": 1088,
    "ciphertext_sha3": "…",
    "shared_secret_blake2b": "…",
    "match_shared_secret": true
  }
}
```

### Reading the analysis report

`emit_summary` prints one-line recaps per analysed pair. Example output:

```
kyber [ML-KEM-768] kem_tvla_decapsulation:fixed vs invalid: |t_time|=5.12, |t_cpu|=5.07, |t_rss|=0.44, t2_time=4.63, MI=0.0314/0.0298/0.0001, Δ=0.42/0.38/0.05 -> flags: time, cpu
```

Interpretation:

- `|t_time|`/`|t_cpu|` over 4.5 with corrected *p* ≤ 10⁻³: statistically significant timing difference.
- `t2_time` > 4.5 indicates second-order leakage (useful for masked code).
- `MI` reports mutual information for (time/cpu/rss); the permutation *p*-value highlights whether dependence is statistically meaningful.
- `Δ` lists Cliff's delta effect sizes (time/cpu/rss).
- `flags` enumerate which metrics tripped thresholds.

### Recommended follow-up checklist

1. **Confirm reproducibility.** Re-run with the same seed, observe stability.
2. **Noise control.** Pin CPU cores (`taskset`/`cpuset`), disable Turbo Boost,
   close background tasks to reduce scheduling variance.
3. **Summarise indicators.** Run `tools/forensic_report.py` on the JSON output to
   rank algorithm/scenario combinations and record the supporting metrics.
4. **Inspect artefacts.** When `--keep-artifacts` is enabled, manually review
   the captured temp directories for key remnants, crash dumps, or logs.
5. **Deep-dive metrics.** Use the JSON output with notebooks to visualise
   histograms, QQ-plots, or run additional tests (e.g., clustering, KDE).
6. **Per-algorithm follow-up.** See `results/forensic_followup.md` for current
   notes and next-step checklists derived from the latest run.

## Detailed findings template

Once data is collected, populate a narrative similar to the following (store
alongside the JSON output):

```
Algorithm: ML-KEM-768
Scenario pair: kem_tvla_decapsulation fixed vs invalid
Iterations: 1 000 per class × 2 independent sessions
Leakage indicators: |t|=5.12 (time, corrected p=7e-5), |t|=4.98 (cpu, corrected p=2e-4),
                    t2_time=4.63 (p=1e-3), MI_time=0.031 (perm p=6e-4), Δ_time=0.42
Suspected cause: Branch misprediction on decrypt failure path.
Artefacts: No files written; stderr clean.
Follow-up: collect traces with perf record; inspect decapsulation constant-time guard.
```

Repeat for each algorithm/parameter set, referencing `analysis` entries and
artefact snapshots.

## Extending the probe

- Add new scenarios by appending to `build_kem_scenarios`/`build_signature_scenarios`.
- Incorporate extra metrics (e.g., hardware counters) by wrapping `operation`
  in external tooling, then merging resulting CSV/JSON into the payload.
- For algorithm-specific fixed inputs (e.g., deterministic ciphertexts), adjust
  the scenario builders to load vectors from disk.

## Limitations and cautions

- **Backend availability.** Without liboqs/native adapters the probe exercises
  placeholder implementations. Install real backends before drawing conclusions.
- **Coarse-grained timing.** Python-level instrumentation cannot observe
  microarchitectural events directly. Use external profilers for fine detail.
- **Environmental sensitivity.** Results depend heavily on host load, CPU
  frequency scaling, and thermal throttling. Record host metadata and replicate
  under controlled conditions.
- **Stateful signatures.** XMSS/XMSSMT consume state; reruns reset state because
  the adapter is reinstantiated per scenario. Treat results carefully.
- **Forensic scope.** The tool snapshots temp directories only. If algorithms
  emit logs elsewhere, incorporate OS-level tracing (auditd, fsnotify) manually.
- **Hardware counters.** Collecting events via `perf stat` or similar introduces
  a local/co-resident attacker vantage; report those results separately from
  remote timing observations.

## References

- Goodwill, B., Jun, B., Jaffe, J., Rohatgi, P. (2011). *A Testing Methodology
  for Side-Channel Resistance Validation.* ISO/IEC 17825:2016.
- Dobraunig, C., Eichlseder, M., Panny, T., Pessl, P. (2023). *KyberSlash: Timing
  Attacks on Kyber on Cortex-M4.*
- Standaert, F.-X., Malkin, T., Yung, M. (2011). *A Unified Framework for the
  Analysis of Side-Channel Key Recovery Attacks.* Journal of Cryptographic
  Engineering.
- Kwong, W., et al. (2020). *RAMBleed: Reads Bits in Memory Without Accessing
  Them.* IEEE Symposium on Security and Privacy.
