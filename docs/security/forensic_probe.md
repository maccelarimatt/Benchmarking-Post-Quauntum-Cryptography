# Forensic Side-Channel Probe

This guide documents the standalone forensic probe (`tools/forensic_probe.py`) that
exercises each registered pqcbench algorithm under side-channel relevant
scenarios, captures rich telemetry, and runs statistical leakage checks. It is
meant for offline investigations rather than CI; default workloads collect
hundreds of samples per scenario and favour completeness over speed.

## Motivation and research baseline

- **Leakage validation.** The probe follows the Test Vector Leakage Assessment
  (TVLA) methodology (Goodwill et al., 2011; ISO/IEC 17825:2016) by comparing
  "fixed" versus "variable" secret executions with Welch's *t*-tests and
  complementary non-parametric checks. KyberSlash-style timing leaks (Dobraunig
  et al., 2023) and Dilithium timing artefacts illustrated that simple timing
  measurements still expose exploitable side channels.
- **Forensic artefacts.** RAMBleed (Kwong et al., 2020) and cold-boot memory
  forensics highlight that post-execution residues (keys in temp files, unique
  error logs) are actionable in investigations. The probe snapshots dedicated
  temp directories per scenario so secret-dependent file activity is observable
  without persisting raw secrets.
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

- **KEMs**: `keygen`, `encapsulate_fixed_public`, `decapsulate_fixed_secret`
  *(TVLA fixed class)*, `decapsulate_variable_secret` *(TVLA variable class)*,
  `decapsulate_fault` *(corrupted ciphertexts to inspect error paths).* 
- **Signatures**: `keygen`, `sign_fixed_secret` *(TVLA fixed class)*,
  `sign_variable_secret` *(TVLA variable class)*, `sign_fault` *(tampered key)*,
  `verify_invalid_signature` *(error-handling traces).* 

Each scenario runs in a private temp directory with environment overrides
(`TMP`, `TEMP`, `TMPDIR`) so any spillovers are isolated.

### Statistical analysis

For every group with at least two labels (e.g., `kem_decapsulation: fixed` vs
`variable`), the probe computes:

- Welch's *t*-statistic (timing, CPU, RSS delta). A |*t*| ≥ 4.5 mirrors the TVLA
  "fail" threshold.
- Mann–Whitney U statistic + *p*-value for the same metrics (robustness to
  heavy-tail distributions).
- Mutual information between the class label and each metric using histogram
  discretisation (30 bins). Values ≥ 0.02 suggest measurable dependency.

Leakage flags are raised whenever either condition triggers.

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
- Restricting work:
  ```bash
  # Only Kyber + Dilithium, keep raw artefacts for manual inspection
  python tools/forensic_probe.py --alg kyber dilithium --keep-artifacts
  ```
- Quick smoke test:
  ```bash
  python tools/forensic_probe.py --iterations 10 --output results/forensic_quick.json
  ```

The CLI options:

| Option | Meaning |
| --- | --- |
| `--iterations` | Samples per scenario (default 800). High values stabilise statistics. |
| `--seed` | Deterministic seed for helper randomness (messages, fault injection). |
| `--alg` | Filter registry keys (e.g., `kyber`, `dilithium`). |
| `--scenario` | Run a subset of scenarios by name. |
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
  "scenario": "decapsulate_fixed_secret",
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
kyber [ML-KEM-768] kem_decapsulation:fixed vs variable: |t_time|=5.12, |t_cpu|=5.07, |t_rss|=0.44, MI=0.0314/0.0298/0.0001 -> flags: time, cpu
```

Interpretation:

- `|t_time|`/`|t_cpu|` over 4.5: statistically significant timing difference.
- `MI` shows mutual information for (time/cpu/rss). Values above 0.02 are notable.
- `flags` enumerate which metrics tripped thresholds.

### Recommended follow-up checklist

1. **Confirm reproducibility.** Re-run with the same seed, observe stability.
2. **Noise control.** Pin CPU cores (`taskset`/`cpuset`), disable Turbo Boost,
   close background tasks to reduce scheduling variance.
3. **Inspect artefacts.** When `--keep-artifacts` is enabled, manually review
   the captured temp directories for key remnants, crash dumps, or logs.
4. **Deep-dive metrics.** Use the JSON output with notebooks to visualise
   histograms, QQ-plots, or run additional tests (e.g., clustering, KDE).

## Detailed findings template

Once data is collected, populate a narrative similar to the following (store
alongside the JSON output):

```
Algorithm: ML-KEM-768
Scenario pair: kem_decapsulation fixed vs variable
Iterations: 800
Leakage indicators: |t|=5.12 (time), |t|=4.98 (cpu), MI_time=0.031
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
