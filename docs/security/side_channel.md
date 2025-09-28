# Side-Channel Leakage Assessment Playbook

This note expands on the forensic probe so non-specialists can follow how we screen
for timing and forensic leakage across pqcbench algorithms.

## What is the forensic probe?

`tools/forensic_probe.py` drives each registered algorithm through carefully chosen
scenarios, records timing/memory/process metadata, and runs statistical leakage
checks. It is **not** a key-recovery attack. Instead, it asks whether observed
signals (time, CPU, memory, artefacts) *depend* on secret-controlled behaviour.
If the distributions differ, we flag leakage and investigate the root cause.

The workflow mirrors **Test Vector Leakage Assessment (TVLA)** practice:
run two classes of inputs that should be indistinguishable in a leak-free
implementation, then apply statistical tests to see if the measurement
collections diverge.

## Threat model

We define attacker vantage points so results map to realistic risks:

- **Remote attacker**: observes wall-clock time across requests (e.g., web API).
- **Local / co-resident attacker**: observes process CPU time and may sample
  hardware performance counters (e.g., `perf stat`), inferring cache or memory
  footprints.
- **Physical / lab attacker** (out of scope here): measures power/EM leakages via
  probes; stronger but requires physical access.

The probe focuses on the remote and local/co-resident perspectives; report each
metric accordingly.

## Why this matters

- **TVLA leakage validation**: The industry-standard TVLA non-specific test uses
  Welch's *t*-test on two classes (usually “fixed” vs “random”). |*t*| ≥ 4.5 with
  low p-value indicates leakage. ([Goodwill et al., 2011](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/08_goodwill.pdf))
- **Timing still leaks PQC**: `KyberSlash` and similar work show Kyber decapsulation can leak via timing, motivating our valid vs invalid decapsulation checks. ([KyberSlash](https://kyberslash.cr.yp.to/kyberslash-20250115.pdf))
- **Forensic artefacts vs side channels**: Cold-boot studies show secrets can
  remain in DRAM after power loss (remanence), while `RAMBleed` demonstrates
  active Rowhammer-style memory reads. We snapshot temp dirs to ensure secrets
  are not written to disk, but we do not attempt Rowhammer. ([Halderman et al., 2008](https://www.usenix.org/legacy/event/sec08/tech/full_papers/halderman/halderman.pdf))
- **Information-theoretic metrics**: Mutual Information Analysis (MIA) and the
  Standaert framework treat leakage as statistical dependence. MI complements
  the TVLA t-test by detecting non-linear effects. ([Standaert et al., 2009](https://www.iacr.org/archive/eurocrypt2009/54790443/54790443.pdf))

## Signals we record

| Signal class | What it captures | Why it can leak |
| --- | --- | --- |
| **Wall-clock time** (`perf_counter_ns`) | End-to-end execution time | Secret-dependent control flow or loops change latency (remote attacker).
| **CPU time** (`process_time_ns`) | CPU cycles consumed | Reveals work done even if wall-clock is noisy (co-resident attacker).
| **Memory deltas** (RSS, heap via `tracemalloc`) | Working-set changes | Error paths or data-dependent buffering alter pages touched.
| **GC/allocation stats** | Python GC counters, allocation deltas | Different object lifetimes expose data-dependent behaviour.
| **Hashed outputs** | Lengths + hashes of keys/ciphertexts/signatures | Allows correlating timing with outputs without storing secrets.
| **Success/failure flags** | Exceptions, verification booleans | Invalid inputs often trigger distinct timing/memory traces.
| **Artefact hashes** | Per-scenario temp directory snapshot | Ensures no secret-dependent files/logs are emitted.
| **Host metadata** | OS, CPU model/frequency, git commit | Required to reproduce results and explain variation.

## TVLA-aligned scenarios

We keep the **secret key fixed** within a session and toggle only public inputs,
matching TVLA’s non-specific methodology.

### KEMs

- `keygen` – baseline
- `encapsulate_fixed_public` – sanity check
- `decapsulate_valid` – **fixed class**: valid ciphertexts under a fixed secret key
- `decapsulate_invalid` – **toggle class**: corrupted ciphertexts under the same key (stresses error-handling branches)

### Signatures

- `keygen`
- `sign_fixed_message` – **fixed class**: one message, fixed secret key
- `sign_random_message` – **toggle class**: random messages, same key
- `sign_fault` – tampered key (fault-injection paths)
- `verify_invalid_signature` – corrupted signature handling

Each scenario runs in an isolated temp directory so artefacts can be examined or discarded deterministically.

## Statistical pipeline

For every TVLA pair (e.g., `kem_tvla_decapsulation: fixed vs invalid`), we compute:

1. **Welch’s t-test** on time/CPU/ΔRSS. We flag leakage when |*t*| ≥ 4.5 **and**
   the Holm–Bonferroni corrected p-value ≤ 10⁻³. The probe also performs a
   second-order TVLA (t-test on squared centred samples) to catch masked leaks.
2. **Non-parametric tests**: Mann–Whitney U and Kolmogorov–Smirnov, corrected
   via Holm–Bonferroni, detect distribution shifts beyond mean differences.
3. **Mutual information + permutation test**: MI is estimated via histograms and
   assigned a permutation p-value (default 10 000 shuffles, α = 10⁻³).
4. **Effect sizes**: Cliff’s delta accompanies each metric so practical impact is
   clear alongside p-values.
5. **Sanity checks**: the script automatically runs label-shuffle (randomised
   class labels) and split-sample (fixed vs fixed) controls to estimate false
   positive rates. Failures here indicate environmental noise or insufficient
   samples.

The JSON report retains all metrics so auditors can rerun corrections or add
secondary tests.

## Operational hygiene

- Pin CPU cores and stabilise frequency (performance governor, disable turbo/SMT if possible).
- Randomise class order within runs (already done via helper RNG) to mitigate drift, as popularised by **dudect**.
- Discard warm-up iterations, or run small inner loops per measurement if the
  platform is noisy.
- Collect **two independent datasets** (different seeds or sessions) and require
  both to fail before declaring leakage. Record all `host` metadata (CPU, kernel,
  governor, git commit).

## Sanity tests supported

- **Label shuffle**: recomputes statistics after randomising class labels;
  leakage should disappear.
- **Fixed-vs-fixed split**: compares two random halves of the fixed class; should
  pass, otherwise the dataset is too noisy.

Use these to validate measurement quality before chasing root causes.

## Generating summaries

After a run you can produce a human-readable summary:

```bash
python tools/forensic_report.py results/forensic_quick.json --format markdown \
  --output results/forensic_summary.md
```

To compare against a previous dataset (out-of-sample robustness), supply a baseline:

```bash
python tools/forensic_report.py results/forensic_new.json --baseline results/forensic_prev.json
```

The report lists delta statistics (`Δt`, `ΔMI`), helping you quantify drift across
machines or sessions.

The report lists flagged algorithms/scenarios, t/MI stats, permutation p-values,
second-order hits, and effect sizes.

## Ethics & data handling

- Never store raw keys, plaintexts, or signatures.
- Only hashes and lengths of outputs are persisted.
- When disclosing leaks, share reproducible symptoms (statistics, scenarios) and
  remediation guidance, not proprietary secrets.

## What’s still missing (roadmap)

- **Higher-order TVLA beyond 2nd order** for masked implementations.
- **Additional effect sizes** (Cohen’s *d*, Hedge’s *g*) for completeness.
- **Open-set fingerprinting reports** if we later add classifiers that attempt
  to identify algorithms from traces.
- **Out-of-sample robustness harness** beyond the current baseline delta report
  (e.g., aggregate dashboards, statistical thresholds).

These are planned as iterative enhancements once the current pipeline is stable.

## References

1. Goodwill, Jun, Jaffe, Rohatgi. *A testing methodology for side-channel resistance validation*.
2. `dudect`: “dude, is my code constant time?” timing-leak detector.
3. Bernstein et al. *KyberSlash* (Kyber decapsulation timing vulnerabilities).
4. Halderman et al. *Lest We Remember: Cold Boot Attacks on Encryption Keys*.
5. Kwong et al. *RAMBleed: Reading Bits in Memory Without Accessing Them*.
6. Standaert, Malkin, Yung. *A Unified Framework for the Analysis of Side-Channel Key-Recovery Attacks*.
7. Gierlichs et al. *Mutual Information Analysis* (CHES 2008).
8. Mangard et al. *A Survey of Side-Channel Leakage Assessment* (MDPI Electronics 12(16), 2023).
