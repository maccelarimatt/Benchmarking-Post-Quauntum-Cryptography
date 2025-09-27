# Shor Estimator Playbook

This note explains how the Shor factoring estimator in `pqcbench.security_estimator`
models quantum resources, surface-code overhead, and the accompanying classical
baseline. It is the reference for the JSON fields surfaced under
`security.resources.shor_profiles` and should provide enough context to cite the
implementation in reports or replicate individual numbers.

## 1. Scope and Summary

* **Algorithms covered.** Only `rsa-pss` and `rsa-oaep` are routed through the
  Shor estimator. All other mechanisms stay on their own lattice/hash/code-based
  estimators.
* **Output.** The estimator reports classical strength (per NIST SP 800‑57),
  sets `quantum_bits = 0` to flag “Shor-breakable” mechanisms, and publishes
  the logical resource curve together with per-scenario surface-code projections
  and a GNFS classical baseline for comparison.
* **Models.** Logical resources use the verbatim Gidney–Ekerå 2019 formulas.
  Magic-state costing keeps Toffoli counts as the primary unit and reports a
  band for T counts (catalyzed vs textbook). Surface-code overhead includes
  both data tiles and magic-state factories with a utilization-aware integer
  search. The classical baseline implements a record-calibrated GNFS model.

## 2. Logical Resource Model (GE 2019)

For an RSA modulus of size `n` bits, the estimator uses the analytic fits from
Gidney & Ekerå’s factoring blueprint [2]:

\[
\begin{aligned}
Q_\text{logical}(n) &= 3n + 0.002\,n\log_2 n,\\
T_\text{Toffoli}(n) &= \bigl(0.3 + 0.0005\,\log_2 n\bigr) n^3,\\
D_\text{meas}(n) &= \bigl(500 + \log_2 n\bigr) n^2.
\end{aligned}
\]

The estimator stores the formulas alongside the evaluated numbers so exports can
be traced back to the source without re-reading the paper. Additional logical
models can be added by extending `SHOR_MODEL_LIBRARY`.

## 3. Toffoli vs. T Counts

* **Primary unit.** All downstream calculations treat Toffoli counts as the
  canonical unit because modern surface-code schedules build Toffoli/CCZ
  factories directly. The JSON therefore exposes `toffoli` and explicitly states
  that Toffolis are the “primary unit”.
* **T-band.** To ease comparisons with papers that still publish T counts, the
  estimator multiplies by two reference factors: 4 T/Toffoli for catalyzed
  constructions (Halving-the-cost style [3]) and 7 T/Toffoli for the textbook
  decomposition. Both values show up under `t_counts`.

## 4. Surface-Code and Factory Model

The helper `_shor_surface_profile` derives one profile per scenario request.
All scenarios share the following ingredients.

1. **Code distance.** A Fowler-style fit sets the physical error-per-operation:

   \[
   p_L(d) = 0.1 \left(\frac{p_\text{phys}}{p_\text{th}}\right)^{(d+1)/2}, \quad
   p_\text{th} = 10^{-2}.
   \]

   We choose the smallest odd `d` such that
   `p_L(d) · (meas_depth + toffoli) ≤ target_fail`.

2. **Physical qubits.**
   * Data block: `Q_data = α_data · Q_logical · d²` (default `α_data = 2.5`).
   * Factory block: `Q_factories = α_factory · Q_factory · d² · count` with
     per-spec logical-qubit footprints. The default factories follow a
     Litinski-style two-stage 116→12 pipeline (`Q_factory = 6 000`,
     `cycles_per_batch = 5·d`). Alternate lightweight 15→1 factories are
     available for slow architectures.

3. **Factory throughput.** Each factory outputs
   `outputs_per_batch / (cycles_per_batch_per_distance · d)` magic states per
   cycle. The scenario’s `factory_overbuild` latches how aggressively to match
   the Toffoli layer rate `toffoli / meas_depth`. If factories cannot keep up,
   runtime is factory-limited; otherwise depth dominates. The JSON reports both
   limits and the max of the two.

4. **Failure accounting.** The profile records `expected_failures`, exposing how
   close the chosen parameters sit to the target budget. The logical work factor
   uses weights (`logical_op_weight_depth`, `logical_op_weight_tof`) so that
   Toffoli layers can be treated as slightly more error-prone than a single
   Clifford depth slot.

### Default Scenarios

| Label         | `p_phys` | Cycle time | Factory spec              | Overbuild | Notes |
|---------------|---------:|-----------:|---------------------------|----------:|-------|
| `ge-baseline` | 1e‑3     | 1 µs       | Litinski 116→12           | 0.05      | Calibrated to the Gidney–Ekerå 8 h / 20 M qubit point.
| `optimistic`  | 5e‑4     | 200 ns     | Litinski 116→12           | 1.0       | Faster cadence with throughput-matched factories.
| `conservative`| 2e‑3     | 5 µs       | Lightweight 15→1 pipeline | 1.5       | Slow ion-trap style; factories dominate budget.

Custom scenarios can be injected by calling `_shor_surface_profile` directly or
by enabling `EstimatorOptions.rsa_surface` in CLI/exports.

## 5. Calibration and Stabilisation

The module auto-calibrates a set of global multipliers once at import. For the
GE baseline (`n=2048`, `p_phys=10⁻³`, `cycle=1 µs`) it solves for:

* `factory_rate_multiplier` – demand-side inflation ensuring the integer
  factory search starts near the GE throughput; currently the optimum is 1.0.
* `factory_supply_scale` – scales per-factory throughput so that the selected
  integer factory count delivers an 8 hour runtime.
* `data_alpha_scale`, `factory_alpha_scale` – shared multipliers on the data and
  factory tile footprints so the total physical qubits match 20 M.

These parameters are published under `extras.calibration` and every calibrated
scenario advertises `calibrated_against="GE-2019-2048"`.

The factory chooser evaluates a small window of integer counts, favouring
solutions that (a) satisfy the throughput requirement, (b) minimise
`max(depth_cycles, factory_cycles)`, and (c) keep utilisation near the target
band (default 70–90%).

## 6. Classical Baseline (GNFS)

The brute-force helper now models the general number field sieve rather than
trial division. For modulus size `n` bits (≈\(N = 2^n\)), the work factor is

\[
\mathrm{L}_N\left[\tfrac{1}{3}, \left(\tfrac{64}{9}\right)^{1/3}\right]
 = \exp\!\left( \left(\tfrac{64}{9}\right)^{1/3} (\ln N)^{1/3} (\ln\ln N)^{2/3} \right).
\]

We calibrate a global constant so that RSA‑250 (829 bits) matches the published
factorisation record of ≈2 700 CPU core-years [8][9]. The JSON exposes the
result in core-years and provides the time-to-solution for three illustrative
core budgets (1, 10³, 10⁶). This makes classical vs quantum trade-offs directly
comparable on plots.

## 7. JSON Field Guide

* `resources.logical` — evaluated GE formulas and the associated prose (single
  source of truth for logical qubits, Toffoli count, depth, and log₂ n bits).
* `resources.shor_profiles` — per-modulus logical entries plus per-scenario
  surface-code overhead, including factory counts, runtime decomposition,
  utilisation metrics, and failure estimates.
* `resources.t_counts` — Toffoli/T band (primary + comparative).
* `resources.calibration` — global scaling factors chosen to match the GE
  baseline point.
* `bruteforce` — GNFS baseline with record-calibrated scaling.
* `rate_details` (per scenario) — `factory_rate_peak` (concurrent demand),
  `factory_rate_target` (after overbuild and multipliers), `factory_rate_available`,
  utilisation/backlog ratios, and the supply/multiplier factors that produced the
  chosen integer factory count.

A typical `rsa-oaep` export now includes the GE baseline showing ≈6.8 M data
qubits + ≈6.6 M factory qubits (one Litinski pipeline) and an 8-hour
factory-limited runtime, matching Table II of [2].

## 8. Extending or Auditing the Model

* **Alternate logical models.** Add new entries to `SHOR_MODEL_LIBRARY` with
  the desired closed forms and select them via `EstimatorOptions.rsa_model`.
* **Custom factories.** Extend `FACTORY_LIBRARY` with pipeline parameters (logical
  footprint, cycles, outputs). Scenario dictionaries may point to new entries.
* **Surface override.** CLI users can set `--sec-phys-error-rate`,
  `--sec-cycle-time-ns`, and `--sec-fail-prob` (or specify a named
  `--sec-quantum-arch`) to regenerate the `surface` block with bespoke
  assumptions.
* **Audit mode.** Enabling the (planned) `estimator --audit` flag will dump the
  selected constants and allow spot-checking against the GE public scripts for a
  handful of moduli.

## 9. References

1. NIST, *Recommendation for Key Management: Part 1 – General*, SP 800‑57 Rev.5 [1].
2. Gidney & Ekerå, *How to factor 2048 bit RSA integers in 8 hours using 20 million noisy qubits*, Quantum 5, 433 (2019) [2][4].
3. Gidney, *Halving the cost of quantum addition*, Quantum 2, 74 (2018) [3].
4. Litinski, *A Game of Surface Codes: Large-scale quantum computing with lattice surgery*, Quantum 3, 128 (2019) [6].
5. Fowler *et al.*, *Surface codes: Towards practical large-scale quantum computation*, Phys. Rev. A 86, 032324 (2012) [5].
6. Ekerå, *How to factor 2048 bit RSA integers with less than a million noisy qubits*, (preprint, May 2025) [7].
7. Boudot *et al.*, *Integer factorization: Another perspective*, (preprint, 2025) [8].
8. RSA factorisation records, Wikipedia [9].

> **Note.** Reference [7] documents more aggressive resource estimates that are
> currently flagged as “experimental” in the literature. We keep the GE 2019
> model as the default but the estimator is structured so that newer models can
> be swapped in once consensus emerges.


[1]: https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf
[2]: https://quantum-journal.org/papers/q-2021-04-15-433/
[3]: https://quantum-journal.org/papers/q-2018-06-18-74/
[4]: https://arxiv.org/abs/1905.09749
[5]: https://link.aps.org/doi/10.1103/PhysRevA.86.032324
[6]: https://quantum-journal.org/papers/q-2019-03-05-128/
[7]: https://arxiv.org/abs/2505.15917
[8]: https://arxiv.org/abs/2507.07055
[9]: https://en.wikipedia.org/wiki/RSA_numbers
