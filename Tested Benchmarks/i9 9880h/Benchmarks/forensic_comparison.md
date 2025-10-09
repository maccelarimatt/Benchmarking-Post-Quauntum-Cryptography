### dilithium (dilithium) — Critical risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (critical)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=7.64) [p=3.45e-14, MI=0.0788, MI-p=1.00e-04, t2=0.98, t2-p=3.29e-01, Δ=-0.293]
  - CPU leak: CPU usage differences significant across classes (|t|=7.75) [p=1.45e-14, MI=0.0792, MI-p=1.00e-04, t2=1.02, t2-p=3.08e-01, Δ=-0.295]
  - RSS leak: Memory-resident footprint varies with leakage classification (|t|=13.64) [p=1.85e-40, MI=0.0489, MI-p=1.00e-04, t2=6.54, t2-p=7.59e-11, Δ=0.318]

### falcon (falcon) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=3.08) [p=2.12e-03, MI=0.0007, MI-p=1.00e+00, t2=1.01, t2-p=3.14e-01, Δ=-0.639]
  - CPU leak: CPU usage differences significant across classes (|t|=3.11) [p=1.93e-03, MI=0.0007, MI-p=1.00e+00, t2=1.01, t2-p=3.14e-01, Δ=-0.642]

### hqc (hqc) — Critical risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (critical)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=3.89) [p=1.04e-04, MI=0.0089, MI-p=3.00e-04, t2=1.38, t2-p=1.67e-01, Δ=0.179]
  - CPU leak: CPU usage differences significant across classes (|t|=6.07) [p=1.56e-09, MI=0.0247, MI-p=1.00e-04, t2=3.07, t2-p=2.20e-03, Δ=0.179]
  - RSS leak: Memory-resident footprint varies with leakage classification (|t|=1.28) [p=2.02e-01, MI=0.0010, MI-p=2.53e-01, t2=1.18, t2-p=2.39e-01, Δ=0.706]

### kyber (kyber) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=1.09) [p=2.75e-01, MI=0.0003, MI-p=4.97e-01, t2=1.00, t2-p=3.17e-01, Δ=-0.058]
  - CPU leak: CPU usage differences significant across classes (|t|=1.09) [p=2.76e-01, MI=0.0003, MI-p=5.04e-01, t2=1.00, t2-p=3.17e-01, Δ=-0.081]

### mayo (mayo) — Critical risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (critical)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=16.91) [p=4.39e-59, MI=0.3500, MI-p=1.00e-04, t2=5.24, t2-p=1.90e-07, Δ=-0.686]
  - CPU leak: CPU usage differences significant across classes (|t|=17.21) [p=5.72e-61, MI=0.3520, MI-p=1.00e-04, t2=5.37, t2-p=9.32e-08, Δ=-0.690]
  - RSS leak: Memory-resident footprint varies with leakage classification (|t|=3.52) [p=4.35e-04, MI=0.0057, MI-p=1.00e-04, t2=0.06, t2-p=9.53e-01, Δ=-0.074]

### rsa-oaep (rsa-oaep) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=11.35) [p=1.23e-28, MI=0.0661, MI-p=1.00e-04, t2=1.79, t2-p=7.39e-02, Δ=0.352]
  - CPU leak: CPU usage differences significant across classes (|t|=15.41) [p=4.70e-50, MI=0.0725, MI-p=1.00e-04, t2=8.73, t2-p=6.23e-18, Δ=0.351]

### sphincs+ (sphincs+) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=2.36) [p=1.87e-02, MI=0.0174, MI-p=1.00e-04, t2=1.15, t2-p=2.49e-01, Δ=0.079]
  - CPU leak: CPU usage differences significant across classes (|t|=2.46) [p=1.42e-02, MI=0.0776, MI-p=1.00e-04, t2=11.01, t2-p=4.36e-27, Δ=0.077]

### Out-of-sample deltas vs baseline
- `dilithium (dilithium) signature_tvla_sign:fixed vs random`: Δt=2.30, Δcpu=2.23, Δrss=6.02, ΔMI=-0.0297
- `dilithium (dilithium) signature_tvla_sign:sanity_shuffle`: Δt=1.58, Δcpu=1.53, Δrss=-1.84, ΔMI=-0.0030
- `dilithium (dilithium) signature_tvla_sign:sanity_fixed_split`: Δt=0.35, Δcpu=0.31, Δrss=-2.18, ΔMI=0.0027
- `falcon (falcon) signature_tvla_sign:fixed vs random`: Δt=4.78, Δcpu=5.62, Δrss=3.97, ΔMI=-0.1446
- `falcon (falcon) signature_tvla_sign:sanity_shuffle`: Δt=1.26, Δcpu=1.07, Δrss=-0.73, ΔMI=-0.0031
- `falcon (falcon) signature_tvla_sign:sanity_fixed_split`: Δt=0.61, Δcpu=0.50, Δrss=-2.06, ΔMI=0.0066
- `hqc (hqc) kem_tvla_decapsulation:fixed vs invalid`: Δt=-6.07, Δcpu=-6.46, Δrss=-7.01, ΔMI=-0.0653
- `hqc (hqc) kem_tvla_decapsulation:sanity_shuffle`: Δt=2.93, Δcpu=1.59, Δrss=-1.18, ΔMI=-0.0034
- `hqc (hqc) kem_tvla_decapsulation:sanity_fixed_split`: Δt=-1.16, Δcpu=1.32, Δrss=-0.58, ΔMI=-0.0082
- `kyber (kyber) kem_tvla_decapsulation:fixed vs invalid`: Δt=5.33, Δcpu=5.45, Δrss=-5.46, ΔMI=-0.0248
- `kyber (kyber) kem_tvla_decapsulation:sanity_shuffle`: Δt=1.43, Δcpu=1.36, Δrss=1.22, ΔMI=-0.0132
- `kyber (kyber) kem_tvla_decapsulation:sanity_fixed_split`: Δt=0.51, Δcpu=0.62, Δrss=0.63, ΔMI=-0.0042
- `mayo (mayo) signature_tvla_sign:fixed vs random`: Δt=-6.44, Δcpu=-6.02, Δrss=-3.70, ΔMI=0.2631
- `mayo (mayo) signature_tvla_sign:sanity_shuffle`: Δt=-1.49, Δcpu=-1.43, Δrss=-1.20, ΔMI=-0.0016
- `mayo (mayo) signature_tvla_sign:sanity_fixed_split`: Δt=1.08, Δcpu=1.17, Δrss=-1.91, ΔMI=0.0104
- `rsa-oaep (rsa-oaep) kem_tvla_decapsulation:fixed vs invalid`: Δt=22.87, Δcpu=29.05, Δrss=-3.19, ΔMI=-0.0043
- `rsa-oaep (rsa-oaep) kem_tvla_decapsulation:sanity_shuffle`: Δt=1.89, Δcpu=1.67, Δrss=1.32, ΔMI=-0.0006
- `rsa-oaep (rsa-oaep) kem_tvla_decapsulation:sanity_fixed_split`: Δt=1.43, Δcpu=0.80, Δrss=0.27, ΔMI=-0.0090
- `rsa-pss (rsa-pss) signature_tvla_sign:fixed vs random`: Δt=8.74, Δcpu=9.99, Δrss=1.46, ΔMI=-0.0229
- `rsa-pss (rsa-pss) signature_tvla_sign:sanity_shuffle`: Δt=0.24, Δcpu=-0.24, Δrss=2.54, ΔMI=-0.0023
- `rsa-pss (rsa-pss) signature_tvla_sign:sanity_fixed_split`: Δt=0.01, Δcpu=0.69, Δrss=0.88, ΔMI=-0.0019
- `sphincs+ (sphincs+) signature_tvla_sign:fixed vs random`: Δt=-3.40, Δcpu=-3.37, Δrss=-0.04, ΔMI=0.0072
- `sphincs+ (sphincs+) signature_tvla_sign:sanity_shuffle`: Δt=-1.44, Δcpu=-0.41, Δrss=-1.31, ΔMI=-0.0080
- `sphincs+ (sphincs+) signature_tvla_sign:sanity_fixed_split`: Δt=0.44, Δcpu=0.39, Δrss=-1.07, ΔMI=0.0026
