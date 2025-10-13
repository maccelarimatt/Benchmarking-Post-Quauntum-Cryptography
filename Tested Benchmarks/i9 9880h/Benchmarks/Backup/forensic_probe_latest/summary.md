### dilithium (ML-DSA-87) — Critical risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (critical)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=3.73) [p=1.97e-04, MI=0.0138, MI-p=3.03e-02, t2=2.63, t2-p=8.69e-03, Δ=0.104]
  - CPU leak: CPU usage differences significant across classes (|t|=3.76) [p=1.76e-04, MI=0.0128, MI-p=8.88e-02, t2=2.66, t2-p=8.00e-03, Δ=0.103]
  - RSS leak: Memory-resident footprint varies with leakage classification (|t|=4.50) [p=7.32e-06, MI=0.0068, MI-p=5.00e-04, t2=2.03, t2-p=4.25e-02, Δ=0.103]

### falcon (Falcon-512) — Critical risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (critical)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=0.91) [p=3.60e-01, MI=0.0108, MI-p=2.33e-01, t2=0.91, t2-p=3.65e-01, Δ=0.070]
  - CPU leak: CPU usage differences significant across classes (|t|=0.94) [p=3.48e-01, MI=0.0093, MI-p=3.38e-01, t2=0.90, t2-p=3.66e-01, Δ=0.064]
  - RSS leak: Memory-resident footprint varies with leakage classification (|t|=7.14) [p=1.48e-12, MI=0.0167, MI-p=1.00e-04, t2=4.16, t2-p=3.42e-05, Δ=0.163]

### falcon (Falcon-1024) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=5.66) [p=1.84e-08, MI=0.0417, MI-p=1.00e-04, t2=3.07, t2-p=2.22e-03, Δ=0.320]
  - CPU leak: CPU usage differences significant across classes (|t|=5.64) [p=2.04e-08, MI=0.0429, MI-p=1.00e-04, t2=3.00, t2-p=2.74e-03, Δ=0.318]

### hqc (HQC-128) — Medium risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (medium)
  - RSS leak: Memory-resident footprint varies with leakage classification (|t|=4.73) [p=2.48e-06, MI=0.0076, MI-p=1.00e-04, t2=2.45, t2-p=1.46e-02, Δ=0.093]

### hqc (HQC-192) — Critical risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (critical)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=1.42) [p=1.57e-01, MI=0.0828, MI-p=1.00e-04, t2=2.21, t2-p=2.75e-02, Δ=0.190]
  - CPU leak: CPU usage differences significant across classes (|t|=1.51) [p=1.32e-01, MI=0.0868, MI-p=1.00e-04, t2=4.39, t2-p=1.24e-05, Δ=0.190]
  - RSS leak: Memory-resident footprint varies with leakage classification (|t|=5.48) [p=5.11e-08, MI=0.0184, MI-p=1.00e-04, t2=4.49, t2-p=7.74e-06, Δ=0.092]

### hqc (HQC-256) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=13.38) [p=1.00e-38, MI=0.3009, MI-p=1.00e-04, t2=3.47, t2-p=5.35e-04, Δ=0.522]
  - CPU leak: CPU usage differences significant across classes (|t|=13.92) [p=1.44e-41, MI=0.3289, MI-p=1.00e-04, t2=6.98, t2-p=4.61e-12, Δ=0.521]

### kyber (ML-KEM-512) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=3.58) [p=3.55e-04, MI=0.0040, MI-p=1.96e-01, t2=0.08, t2-p=9.40e-01, Δ=0.678]
  - CPU leak: CPU usage differences significant across classes (|t|=3.64) [p=2.78e-04, MI=0.0044, MI-p=2.32e-01, t2=0.08, t2-p=9.36e-01, Δ=0.636]

### kyber (ML-KEM-768) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=0.98) [p=3.30e-01, MI=0.0004, MI-p=1.00e+00, t2=1.00, t2-p=3.17e-01, Δ=0.287]
  - CPU leak: CPU usage differences significant across classes (|t|=0.97) [p=3.32e-01, MI=0.0004, MI-p=1.00e+00, t2=1.00, t2-p=3.17e-01, Δ=0.302]

### kyber (ML-KEM-1024) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=1.64) [p=1.00e-01, MI=0.0089, MI-p=6.20e-03, t2=0.60, t2-p=5.47e-01, Δ=0.522]
  - CPU leak: CPU usage differences significant across classes (|t|=1.81) [p=7.06e-02, MI=0.0088, MI-p=4.30e-03, t2=0.60, t2-p=5.50e-01, Δ=0.485]

### mayo (MAYO-1) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=2.13) [p=3.37e-02, MI=0.0352, MI-p=1.00e-04, t2=1.16, t2-p=2.44e-01, Δ=0.142]
  - CPU leak: CPU usage differences significant across classes (|t|=2.21) [p=2.74e-02, MI=0.0387, MI-p=1.00e-04, t2=1.40, t2-p=1.61e-01, Δ=0.143]

### mayo (MAYO-3) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=0.61) [p=5.43e-01, MI=0.0136, MI-p=3.68e-02, t2=0.15, t2-p=8.81e-01, Δ=0.121]
  - CPU leak: CPU usage differences significant across classes (|t|=0.63) [p=5.29e-01, MI=0.0126, MI-p=7.34e-02, t2=0.06, t2-p=9.49e-01, Δ=0.105]

### mayo (MAYO-5) — Critical risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (critical)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=0.12) [p=9.02e-01, MI=0.0329, MI-p=1.00e-04, t2=1.71, t2-p=8.76e-02, Δ=0.075]
  - CPU leak: CPU usage differences significant across classes (|t|=0.18) [p=8.57e-01, MI=0.0354, MI-p=1.00e-04, t2=1.66, t2-p=9.70e-02, Δ=0.073]
  - RSS leak: Memory-resident footprint varies with leakage classification (|t|=2.55) [p=1.08e-02, MI=0.0089, MI-p=1.00e-04, t2=1.05, t2-p=2.96e-01, Δ=0.079]

### rsa-oaep (RSA-3072-OAEP) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=0.80) [p=4.23e-01, MI=0.0175, MI-p=1.00e-04, t2=0.09, t2-p=9.25e-01, Δ=0.068]
  - CPU leak: CPU usage differences significant across classes (|t|=0.55) [p=5.82e-01, MI=0.0442, MI-p=1.00e-04, t2=1.21, t2-p=2.25e-01, Δ=0.067]

### rsa-oaep (RSA-7680-OAEP) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=12.16) [p=2.46e-32, MI=0.1604, MI-p=1.00e-04, t2=8.68, t2-p=9.66e-18, Δ=0.169]
  - CPU leak: CPU usage differences significant across classes (|t|=12.68) [p=7.13e-35, MI=0.1782, MI-p=1.00e-04, t2=10.72, t2-p=7.22e-26, Δ=0.170]

### rsa-pss (RSA-3072-PSS) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=7.19) [p=9.93e-13, MI=0.0896, MI-p=1.00e-04, t2=0.62, t2-p=5.35e-01, Δ=0.555]
  - CPU leak: CPU usage differences significant across classes (|t|=12.25) [p=5.70e-33, MI=0.2011, MI-p=1.00e-04, t2=1.19, t2-p=2.36e-01, Δ=0.560]

### rsa-pss (RSA-7680-PSS) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=17.93) [p=1.56e-61, MI=0.2589, MI-p=1.00e-04, t2=8.26, t2-p=5.71e-16, Δ=-0.786]
  - CPU leak: CPU usage differences significant across classes (|t|=18.68) [p=8.61e-66, MI=0.2984, MI-p=1.00e-04, t2=9.04, t2-p=1.09e-18, Δ=-0.798]

### sphincs+ (SPHINCS+-SHAKE-128s-simple) — Medium risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (medium)
  - CPU leak: CPU usage differences significant across classes (|t|=3.09) [p=2.01e-03, MI=0.0194, MI-p=1.00e-03, t2=3.09, t2-p=2.04e-03, Δ=-0.061]

### sphincs+ (SPHINCS+-SHAKE-192s-simple) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=15.06) [p=2.04e-47, MI=0.2394, MI-p=1.00e-04, t2=3.70, t2-p=2.27e-04, Δ=-0.617]
  - CPU leak: CPU usage differences significant across classes (|t|=17.50) [p=5.54e-61, MI=0.2398, MI-p=1.00e-04, t2=6.97, t2-p=6.12e-12, Δ=-0.618]
