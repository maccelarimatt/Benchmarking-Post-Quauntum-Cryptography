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

### bike (BIKE-L1) — Medium risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (medium)
  - RSS leak: Memory-resident footprint varies with leakage classification (|t|=6.11) [p=1.41e-09, MI=0.0275, MI-p=1.00e-04, t2=1.14, t2-p=2.55e-01, Δ=0.208]

### bike (BIKE-L3) — Critical risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (critical)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=3.74) [p=1.98e-04, MI=0.0582, MI-p=1.00e-04, t2=5.30, t2-p=1.62e-07, Δ=0.042]
  - CPU leak: CPU usage differences significant across classes (|t|=3.70) [p=2.27e-04, MI=0.0575, MI-p=1.00e-04, t2=5.31, t2-p=1.54e-07, Δ=0.041]
  - RSS leak: Memory-resident footprint varies with leakage classification (|t|=4.03) [p=6.04e-05, MI=0.0184, MI-p=1.00e-04, t2=5.06, t2-p=5.27e-07, Δ=0.070]

### bike (BIKE-L5) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=2.02) [p=4.40e-02, MI=0.0260, MI-p=3.00e-04, t2=0.35, t2-p=7.24e-01, Δ=-0.107]
  - CPU leak: CPU usage differences significant across classes (|t|=2.03) [p=4.31e-02, MI=0.0270, MI-p=8.00e-04, t2=0.13, t2-p=8.93e-01, Δ=-0.108]

### classic-mceliece (Classic-McEliece-348864f) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=1.07) [p=2.85e-01, MI=0.0007, MI-p=1.00e+00, t2=1.00, t2-p=3.17e-01, Δ=-0.414]
  - CPU leak: CPU usage differences significant across classes (|t|=1.07) [p=2.85e-01, MI=0.0007, MI-p=1.00e+00, t2=1.00, t2-p=3.17e-01, Δ=-0.425]

### classic-mceliece (Classic-McEliece-460896f) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=3.74) [p=1.93e-04, MI=0.0314, MI-p=2.00e-04, t2=2.84, t2-p=4.56e-03, Δ=0.026]
  - CPU leak: CPU usage differences significant across classes (|t|=3.99) [p=7.10e-05, MI=0.0322, MI-p=1.00e-04, t2=3.28, t2-p=1.09e-03, Δ=-0.031]

### classic-mceliece (Classic-McEliece-6688128f) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=8.09) [p=1.72e-15, MI=0.3900, MI-p=1.00e-04, t2=0.63, t2-p=5.32e-01, Δ=0.898]
  - CPU leak: CPU usage differences significant across classes (|t|=8.20) [p=7.24e-16, MI=0.4245, MI-p=1.00e-04, t2=0.52, t2-p=6.04e-01, Δ=0.894]

### cross (cross-rsdpg-128-balanced) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=0.97) [p=3.31e-01, MI=0.0329, MI-p=1.00e-04, t2=0.71, t2-p=4.78e-01, Δ=0.281]
  - CPU leak: CPU usage differences significant across classes (|t|=0.88) [p=3.76e-01, MI=0.0314, MI-p=4.00e-04, t2=0.90, t2-p=3.69e-01, Δ=0.261]

### cross (cross-rsdpg-192-balanced) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=1.47) [p=1.43e-01, MI=0.0349, MI-p=1.00e-04, t2=0.63, t2-p=5.29e-01, Δ=-0.083]
  - CPU leak: CPU usage differences significant across classes (|t|=1.51) [p=1.32e-01, MI=0.0415, MI-p=1.00e-04, t2=0.61, t2-p=5.41e-01, Δ=-0.086]

### cross (cross-rsdpg-256-balanced) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=1.68) [p=9.26e-02, MI=0.0318, MI-p=1.00e-04, t2=0.31, t2-p=7.59e-01, Δ=0.293]
  - CPU leak: CPU usage differences significant across classes (|t|=1.69) [p=9.13e-02, MI=0.0260, MI-p=2.60e-03, t2=0.36, t2-p=7.18e-01, Δ=0.291]

### fn-dsa (Falcon-512) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=1.55) [p=1.23e-01, MI=0.0059, MI-p=8.71e-01, t2=0.93, t2-p=3.52e-01, Δ=0.418]
  - CPU leak: CPU usage differences significant across classes (|t|=1.53) [p=1.27e-01, MI=0.0091, MI-p=8.70e-01, t2=0.63, t2-p=5.32e-01, Δ=0.412]

### fn-dsa (Falcon-1024) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=2.90) [p=3.90e-03, MI=0.0108, MI-p=5.00e-04, t2=1.78, t2-p=7.61e-02, Δ=-0.168]
  - CPU leak: CPU usage differences significant across classes (|t|=5.00) [p=6.95e-07, MI=0.0220, MI-p=1.76e-02, t2=3.73, t2-p=2.07e-04, Δ=-0.168]

### frodokem (FrodoKEM-640-AES) — Critical risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (critical)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=2.50) [p=1.27e-02, MI=0.0243, MI-p=4.00e-04, t2=2.03, t2-p=4.31e-02, Δ=-0.249]
  - CPU leak: CPU usage differences significant across classes (|t|=2.51) [p=1.23e-02, MI=0.0271, MI-p=1.00e-04, t2=1.96, t2-p=4.99e-02, Δ=-0.251]
  - RSS leak: Memory-resident footprint varies with leakage classification (|t|=7.00) [p=5.21e-12, MI=0.0282, MI-p=1.00e-04, t2=5.48, t2-p=5.63e-08, Δ=0.183]

### frodokem (FrodoKEM-976-AES) — Critical risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (critical)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=4.13) [p=4.07e-05, MI=0.0593, MI-p=1.00e-04, t2=2.65, t2-p=8.26e-03, Δ=0.022]
  - CPU leak: CPU usage differences significant across classes (|t|=4.16) [p=3.56e-05, MI=0.0554, MI-p=1.00e-04, t2=2.66, t2-p=8.00e-03, Δ=0.021]
  - RSS leak: Memory-resident footprint varies with leakage classification (|t|=4.93) [p=9.80e-07, MI=0.0770, MI-p=1.00e-04, t2=7.87, t2-p=1.18e-14, Δ=0.100]

### frodokem (FrodoKEM-1344-AES) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=0.68) [p=4.99e-01, MI=0.1538, MI-p=1.00e-04, t2=1.45, t2-p=1.48e-01, Δ=0.245]
  - CPU leak: CPU usage differences significant across classes (|t|=0.65) [p=5.17e-01, MI=0.1500, MI-p=1.00e-04, t2=1.44, t2-p=1.50e-01, Δ=0.243]

### ml-dsa (ML-DSA-44) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=2.77) [p=5.73e-03, MI=0.0142, MI-p=1.06e-01, t2=0.58, t2-p=5.59e-01, Δ=0.152]
  - CPU leak: CPU usage differences significant across classes (|t|=2.74) [p=6.17e-03, MI=0.0141, MI-p=7.44e-02, t2=0.47, t2-p=6.38e-01, Δ=0.148]

### ml-dsa (ML-DSA-87) — High risk
- **Scenario:** `signature_tvla_sign:sanity_fixed_split` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=1.22) [p=2.21e-01, MI=0.0488, MI-p=4.00e-04, t2=0.04, t2-p=9.65e-01, Δ=0.114]
  - CPU leak: CPU usage differences significant across classes (|t|=1.18) [p=2.41e-01, MI=0.0518, MI-p=3.00e-04, t2=0.06, t2-p=9.54e-01, Δ=0.112]

### ml-kem (ML-KEM-512) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=1.45) [p=1.47e-01, MI=0.0255, MI-p=4.00e-04, t2=0.61, t2-p=5.41e-01, Δ=0.284]
  - CPU leak: CPU usage differences significant across classes (|t|=1.59) [p=1.11e-01, MI=0.0334, MI-p=1.00e-04, t2=1.05, t2-p=2.95e-01, Δ=0.263]

### ml-kem (ML-KEM-768) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=2.27) [p=2.37e-02, MI=0.0215, MI-p=8.80e-03, t2=1.31, t2-p=1.90e-01, Δ=0.548]
  - CPU leak: CPU usage differences significant across classes (|t|=2.38) [p=1.75e-02, MI=0.0233, MI-p=1.30e-03, t2=1.39, t2-p=1.65e-01, Δ=0.512]

### ml-kem (ML-KEM-1024) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=1.21) [p=2.26e-01, MI=0.0062, MI-p=8.12e-02, t2=0.90, t2-p=3.66e-01, Δ=0.606]
  - CPU leak: CPU usage differences significant across classes (|t|=1.18) [p=2.39e-01, MI=0.0062, MI-p=7.93e-02, t2=0.89, t2-p=3.72e-01, Δ=0.525]

### ntru (NTRU-HPS-2048-509) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=5.92) [p=5.37e-09, MI=0.0078, MI-p=1.17e-02, t2=1.14, t2-p=2.55e-01, Δ=0.849]
  - CPU leak: CPU usage differences significant across classes (|t|=5.97) [p=4.04e-09, MI=0.0073, MI-p=2.57e-02, t2=1.15, t2-p=2.52e-01, Δ=0.834]

### ntru (NTRU-HPS-2048-677) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=6.02) [p=2.81e-09, MI=0.0141, MI-p=5.00e-04, t2=1.41, t2-p=1.59e-01, Δ=0.674]
  - CPU leak: CPU usage differences significant across classes (|t|=6.19) [p=9.91e-10, MI=0.0178, MI-p=3.00e-04, t2=1.42, t2-p=1.57e-01, Δ=0.663]

### ntru (NTRU-HPS-4096-821) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=3.84) [p=1.34e-04, MI=0.0112, MI-p=3.57e-02, t2=1.64, t2-p=1.01e-01, Δ=0.554]
  - CPU leak: CPU usage differences significant across classes (|t|=3.88) [p=1.13e-04, MI=0.0110, MI-p=2.35e-02, t2=1.62, t2-p=1.06e-01, Δ=0.517]

### ntruprime (sntrup761) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=3.94) [p=8.59e-05, MI=0.0542, MI-p=1.00e-04, t2=0.71, t2-p=4.77e-01, Δ=0.677]
  - CPU leak: CPU usage differences significant across classes (|t|=4.05) [p=5.62e-05, MI=0.0587, MI-p=1.00e-04, t2=0.84, t2-p=4.03e-01, Δ=0.639]
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=3.83) [p=1.36e-04, MI=0.0907, MI-p=1.00e-04, t2=0.92, t2-p=3.56e-01, Δ=0.613]
  - CPU leak: CPU usage differences significant across classes (|t|=3.84) [p=1.30e-04, MI=0.0927, MI-p=1.00e-04, t2=0.93, t2-p=3.51e-01, Δ=0.581]
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=0.12) [p=9.03e-01, MI=0.0162, MI-p=4.14e-02, t2=0.83, t2-p=4.09e-01, Δ=0.543]
  - CPU leak: CPU usage differences significant across classes (|t|=0.08) [p=9.40e-01, MI=0.0150, MI-p=4.95e-02, t2=0.87, t2-p=3.87e-01, Δ=0.526]

### slh-dsa (SLH_DSA_PURE_SHA2_128S) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=5.32) [p=1.47e-07, MI=0.0277, MI-p=1.00e-04, t2=2.75, t2-p=6.22e-03, Δ=-0.093]
  - CPU leak: CPU usage differences significant across classes (|t|=5.65) [p=2.43e-08, MI=0.0351, MI-p=1.00e-04, t2=4.24, t2-p=2.66e-05, Δ=-0.090]

### snova (SNOVA_25_8_3) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=0.11) [p=9.16e-01, MI=0.0076, MI-p=8.61e-01, t2=0.88, t2-p=3.80e-01, Δ=0.150]
  - CPU leak: CPU usage differences significant across classes (|t|=0.03) [p=9.75e-01, MI=0.0104, MI-p=6.46e-01, t2=0.75, t2-p=4.51e-01, Δ=0.146]

### snova (SNOVA_60_10_4) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=1.61) [p=1.07e-01, MI=0.0162, MI-p=1.20e-01, t2=2.00, t2-p=4.61e-02, Δ=0.027]
  - CPU leak: CPU usage differences significant across classes (|t|=1.61) [p=1.07e-01, MI=0.0164, MI-p=1.05e-01, t2=2.00, t2-p=4.62e-02, Δ=0.028]

### uov (OV-Is) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=1.34) [p=1.80e-01, MI=0.0054, MI-p=5.97e-01, t2=1.27, t2-p=2.05e-01, Δ=0.119]
  - CPU leak: CPU usage differences significant across classes (|t|=1.43) [p=1.53e-01, MI=0.0042, MI-p=7.43e-01, t2=1.33, t2-p=1.83e-01, Δ=0.119]
