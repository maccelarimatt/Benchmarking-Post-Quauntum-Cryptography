### falcon (Falcon-512) — Medium risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (medium)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=34.87) [p=6.59e-197, MI=0.3215, MI-p=1.00e-04, t2=4.27, t2-p=2.06e-05, Δ=0.728]

### falcon (Falcon-1024) — Medium risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (medium)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=4.43) [p=1.03e-05, MI=0.0244, MI-p=1.00e-04, t2=5.25, t2-p=1.87e-07, Δ=0.038]

### hqc (HQC-128) — Medium risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (medium)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=4.50) [p=7.72e-06, MI=0.0083, MI-p=1.60e-03, t2=1.82, t2-p=6.95e-02, Δ=-0.387]

### hqc (HQC-192) — Medium risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (medium)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=22.91) [p=5.98e-100, MI=0.5245, MI-p=1.00e-04, t2=0.58, t2-p=5.63e-01, Δ=-0.956]

### hqc (HQC-256) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=1.25) [p=2.12e-01, MI=0.2680, MI-p=1.00e-04, t2=4.88, t2-p=1.16e-06, Δ=0.271]
  - RSS leak: Memory-resident footprint varies with leakage classification (|t|=0.00) [p=9.97e-01, MI=0.0049, MI-p=3.68e-01, t2=0.47, t2-p=6.39e-01, Δ=0.172]

### kyber (ML-KEM-512) — Medium risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (medium)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=3.46) [p=5.51e-04, MI=0.0292, MI-p=1.00e-04, t2=0.69, t2-p=4.92e-01, Δ=0.373]

### kyber (ML-KEM-768) — Medium risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (medium)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=3.54) [p=4.19e-04, MI=0.0106, MI-p=3.10e-03, t2=0.05, t2-p=9.62e-01, Δ=0.394]

### kyber (ML-KEM-1024) — Medium risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (medium)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=2.85) [p=4.43e-03, MI=0.0123, MI-p=2.00e-04, t2=1.01, t2-p=3.13e-01, Δ=0.409]

### mayo (MAYO-3) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=1.10) [p=2.71e-01, MI=0.0205, MI-p=1.00e-04, t2=0.14, t2-p=8.92e-01, Δ=0.114]
  - RSS leak: Memory-resident footprint varies with leakage classification (|t|=0.38) [p=7.01e-01, MI=0.0032, MI-p=3.79e-02, t2=0.07, t2-p=9.46e-01, Δ=0.174]

### mayo (MAYO-5) — Medium risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (medium)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=13.64) [p=4.35e-40, MI=0.4176, MI-p=1.00e-04, t2=2.73, t2-p=6.43e-03, Δ=0.759]

### rsa-oaep (RSA-3072-OAEP) — Medium risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (medium)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=17.65) [p=8.08e-64, MI=0.3448, MI-p=1.00e-04, t2=0.10, t2-p=9.23e-01, Δ=0.744]

### rsa-oaep (RSA-7680-OAEP) — High risk
- **Scenario:** `kem_tvla_decapsulation:fixed vs invalid` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=3.08) [p=2.09e-03, MI=0.0171, MI-p=1.00e-04, t2=0.65, t2-p=5.17e-01, Δ=0.155]
  - CPU leak: CPU usage differences significant across classes (|t|=2.61) [p=9.22e-03, MI=0.0162, MI-p=8.00e-04, t2=0.54, t2-p=5.89e-01, Δ=0.094]

### rsa-pss (RSA-3072-PSS) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=10.98) [p=2.19e-26, MI=0.0692, MI-p=1.00e-04, t2=2.19, t2-p=2.87e-02, Δ=-0.918]
  - RSS leak: Memory-resident footprint varies with leakage classification (|t|=0.91) [p=3.64e-01, MI=0.0035, MI-p=4.41e-01, t2=0.37, t2-p=7.11e-01, Δ=0.102]

### rsa-pss (RSA-7680-PSS) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=5.98) [p=2.75e-09, MI=0.3236, MI-p=1.00e-04, t2=1.52, t2-p=1.29e-01, Δ=0.522]
  - CPU leak: CPU usage differences significant across classes (|t|=4.71) [p=2.75e-06, MI=0.0080, MI-p=1.00e-04, t2=0.16, t2-p=8.76e-01, Δ=0.121]

### sphincs+ (SPHINCS+-SHAKE-128s-simple) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=1.75) [p=7.95e-02, MI=0.0273, MI-p=1.00e-04, t2=3.38, t2-p=7.56e-04, Δ=0.069]
  - CPU leak: CPU usage differences significant across classes (|t|=0.82) [p=4.13e-01, MI=0.0080, MI-p=2.00e-04, t2=3.27, t2-p=1.12e-03, Δ=-0.006]

### sphincs+ (SPHINCS+-SHAKE-192s-simple) — High risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (high)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=10.48) [p=8.14e-25, MI=0.0640, MI-p=1.00e-04, t2=7.11, t2-p=2.18e-12, Δ=0.147]
  - CPU leak: CPU usage differences significant across classes (|t|=9.39) [p=2.10e-20, MI=0.0465, MI-p=1.00e-04, t2=6.89, t2-p=7.79e-12, Δ=0.232]

### sphincs+ (SPHINCS+-SHAKE-256s-simple) — Medium risk
- **Scenario:** `signature_tvla_sign:fixed vs random` (medium)
  - TIME leak: Timing variance between leakage classes exceeds TVLA threshold (|t|=0.62) [p=5.37e-01, MI=0.0408, MI-p=1.00e-04, t2=1.84, t2-p=6.61e-02, Δ=0.129]
