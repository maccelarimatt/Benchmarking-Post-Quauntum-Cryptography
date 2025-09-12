# pqcbench-rsa

Classical RSA adapters used as baselines:
- `rsa-oaep`: KEM-style wrapper around RSA-OAEP (encrypts a random 32-byte secret)
- `rsa-pss`: RSA-PSS signatures

Notes
- Implemented using `cryptography` primitives
- Intended only for benchmarking alongside PQC algorithms
