# Test Vectors: Fetch & Matrix

This folder is prepped to stage three authoritative sources of vectors:
- **NIST ACVP**: Final JSON vectors for **ML-KEM** and **ML-DSA**.
- **Project Wycheproof**: RSA OAEP & PSS (valid + negative) JSON vectors; also coverage for ML-KEM/ML-DSA.
- **PQClean**: Known Answer Tests (KATs) for Kyber, Dilithium, Falcon, SPHINCS+, XMSSMT, HQC (as available).

## Quick start

# From repo root
```
python3 fetch_vectors.py --dest ./data/vectors
```
The script will:
Download the zip archives of the three upstream repos.
Extract only the relevant subfolders/files into ./data/vectors/{nist_acvp,wycheproof,pqclean}.
Create a vector_manifest.json (paths + SHA-256) for reproducibility.
Re-run with --force to refresh.
Using the matrix
See test_matrix.yaml for the exact operations/parameters (repeats, warmups, OAEP message lengths, etc.).
Your benchmark harness should read this file and iterate.
