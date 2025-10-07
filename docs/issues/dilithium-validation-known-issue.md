# Dilithium Validation Known Issue

## Summary
`run-dilithium --tests` (and the corresponding pytest coverage) fails in two common situations:

1. **Missing vectors/binaries (fresh liboqs build).** The ACVP/KAT helpers rely on liboqs test binaries that are *not* built by default. Until those artifacts exist the harness reports missing vectors and the Dilithium test cases fail before execution begins.
2. **Signature mismatches with `vectors_sig`.** On newer liboqs commits (e.g. `f629296e` and friends) the deterministic Dilithium signer embedded in `vectors_sig` diverges from the ACVP fixtures supplied by NIST 1.1.0.40. The tool therefore emits `ML-DSA-65 ERROR: signature doesn't match!` for a subset of cases even though the adapter succeeds. The liboqs team is tracking this regression; the shipped vectors still reflect the earlier FIPS-ready reference implementation.

## Symptoms
- `pytest -k dilithium` or `run-dilithium --tests` raises `FileNotFoundError` / `Missing binary vectors_sig` / `PQCNativeError` pointing at `liboqs/tests/vectors_sig`.
- Validation blocks in the exported JSON show `status = failed` with `reason = missing_binary`.

## Root Cause
The Dilithium validation path wraps liboqs' deterministic self-tests. Those binaries (and the ACVP vector bundles) are only produced when liboqs is built with `PQCBENCH_ENABLE_LIBOQS_TESTS=ON` and the Git LFS assets for `liboqs/tests/ACVP_Vectors` are fetched. Without them the harness cannot replay the vectors, so the tests fail early.

## Workaround
1. Rebuild the native helper with validation support:
   ```bash
   cmake -S native -B native/build -DPQCBENCH_ENABLE_LIBOQS_TESTS=ON
   cmake --build native/build --target vectors_sig
   git lfs pull liboqs/tests/ACVP_Vectors
   ```
2. Ensure `PQCBENCH_NATIVE_LIB` points at the rebuilt library (or reinstall `libs/adapters/native`).
3. If you are on a liboqs commit that triggers deterministic mismatches, either:
   - temporarily build liboqs from the latest tagged release (`0.10.x`/`0.11.x` once published) whose `vectors_sig` matches the ACVP fixtures, **or**
   - rebuild with `-DOQS_USE_OPENSSL_SHA3=OFF` to force the reference SHAKE paths, which restores the expected signatures on macOS/Linux hosts without AVX512, **or**
   - skip Dilithium validation during routine CI runs (`run-dilithium --runs …` without `--tests`) until the upstream fix lands.
4. Re-run the Dilithium validation command/tests; they pass once binaries and matching vectors are in place.

## Status
Keeping Dilithium validation optional avoids forcing every contributor to compile the heavy liboqs test suite. Missing binaries and the current liboqs regression are therefore treated as **known issues** rather than hard blockers. The plan is to add a pre-flight check that downgrades missing binaries to a documented skip and to bump the tracked liboqs commit once the deterministic signature fix is merged upstream.
