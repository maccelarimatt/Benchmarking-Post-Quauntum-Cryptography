# Native Backend Sanity Checks

Quick reference for validating that the GUI and CLI use the C backend
(`pqcbench_native`) successfully. Useful after rebuilding liboqs or tweaking the
native adapters.

## Snapshot Validation

Environment:
- `PQCBENCH_NATIVE_LIB = native/build/Release/pqcbench_native.dll`
- `PYTHONPATH` includes `libs/core/src` and `libs/adapters/native/src`

Observed round-trips:
- **ML-KEM-768 (Kyber)** – keygen/encapsulate/decapsulate, lengths
  `(pk=1184, sk=2400, ct=1088, ss=32)`.
- **ML-DSA-65 (Dilithium)** – keygen/sign/verify, signature length `3309` bytes.
- **Falcon-512** – keygen/sign/verify, signature length `655` bytes.
- **SPHINCS+ SHA2-128s-simple** – keygen/sign/verify, signature length `7856` bytes.
- **HQC** – skipped in the sample build (liboqs compiled without HQC support);
  expect `PQCNativeError: No supported HQC mechanism found`.

Run the quick smoke test in PowerShell:
```powershell
$env:PQCBENCH_NATIVE_LIB = (Resolve-Path 'native/build/Release/pqcbench_native.dll').Path
$env:PYTHONPATH = 'libs/core/src;libs/adapters/native/src'
python -c "from pqcbench import registry; import os; os.environ['PQCBENCH_KYBER_ALG']='ML-KEM-768';
cls = registry.get('kyber'); pk, sk = cls().keygen(); ct, ss = cls().encapsulate(pk);
ss2 = cls().decapsulate(sk, ct); print('kyber-ok', ss == ss2, len(pk), len(sk), len(ct), len(ss))"
```

## Classical RSA on the Native Path

To force RSA benchmarks through the native library (OpenSSL-backed):
```powershell
$env:PQCBENCH_NATIVE_LIB = (Resolve-Path 'native/build/Release/pqcbench_native.dll').Path
$env:PYTHONPATH = 'apps/cli/src;libs/core/src;libs/adapters/native/src'
run-rsa-oaep --runs 10 --export results/rsa_oaep.json
run-rsa-pss --runs 10 --export results/rsa_pss.json
```

Notes:
- Swap `Release` for `RelWithDebInfo` or `Debug` to match your build.
- Change `PQCBENCH_RSA_BITS` (defaults to 2048) to benchmark alternate modulus
  sizes.
- Confirm native dispatch with:
  ```bash
  python -c "from pqcbench_cli.runners import common; from pqcbench import registry;
  common._load_adapters(); print(registry.get('rsa-oaep').__module__)"  # expect pqcbench_native.rsa
  ```
- Add `--no-cold` to any runner to reuse the same process for warm-cache runs.

## How the Native Path Works

### Flow Overview
`GUI request` → `run_kem/run_sig` → registry resolves adapter → Python wrapper in
`pqcbench_native` → `_core` (ctypes bridge) → `pqcbench_native` shared library →
liboqs/OpenSSL implementations.

### GUI Touchpoints
- Routes live in `apps/gui/src/webapp/app.py` (see lines 41 and 60).
- Runners reuse the CLI helpers (`apps/cli/src/pqcbench_cli/runners/common.py`
  lines 583 for KEM, 622 for signatures).

### Adapter Loading Order
- Loader tries `pqcbench_rsa`, then `pqcbench_liboqs`, then `pqcbench_native`
  (`common.py:45`).
- Registry is “last writer wins” (`libs/core/src/pqcbench/registry.py:16`), so
  native implementations override the Python shims when available.

### Python ↔ C Bridge
- ctypes wrapper in `libs/adapters/native/src/pqcbench_native/_core.py` mirrors
  `pqcbench_buffer` and exposes `kem_*`, `sig_*`, and `rsa_*` functions.
- Output buffers allocated in C are freed via `pqcbench_free()` after conversion
  back to Python bytes (`_core.py:141`).

### C Implementation Highlights
- API defined in `native/include/pqcbench_native.h` with status codes for
  `OK/UNSUPPORTED/RUNTIME/ALLOC`.
- KEM/SIG paths call into liboqs (`native/src/pqcbench_native.c:87-260`).
- Optional RSA path uses OpenSSL EVP routines (`native/src/pqcbench_native.c:288+`).

### Environment Overrides
- KEM selection: `PQCBENCH_KYBER_ALG`, `PQCBENCH_HQC_ALG` (fallbacks include
  NIST and legacy names).
- Signature selection: `PQCBENCH_DILITHIUM_ALG`, `PQCBENCH_FALCON_ALG`,
  `PQCBENCH_SPHINCS_ALG`, `PQCBENCH_MAYO_ALG`.
- `resolve_algorithm()` checks native support before instantiating adapters.

## GUI Verification Checklist
- Set `PQCBENCH_NATIVE_LIB` before launching Flask.
- Start the app: `python apps/gui/src/webapp/app.py`.
- In another shell, confirm registry resolution:
  ```bash
  python -c "from pqcbench_cli.runners import common; from pqcbench import registry;
  print(registry.get('kyber').__module__)"  # expect pqcbench_native.kem
  ```
- Ignore the optional Python RSA adapter warning once `cryptography` is
  installed. liboqs version mismatch warnings refer to the Python package and do
  not affect the native backend.
