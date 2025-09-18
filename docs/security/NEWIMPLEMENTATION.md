Sanity check complete. I verified that GUI runs against the native C backend and that native KEM/SIG operations round‑trip correctly.

Native Sanity Checks

Environment used: PQCBENCH_NATIVE_LIB → native/build/Release/pqcbench_native.dll
KEM ML-KEM-768 (Kyber): keygen/encap/decap round‑trip ok; sizes match expectations
Output: kyber-ok True, pk=1184, sk=2400, ct=1088, ss=32
SIG ML-DSA-65 (Dilithium): keygen/sign/verify ok
Output: dilithium-ok True, pk=1952, sk=4032, sig=3309
SIG Falcon‑512: keygen/sign/verify ok
Output: falcon-ok True, pk=897, sk=1281, sig=655
SIG SPHINCS+ SHA2‑128s‑simple: keygen/sign/verify ok
Output: sphincs-ok True, pk=32, sk=64, sig=7856
HQC KEM: not enabled in your current native liboqs build (expected if liboqs was built without HQC)
Output: hqc-skip PQCNativeError: No supported HQC mechanism found in native backend
You can re-run these locally:

PowerShell
$env:PQCBENCH_NATIVE_LIB=(Resolve-Path 'native/build/Release/pqcbench_native.dll').Path
$env:PYTHONPATH='libs/core/src;libs/adapters/native/src'
python -c "from pqcbench import registry; import pqcbench_native, os; os.environ['PQCBENCH_KYBER_ALG']='ML-KEM-768'; k=registry.get('kyber')(); pk,sk=k.keygen(); ct,ss=k.encapsulate(pk); ss2=k.decapsulate(sk,ct); print('kyber-ok', ss==ss2, len(pk), len(sk), len(ct), len(ss))"
How Native Calls Work (Deep Dive)

Flow Overview

GUI submits → run_kem/run_sig invoked → registry resolves algorithm class → pqcbench_native adapter instance → pqcbench_native._core ctypes → pqcbench_native.dll functions → liboqs (and OpenSSL for RSA)
GUI Integration

Imports CLI runners and calls run_kem/run_sig: apps/gui/src/webapp/app.py:41
Ensures adapters are loaded before use: apps/gui/src/webapp/app.py:60
Runners dispatch to registry and measure ops: apps/cli/src/pqcbench_cli/runners/common.py:583 (KEM), apps/cli/src/pqcbench_cli/runners/common.py:622 (SIG)
Adapter Loading And Precedence

Loader tries: pqcbench_rsa → pqcbench_liboqs → pqcbench_native and logs optional warnings: apps/cli/src/pqcbench_cli/runners/common.py:45
Registry is “last writer wins”: libs/core/src/pqcbench/registry.py:16
Because native loads last, native classes override liboqs Python adapters when available.
Native Adapter Classes (Python)

KEM: pqcbench_native.kem.Kyber and HQC register as kyber/hqc: libs/adapters/native/src/pqcbench_native/kem.py:28
Methods call _core: kem_keypair, kem_encapsulate, kem_decapsulate
Algorithm chosen via env (e.g., PQCBENCH_KYBER_ALG) and resolve_algorithm
SIG: pqcbench_native.sig.{Dilithium,Falcon,SphincsPlus,Mayo}: libs/adapters/native/src/pqcbench_native/sig.py:24
Methods call _core: sig_keypair, sig_sign, sig_verify
Algorithm chosen via env (e.g., PQCBENCH_DILITHIUM_ALG)
Python↔C Bridge (ctypes)

Buffer struct mirror and function prototypes: libs/adapters/native/src/pqcbench_native/_core.py:13, :75
_Buffer = (void* data, size_t len), backed by pqcbench_buffer in C
Exported function mappings:
KEM: pqcbench_kem_is_supported, pqcbench_kem_keypair, pqcbench_kem_encapsulate, pqcbench_kem_decapsulate
SIG: pqcbench_sig_is_supported, pqcbench_sig_keypair, pqcbench_sig_sign, pqcbench_sig_verify
RSA: pqcbench_has_rsa, pqcbench_rsa_* (when compiled with OpenSSL)
Memory management:
C side allocates output buffers; Python converts with _buffer_to_bytes() and calls pqcbench_free() to release C memory: libs/adapters/native/src/pqcbench_native/_core.py:141
C Implementation (native DLL)

Header defines API ABI: native/include/pqcbench_native.h:33
pqcbench_buffer { uint8_t* data; size_t len; }
Status codes: OK / UNSUPPORTED / RUNTIME / ALLOC
KEM via liboqs:
OQS_KEM_new, OQS_KEM_keypair, OQS_KEM_encaps, OQS_KEM_decaps: native/src/pqcbench_native.c:87, :121, :158
SIG via liboqs:
OQS_SIG_new, OQS_SIG_keypair, OQS_SIG_sign, OQS_SIG_verify: native/src/pqcbench_native.c:196, :230, :260
RSA via OpenSSL (optional):
OAEP and PSS set up via EVP APIs; presence advertised by pqcbench_has_rsa: native/src/pqcbench_native.c:288
Algorithm Selection (Env Support)

KEM: PQCBENCH_KYBER_ALG, PQCBENCH_HQC_ALG; fallbacks include NIST names and legacy names: libs/adapters/native/src/pqcbench_native/kem.py:33
SIG: PQCBENCH_DILITHIUM_ALG, PQCBENCH_FALCON_ALG, PQCBENCH_SPHINCS_ALG, PQCBENCH_MAYO_ALG: libs/adapters/native/src/pqcbench_native/sig.py:18
Helper resolve_algorithm() checks native support via *_is_supported: libs/adapters/native/src/pqcbench_native/_core.py:156
Ensuring Native Is Used In GUI

Set the DLL path (robust): $env:PQCBENCH_NATIVE_LIB=(Resolve-Path 'native/build/Release/pqcbench_native.dll').Path
Start GUI: python apps/gui/src/webapp/app.py
Verify backend resolution in a side shell:
$env:PYTHONPATH='apps/cli/src;libs/core/src'
python -c "from pqcbench_cli.runners import common; from pqcbench import registry; print(registry.get('kyber').__module__)" → prints pqcbench_native.kem
Notes:

The RSA adapter import warning was from the optional Python RSA adapter; I installed cryptography so that log noise is gone. It never blocked the native path.
The liboqs version mismatch warning is from the Python liboqs package; your native backend uses the compiled liboqs bundled into the DLL. It’s harmless when using native.