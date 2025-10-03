# PQC Image Encryption Visualizer – Deep Dive

This document explains, in detail, how the PQC image encryption demo inside `apps/gui` works. The walkthrough covers the backend cryptography (implemented in [`apps/gui/src/webapp/pqc_visual.py`](../apps/gui/src/webapp/pqc_visual.py)), the FastAPI-style Flask endpoints that expose it, and the browser code that orchestrates the four visualization panels. The goal is to make it easy to understand and extend the demo, or to port the ideas into production software.

---

## 1. High-level Architecture

The visualizer is intentionally split into three layers:

```
┌───────────────────────────────┐
│  Browser (vanilla JS)         │
│  - Renders canvases (a)–(d)   │
│  - Handles file uploads       │
│  - Calls JSON APIs            │
└──────────────┬────────────────┘
               │ HTTPS POSTs
┌──────────────▼────────────────┐
│  Flask routes (app.py)        │
│  - /api/pqc/encrypt-image     │
│  - /api/pqc/decrypt-image     │
│  - /api/pqc/kem/*, /sig/*     │
└──────────────┬────────────────┘
               │ Python calls
┌──────────────▼────────────────┐
│  pqc_visual.py helpers        │
│  - Wrap liboqs KEM + SIG      │
│  - HKDF + ChaCha20 stream     │
│  - Row permutation metadata   │
└───────────────────────────────┘
```

Key Python dependencies:

- **`oqs`** (via `liboqs-python`): exposes Kyber, HQC, Dilithium, Falcon, and SPHINCS+. Because some packaged builds may omit newer symbols (e.g., `OQS_SIG_supports_ctx_str`), the web app imports it through a small shim in [`pqc_visual.py`](../apps/gui/src/webapp/pqc_visual.py). The shim tries a normal import first; if `AttributeError` is raised it rewrites the vendored `oqs.py` in-memory to guard the missing symbol and retries. No files inside the liboqs repository are modified on disk.
- **`cryptography`**: provides HKDF (`hashes.SHA256`) and the ChaCha20 keystream via `ChaCha20Poly1305`. We ignore the AEAD tag and use the keystream solely as a fast XOR stream cipher.
- **`Pillow`** is not required for encryption—image decoding happens client-side—but `_load_image_rgba` in `pqc_visual.py` can use it when the backend is asked to load bytes.

---

## 2. Encryption Pipeline (server side)

All encryption logic resides in [`encrypt_image_payload`](../apps/gui/src/webapp/pqc_visual.py#L235). The function consumes an `EncryptRequest` JSON document (see §4) and produces an `EncryptResponse`. The major stages are:

### 2.1 Input validation and image loading
1. Base64-decode the raw RGBA payload (or raise `PQCError` if decoding fails).
2. Convert the image into an RGBA byte array and record its width & height. Each pixel contributes four bytes (R, G, B, A).

### 2.2 KEM key agreement (liboqs)
1. Resolve the requested KEM name, e.g. `Kyber512` or `HQC-192`. `_resolve_kem_name` ensures the algorithm is enabled in the local liboqs build.
2. Instantiate a receiver `KeyEncapsulation` object, generate a keypair `(pk, sk)`, and export the secret key.
3. Instantiate a sender object and encapsulate to the public key, obtaining `(ciphertext, shared_secret)`.
4. Decapsulate on the receiver side to recover the same 32-byte shared secret.
5. Measure and return the total time (milliseconds) for diagnostics.

> **Why derive and decapsulate immediately?** The demo simulates a two-party flow entirely on the server for reproducibility, so the shared secret is available immediately. In a real deployment, the encapsulation would happen client-side instead.

### 2.3 Nonce and key derivation
1. Compute a 96-bit nonce. If the “demo seed” toggle is on, we derive the nonce deterministically from `SHA-256(image_bytes)[:12]`; otherwise we use `secrets.token_bytes(12)`.
2. Feed the shared secret into HKDF (SHA-256) twice with different `info` labels:
   - `enc_key = HKDF(shared_secret, salt=nonce, info=b"image-enc", length=32)`
   - `perm_key = HKDF(shared_secret, salt=nonce, info=b"perm", length=32)`

Using different `info` labels avoids key reuse between the stream cipher and the permutation PRNG.

### 2.4 Row permutation with banding
1. `_apply_row_permutation` shuffles each row deterministically, yielding `permuted_pixels` and metadata describing what happened:
   - For each row, derive a coin flip to decide whether to reverse it.
   - Derive a circular shift amount `shift ∈ [0, width)` and rotate the row.
2. The metadata is a `PermMeta` object: two arrays (`shifts`, `flips`) with one entry per row. This is returned to the client so decryption can undo the exact permutation.
3. The permutation is seeded with `perm_key`, `nonce`, and the image dimensions, making it unpredictable without the shared secret. The intentional row-wise shift introduces horizontal “banding” so the ciphertext matches the reference visualization.

### 2.5 ChaCha20 keystream + XOR
1. Use `enc_key` and the same nonce to create a ChaCha20 keystream with length equal to `len(permuted_pixels)`.
2. XOR the keystream with the permuted pixel bytes, producing the ciphertext. Timing is captured as `symEncryptMs` for the UI.

### 2.6 Signature over original pixels
1. Resolve the requested signature scheme (`Dilithium2`, `Falcon-512`, `SPHINCS+-SHA2-128s`).
2. Generate a signature keypair using `oqs.Signature` and compute `signature = sign( SHA256(original_rgba) )`.
3. The signature and public key are included in the response so the frontend can verify integrity after decrypting.

### 2.7 Response payload
The response returns:

- KEM public/secret key (Base64), ciphertext, shared timings, nonce, and metadata describing the permutation.
- Signature public key, signature bytes, and a SHA-256 digest of the original data (mainly for debugging).
- Flags like `demoSeedUsed` and `ciphertextLen` for the session panel.

---

## 3. Decryption Pipeline (server side)

[`decrypt_image_payload`](../apps/gui/src/webapp/pqc_visual.py#L309) accepts the `DecryptRequest` JSON payload and supports two scenarios: correct-key recovery and “wrong key” preview.

1. **Input validation**: confirm width, height, nonce length, and Base64 encodings. Reconstitute the `PermMeta` object.
2. **Decapsulation**: instantiate the requested KEM with the provided secret key and decapsulate the ciphertext to recover the shared secret.
3. **Wrong-key option**: If `wrongKey` is true, flip the least-significant bit of the first byte of the shared secret before deriving keys. This spoils the keystream while still allowing us to attempt permutation reversal, creating the “ghost” image.
4. **Key derivation**: same HKDF calls as in encryption to recover `enc_key`.
5. **Keystream + XOR**: generate ChaCha20 keystream, XOR with the ciphertext to obtain the permuted plaintext.
6. **Undo permutation**: `_undo_row_permutation` uses `PermMeta` to reverse per-row flips and shifts, reconstructing the original raster order.
7. **Signature verification**: when decrypting with the genuine key, recompute `SHA256(recovered_pixels)` and call `sig_verify`. The boolean result is returned so the frontend can color the badge.

Outputs:

- For `wrongKey=true`, the endpoint returns only `wrongKeyPreviewBytes` (RGBA base64) so the UI can draw panel (c).
- For correct-key requests, it returns `recoveredImageBytes` and, where available, `verifyOk`.

---

## 4. API Contracts

The Flask app (`app.py`) exposes thin JSON wrappers around the helper functions. Key endpoints:

| Method | Path                        | Purpose                        |
|--------|-----------------------------|--------------------------------|
| POST   | `/api/pqc/encrypt-image`    | Run the full pipeline (§2).    |
| POST   | `/api/pqc/decrypt-image`    | Run decryption (§3).           |
| POST   | `/api/pqc/kem/keypair`      | Optional utility for demos.    |
| POST   | `/api/pqc/kem/encapsulate`  | Encapsulation helper.          |
| POST   | `/api/pqc/kem/decapsulate`  | Decapsulation helper.          |
| POST   | `/api/pqc/sig/keypair`      | Signature key generation.      |
| POST   | `/api/pqc/sig/sign`         | Sign arbitrary message bytes.  |
| POST   | `/api/pqc/sig/verify`       | Verify signature.              |

The TypeScript-style types documented in the prompt are faithfully implemented—see the return value in `encrypt_image_payload` and the expected fields inside `decrypt_image_payload`.

---

## 5. Frontend Workflow (vanilla JS)

The browser code lives in [`apps/gui/src/static/js/pqc-image-app.js`](../apps/gui/src/static/js/pqc-image-app.js). It uses only DOM APIs; there are no build steps:

1. **File ingestion**: the user selects an image, the script draws it to an off-screen canvas to obtain RGBA data, and it renders the original image in panel (a).
2. **Random pad**: `fillRandomBytes` fills an RGB buffer in ≤65 536 byte chunks (to respect WebCrypto limits) and draws panel (d).
3. **Encrypt button**: constructs an `EncryptRequest` with Base64-encoded bytes and sends it to `/api/pqc/encrypt-image`. On success it draws panel (b) from the ciphertext bytes (interpreted as RGB noise), updates metrics, and enables the decrypt buttons.
4. **Decrypt (correct key)**: sends the saved metadata to `/api/pqc/decrypt-image` with `wrongKey=false`. The recovered image is shown in a modal, and the signature badge switches to “verified” or “mismatch”.
5. **Decrypt with wrong key**: same call but with `wrongKey=true`. Panel (c) renders the faint ghost image.

All canvases are rendered via `CanvasRenderingContext2D.putImageData`. Because we retain the permutation metadata and nonce client-side, the demo does not need to persist anything on the server.

---

## 6. Permutation Metadata Format

`PermMeta` serializes as:

```json
{
  "shifts": [2, 0, 5, …],
  "flips": [false, true, false, …]
}
```

- `shifts[i]` is the circular right-shift applied to row `i` after potential reversal.
- `flips[i]` is `true` if row `i` was reversed.
- Both arrays contain exactly `height` entries.

To undo a permutation, we (a) reverse the row if `flips[i]` was true, then (b) rotate left by `shifts[i]`.

---

## 7. Security Considerations

- **Demo seed**: deterministic mode is for reproducible visuals only. In production you must use a fresh random nonce per encryption.
- **ChaCha20 without Poly1305 tag**: we treat ChaCha20 as a stream cipher. Integrity is provided separately by the PQ signature. For real deployments, consider an AEAD (e.g. ChaCha20-Poly1305) in addition to the signature or MAC.
- **Permutation leakage**: Row permutations introduce structured noise (banding) intentionally. Removing it would produce even higher-entropy ciphertext visuals.
- **Key material exposure**: The demo returns KEM secret keys to the browser so “correct decrypt” can run locally. In a real system these keys must stay server-side.
- **Wrong-key preview**: Flipping a single bit in the shared secret is enough to obliterate the decrypted image, demonstrating sensitivity of the keystream. It is not a real cryptanalytic test but reinforces the avalanche effect.

---

## 8. Extending the Demo

1. **Alternative symmetric ciphers**: Swap ChaCha20 for AES-CTR by replacing `_keystream_chacha20`. HKDF derivation stays the same.
2. **Additional permutations**: `_apply_row_permutation` can be replaced with full block-based shuffles, random column permutations, or wavelet transforms, as long as metadata for inversion is preserved.
3. **Streaming support**: Split the image into tiles and process each chunk with its own nonce (similar to how video codecs operate) for very large payloads.
4. **Pipeline integration**: The `/api/pqc/kem/*` and `/api/pqc/sig/*` endpoints already expose raw operations. They can be combined with other services for benchmarking or auditing.

---

## 9. Quick Reference

| Component | File | Responsibility |
|-----------|------|----------------|
| Backend helpers | [`pqc_visual.py`](../apps/gui/src/webapp/pqc_visual.py) | KEM/SIG wrappers, HKDF, permutations, ChaCha20 |
**Import shim** (pqc_visual.py)
: Coordinates the dynamic import described above. It tries `import oqs` normally, and if liboqs's Python wrapper raises an `AttributeError` for `OQS_SIG_supports_ctx_str`, it reloads the module from the local `liboqs-python` checkout, wraps the problematic assignments in `hasattr` guards, installs the patched module in `sys.modules`, and re-issues the import. This keeps the demo working across mixed liboqs versions without touching the vendored sources.

| HTTP layer | [`app.py`](../apps/gui/src/webapp/app.py) | Flask routes exposing JSON APIs |
| Frontend logic | [`pqc-image-app.js`](../apps/gui/src/static/js/pqc-image-app.js) | DOM wiring, canvas rendering, API calls |
| Template | [`image_encryption.html`](../apps/gui/src/templates/image_encryption.html) | Layout matching the main site |

With this breakdown you should be able to trace any byte from the uploaded image through encapsulation, permutation, encryption, signature, and back again.
