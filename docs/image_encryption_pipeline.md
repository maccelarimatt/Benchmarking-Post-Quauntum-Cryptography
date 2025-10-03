# PQC Image Encryption Visualizer - Overview

This note explains how the image demo inside `apps/gui` works and keeps the description close to the current code. The goal is to make the flow easy to follow so you can tweak the demo or reuse parts of it elsewhere.

---

## Main Pieces

- **Browser (vanilla JS)** - reads the image file, shows the four canvases, and calls the JSON APIs.
- **Flask routes (`app.py`)** - expose `/api/pqc/encrypt-image` and `/api/pqc/decrypt-image` plus a few helper endpoints.
- **`pqc_visual.py` helpers** - wrap liboqs for KEM/signature work, run HKDF + ChaCha20, and handle the row permutation metadata.

Key Python dependencies:

- `oqs` (from `liboqs-python`) provides the PQ KEM and signature algorithms.
- `cryptography` supplies HKDF (SHA-256) and the ChaCha20 keystream via `ChaCha20Poly1305`.
- `Pillow` decodes the uploaded image file into RGBA bytes; the frontend sends the original file contents, not raw pixels.

---

## Encryption Flow (server)

Implemented in [`encrypt_image_payload`](../apps/gui/src/webapp/pqc_visual.py#L235).

1. **Decode the upload** - `imageBytesBase64` holds the original file. `_load_image_rgba` uses Pillow to open it, convert to RGBA, and capture `width` and `height`.
2. **KEM handshake** - create a receiver `KeyEncapsulation` object for the requested scheme (e.g. Kyber, HQC). Generate `(public_key, secret_key)`, encapsulate with a transient sender object, and decapsulate to recover the shared secret. Timing is recorded for the UI.
3. **Nonce and keys** - build a 12-byte nonce. Deterministic demo mode uses `SHA256(rgba_bytes)[:12]`; otherwise a random nonce from `secrets.token_bytes(12)` is returned. HKDF derives two 32-byte keys from the shared secret: `enc_key` (info=`b"image-enc"`) and `perm_key` (info=`b"perm"`).
4. **Row permutation** - `_apply_row_permutation` seeds `random.Random` with `SHA256(perm_key || nonce || width || height)`. For each row it chooses a right-rotation amount and optionally flips the row (reverse order). The order is rotate first, then flip. Metadata (`PermMeta`) stores the per-row shift and flip decisions.
5. **ChaCha20 keystream + XOR** - `_keystream_chacha20` uses `ChaCha20Poly1305` to generate bytes equal to the image length. XOR that stream with the permuted pixels to produce the ciphertext; the execution time is reported as `symEncryptMs`.
6. **Signature** - create a fresh signature keypair for the requested algorithm, hash the original RGBA bytes with SHA-256, and sign the digest. The response includes the signature, its public key, and the digest (useful for debugging).
7. **Response** - the JSON payload contains the user-facing algorithm names, Base64-encoded keys, ciphertext, nonce, `permMeta`, timings, signature info, `demoSeedUsed`, and `ciphertextLen`.

---

## Decryption Flow (server)

Handled by [`decrypt_image_payload`](../apps/gui/src/webapp/pqc_visual.py#L309).

1. **Validate inputs** - check width, height, nonce length, and Base64 fields. Recreate `PermMeta` from the JSON arrays.
2. **Decapsulate** - instantiate the KEM with the provided secret key and decapsulate the ciphertext to rebuild the shared secret.
3. **Wrong-key preview** - if `wrongKey` is true, flip the lowest bit of the first byte of the shared secret before continuing. That keeps the permutation metadata valid but ruins the keystream.
4. **Derive stream key** - HKDF derives `enc_key` again using the stored nonce and the same info string (`b"image-enc"`). The permutation key is not needed because the exact metadata is supplied by the client.
5. **Undo the keystream** - rebuild the ChaCha20 stream, XOR with the ciphertext, and obtain the permuted pixel buffer.
6. **Undo the permutation** - `_undo_row_permutation` reverses each row if `flips[i]` is true and then rotates the row left by `shifts[i]`, restoring the original RGBA order.
7. **Signature check** - for real decrypts recompute `SHA256(recovered_pixels)` and call `sig_verify` with the provided public key and signature. The boolean result (`verifyOk`) drives the badge in the UI. Wrong-key requests skip this and only return a preview buffer.

Responses contain either `wrongKeyPreviewBytes` (when `wrongKey` is true) or `recoveredImageBytes` plus `verifyOk` when available.

---

## Frontend Flow (browser)

Source: [`apps/gui/src/static/js/pqc-image-app.js`](../apps/gui/src/static/js/pqc-image-app.js).

- When the user selects a file, it is drawn to an off-screen canvas for display and the original bytes are cached in memory.
- Clicking **Encrypt** sends the Base64 file bytes, chosen KEM/SIG names, and the demo-seed flag to `/api/pqc/encrypt-image`. The ciphertext canvas is rendered from the response, metrics are updated, and decrypt buttons are enabled.
- Clicking **Decrypt** posts all returned metadata back to `/api/pqc/decrypt-image`. Success draws the recovered image, opens the modal, and updates the signature badge.
- Clicking **Wrong key** sets `wrongKey=true` and draws the "ghost" preview using the same endpoint.
- The random pad panel uses `crypto.getRandomValues` to fill an RGB buffer, falling back to `Math.random` if needed.

The frontend keeps nonce, permutation metadata, and keys in memory, so the server stays stateless between calls.

---

## Permutation Metadata

Example structure:

```json
{
  "shifts": [2, 0, 5],
  "flips": [false, true, false]
}
```

- `shifts[i]` counts how many pixels row `i` was rotated to the right **before** any flip.
- `flips[i]` records whether row `i` was reversed.
- To invert the permutation: if `flips[i]` is true, reverse the row, then rotate it left by `shifts[i]`.

---

## Security Notes

- The "demo seed" makes runs reproducible by hashing the image pixels. Production code should always use a fresh random nonce.
- ChaCha20 is used purely as a stream cipher; integrity comes from the PQ signature. In a real system you would keep the signature and consider an AEAD or MAC as well.
- The demo returns the KEM secret key to the browser so everything can run locally. Real deployments must never expose secret keys.
- Row permutations are intentionally simple, so ciphertext images show visible banding that matches the visualization published with the project.

---

## File Reference

| Component | File | Purpose |
|-----------|------|---------|
| Backend helpers | [`pqc_visual.py`](../apps/gui/src/webapp/pqc_visual.py) | KEM/SIG wrappers, HKDF, permutation, ChaCha20 |
| HTTP layer | [`app.py`](../apps/gui/src/webapp/app.py) | Flask routes that serve JSON and templates |
| Frontend logic | [`pqc-image-app.js`](../apps/gui/src/static/js/pqc-image-app.js) | Canvas rendering and API calls |
| Template | [`image_encryption.html`](../apps/gui/src/templates/image_encryption.html) | Layout for the image demo |

With this map you can trace an uploaded byte from the browser, through key exchange and encryption, and back again during decryption.
