from __future__ import annotations

import base64
import hashlib
import io
import os
import random
import secrets
import sys
import time
import importlib
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterable, List, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_PROJECT_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "liboqs").exists())
_LIBOQS_PYTHON = _PROJECT_ROOT / "liboqs-python"
if _LIBOQS_PYTHON.exists() and str(_LIBOQS_PYTHON) not in sys.path:
    sys.path.insert(0, str(_LIBOQS_PYTHON))

if "OQS_LIB_PATH" not in os.environ:
    for _candidate in (
        _PROJECT_ROOT / "liboqs" / "build" / "bin" / "Release" / "oqs.dll",
        _PROJECT_ROOT / "liboqs" / "build" / "lib" / "liboqs.dylib",
        _PROJECT_ROOT / "liboqs" / "build" / "lib" / "liboqs.so",
    ):
        if _candidate.exists():
            os.environ["OQS_LIB_PATH"] = str(_candidate)
            break



def _rewrite_oqs_source(source: str) -> str:
    lines = source.splitlines()
    out: List[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped == "native().OQS_SIG_supports_ctx_str.restype = ct.c_bool":
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}if hasattr(native(), 'OQS_SIG_supports_ctx_str'):")
            out.append(f"{indent}    native().OQS_SIG_supports_ctx_str.restype = ct.c_bool")
        elif stripped == "native().OQS_SIG_supports_ctx_str.argtypes = [ct.c_char_p]":
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}if hasattr(native(), 'OQS_SIG_supports_ctx_str'):")
            out.append(f"{indent}    native().OQS_SIG_supports_ctx_str.argtypes = [ct.c_char_p]")
        elif stripped == "return bool(native().OQS_SIG_supports_ctx_str(ct.create_string_buffer(alg_name.encode())))":
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}if not hasattr(native(), 'OQS_SIG_supports_ctx_str'):")
            out.append(f"{indent}    return False")
            out.append(f"{indent}return bool(native().OQS_SIG_supports_ctx_str(ct.create_string_buffer(alg_name.encode())))")
        else:
            out.append(line)
    return "\n".join(out) + "\n"



def _inject_patched_oqs_module() -> ModuleType:
    path = _LIBOQS_PYTHON / "oqs" / "oqs.py"
    if not path.exists():
        raise ImportError("oqs module not found in local liboqs-python directory")
    source = path.read_text(encoding="utf-8")
    patched = _rewrite_oqs_source(source)
    module = ModuleType("oqs.oqs")
    module.__file__ = str(path)
    module.__package__ = "oqs"
    exec(compile(patched, str(path), "exec"), module.__dict__)
    sys.modules["oqs.oqs"] = module
    return module



def _import_oqs():
    try:
        return importlib.import_module("oqs")
    except AttributeError as exc:
        if "OQS_SIG_supports_ctx_str" not in str(exc):
            raise
        sys.modules.pop("oqs", None)
        sys.modules.pop("oqs.oqs", None)
        _inject_patched_oqs_module()
        importlib.invalidate_caches()
        return importlib.import_module("oqs")



oqs = _import_oqs()

CHANNELS = 4

HKDF_INFO_ENC = b"image-enc"
HKDF_INFO_PERM = b"perm"
HKDF_INFO_ROW = b"row-perm"

KEM_ALIASES: Dict[str, str] = {
    "Kyber512": "Kyber512",
    "ML-KEM-512": "Kyber512",
    "Kyber768": "Kyber768",
    "ML-KEM-768": "Kyber768",
    "HQC-128": "HQC-128",
    "HQC-192": "HQC-192",
}

SIG_ALIASES: Dict[str, str] = {
    "Dilithium2": "Dilithium2",
    "ML-DSA-44": "Dilithium2",
    "Falcon-512": "Falcon-512",
    "SPHINCS+-SHA2-128s": "SPHINCS+-SHA2-128s",
}


class PQCError(RuntimeError):
    """Raised when PQC operations fail or input is invalid."""


@dataclass
class PermMeta:
    shifts: List[int]
    flips: List[bool]

    def to_api(self) -> Dict[str, List[int] | List[bool]]:
        return {"shifts": self.shifts, "flips": self.flips}


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(field: str, value: Any) -> bytes:
    if not isinstance(value, str):
        raise PQCError(f"{field} must be a base64-encoded string.")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # pragma: no cover - defensive
        raise PQCError(f"{field} is not valid base64.") from exc


def _resolve_kem_name(name: Any) -> str:
    if not isinstance(name, str) or not name.strip():
        raise PQCError("KEM selection is required.")
    canonical = KEM_ALIASES.get(name.strip(), name.strip())
    if not oqs.is_kem_enabled(canonical):  # pragma: no cover - depends on runtime build
        raise PQCError(f"KEM '{name}' is not enabled in liboqs.")
    return canonical


def _resolve_sig_name(name: Any) -> str:
    if not isinstance(name, str) or not name.strip():
        raise PQCError("Signature selection is required.")
    canonical = SIG_ALIASES.get(name.strip(), name.strip())
    if not oqs.is_sig_enabled(canonical):  # pragma: no cover - depends on runtime build
        raise PQCError(f"Signature '{name}' is not enabled in liboqs.")
    return canonical


def generate_kem_keypair(kem_name: str) -> Tuple[bytes, bytes]:
    kem = _resolve_kem_name(kem_name)
    with oqs.KeyEncapsulation(kem) as kem_obj:
        public_key = kem_obj.generate_keypair()
        secret_key = kem_obj.export_secret_key()
    return public_key, secret_key


def kem_encapsulate(kem_name: str, public_key: bytes) -> Tuple[bytes, bytes]:
    kem = _resolve_kem_name(kem_name)
    if not isinstance(public_key, (bytes, bytearray)):
        raise PQCError("Public key must be bytes.")
    with oqs.KeyEncapsulation(kem) as kem_obj:
        ciphertext, shared_secret = kem_obj.encap_secret(bytes(public_key))
    return ciphertext, shared_secret


def kem_decapsulate(kem_name: str, secret_key: bytes, ciphertext: bytes) -> bytes:
    kem = _resolve_kem_name(kem_name)
    if not isinstance(secret_key, (bytes, bytearray)):
        raise PQCError("Secret key must be bytes.")
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise PQCError("Ciphertext must be bytes.")
    with oqs.KeyEncapsulation(kem, bytes(secret_key)) as kem_obj:
        shared_secret = kem_obj.decap_secret(bytes(ciphertext))
    return shared_secret


def generate_sig_keypair(sig_name: str) -> Tuple[bytes, bytes]:
    sig = _resolve_sig_name(sig_name)
    with oqs.Signature(sig) as sig_obj:
        public_key = sig_obj.generate_keypair()
        secret_key = sig_obj.export_secret_key()
    return public_key, secret_key


def sig_sign(sig_name: str, secret_key: bytes, message: bytes) -> bytes:
    sig = _resolve_sig_name(sig_name)
    if not isinstance(secret_key, (bytes, bytearray)):
        raise PQCError("Secret key must be bytes.")
    with oqs.Signature(sig, bytes(secret_key)) as sig_obj:
        return sig_obj.sign(bytes(message))


def sig_verify(sig_name: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    sig = _resolve_sig_name(sig_name)
    if not isinstance(public_key, (bytes, bytearray)):
        raise PQCError("Public key must be bytes.")
    with oqs.Signature(sig) as sig_obj:
        return bool(sig_obj.verify(bytes(message), bytes(signature), bytes(public_key)))


def _derive_key(shared_secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(shared_secret)


def _apply_row_permutation(data: bytes, width: int, height: int, perm_key: bytes, nonce: bytes) -> Tuple[bytes, PermMeta]:
    if width <= 0 or height <= 0:
        raise PQCError("Image dimensions must be positive.")
    row_bytes = width * CHANNELS
    if len(data) != row_bytes * height:
        raise PQCError("RGBA payload length does not match width/height.")
    seed_material = hashlib.sha256(perm_key + nonce + width.to_bytes(4, "little") + height.to_bytes(4, "little")).digest()
    rng = random.Random(int.from_bytes(seed_material, "big"))
    out = bytearray(len(data))
    shifts: List[int] = []
    flips: List[bool] = []
    for row_idx in range(height):
        start = row_idx * row_bytes
        view = memoryview(data)[start : start + row_bytes]
        pixels = [bytes(view[i : i + CHANNELS]) for i in range(0, row_bytes, CHANNELS)]
        shift = rng.randrange(width) if width > 1 else 0
        flip_flag = bool(rng.getrandbits(1))
        if shift:
            shift %= width
            pixels = pixels[-shift:] + pixels[:-shift]
        if flip_flag:
            pixels.reverse()
        shifts.append(int(shift))
        flips.append(flip_flag)
        out[start : start + row_bytes] = b"".join(pixels)
    return bytes(out), PermMeta(shifts=shifts, flips=flips)


def _undo_row_permutation(data: bytes, width: int, height: int, meta: PermMeta) -> bytes:
    row_bytes = width * CHANNELS
    if len(data) != row_bytes * height:
        raise PQCError("Ciphertext/plaintext length mismatch for provided dimensions.")
    if len(meta.shifts) != height or len(meta.flips) != height:
        raise PQCError("Permutation metadata length mismatch.")
    out = bytearray(len(data))
    for row_idx in range(height):
        start = row_idx * row_bytes
        view = memoryview(data)[start : start + row_bytes]
        pixels = [bytes(view[i : i + CHANNELS]) for i in range(0, row_bytes, CHANNELS)]
        flip_flag = bool(meta.flips[row_idx])
        shift = int(meta.shifts[row_idx]) % width if width > 0 else 0
        if flip_flag:
            pixels.reverse()
        if shift:
            pixels = pixels[shift:] + pixels[:shift]
        out[start : start + row_bytes] = b"".join(pixels)
    return bytes(out)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _load_image_rgba(image_bytes: bytes) -> Tuple[bytes, int, int]:
    try:
        from PIL import Image  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        raise PQCError("Pillow is required for image processing.") from exc
    with Image.open(io.BytesIO(image_bytes)) as img:  # type: ignore
        rgba = img.convert("RGBA")
        width, height = rgba.size
        return rgba.tobytes(), width, height


def _keystream_chacha20(key: bytes, nonce: bytes, length: int) -> bytes:
    if length <= 0:
        return b""
    if len(nonce) != 12:
        raise PQCError("ChaCha20 nonce must be 12 bytes (96 bits).")
    cipher = ChaCha20Poly1305(key)
    zero = b"\x00" * length
    stream = cipher.encrypt(nonce, zero, None)
    return stream[:length]


def encrypt_image_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    image_b64 = payload.get("imageBytesBase64")
    image_bytes = _b64decode("imageBytesBase64", image_b64)
    use_demo_seed = bool(payload.get("useDemoSeed", False))
    rgba_bytes, width, height = _load_image_rgba(image_bytes)

    kem_name = _resolve_kem_name(payload.get("kem"))
    sig_name = _resolve_sig_name(payload.get("sig"))

    kem_start = time.perf_counter()
    with oqs.KeyEncapsulation(kem_name) as receiver:
        kem_public = receiver.generate_keypair()
        kem_secret = receiver.export_secret_key()
        with oqs.KeyEncapsulation(kem_name) as sender:
            kem_ciphertext, _shared_secret_sender = sender.encap_secret(kem_public)
        shared_secret = receiver.decap_secret(kem_ciphertext)
    kem_ms = (time.perf_counter() - kem_start) * 1000.0

    if use_demo_seed:
        nonce = hashlib.sha256(rgba_bytes).digest()[:12]
    else:
        nonce = secrets.token_bytes(12)

    enc_key = _derive_key(shared_secret, nonce, HKDF_INFO_ENC)
    perm_key = _derive_key(shared_secret, nonce, HKDF_INFO_PERM)

    permuted_pixels, perm_meta = _apply_row_permutation(rgba_bytes, width, height, perm_key, nonce)

    sym_start = time.perf_counter()
    stream = _keystream_chacha20(enc_key, nonce, len(permuted_pixels))
    image_ciphertext = _xor_bytes(permuted_pixels, stream)
    sym_ms = (time.perf_counter() - sym_start) * 1000.0

    message_digest = hashlib.sha256(rgba_bytes).digest()
    with oqs.Signature(sig_name) as signer:
        sig_public = signer.generate_keypair()
        signature = signer.sign(message_digest)

    return {
        "kem": payload.get("kem"),
        "sig": payload.get("sig"),
        "kemPublicKey": _b64encode(kem_public),
        "kemSecretKey": _b64encode(kem_secret),
        "kemCiphertext": _b64encode(kem_ciphertext),
        "kemEncapMs": kem_ms,
        "nonce": _b64encode(nonce),
        "width": width,
        "height": height,
        "ciphertext": _b64encode(image_ciphertext),
        "ciphertextLen": len(image_ciphertext),
        "permMeta": perm_meta.to_api(),
        "signature": _b64encode(signature),
        "sigPublicKey": _b64encode(sig_public),
        "sigAlgorithm": payload.get("sig"),
        "symEncryptMs": sym_ms,
        "demoSeedUsed": use_demo_seed,
        "messageDigest": _b64encode(message_digest),
    }


def _parse_perm_meta(meta: Any, expected_rows: int) -> PermMeta:
    if not isinstance(meta, dict):
        raise PQCError("permMeta must be an object with shifts/flips.")
    shifts = meta.get("shifts")
    flips = meta.get("flips")
    if not isinstance(shifts, Iterable) or not isinstance(flips, Iterable):
        raise PQCError("permMeta must include 'shifts' and 'flips' arrays.")
    shifts_list = [int(v) for v in shifts]
    flips_list = [bool(v) for v in flips]
    if len(shifts_list) != expected_rows or len(flips_list) != expected_rows:
        raise PQCError("permMeta arrays must match the image height.")
    return PermMeta(shifts=shifts_list, flips=flips_list)


def decrypt_image_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    width = int(payload.get("width"))
    height = int(payload.get("height"))
    if width <= 0 or height <= 0:
        raise PQCError("Width and height must be positive integers.")

    cipher_bytes = _b64decode("ciphertext", payload.get("ciphertext"))
    nonce = _b64decode("nonce", payload.get("nonce"))
    if len(nonce) != 12:
        raise PQCError("Nonce must be 12 bytes (base64 encoded).")

    kem_ciphertext = _b64decode("kemCiphertext", payload.get("kemCiphertext"))
    kem_secret_key = _b64decode("kemSecretKey", payload.get("kemSecretKey"))
    kem_name = _resolve_kem_name(payload.get("kem"))

    perm_meta = _parse_perm_meta(payload.get("permMeta"), height)

    wrong_key = bool(payload.get("wrongKey", False))

    with oqs.KeyEncapsulation(kem_name, kem_secret_key) as kem_obj:
        shared_secret = kem_obj.decap_secret(kem_ciphertext)

    if wrong_key and shared_secret:
        mutated = bytearray(shared_secret)
        mutated[0] ^= 0x01
        shared_secret = bytes(mutated)

    enc_key = _derive_key(shared_secret, nonce, HKDF_INFO_ENC)
    stream = _keystream_chacha20(enc_key, nonce, len(cipher_bytes))
    permuted_plain = _xor_bytes(cipher_bytes, stream)
    recovered = _undo_row_permutation(permuted_plain, width, height, perm_meta)

    if wrong_key:
        return {"wrongKeyPreviewBytes": _b64encode(recovered)}

    sig_name = payload.get("sig")
    signature_b64 = payload.get("signature")
    sig_public_b64 = payload.get("sigPublicKey")
    verify_ok: bool | None = None
    if sig_name and signature_b64 and sig_public_b64:
        signature = _b64decode("signature", signature_b64)
        sig_public = _b64decode("sigPublicKey", sig_public_b64)
        digest = hashlib.sha256(recovered).digest()
        verify_ok = sig_verify(sig_name, sig_public, digest, signature)

    response: Dict[str, Any] = {
        "recoveredImageBytes": _b64encode(recovered),
    }
    if verify_ok is not None:
        response["verifyOk"] = bool(verify_ok)
    return response


