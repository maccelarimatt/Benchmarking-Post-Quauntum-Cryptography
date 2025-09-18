from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Callable, Optional, Sequence, Tuple


class PQCNativeError(RuntimeError):
    pass


class _Buffer(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.c_void_p),
        ("len", ctypes.c_size_t),
    ]


def _default_candidates() -> Sequence[Path]:
    env = os.getenv("PQCBENCH_NATIVE_LIB")
    if env:
        yield Path(env)
    here = Path(__file__).resolve()
    visited: set[Path] = set()
    names = [
        "pqcbench_native.dll",
        "libpqcbench_native.dll",
        "libpqcbench_native.so",
        "libpqcbench_native.dylib",
    ]
    # Prefer RelWithDebInfo over Release/Debug if multiple configs exist
    # so development builds with additional algorithms (e.g., HQC) win.
    subdirs = [Path("RelWithDebInfo"), Path("Release"), Path("Debug"), Path(".")]

    for parent in here.parents:
        candidates: list[Path] = []
        if parent.name == "native":
            candidates.append(parent)
        native_dir = parent / "native"
        if native_dir.exists():
            candidates.append(native_dir)
        for native_home in candidates:
            if native_home in visited:
                continue
            visited.add(native_home)
            build_dir = native_home / "build"
            if not build_dir.exists():
                continue
            for sub in subdirs:
                for name in names:
                    candidate = build_dir / sub / name
                    yield candidate


def _load_library() -> ctypes.CDLL:
    for path in _default_candidates():
        if path.is_file():
            return ctypes.CDLL(str(path))
    raise PQCNativeError(
        "Unable to locate pqcbench_native shared library. "
        "Build it via CMake (see native/README.md) or point PQCBENCH_NATIVE_LIB to the compiled binary."
    )


_lib = _load_library()


_pqc_status = ctypes.c_int
_pqc_bool = ctypes.c_int
_c_char_p = ctypes.c_char_p
_c_size_t = ctypes.c_size_t
_c_uint8_p = ctypes.POINTER(ctypes.c_uint8)
_NULL_UINT8_P = ctypes.cast(ctypes.c_void_p(), _c_uint8_p)


_lib.pqcbench_free.argtypes = [ctypes.c_void_p]
_lib.pqcbench_free.restype = None

_lib.pqcbench_kem_is_supported.argtypes = [_c_char_p]
_lib.pqcbench_kem_is_supported.restype = _pqc_bool

_lib.pqcbench_kem_keypair.argtypes = [_c_char_p, ctypes.POINTER(_Buffer), ctypes.POINTER(_Buffer)]
_lib.pqcbench_kem_keypair.restype = _pqc_status

_lib.pqcbench_kem_encapsulate.argtypes = [_c_char_p, _c_uint8_p, _c_size_t, ctypes.POINTER(_Buffer), ctypes.POINTER(_Buffer)]
_lib.pqcbench_kem_encapsulate.restype = _pqc_status

_lib.pqcbench_kem_decapsulate.argtypes = [_c_char_p, _c_uint8_p, _c_size_t, _c_uint8_p, _c_size_t, ctypes.POINTER(_Buffer)]
_lib.pqcbench_kem_decapsulate.restype = _pqc_status

_lib.pqcbench_sig_is_supported.argtypes = [_c_char_p]
_lib.pqcbench_sig_is_supported.restype = _pqc_bool

_lib.pqcbench_sig_keypair.argtypes = [_c_char_p, ctypes.POINTER(_Buffer), ctypes.POINTER(_Buffer)]
_lib.pqcbench_sig_keypair.restype = _pqc_status

_lib.pqcbench_sig_sign.argtypes = [_c_char_p, _c_uint8_p, _c_size_t, _c_uint8_p, _c_size_t, ctypes.POINTER(_Buffer)]
_lib.pqcbench_sig_sign.restype = _pqc_status

_lib.pqcbench_sig_verify.argtypes = [_c_char_p, _c_uint8_p, _c_size_t, _c_uint8_p, _c_size_t, _c_uint8_p, _c_size_t, ctypes.POINTER(_pqc_bool)]
_lib.pqcbench_sig_verify.restype = _pqc_status

try:
    _lib.pqcbench_has_rsa.restype = _pqc_bool
    HAS_RSA = bool(_lib.pqcbench_has_rsa())
except AttributeError:
    HAS_RSA = True

_lib.pqcbench_rsa_keypair.argtypes = [ctypes.c_int, ctypes.POINTER(_Buffer), ctypes.POINTER(_Buffer)]
_lib.pqcbench_rsa_keypair.restype = _pqc_status

_lib.pqcbench_rsa_encapsulate.argtypes = [_c_uint8_p, _c_size_t, _c_size_t, ctypes.POINTER(_Buffer), ctypes.POINTER(_Buffer)]
_lib.pqcbench_rsa_encapsulate.restype = _pqc_status

_lib.pqcbench_rsa_decapsulate.argtypes = [_c_uint8_p, _c_size_t, _c_uint8_p, _c_size_t, ctypes.POINTER(_Buffer)]
_lib.pqcbench_rsa_decapsulate.restype = _pqc_status

_lib.pqcbench_rsa_sign.argtypes = [_c_uint8_p, _c_size_t, _c_uint8_p, _c_size_t, ctypes.POINTER(_Buffer)]
_lib.pqcbench_rsa_sign.restype = _pqc_status

_lib.pqcbench_rsa_verify.argtypes = [_c_uint8_p, _c_size_t, _c_uint8_p, _c_size_t, _c_uint8_p, _c_size_t, ctypes.POINTER(_pqc_bool)]
_lib.pqcbench_rsa_verify.restype = _pqc_status


def _encode_name(name: str) -> bytes:
    try:
        return name.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PQCNativeError(f"Algorithm name must be ASCII: {name!r}") from exc


def _status_ok(status: int, context: str) -> None:
    if status == 0:
        return
    if status == 1:
        raise PQCNativeError(f"{context}: algorithm unsupported by native backend")
    if status == 3:
        raise PQCNativeError(f"{context}: allocation failed")
    raise PQCNativeError(f"{context}: native operation failed (status={status})")


def _buffer_to_bytes(buf: _Buffer) -> bytes:
    if not buf.data or buf.len == 0:
        return b""
    data = ctypes.string_at(buf.data, buf.len)
    _lib.pqcbench_free(buf.data)
    return data


def _to_uint8_ptr(data: bytes) -> Tuple[Optional[ctypes.Array], _c_uint8_p]:
    if not data:
        return None, _NULL_UINT8_P
    arr = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
    return arr, ctypes.cast(arr, _c_uint8_p)


def kem_is_supported(name: str) -> bool:
    return bool(_lib.pqcbench_kem_is_supported(_encode_name(name)))


def sig_is_supported(name: str) -> bool:
    return bool(_lib.pqcbench_sig_is_supported(_encode_name(name)))


def kem_keypair(name: str) -> Tuple[bytes, bytes]:
    pk = _Buffer()
    sk = _Buffer()
    status = _lib.pqcbench_kem_keypair(_encode_name(name), ctypes.byref(pk), ctypes.byref(sk))
    _status_ok(status, f"KEM keypair ({name})")
    return _buffer_to_bytes(pk), _buffer_to_bytes(sk)


def kem_encapsulate(name: str, public_key: bytes) -> Tuple[bytes, bytes]:
    ct = _Buffer()
    ss = _Buffer()
    pk_arr, pk_ptr = _to_uint8_ptr(public_key)
    status = _lib.pqcbench_kem_encapsulate(
        _encode_name(name),
        pk_ptr,
        len(public_key),
        ctypes.byref(ct),
        ctypes.byref(ss),
    )
    _ = pk_arr
    _status_ok(status, f"KEM encapsulate ({name})")
    return _buffer_to_bytes(ct), _buffer_to_bytes(ss)


def kem_decapsulate(name: str, secret_key: bytes, ciphertext: bytes) -> bytes:
    ss = _Buffer()
    sk_arr, sk_ptr = _to_uint8_ptr(secret_key)
    ct_arr, ct_ptr = _to_uint8_ptr(ciphertext)
    status = _lib.pqcbench_kem_decapsulate(
        _encode_name(name),
        sk_ptr,
        len(secret_key),
        ct_ptr,
        len(ciphertext),
        ctypes.byref(ss),
    )
    _ = sk_arr, ct_arr
    _status_ok(status, f"KEM decapsulate ({name})")
    return _buffer_to_bytes(ss)


def sig_keypair(name: str) -> Tuple[bytes, bytes]:
    pk = _Buffer()
    sk = _Buffer()
    status = _lib.pqcbench_sig_keypair(_encode_name(name), ctypes.byref(pk), ctypes.byref(sk))
    _status_ok(status, f"Signature keypair ({name})")
    return _buffer_to_bytes(pk), _buffer_to_bytes(sk)


def sig_sign(name: str, secret_key: bytes, message: bytes) -> bytes:
    sig = _Buffer()
    sk_arr, sk_ptr = _to_uint8_ptr(secret_key)
    msg_arr, msg_ptr = _to_uint8_ptr(message)
    status = _lib.pqcbench_sig_sign(
        _encode_name(name),
        sk_ptr,
        len(secret_key),
        msg_ptr,
        len(message),
        ctypes.byref(sig),
    )
    _ = sk_arr, msg_arr
    _status_ok(status, f"Signature sign ({name})")
    return _buffer_to_bytes(sig)


def sig_verify(name: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    result = _pqc_bool()
    pk_arr, pk_ptr = _to_uint8_ptr(public_key)
    msg_arr, msg_ptr = _to_uint8_ptr(message)
    sig_arr, sig_ptr = _to_uint8_ptr(signature)
    status = _lib.pqcbench_sig_verify(
        _encode_name(name),
        pk_ptr,
        len(public_key),
        msg_ptr,
        len(message),
        sig_ptr,
        len(signature),
        ctypes.byref(result),
    )
    _ = pk_arr, msg_arr, sig_arr
    _status_ok(status, f"Signature verify ({name})")
    return bool(result.value)


def rsa_keypair(bits: int) -> Tuple[bytes, bytes]:
    if not HAS_RSA:
        raise PQCNativeError("Native library was built without RSA support")
    pk = _Buffer()
    sk = _Buffer()
    status = _lib.pqcbench_rsa_keypair(bits, ctypes.byref(pk), ctypes.byref(sk))
    _status_ok(status, f"RSA keypair ({bits}-bit)")
    return _buffer_to_bytes(pk), _buffer_to_bytes(sk)


def rsa_encapsulate(public_key: bytes, secret_len: int) -> Tuple[bytes, bytes]:
    if not HAS_RSA:
        raise PQCNativeError("Native library was built without RSA support")
    ct = _Buffer()
    ss = _Buffer()
    pk_arr, pk_ptr = _to_uint8_ptr(public_key)
    status = _lib.pqcbench_rsa_encapsulate(
        pk_ptr,
        len(public_key),
        secret_len,
        ctypes.byref(ct),
        ctypes.byref(ss),
    )
    _ = pk_arr
    _status_ok(status, "RSA encapsulate")
    return _buffer_to_bytes(ct), _buffer_to_bytes(ss)


def rsa_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    if not HAS_RSA:
        raise PQCNativeError("Native library was built without RSA support")
    ss = _Buffer()
    sk_arr, sk_ptr = _to_uint8_ptr(secret_key)
    ct_arr, ct_ptr = _to_uint8_ptr(ciphertext)
    status = _lib.pqcbench_rsa_decapsulate(
        sk_ptr,
        len(secret_key),
        ct_ptr,
        len(ciphertext),
        ctypes.byref(ss),
    )
    _ = sk_arr, ct_arr
    _status_ok(status, "RSA decapsulate")
    return _buffer_to_bytes(ss)


def rsa_sign(secret_key: bytes, message: bytes) -> bytes:
    if not HAS_RSA:
        raise PQCNativeError("Native library was built without RSA support")
    sig = _Buffer()
    sk_arr, sk_ptr = _to_uint8_ptr(secret_key)
    msg_arr, msg_ptr = _to_uint8_ptr(message)
    status = _lib.pqcbench_rsa_sign(
        sk_ptr,
        len(secret_key),
        msg_ptr,
        len(message),
        ctypes.byref(sig),
    )
    _ = sk_arr, msg_arr
    _status_ok(status, "RSA sign")
    return _buffer_to_bytes(sig)


def rsa_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if not HAS_RSA:
        raise PQCNativeError("Native library was built without RSA support")
    result = _pqc_bool()
    pk_arr, pk_ptr = _to_uint8_ptr(public_key)
    msg_arr, msg_ptr = _to_uint8_ptr(message)
    sig_arr, sig_ptr = _to_uint8_ptr(signature)
    status = _lib.pqcbench_rsa_verify(
        pk_ptr,
        len(public_key),
        msg_ptr,
        len(message),
        sig_ptr,
        len(signature),
        ctypes.byref(result),
    )
    _ = pk_arr, msg_arr, sig_arr
    _status_ok(status, "RSA verify")
    return bool(result.value)


def resolve_algorithm(env_var: str, candidates: Sequence[str], is_supported: Callable[[str], bool]) -> Optional[str]:
    order: list[str] = []
    env_value = os.getenv(env_var)
    if env_value:
        order.append(env_value)
    for candidate in candidates:
        if candidate not in order:
            order.append(candidate)
    for name in order:
        if is_supported(name):
            return name
    return None
