
from __future__ import annotations
from typing import Tuple
from pqcbench import registry
from ._util import try_import_oqs, resolve_algorithm, pick_sig_algorithm, pick_stateful_sig_algorithm

_oqs = try_import_oqs()

if _oqs is None:
    # Fallback placeholders if python-oqs/liboqs not available
    @registry.register("dilithium")
    class DilithiumPlaceholder:
        name = "dilithium"
        def keygen(self) -> Tuple[bytes, bytes]:
            return b"pk", b"sk"
        def sign(self, secret_key: bytes, message: bytes) -> bytes:
            return b"sig"
        def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
            return True

    @registry.register("falcon")
    class FalconPlaceholder:
        name = "falcon"
        def keygen(self) -> Tuple[bytes, bytes]:
            return b"pk", b"sk"
        def sign(self, secret_key: bytes, message: bytes) -> bytes:
            return b"sig"
        def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
            return True

    @registry.register("sphincs+")
    class SphincsPlusPlaceholder:
        name = "sphincs+"
        def keygen(self) -> Tuple[bytes, bytes]:
            return b"pk", b"sk"
        def sign(self, secret_key: bytes, message: bytes) -> bytes:
            return b"sig"
        def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
            return True

    @registry.register("xmssmt")
    class XmssmtPlaceholder:
        name = "xmssmt"
        def keygen(self) -> Tuple[bytes, bytes]:
            return b"pk", b"sk"
        def sign(self, secret_key: bytes, message: bytes) -> bytes:
            return b"sig"
        def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
            return True
    
    @registry.register("mayo")
    class MayoPlaceholder:
        name = "mayo"
        def keygen(self) -> Tuple[bytes, bytes]:
            return b"pk", b"sk"
        def sign(self, secret_key: bytes, message: bytes) -> bytes:
            return b"sig"
        def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
            return True
else:
    # Real liboqs-backed adapters
    @registry.register("dilithium")
    class Dilithium:
        name = "dilithium"

        def __init__(self) -> None:
            self.alg = pick_sig_algorithm(
                _oqs,
                "PQCBENCH_DILITHIUM_ALG",
                [
                    "ML-DSA-65",
                    "ML-DSA-87",
                    "ML-DSA-110",
                    "Dilithium2",
                    "Dilithium3",
                    "Dilithium5",
                ],
            )
            if not self.alg:
                raise RuntimeError("No supported Dilithium/ML-DSA algorithm enabled in liboqs")

        def keygen(self) -> Tuple[bytes, bytes]:
            with _oqs.Signature(self.alg) as s:
                pk = s.generate_keypair()
                sk = s.export_secret_key()
                return pk, sk

        def sign(self, secret_key: bytes, message: bytes) -> bytes:
            with _oqs.Signature(self.alg, secret_key=secret_key) as s:
                return s.sign(message)

        def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
            with _oqs.Signature(self.alg) as v:
                return v.verify(message, signature, public_key)

    @registry.register("falcon")
    class Falcon:
        name = "falcon"

        def __init__(self) -> None:
            self.alg = pick_sig_algorithm(
                _oqs,
                "PQCBENCH_FALCON_ALG",
                ["Falcon-512", "Falcon-1024"],
            )
            if not self.alg:
                raise RuntimeError("No supported Falcon algorithm enabled in liboqs")

        def keygen(self) -> Tuple[bytes, bytes]:
            with _oqs.Signature(self.alg) as s:
                pk = s.generate_keypair()
                sk = s.export_secret_key()
                return pk, sk

        def sign(self, secret_key: bytes, message: bytes) -> bytes:
            with _oqs.Signature(self.alg, secret_key=secret_key) as s:
                return s.sign(message)

        def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
            with _oqs.Signature(self.alg) as v:
                return v.verify(message, signature, public_key)

    @registry.register("sphincs+")
    class SphincsPlus:
        name = "sphincs+"

        def __init__(self) -> None:
            self.alg = pick_sig_algorithm(
                _oqs,
                "PQCBENCH_SPHINCS_ALG",
                [
                    "SPHINCS+-SHA2-128f-simple",
                    "SPHINCS+-SHA2-128f-robust",
                    "SPHINCS+-SHA2-128s-simple",
                    "SPHINCS+-SHAKE-128f-simple",
                    "SPHINCS+-SHAKE-128s-simple",
                ],
            )
            if not self.alg:
                raise RuntimeError("No supported SPHINCS+ algorithm enabled in liboqs")

        def keygen(self) -> Tuple[bytes, bytes]:
            with _oqs.Signature(self.alg) as s:
                pk = s.generate_keypair()
                sk = s.export_secret_key()
                return pk, sk

        def sign(self, secret_key: bytes, message: bytes) -> bytes:
            with _oqs.Signature(self.alg, secret_key=secret_key) as s:
                return s.sign(message)

        def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
            with _oqs.Signature(self.alg) as v:
                return v.verify(message, signature, public_key)

    @registry.register("xmssmt")
    class Xmssmt:
        name = "xmssmt"

        def __init__(self) -> None:
            # XMSS/XMSSMT are stateful signatures; use StatefulSignature API
            self.alg = pick_stateful_sig_algorithm(
                _oqs,
                "PQCBENCH_XMSSMT_ALG",
                [
                    "XMSSMT-SHA2_20/2_256",
                    "XMSSMT-SHA2_20/4_256",
                    "XMSS-SHA2_20_256",  # single-tree variant as fallback
                ],
            )
            if not self.alg:
                raise RuntimeError("No supported XMSS/XMSSMT algorithm enabled in liboqs")

        def keygen(self) -> Tuple[bytes, bytes]:
            with _oqs.StatefulSignature(self.alg) as s:
                pk = s.generate_keypair()
                sk = s.export_secret_key()
                return pk, sk

        def sign(self, secret_key: bytes, message: bytes) -> bytes:
            with _oqs.StatefulSignature(self.alg, secret_key=secret_key) as s:
                return s.sign(message)

        def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
            with _oqs.StatefulSignature(self.alg) as v:
                return v.verify(message, signature, public_key)

    @registry.register("mayo")
    class Mayo:
        name = "mayo"

        def __init__(self) -> None:
            # Support multiple parameter sets via env override or first available
            # Common liboqs names: MAYO-1, MAYO-2, MAYO-3, MAYO-5
            self.alg = pick_sig_algorithm(
                _oqs,
                "PQCBENCH_MAYO_ALG",
                [
                    "MAYO-2",
                    "MAYO-1",
                    "MAYO-3",
                    "MAYO-5",
                ],
            )
            if not self.alg:
                raise RuntimeError("No supported MAYO algorithm enabled in liboqs")

        def keygen(self) -> Tuple[bytes, bytes]:
            with _oqs.Signature(self.alg) as s:
                pk = s.generate_keypair()
                sk = s.export_secret_key()
                return pk, sk

        def sign(self, secret_key: bytes, message: bytes) -> bytes:
            with _oqs.Signature(self.alg, secret_key=secret_key) as s:
                return s.sign(message)

        def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
            with _oqs.Signature(self.alg) as v:
                return v.verify(message, signature, public_key)
