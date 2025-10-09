
from __future__ import annotations
from typing import Tuple
from pqcbench import registry
from ._util import try_import_oqs, pick_kem_algorithm

_oqs = try_import_oqs()

if _oqs is None:
    # Fallback placeholders if python-oqs/liboqs not available
    @registry.register("kyber")
    class KyberPlaceholder:
        name = "kyber"
        def keygen(self) -> Tuple[bytes, bytes]:
            return b"pk", b"sk"
        def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
            return b"ct", b"ss"
        def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
            return b"ss"

    @registry.register("hqc")
    class HQCPlaceholder:
        name = "hqc"
        def keygen(self) -> Tuple[bytes, bytes]:
            return b"pk", b"sk"
        def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
            return b"ct", b"ss"
        def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
            return b"ss"
else:
    # Real liboqs-backed adapters
    @registry.register("kyber")
    class Kyber:
        name = "kyber"

        def __init__(self) -> None:
            # Prefer NIST names, then legacy names; try instantiation to confirm availability
            self.alg = pick_kem_algorithm(
                _oqs,
                "PQCBENCH_KYBER_ALG",
                [
                    "ML-KEM-768",
                    "ML-KEM-1024",
                    "Kyber768",
                    "Kyber1024",
                    "Kyber512",
                ],
            )
            if not self.alg:
                raise RuntimeError("No supported Kyber/ML-KEM algorithm enabled in liboqs")

        def keygen(self) -> Tuple[bytes, bytes]:
            with _oqs.KeyEncapsulation(self.alg) as kem:
                pk = kem.generate_keypair()
                sk = kem.export_secret_key()
                return pk, sk

        def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
            with _oqs.KeyEncapsulation(self.alg) as kem:
                ct, ss = kem.encap_secret(public_key)
                return ct, ss

        def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
            with _oqs.KeyEncapsulation(self.alg, secret_key=secret_key) as kem:
                ss = kem.decap_secret(ciphertext)
                return ss

    @registry.register("hqc")
    class HQC:
        name = "hqc"

        def __init__(self) -> None:
            # Names vary across liboqs versions; try instantiation
            self.alg = pick_kem_algorithm(
                _oqs,
                "PQCBENCH_HQC_ALG",
                [
                    "HQC-128",
                    "HQC-192",
                    "HQC-256",
                    "HQC-128-1-CCA2",
                    "HQC-192-1-CCA2",
                    "HQC-256-1-CCA2",
                ],
            )
            if not self.alg:
                raise RuntimeError("No supported HQC algorithm enabled in liboqs")

        def keygen(self) -> Tuple[bytes, bytes]:
            with _oqs.KeyEncapsulation(self.alg) as kem:
                pk = kem.generate_keypair()
                sk = kem.export_secret_key()
                return pk, sk

        def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
            with _oqs.KeyEncapsulation(self.alg) as kem:
                ct, ss = kem.encap_secret(public_key)
                return ct, ss

        def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
            with _oqs.KeyEncapsulation(self.alg, secret_key=secret_key) as kem:
                ss = kem.decap_secret(ciphertext)
                return ss
