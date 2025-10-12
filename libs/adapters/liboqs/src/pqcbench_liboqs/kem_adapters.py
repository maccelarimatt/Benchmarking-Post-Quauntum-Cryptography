
from __future__ import annotations
from typing import Tuple
from pqcbench import registry
from ._util import try_import_oqs, resolve_algorithm, pick_kem_algorithm

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

    @registry.register("bike")
    class BikePlaceholder:
        name = "bike"
        def keygen(self) -> Tuple[bytes, bytes]:
            return b"pk", b"sk"
        def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
            return b"ct", b"ss"
        def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
            return b"ss"

    @registry.register("classic-mceliece")
    class ClassicMcEliecePlaceholder:
        name = "classic-mceliece"
        def keygen(self) -> Tuple[bytes, bytes]:
            return b"pk", b"sk"
        def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
            return b"ct", b"ss"
        def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
            return b"ss"

    @registry.register("frodokem")
    class FrodoKEMPlaceholder:
        name = "frodokem"
        def keygen(self) -> Tuple[bytes, bytes]:
            return b"pk", b"sk"
        def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
            return b"ct", b"ss"
        def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
            return b"ss"

    @registry.register("ntru")
    class NTRUPlaceholder:
        name = "ntru"
        def keygen(self) -> Tuple[bytes, bytes]:
            return b"pk", b"sk"
        def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
            return b"ct", b"ss"
        def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
            return b"ss"

    @registry.register("ntruprime")
    class NTRUPrimePlaceholder:
        name = "ntruprime"
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

    @registry.register("bike")
    class BIKE:
        name = "bike"

        def __init__(self) -> None:
            self.alg = pick_kem_algorithm(
                _oqs,
                "PQCBENCH_BIKE_ALG",
                [
                    "BIKE-L3",
                    "BIKE-L5",
                    "BIKE-L1",
                ],
            )
            if not self.alg:
                raise RuntimeError("No supported BIKE mechanism enabled in liboqs")

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

    @registry.register("classic-mceliece")
    class ClassicMcEliece:
        name = "classic-mceliece"

        def __init__(self) -> None:
            self.alg = pick_kem_algorithm(
                _oqs,
                "PQCBENCH_CLASSIC_MCELIECE_ALG",
                [
                    "Classic-McEliece-460896f",
                    "Classic-McEliece-6688128f",
                    "Classic-McEliece-6960119f",
                    "Classic-McEliece-8192128f",
                    "Classic-McEliece-460896",
                    "Classic-McEliece-348864f",
                    "Classic-McEliece-348864",
                    "Classic-McEliece-6688128",
                    "Classic-McEliece-6960119",
                    "Classic-McEliece-8192128",
                ],
            )
            if not self.alg:
                raise RuntimeError("No supported Classic McEliece mechanism enabled in liboqs")

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

    @registry.register("frodokem")
    class FrodoKEM:
        name = "frodokem"

        def __init__(self) -> None:
            self.alg = pick_kem_algorithm(
                _oqs,
                "PQCBENCH_FRODOKEM_ALG",
                [
                    "FrodoKEM-976-AES",
                    "FrodoKEM-976-SHAKE",
                    "FrodoKEM-640-AES",
                    "FrodoKEM-640-SHAKE",
                    "FrodoKEM-1344-AES",
                    "FrodoKEM-1344-SHAKE",
                ],
            )
            if not self.alg:
                raise RuntimeError("No supported FrodoKEM mechanism enabled in liboqs")

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

    @registry.register("ntru")
    class NTRU:
        name = "ntru"

        def __init__(self) -> None:
            self.alg = pick_kem_algorithm(
                _oqs,
                "PQCBENCH_NTRU_ALG",
                [
                    "NTRU-HPS-2048-677",
                    "NTRU-HRSS-701",
                    "NTRU-HPS-4096-821",
                    "NTRU-HPS-4096-1229",
                    "NTRU-HPS-2048-509",
                    "NTRU-HRSS-1373",
                ],
            )
            if not self.alg:
                raise RuntimeError("No supported NTRU mechanism enabled in liboqs")

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

    @registry.register("ntruprime")
    class NTRUPrime:
        name = "ntruprime"

        def __init__(self) -> None:
            self.alg = pick_kem_algorithm(
                _oqs,
                "PQCBENCH_NTRUPRIME_ALG",
                [
                    "sntrup761",
                    "sntrup653",
                    "sntrup1277",
                    "ntrulpr653",
                    "ntrulpr761",
                    "ntrulpr857",
                    "ntrulpr1277",
                ],
            )
            if not self.alg:
                raise RuntimeError("No supported NTRU Prime mechanism enabled in liboqs")

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
