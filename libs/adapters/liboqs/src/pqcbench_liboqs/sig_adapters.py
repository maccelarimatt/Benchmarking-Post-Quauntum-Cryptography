
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

    @registry.register("cross")
    class CrossPlaceholder:
        name = "cross"
        def keygen(self) -> Tuple[bytes, bytes]:
            return b"pk", b"sk"
        def sign(self, secret_key: bytes, message: bytes) -> bytes:
            return b"sig"
        def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
            return True

    @registry.register("slh-dsa")
    class SLHDSAPlaceholder:
        name = "slh-dsa"
        def keygen(self) -> Tuple[bytes, bytes]:
            return b"pk", b"sk"
        def sign(self, secret_key: bytes, message: bytes) -> bytes:
            return b"sig"
        def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
            return True

    @registry.register("snova")
    class SNOVAPlaceholder:
        name = "snova"
        def keygen(self) -> Tuple[bytes, bytes]:
            return b"pk", b"sk"
        def sign(self, secret_key: bytes, message: bytes) -> bytes:
            return b"sig"
        def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
            return True

    @registry.register("uov")
    class UOVPlaceholder:
        name = "uov"
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
                if hasattr(s, "sign_deterministic"):
                    return s.sign_deterministic(message)
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
                if hasattr(s, "sign_deterministic"):
                    return s.sign_deterministic(message)
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
                if hasattr(s, "sign_deterministic"):
                    return s.sign_deterministic(message)
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

    @registry.register("cross")
    class Cross:
        name = "cross"

        def __init__(self) -> None:
            self.alg = pick_sig_algorithm(
                _oqs,
                "PQCBENCH_CROSS_ALG",
                [
                    "cross-rsdpg-256-balanced",
                    "cross-rsdpg-256-fast",
                    "cross-rsdpg-256-small",
                    "cross-rsdp-256-balanced",
                    "cross-rsdp-256-fast",
                    "cross-rsdp-256-small",
                    "cross-rsdpg-192-balanced",
                    "cross-rsdpg-192-fast",
                    "cross-rsdpg-192-small",
                    "cross-rsdp-192-balanced",
                    "cross-rsdp-192-fast",
                    "cross-rsdp-192-small",
                    "cross-rsdpg-128-balanced",
                    "cross-rsdpg-128-fast",
                    "cross-rsdpg-128-small",
                    "cross-rsdp-128-balanced",
                    "cross-rsdp-128-fast",
                    "cross-rsdp-128-small",
                ],
            )
            if not self.alg:
                raise RuntimeError("No supported CROSS algorithm enabled in liboqs")

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

    @registry.register("slh-dsa")
    class SLHDSA:
        name = "slh-dsa"

        def __init__(self) -> None:
            self.alg = pick_sig_algorithm(
                _oqs,
                "PQCBENCH_SLH_DSA_ALG",
                [
                    "SLH_DSA_PURE_SHA2_256S",
                    "SLH_DSA_PURE_SHA2_256F",
                    "SLH_DSA_PURE_SHA2_192S",
                    "SLH_DSA_PURE_SHA2_192F",
                    "SLH_DSA_PURE_SHA2_128S",
                    "SLH_DSA_PURE_SHA2_128F",
                    "SLH_DSA_PURE_SHAKE_256S",
                    "SLH_DSA_PURE_SHAKE_256F",
                    "SLH_DSA_PURE_SHAKE_192S",
                    "SLH_DSA_PURE_SHAKE_192F",
                    "SLH_DSA_PURE_SHAKE_128S",
                    "SLH_DSA_PURE_SHAKE_128F",
                ],
            )
            if not self.alg:
                raise RuntimeError("No supported SLH-DSA algorithm enabled in liboqs")

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

    @registry.register("snova")
    class SNOVA:
        name = "snova"

        def __init__(self) -> None:
            self.alg = pick_sig_algorithm(
                _oqs,
                "PQCBENCH_SNOVA_ALG",
                [
                    "SNOVA_60_10_4",
                    "SNOVA_37_17_2",
                    "SNOVA_49_11_3",
                    "SNOVA_37_8_4",
                    "SNOVA_56_25_2",
                    "SNOVA_29_6_5",
                    "SNOVA_25_8_3",
                    "SNOVA_24_5_5",
                ],
            )
            if not self.alg:
                raise RuntimeError("No supported SNOVA algorithm enabled in liboqs")

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

    @registry.register("uov")
    class UOV:
        name = "uov"

        def __init__(self) -> None:
            self.alg = pick_sig_algorithm(
                _oqs,
                "PQCBENCH_UOV_ALG",
                [
                    "OV-V-pkc-skc",
                    "OV-V-pkc",
                    "OV-V",
                    "OV-III-pkc-skc",
                    "OV-III-pkc",
                    "OV-III",
                    "OV-Ip-pkc-skc",
                    "OV-Ip-pkc",
                    "OV-Ip",
                    "OV-Is-pkc-skc",
                    "OV-Is-pkc",
                    "OV-Is",
                ],
            )
            if not self.alg:
                raise RuntimeError("No supported UOV algorithm enabled in liboqs")

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
