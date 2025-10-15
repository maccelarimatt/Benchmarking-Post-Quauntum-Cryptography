from __future__ import annotations

import os

from pqcbench import registry

from ._core import (
    PQCNativeError,
    resolve_algorithm,
    sig_is_supported,
    sig_keypair,
    sig_sign,
    sig_verify,
)


def _pick_signature(env_var: str, candidates: list[str], legacy_env: str | None, label: str) -> str:
    order: list[str] = []
    if legacy_env:
        order.append(legacy_env)
    order.extend(candidates)
    algorithm = resolve_algorithm(env_var, order, sig_is_supported)
    if not algorithm:
        raise PQCNativeError(f"No supported {label} mechanism found in native backend")
    return algorithm


@registry.register("dilithium")
class Dilithium:
    name = "dilithium"

    def __init__(self) -> None:
        legacy = os.getenv("DILITHIUM_MECH")
        self.algorithm = _pick_signature(
            "PQCBENCH_DILITHIUM_ALG",
            [
                "ML-DSA-65",
                "ML-DSA-87",
                "ML-DSA-110",
                "Dilithium2",
                "Dilithium3",
                "Dilithium5",
            ],
            legacy,
            "Dilithium/ML-DSA",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return sig_keypair(self.algorithm)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        return sig_sign(self.algorithm, secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return sig_verify(self.algorithm, public_key, message, signature)


@registry.register("falcon")
class Falcon:
    name = "falcon"

    def __init__(self) -> None:
        legacy = os.getenv("FALCON_MECH")
        self.algorithm = _pick_signature(
            "PQCBENCH_FALCON_ALG",
            ["Falcon-512", "Falcon-1024"],
            legacy,
            "Falcon",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return sig_keypair(self.algorithm)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        return sig_sign(self.algorithm, secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return sig_verify(self.algorithm, public_key, message, signature)


@registry.register("sphincs+")
class SphincsPlus:
    name = "sphincs+"

    def __init__(self) -> None:
        legacy = os.getenv("SPHINCS_MECH")
        self.algorithm = _pick_signature(
            "PQCBENCH_SPHINCS_ALG",
            [
                "SPHINCS+-SHA2-128f-simple",
                "SPHINCS+-SHA2-128f-robust",
                "SPHINCS+-SHA2-128s-simple",
                "SPHINCS+-SHAKE-128f-simple",
                "SPHINCS+-SHAKE-128s-simple",
            ],
            legacy,
            "SPHINCS+",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return sig_keypair(self.algorithm)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        return sig_sign(self.algorithm, secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return sig_verify(self.algorithm, public_key, message, signature)


@registry.register("mayo")
class Mayo:
    name = "mayo"

    def __init__(self) -> None:
        legacy = os.getenv("MAYO_MECH")
        self.algorithm = _pick_signature(
            "PQCBENCH_MAYO_ALG",
            [
                "MAYO-2",
                "MAYO-1",
                "MAYO-3",
                "MAYO-5",
            ],
            legacy,
            "MAYO",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return sig_keypair(self.algorithm)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        return sig_sign(self.algorithm, secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return sig_verify(self.algorithm, public_key, message, signature)


@registry.register("cross")
class Cross:
    name = "cross"

    def __init__(self) -> None:
        legacy = os.getenv("CROSS_MECH")
        self.algorithm = _pick_signature(
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
            legacy,
            "CROSS",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return sig_keypair(self.algorithm)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        return sig_sign(self.algorithm, secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return sig_verify(self.algorithm, public_key, message, signature)


@registry.register("slh-dsa")
class SLHDSA:
    name = "slh-dsa"

    def __init__(self) -> None:
        legacy = os.getenv("SLH_DSA_MECH")
        self.algorithm = _pick_signature(
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
            legacy,
            "SLH-DSA",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return sig_keypair(self.algorithm)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        return sig_sign(self.algorithm, secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return sig_verify(self.algorithm, public_key, message, signature)


@registry.register("snova")
class SNOVA:
    name = "snova"

    def __init__(self) -> None:
        legacy = os.getenv("SNOVA_MECH")
        self.algorithm = _pick_signature(
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
            legacy,
            "SNOVA",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return sig_keypair(self.algorithm)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        return sig_sign(self.algorithm, secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return sig_verify(self.algorithm, public_key, message, signature)


@registry.register("uov")
class UOV:
    name = "uov"

    def __init__(self) -> None:
        legacy = os.getenv("UOV_MECH")
        self.algorithm = _pick_signature(
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
            legacy,
            "UOV",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return sig_keypair(self.algorithm)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        return sig_sign(self.algorithm, secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return sig_verify(self.algorithm, public_key, message, signature)
