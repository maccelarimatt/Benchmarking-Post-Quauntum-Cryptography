from __future__ import annotations

import os

from pqcbench import registry

from ._core import (
    PQCNativeError,
    kem_decapsulate,
    kem_encapsulate,
    kem_is_supported,
    kem_keypair,
    resolve_algorithm,
)


def _pick_kem(env_var: str, candidates: list[str], legacy_env: str | None, label: str) -> str:
    order = []
    if legacy_env:
        order.append(legacy_env)
    order.extend(candidates)
    algorithm = resolve_algorithm(env_var, order, kem_is_supported)
    if not algorithm:
        raise PQCNativeError(f"No supported {label} mechanism found in native backend")
    return algorithm


@registry.register("kyber")
class Kyber:
    name = "kyber"

    def __init__(self) -> None:
        legacy = os.getenv("KYBER_MECH")
        self.algorithm = _pick_kem(
            "PQCBENCH_KYBER_ALG",
            [
                "ML-KEM-768",
                "ML-KEM-1024",
                "Kyber768",
                "Kyber1024",
                "Kyber512",
            ],
            legacy,
            "Kyber/ML-KEM",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return kem_keypair(self.algorithm)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        return kem_encapsulate(self.algorithm, public_key)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return kem_decapsulate(self.algorithm, secret_key, ciphertext)


@registry.register("hqc")
class HQC:
    name = "hqc"

    def __init__(self) -> None:
        legacy = os.getenv("HQC_MECH")
        self.algorithm = _pick_kem(
            "PQCBENCH_HQC_ALG",
            [
                "HQC-128",
                "HQC-192",
                "HQC-256",
                "HQC-128-1-CCA2",
                "HQC-192-1-CCA2",
                "HQC-256-1-CCA2",
            ],
            legacy,
            "HQC",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return kem_keypair(self.algorithm)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        return kem_encapsulate(self.algorithm, public_key)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return kem_decapsulate(self.algorithm, secret_key, ciphertext)
