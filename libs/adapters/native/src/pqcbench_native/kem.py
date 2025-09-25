from __future__ import annotations

import os
from typing import Sequence, Tuple

from pqcbench import registry

from ._core import (
    PQCNativeError,
    kem_decapsulate,
    kem_encapsulate,
    kem_is_supported,
    kem_keypair,
    resolve_algorithm,
)


_KEM_ALGORITHM_CACHE: dict[Tuple[str, Tuple[str, ...], Tuple[str, ...]], str] = {}


def _pick_kem(
    env_var: str,
    candidates: Sequence[str],
    legacy_envs: Sequence[str],
    label: str,
) -> str:
    key = (env_var, tuple(candidates), tuple(legacy_envs))
    cached = _KEM_ALGORITHM_CACHE.get(key)
    if cached:
        return cached

    order: list[str] = []
    for env_name in legacy_envs:
        val = os.getenv(env_name)
        if val:
            order.append(val)
    order.extend(candidates)

    algorithm = resolve_algorithm(env_var, order, kem_is_supported)
    if not algorithm:
        raise PQCNativeError(f"No supported {label} mechanism found in native backend")

    _KEM_ALGORITHM_CACHE[key] = algorithm
    return algorithm


@registry.register("kyber")
class Kyber:
    name = "kyber"

    def __init__(self) -> None:
        self.algorithm = _pick_kem(
            "PQCBENCH_KYBER_ALG",
            (
                "ML-KEM-768",
                "ML-KEM-1024",
                "Kyber768",
                "Kyber1024",
                "Kyber512",
            ),
            ("KYBER_MECH",),
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
        self.algorithm = _pick_kem(
            "PQCBENCH_HQC_ALG",
            (
                "HQC-128",
                "HQC-192",
                "HQC-256",
                "HQC-128-1-CCA2",
                "HQC-192-1-CCA2",
                "HQC-256-1-CCA2",
            ),
            ("HQC_MECH",),
            "HQC",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return kem_keypair(self.algorithm)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        return kem_encapsulate(self.algorithm, public_key)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return kem_decapsulate(self.algorithm, secret_key, ciphertext)
