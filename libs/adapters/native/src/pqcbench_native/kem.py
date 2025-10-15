from __future__ import annotations

import os
from typing import Sequence, Tuple, Optional

from pqcbench import registry

from ._core import (
    PQCNativeError,
    kem_decapsulate,
    kem_encapsulate,
    kem_is_supported,
    kem_keypair,
    resolve_algorithm,
)


_KEM_ALGORITHM_CACHE: dict[Tuple[str, Optional[str], Tuple[Optional[str], ...], Tuple[str, ...]], str] = {}


def _pick_kem(
    env_var: str,
    candidates: Sequence[str],
    legacy_envs: Sequence[str],
    label: str,
) -> str:
    env_value = os.getenv(env_var)
    legacy_values = tuple(os.getenv(name) for name in legacy_envs)
    key = (env_var, env_value, legacy_values, tuple(candidates))
    cached = _KEM_ALGORITHM_CACHE.get(key)
    if cached:
        return cached

    order: list[str] = []
    if env_value:
        order.append(env_value)
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


@registry.register("bike")
class BIKE:
    name = "bike"

    def __init__(self) -> None:
        self.algorithm = _pick_kem(
            "PQCBENCH_BIKE_ALG",
            (
                "BIKE-L3",
                "BIKE-L5",
                "BIKE-L1",
            ),
            ("BIKE_MECH",),
            "BIKE",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return kem_keypair(self.algorithm)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        return kem_encapsulate(self.algorithm, public_key)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return kem_decapsulate(self.algorithm, secret_key, ciphertext)


@registry.register("classic-mceliece")
class ClassicMcEliece:
    name = "classic-mceliece"

    def __init__(self) -> None:
        self.algorithm = _pick_kem(
            "PQCBENCH_CLASSIC_MCELIECE_ALG",
            (
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
            ),
            ("CLASSIC_MCELIECE_MECH", "MCELIECE_MECH"),
            "Classic McEliece",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return kem_keypair(self.algorithm)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        return kem_encapsulate(self.algorithm, public_key)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return kem_decapsulate(self.algorithm, secret_key, ciphertext)


@registry.register("frodokem")
class FrodoKEM:
    name = "frodokem"

    def __init__(self) -> None:
        self.algorithm = _pick_kem(
            "PQCBENCH_FRODOKEM_ALG",
            (
                "FrodoKEM-976-AES",
                "FrodoKEM-976-SHAKE",
                "FrodoKEM-640-AES",
                "FrodoKEM-640-SHAKE",
                "FrodoKEM-1344-AES",
                "FrodoKEM-1344-SHAKE",
            ),
            ("FRODOKEM_MECH",),
            "FrodoKEM",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return kem_keypair(self.algorithm)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        return kem_encapsulate(self.algorithm, public_key)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return kem_decapsulate(self.algorithm, secret_key, ciphertext)


@registry.register("ntru")
class NTRU:
    name = "ntru"

    def __init__(self) -> None:
        self.algorithm = _pick_kem(
            "PQCBENCH_NTRU_ALG",
            (
                "NTRU-HPS-2048-677",
                "NTRU-HRSS-701",
                "NTRU-HPS-4096-821",
                "NTRU-HPS-4096-1229",
                "NTRU-HPS-2048-509",
                "NTRU-HRSS-1373",
            ),
            ("NTRU_MECH",),
            "NTRU",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return kem_keypair(self.algorithm)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        return kem_encapsulate(self.algorithm, public_key)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return kem_decapsulate(self.algorithm, secret_key, ciphertext)


@registry.register("ntruprime")
class NTRUPrime:
    name = "ntruprime"

    def __init__(self) -> None:
        self.algorithm = _pick_kem(
            "PQCBENCH_NTRUPRIME_ALG",
            (
                "sntrup761",
                "sntrup653",
                "sntrup1277",
                "ntrulpr653",
                "ntrulpr761",
                "ntrulpr857",
                "ntrulpr1277",
            ),
            ("NTRUPRIME_MECH", "SNTRUP_MECH"),
            "NTRU Prime",
        )

    def keygen(self) -> tuple[bytes, bytes]:
        return kem_keypair(self.algorithm)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        return kem_encapsulate(self.algorithm, public_key)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return kem_decapsulate(self.algorithm, secret_key, ciphertext)
