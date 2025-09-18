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
    order = []
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
