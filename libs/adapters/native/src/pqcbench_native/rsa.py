from __future__ import annotations

import os

from pqcbench import registry

from ._core import (
    HAS_RSA,
    rsa_decapsulate,
    rsa_encapsulate,
    rsa_keypair,
    rsa_sign,
    rsa_verify,
)


def _rsa_bits() -> int:
    override = os.getenv("PQCBENCH_RSA_BITS")
    if override:
        try:
            return int(override)
        except ValueError:
            raise ValueError("PQCBENCH_RSA_BITS must be an integer")
    return 2048


_RSA_SHARED_SECRET_LEN = 32


if HAS_RSA:

    @registry.register("rsa-oaep")
    class RSAKEM:
        name = "rsa-oaep"

        def __init__(self) -> None:
            self._bits = _rsa_bits()
            self.mech = f"RSA-{self._bits}-OAEP"
            self.algorithm = self.mech

        def keygen(self) -> tuple[bytes, bytes]:
            return rsa_keypair(self._bits)

        def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
            return rsa_encapsulate(public_key, _RSA_SHARED_SECRET_LEN)

        def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
            return rsa_decapsulate(secret_key, ciphertext)


    @registry.register("rsa-pss")
    class RSASignature:
        name = "rsa-pss"

        def __init__(self) -> None:
            self._bits = _rsa_bits()
            self.mech = f"RSA-{self._bits}-PSS"
            self.algorithm = self.mech

        def keygen(self) -> tuple[bytes, bytes]:
            return rsa_keypair(self._bits)

        def sign(self, secret_key: bytes, message: bytes) -> bytes:
            return rsa_sign(secret_key, message)

        def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
            return rsa_verify(public_key, message, signature)
