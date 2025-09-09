
from __future__ import annotations
from typing import Tuple
from pqcbench import registry

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
