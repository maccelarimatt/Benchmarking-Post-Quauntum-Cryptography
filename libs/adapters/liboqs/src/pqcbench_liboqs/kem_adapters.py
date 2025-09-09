
from __future__ import annotations
from typing import Tuple
from pqcbench import registry

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
