
from __future__ import annotations
from typing import Protocol, Tuple

"""Algorithm interfaces used by adapters.

Adapters implement these Protocols and register themselves into the global
registry. The CLI/GUI interact only with these interfaces, never with vendor
libraries directly.
"""

class KEM(Protocol):
    """Key Encapsulation Mechanism contract."""
    name: str
    def keygen(self) -> Tuple[bytes, bytes]: ...
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]: ...
    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes: ...

class Signature(Protocol):
    """Digital Signature contract."""
    name: str
    def keygen(self) -> Tuple[bytes, bytes]: ...
    def sign(self, secret_key: bytes, message: bytes) -> bytes: ...
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...
