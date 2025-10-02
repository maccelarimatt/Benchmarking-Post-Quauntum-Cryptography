from __future__ import annotations
from typing import Tuple
from pqcbench import registry

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os

def _gen_rsa_keypair(bits: int = 2048):
    sk = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    pk = sk.public_key()
    sk_bytes = sk.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pk_bytes = pk.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pk_bytes, sk_bytes


def _rsa_bits() -> int:
    override = os.getenv("PQCBENCH_RSA_BITS")
    if override:
        try:
            return int(override)
        except ValueError as exc:
            raise ValueError("PQCBENCH_RSA_BITS must be an integer") from exc
    return 2048

def _load_private_key(sk_bytes: bytes):
    return serialization.load_der_private_key(sk_bytes, password=None, backend=default_backend())

def _load_public_key(pk_bytes: bytes):
    return serialization.load_der_public_key(pk_bytes, backend=default_backend())

@registry.register("rsa-oaep")
class RSAKEM:
    """KEM-style wrapper around RSA-OAEP using cryptography.

    Not a real KEM; we sample a random 32-byte secret and encrypt it with
    RSA-OAEP to provide a classical baseline for comparison.
    """
    name = "rsa-oaep"

    def __init__(self) -> None:
        self._bits = _rsa_bits()
        self.mech = f"RSA-{self._bits}-OAEP"
        self.algorithm = self.mech

    def keygen(self) -> Tuple[bytes, bytes]:
        return _gen_rsa_keypair(self._bits)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        # KEM-style: sample a random shared secret and encrypt it with RSA-OAEP
        pk = _load_public_key(public_key)
        ss = os.urandom(32)
        ct = pk.encrypt(
            ss,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None),
        )
        return ct, ss

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        sk = _load_private_key(secret_key)
        try:
            ss = sk.decrypt(
                ciphertext,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None),
            )
            return ss
        except Exception:
            # Constant-length failure response to keep wrapper behaviour uniform.
            return b"\x00" * 32

@registry.register("rsa-pss")
class RSASignature:
    """RSA-PSS signature adapter using cryptography (baseline)."""
    name = "rsa-pss"
    hash_algorithm = hashes.SHA256
    hash_algorithm_name = "sha256"
    hash_digest_size = hashes.SHA256().digest_size
    mgf_hash_algorithm = hashes.SHA256
    mgf_hash_algorithm_name = "sha256"
    salt_length = hash_digest_size  # Recommended salt length: match hash size

    def __init__(self) -> None:
        self._bits = _rsa_bits()
        self.mech = f"RSA-{self._bits}-PSS"
        self.algorithm = self.mech

    def keygen(self) -> Tuple[bytes, bytes]:
        return _gen_rsa_keypair(self._bits)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        sk = _load_private_key(secret_key)
        return sk.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(self.mgf_hash_algorithm()),
                salt_length=self.salt_length,
            ),
            self.hash_algorithm(),
        )

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        pk = _load_public_key(public_key)
        try:
            pk.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(self.mgf_hash_algorithm()),
                    salt_length=self.salt_length,
                ),
                self.hash_algorithm(),
            )
            return True
        except Exception:
            return False
