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

def _load_private_key(sk_bytes: bytes):
    return serialization.load_der_private_key(sk_bytes, password=None, backend=default_backend())

def _load_public_key(pk_bytes: bytes):
    return serialization.load_der_public_key(pk_bytes, backend=default_backend())

@registry.register("rsa-oaep")
class RSAKEM:
    name = "rsa-oaep"
    def keygen(self) -> Tuple[bytes, bytes]:
        return _gen_rsa_keypair(2048)

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
        ss = sk.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None),
        )
        return ss

@registry.register("rsa-pss")
class RSASignature:
    name = "rsa-pss"
    def keygen(self) -> Tuple[bytes, bytes]:
        return _gen_rsa_keypair(2048)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        sk = _load_private_key(secret_key)
        return sk.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        pk = _load_public_key(public_key)
        try:
            pk.verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False
