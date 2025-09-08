# providers/oqs_provider.py
from __future__ import annotations
from typing import Tuple
import oqs

class Provider:
    def kem_encapsulate(self, scheme: str, public_key: bytes) -> Tuple[bytes, bytes]:
        # Map common aliases
        scheme = scheme_alias(scheme)
        with oqs.KeyEncapsulation(scheme) as kem:
            # oqs needs its own pubkey format; import
            kem.import_public_key(public_key)
            ct, ss = kem.encap_secret()
            return ct, ss

    def kem_decapsulate(self, scheme: str, secret_key: bytes, ciphertext: bytes) -> bytes:
        scheme = scheme_alias(scheme)
        with oqs.KeyEncapsulation(scheme) as kem:
            kem.import_secret_key(secret_key)
            ss = kem.decap_secret(ciphertext)
            return ss

    def sign(self, scheme: str, secret_key: bytes, msg: bytes) -> bytes:
        scheme = dsa_alias(scheme)
        with oqs.Signature(scheme) as sig:
            sig.import_secret_key(secret_key)
            return sig.sign(msg)

    def verify(self, scheme: str, public_key: bytes, msg: bytes, signature: bytes) -> bool:
        scheme = dsa_alias(scheme)
        with oqs.Signature(scheme) as sig:
            sig.import_public_key(public_key)
            return sig.verify(msg, signature)

    # RSA not implemented here; harness will fallback to `cryptography` if available.

def scheme_alias(name: str) -> str:
    n = (name or "").lower().replace("_", "-")
    if "ml-kem" in n or "kyber" in n:
        if "512" in n: return "Kyber512"
        if "768" in n: return "Kyber768"
        if "1024" in n: return "Kyber1024"
        return "Kyber768"
    return name

def dsa_alias(name: str) -> str:
    n = (name or "").lower().replace("_", "-")
    if "ml-dsa" in n or "dilithium" in n:
        if "44" in n or "2" in n: return "Dilithium2"
        if "65" in n or "3" in n: return "Dilithium3"
        if "87" in n or "5" in n: return "Dilithium5"
        return "Dilithium3"
    return name
