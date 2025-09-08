# providers/pqcrypto_provider.py
from __future__ import annotations
from typing import Tuple
import importlib

# ---- Helpers ---------------------------------------------------------------

def kem_alias(name: str) -> str:
    n = (name or "").lower().replace("_", "-")
    # Accept ML-KEM or Kyber aliases
    if "ml-kem" in n or "kyber" in n:
        if "512" in n:  return "pqcrypto.kem.kyber512"
        if "768" in n:  return "pqcrypto.kem.kyber768"
        if "1024" in n: return "pqcrypto.kem.kyber1024"
        # default if omitted
        return "pqcrypto.kem.kyber768"
    return n

def dsa_alias(name: str) -> str:
    n = (name or "").lower().replace("_", "-")
    # Accept ML-DSA (Dilithium) aliases
    if "ml-dsa" in n or "dilithium" in n:
        if "44" in n or "2" in n: return "pqcrypto.sign.dilithium2"
        if "65" in n or "3" in n: return "pqcrypto.sign.dilithium3"
        if "87" in n or "5" in n: return "pqcrypto.sign.dilithium5"
        return "pqcrypto.sign.dilithium3"
    return n

# ---- Provider --------------------------------------------------------------

class Provider:
    """
    KEM: uses pqcrypto.kem.kyber{512,768,1024}
      - encapsulate(pk) -> (ct, ss)
      - decapsulate(ct, sk) -> ss
    SIG: uses pqcrypto.sign.dilithium{2,3,5}
      - sign_detached emulated via sign(msg, sk) that returns sm = sig||msg
      - verify_detached emulated via open(sig||msg, pk)
    All inputs/outputs are raw bytes.
    """

    # --- KEM (Kyber / ML-KEM) ---

    def kem_encapsulate(self, scheme: str, public_key: bytes) -> Tuple[bytes, bytes]:
        modname = kem_alias(scheme)
        mod = importlib.import_module(modname)
        # pqcrypto expects 'encapsulate(pk)' and returns (ct, ss)
        ct, ss = mod.encapsulate(public_key)
        return ct, ss

    def kem_decapsulate(self, scheme: str, secret_key: bytes, ciphertext: bytes) -> bytes:
        modname = kem_alias(scheme)
        mod = importlib.import_module(modname)
        ss = mod.decapsulate(ciphertext, secret_key)
        return ss

    # --- Signatures (Dilithium / ML-DSA) ---

    def sign(self, scheme: str, secret_key: bytes, msg: bytes) -> bytes:
        """
        Return a DETACHED signature.
        pqcrypto.sign.<scheme>.sign(msg, sk) returns sm = sig || msg.
        We split off the signature and return it.
        """
        modname = dsa_alias(scheme)
        mod = importlib.import_module(modname)
        sm = mod.sign(msg, secret_key)  # bytes(sig || msg)
        sig = sm[:-len(msg)] if len(msg) > 0 else sm
        return sig

    def verify(self, scheme: str, public_key: bytes, msg: bytes, signature: bytes) -> bool:
        """
        Verify a DETACHED signature by rebuilding sm = sig || msg and calling open(sm, pk),
        which returns the recovered message on success or raises on failure.
        """
        modname = dsa_alias(scheme)
        mod = importlib.import_module(modname)
        sm = signature + msg
        try:
            recovered = mod.open(sm, public_key)
            return recovered == msg
        except Exception:
            return False

    # Optional RSA methods are omitted; the harness falls back to `cryptography` if present.
