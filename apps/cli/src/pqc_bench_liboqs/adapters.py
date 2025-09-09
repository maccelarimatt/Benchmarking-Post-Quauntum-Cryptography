from __future__ import annotations
import os
from typing import Tuple, List
from pqcbench import registry

try:
    import oqs  # provided by liboqs-python
except Exception as e:
    # Keep import-time errors obvious so runners show a clear message.
    raise RuntimeError("Failed to import 'oqs'. Did you 'pip install liboqs-python' in this venv?") from e


def _pick(preferred: List[str], available: List[str], fallback_contains: List[str]) -> str:
    # Environment override first (if exact match)
    for env in preferred:
        if env and env in available:
            return env
    # Then first preferred that exists
    for name in preferred:
        if name and name in available:
            return name
    # Then any available that contains one of the tokens
    for token in fallback_contains:
        for a in available:
            if token in a:
                return a
    raise RuntimeError(f"No matching mechanism found. Available: {available}")

# ---------- KEMs ----------

class _OQSKEM:
    def __init__(self, mech: str):
        self.mech = mech

    def keygen(self) -> Tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(self.mech) as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
        return pk, sk

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(self.mech) as kem:
            ct, ss = kem.encap_secret(public_key)
        return ct, ss

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        # init with a secret key for decapsulation
        with oqs.KeyEncapsulation(self.mech, secret_key) as kem:
            ss = kem.decap_secret(ciphertext)
        return ss


@registry.register("kyber")
class Kyber(_OQSKEM):
    """Default: ML-KEM-768 if available (aka Kyber768)."""
    def __init__(self):
        kems = oqs.get_enabled_kem_mechanisms()
        mech = _pick(
            preferred=[os.getenv("KYBER_MECH"), "ML-KEM-768", "Kyber768", "ML-KEM-512", "Kyber512", "ML-KEM-1024", "Kyber1024"],
            available=kems,
            fallback_contains=["ML-KEM", "Kyber"],
        )
        super().__init__(mech)


@registry.register("hqc")
class HQC(_OQSKEM):
    """Default: HQC-192 if available."""
    def __init__(self):
        kems = oqs.get_enabled_kem_mechanisms()
        mech = _pick(
            preferred=[os.getenv("HQC_MECH"), "HQC-192", "HQC-256", "HQC-128"],
            available=kems,
            fallback_contains=["HQC"],
        )
        super().__init__(mech)


# ---------- Signatures (stateless) ----------

class _OQSSignature:
    def __init__(self, mech: str):
        self.mech = mech

    def keygen(self) -> Tuple[bytes, bytes]:
        with oqs.Signature(self.mech) as sig:
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
        return pk, sk

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        # Some liboqs versions add a context-string API; try plain first then context variant.
        with oqs.Signature(self.mech, secret_key) as sig:
            try:
                return sig.sign(message)
            except TypeError:
                # Newer API exposes sign_with_ctx_str / verify_with_ctx_str
                return sig.sign_with_ctx_str(message, b"")

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        with oqs.Signature(self.mech) as sig:
            try:
                return sig.verify(message, signature, public_key)
            except TypeError:
                return sig.verify_with_ctx_str(message, signature, public_key, b"")


@registry.register("dilithium")
class Dilithium(_OQSSignature):
    """Default: ML-DSA-65 (≈ Dilithium-3) if available."""
    def __init__(self):
        sigs = oqs.get_enabled_sig_mechanisms()
        mech = _pick(
            preferred=[os.getenv("DILITHIUM_MECH"), "ML-DSA-65", "Dilithium3", "ML-DSA-44", "Dilithium2", "ML-DSA-87", "Dilithium5"],
            available=sigs,
            fallback_contains=["ML-DSA", "Dilithium"],
        )
        super().__init__(mech)


@registry.register("falcon")
class Falcon(_OQSSignature):
    """Default: Falcon-512."""
    def __init__(self):
        sigs = oqs.get_enabled_sig_mechanisms()
        mech = _pick(
            preferred=[os.getenv("FALCON_MECH"), "Falcon-512", "Falcon-1024"],
            available=sigs,
            fallback_contains=["Falcon"],
        )
        super().__init__(mech)


@registry.register("sphincsplus")
class SphincsPlus(_OQSSignature):
    """Default: SPHINCS+-SHA2-128s-simple (fallback to any SPHINCS+)."""
    def __init__(self):
        sigs = oqs.get_enabled_sig_mechanisms()
        mech = _pick(
            preferred=[os.getenv("SPHINCSPLUS_MECH"), "SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHA2-128f-simple"],
            available=sigs,
            fallback_contains=["SPHINCS+"],
        )
        super().__init__(mech)


# ---------- Signatures (stateful) ----------

@registry.register("xmssmt")
class XMSSMT:
    """Simplified wrapper using stateful signatures (one sign per key in our microbench)."""
    def __init__(self):
        self._mech = None
        st = getattr(oqs, "get_enabled_stateful_sig_mechanisms", lambda: [])
        mechs = list(st())
        # Prefer a common XMSSMT parameter set; otherwise any XMSSMT
        self._mech = _pick(
            preferred=[os.getenv("XMSSMT_MECH"), "XMSSMT-SHA2_20/2_256", "XMSSMT-SHA2_20/4_256"],
            available=mechs,
            fallback_contains=["XMSSMT"],
        )

    def keygen(self) -> Tuple[bytes, bytes]:
        with oqs.StatefulSignature(self._mech) as ssig:
            pk = ssig.generate_keypair()
            sk = ssig.export_secret_key()
        return pk, sk

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        with oqs.StatefulSignature(self._mech, secret_key) as ssig:
            # stateful sigs consume state; our microbench runs with fresh keys each time
            return ssig.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        with oqs.StatefulSignature(self._mech) as ssig:
            return ssig.verify(message, signature, public_key)
