from __future__ import annotations
"""Canonical parameter hints for common mechanisms.

This module maps mechanism identifiers (as used by liboqs and FIPS names)
to lightweight parameter records that the security estimator can consume to
select model presets and NIST floors.

Note: These are not complete scheme parameters; for rigorous lattice
estimation, pass full parameter tuples to external tools. We store what we
need for categorisation and basic reporting.
"""
from dataclasses import dataclass, asdict
from typing import Dict, Optional, Any


@dataclass
class ParamHint:
    family: str            # e.g., ML-KEM, ML-DSA, Falcon, HQC, RSA, SPHINCS+
    mechanism: str         # exact mechanism name as emitted by adapters
    category_floor: int    # 128/192/256
    notes: str = ""
    extras: Dict[str, Any] | None = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


_PARAMS: Dict[str, ParamHint] = {}

def _add(alias_list, family: str, category_floor: int, notes: str = "", extras: Dict[str, Any] | None = None):
    for alias in alias_list:
        _PARAMS[alias.lower()] = ParamHint(family=family, mechanism=alias, category_floor=category_floor, notes=notes, extras=extras or {})


# ML-KEM (Kyber)
# Include common noise parameters (eta1, eta2) to help external estimators map to sigma.
_add(["ML-KEM-512", "Kyber512"], family="ML-KEM", category_floor=128,
     notes="k=2; ring n=256; q=3329; eta1=3, eta2=2",
     extras={"k": 2, "n": 256, "q": 3329, "eta1": 3, "eta2": 2})
_add(["ML-KEM-768", "Kyber768"], family="ML-KEM", category_floor=192,
     notes="k=3; ring n=256; q=3329; eta1=2, eta2=2",
     extras={"k": 3, "n": 256, "q": 3329, "eta1": 2, "eta2": 2})
_add(["ML-KEM-1024", "Kyber1024"], family="ML-KEM", category_floor=256,
     notes="k=4; ring n=256; q=3329; eta1=2, eta2=2",
     extras={"k": 4, "n": 256, "q": 3329, "eta1": 2, "eta2": 2})

# ML-DSA (Dilithium)
# Provide typical module ranks (k, l) and modulus for reference; detailed parameters are scheme-specific.
_add(["ML-DSA-44", "Dilithium2"], family="ML-DSA", category_floor=128,
     notes="k=4, l=4; n=256; q=8380417",
     extras={"k": 4, "l": 4, "n": 256, "q": 8380417})
_add(["ML-DSA-65", "Dilithium3"], family="ML-DSA", category_floor=192,
     notes="k=6, l=5; n=256; q=8380417",
     extras={"k": 6, "l": 5, "n": 256, "q": 8380417})
_add(["ML-DSA-87", "Dilithium5"], family="ML-DSA", category_floor=256,
     notes="k=8, l=7; n=256; q=8380417",
     extras={"k": 8, "l": 7, "n": 256, "q": 8380417})
# Some liboqs builds expose ML-DSA-110; treat as Cat-5 floor for labeling
_add(["ML-DSA-110"], family="ML-DSA", category_floor=256,
     notes="non-FIPS param; treated as Cat-5 floor for labeling")

# Falcon (FN-DSA)
# Provide common ring dimension and modulus for reference (NTRU lattice over Z_q[x]/(x^n+1)).
_add(["Falcon-512"], family="Falcon", category_floor=128,
     notes="n=512; q=12289; NTRU lattice",
     extras={"n": 512, "q": 12289})
_add(["Falcon-1024"], family="Falcon", category_floor=256,
     notes="n=1024; q=12289; NTRU lattice",
     extras={"n": 1024, "q": 12289})

# HQC (code-based)
_add(["HQC-128"], family="HQC", category_floor=128)
_add(["HQC-192"], family="HQC", category_floor=192)
_add(["HQC-256"], family="HQC", category_floor=256)
# Some liboqs names carry CCA2 suffix; map them to the same floors
_add(["HQC-128-1-CCA2"], family="HQC", category_floor=128)
_add(["HQC-192-1-CCA2"], family="HQC", category_floor=192)
_add(["HQC-256-1-CCA2"], family="HQC", category_floor=256)

# SPHINCS+ (hash-based) — many variants; approximate by suffix
_add(["SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHA2-128f-simple"], family="SPHINCS+", category_floor=128)
_add(["SPHINCS+-SHA2-192s-simple", "SPHINCS+-SHA2-192f-simple"], family="SPHINCS+", category_floor=192)
_add(["SPHINCS+-SHA2-256s-simple", "SPHINCS+-SHA2-256f-simple"], family="SPHINCS+", category_floor=256)
_add(["SPHINCS+-SHA2-128f-robust"], family="SPHINCS+", category_floor=128)
_add(["SPHINCS+-SHAKE-128s-simple", "SPHINCS+-SHAKE-128f-simple"], family="SPHINCS+", category_floor=128)

# XMSSMT — security target depends on the parameter set; provide common examples
_add(["XMSSMT-SHA2_20/2_256"], family="XMSSMT", category_floor=128)
_add(["XMSSMT-SHA2_20/4_256"], family="XMSSMT", category_floor=192)
_add(["XMSS-SHA2_20_256"], family="XMSS", category_floor=128)

# MAYO (multivariate signatures) — approximate by level name
_add(["MAYO-1"], family="MAYO", category_floor=128, notes="multivariate (MQ) signature")
_add(["MAYO-2"], family="MAYO", category_floor=160, notes="multivariate (MQ) signature")
_add(["MAYO-3"], family="MAYO", category_floor=192, notes="multivariate (MQ) signature")
_add(["MAYO-5"], family="MAYO", category_floor=256, notes="multivariate (MQ) signature")


def find(mechanism: Optional[str]) -> Optional[ParamHint]:
    if not mechanism:
        return None
    return _PARAMS.get(mechanism.lower())
