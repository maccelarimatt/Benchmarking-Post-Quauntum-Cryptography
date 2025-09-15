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
_add(["ML-KEM-512", "Kyber512"], family="ML-KEM", category_floor=128, notes="k=2; ring n=256; q=3329", extras={"k": 2, "n": 256, "q": 3329})
_add(["ML-KEM-768", "Kyber768"], family="ML-KEM", category_floor=192, notes="k=3; ring n=256; q=3329", extras={"k": 3, "n": 256, "q": 3329})
_add(["ML-KEM-1024", "Kyber1024"], family="ML-KEM", category_floor=256, notes="k=4; ring n=256; q=3329", extras={"k": 4, "n": 256, "q": 3329})

# ML-DSA (Dilithium)
_add(["ML-DSA-44", "Dilithium2"], family="ML-DSA", category_floor=128, notes="baseline Dilithium level 2")
_add(["ML-DSA-65", "Dilithium3"], family="ML-DSA", category_floor=192, notes="baseline Dilithium level 3")
_add(["ML-DSA-87", "Dilithium5"], family="ML-DSA", category_floor=256, notes="baseline Dilithium level 5")

# Falcon (FN-DSA)
_add(["Falcon-512"], family="Falcon", category_floor=128)
_add(["Falcon-1024"], family="Falcon", category_floor=256)

# HQC (code-based)
_add(["HQC-128"], family="HQC", category_floor=128)
_add(["HQC-192"], family="HQC", category_floor=192)
_add(["HQC-256"], family="HQC", category_floor=256)

# SPHINCS+ (hash-based) — many variants; approximate by suffix
_add(["SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHA2-128f-simple"], family="SPHINCS+", category_floor=128)
_add(["SPHINCS+-SHA2-192s-simple", "SPHINCS+-SHA2-192f-simple"], family="SPHINCS+", category_floor=192)
_add(["SPHINCS+-SHA2-256s-simple", "SPHINCS+-SHA2-256f-simple"], family="SPHINCS+", category_floor=256)

# XMSSMT — security target depends on the parameter set; provide common examples
_add(["XMSSMT-SHA2_20/2_256"], family="XMSSMT", category_floor=128)
_add(["XMSSMT-SHA2_20/4_256"], family="XMSSMT", category_floor=192)


def find(mechanism: Optional[str]) -> Optional[ParamHint]:
    if not mechanism:
        return None
    return _PARAMS.get(mechanism.lower())

