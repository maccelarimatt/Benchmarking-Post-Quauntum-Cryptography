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
     extras={
         "k": 2,
         "n": 256,
         "q": 3329,
         "eta1": 3,
         "eta2": 2,
         "sizes_bytes": {"public_key": 800, "secret_key": 1632, "ciphertext": 768, "shared_secret": 32},
     })
_add(["ML-KEM-768", "Kyber768"], family="ML-KEM", category_floor=192,
     notes="k=3; ring n=256; q=3329; eta1=2, eta2=2",
     extras={
         "k": 3,
         "n": 256,
         "q": 3329,
         "eta1": 2,
         "eta2": 2,
         "sizes_bytes": {"public_key": 1184, "secret_key": 2400, "ciphertext": 1088, "shared_secret": 32},
     })
_add(["ML-KEM-1024", "Kyber1024"], family="ML-KEM", category_floor=256,
     notes="k=4; ring n=256; q=3329; eta1=2, eta2=2",
     extras={
         "k": 4,
         "n": 256,
         "q": 3329,
         "eta1": 2,
         "eta2": 2,
         "sizes_bytes": {"public_key": 1568, "secret_key": 3168, "ciphertext": 1568, "shared_secret": 32},
     })

# ML-DSA (Dilithium)
# Provide typical module ranks (k, l) and modulus for reference; detailed parameters are scheme-specific.
_add(["ML-DSA-44", "Dilithium2"], family="ML-DSA", category_floor=128,
     notes="k=4, l=4; n=256; q=8380417; eta=2",
     extras={
         "k": 4,
         "l": 4,
         "n": 256,
         "q": 8380417,
         "eta": 2,
         "sizes_bytes": {"public_key": 1312, "secret_key": 2528, "signature": 2420},
     })
_add(["ML-DSA-65", "Dilithium3"], family="ML-DSA", category_floor=192,
     notes="k=6, l=5; n=256; q=8380417; eta=4",
     extras={
         "k": 6,
         "l": 5,
         "n": 256,
         "q": 8380417,
         "eta": 4,
         "sizes_bytes": {"public_key": 1952, "secret_key": 4000, "signature": 3309, "signature_min": 3293},
     })
_add(["ML-DSA-87", "Dilithium5"], family="ML-DSA", category_floor=256,
     notes="k=8, l=7; n=256; q=8380417; eta=2",
     extras={
         "k": 8,
         "l": 7,
         "n": 256,
         "q": 8380417,
         "eta": 2,
         "sizes_bytes": {"public_key": 2592, "secret_key": 4864, "signature": 4627},
     })
# Some liboqs builds expose ML-DSA-110; treat as Cat-5 floor for labeling
_add(["ML-DSA-110"], family="ML-DSA", category_floor=256,
     notes="non-FIPS param; treated as Cat-5 floor for labeling")

# Falcon (FN-DSA)
# Provide common ring dimension and modulus for reference (NTRU lattice over Z_q[x]/(x^n+1)).
_add(["Falcon-512"], family="Falcon", category_floor=128,
     notes="n=512; q=12289; NTRU lattice",
     extras={
         "n": 512,
         "q": 12289,
         "sizes_bytes": {
             "public_key": 897,
             "secret_key": 1281,
             "signature": 666,
            "signature_note": "Deterministic padded encoding = 666 bytes; compressed signatures vary ~650-670 bytes; uncompressed ~752 bytes.",
         },
     })
_add(["Falcon-1024"], family="Falcon", category_floor=256,
     notes="n=1024; q=12289; NTRU lattice",
     extras={
         "n": 1024,
         "q": 12289,
         "sizes_bytes": {
             "public_key": 1793,
             "secret_key": 2305,
             "signature": 1280,
            "signature_note": "Deterministic padded = 1280 bytes; compressed signatures vary; uncompressed ~1536 bytes.",
         },
     })

# RSA (classical baseline)
_add(["rsa-oaep"], family="RSA", category_floor=112,
     notes="RSA-2048 OAEP baseline; assesses Shor breakability in quantum models",
     extras={"modulus_bits": 2048, "public_exponent": 65537})
_add(["rsa-pss"], family="RSA", category_floor=112,
     notes="RSA-2048 PSS signature baseline; salt length matches hash size",
     extras={"modulus_bits": 2048, "public_exponent": 65537})

# HQC (code-based) — include structural parameters from PQClean
_add(["HQC-128"], family="HQC", category_floor=128,
     notes="n=17669; RS n1=46,k=16,delta=15; RM n2=384; omega=66; omega_e=75; omega_r=75",
     extras={
         "n": 17669,
         "k": 16,
         "w": 66,
         "n1": 46,
         "n2": 384,
         "omega": 66,
         "omega_e": 75,
         "omega_r": 75,
         "delta": 15,
         "sizes_bytes": {"public_key": 2249, "secret_key": 2305, "ciphertext": 4433, "shared_secret": 64},
     })
_add(["HQC-192"], family="HQC", category_floor=192,
     notes="n=35851; RS n1=56,k=24,delta=16; RM n2=640; omega=100; omega_e=114; omega_r=114",
     extras={
         "n": 35851,
         "k": 24,
         "w": 100,
         "n1": 56,
         "n2": 640,
         "omega": 100,
         "omega_e": 114,
         "omega_r": 114,
         "delta": 16,
         "sizes_bytes": {"public_key": 4522, "secret_key": 4586, "ciphertext": 8978, "shared_secret": 64},
     })
_add(["HQC-256"], family="HQC", category_floor=256,
     notes="n=57637; RS n1=90,k=32,delta=29; RM n2=640; omega=131; omega_e=149; omega_r=149",
     extras={
         "n": 57637,
         "k": 32,
         "w": 131,
         "n1": 90,
         "n2": 640,
         "omega": 131,
         "omega_e": 149,
         "omega_r": 149,
         "delta": 29,
         "sizes_bytes": {"public_key": 7245, "secret_key": 7317, "ciphertext": 14421, "shared_secret": 64},
     })
# Some liboqs names carry CCA2 suffix; map them to the same floors (reuse closest set)
_add(["HQC-128-1-CCA2"], family="HQC", category_floor=128,
     notes="alias of HQC-128",
     extras={"n": 17669, "k": 16, "w": 66, "n1": 46, "n2": 384, "omega": 66, "omega_e": 75, "omega_r": 75, "delta": 15})
_add(["HQC-192-1-CCA2"], family="HQC", category_floor=192,
     notes="alias of HQC-192",
     extras={"n": 35851, "k": 24, "w": 100, "n1": 56, "n2": 640, "omega": 100, "omega_e": 114, "omega_r": 114, "delta": 16})
_add(["HQC-256-1-CCA2"], family="HQC", category_floor=256,
     notes="alias of HQC-256",
     extras={"n": 57637, "k": 32, "w": 131, "n1": 90, "n2": 640, "omega": 131, "omega_e": 149, "omega_r": 149, "delta": 29})

# BIKE (QC-MDPC) — two sparse polynomials of constant weight D per parameter set
_add(["BIKE-L1"], family="BIKE", category_floor=128,
     notes="Round-4 BIKE; r=12323, weight per polynomial D=71",
     extras={
         "r_bits": 12323,
         "weight_per_vector": 71,
         "n0": 2,
         "sizes_bytes": {"public_key": 1541, "secret_key": 5223, "ciphertext": 1573, "shared_secret": 32},
     })
_add(["BIKE-L3"], family="BIKE", category_floor=192,
     notes="Round-4 BIKE; r=24659, weight per polynomial D=103",
     extras={
         "r_bits": 24659,
         "weight_per_vector": 103,
         "n0": 2,
         "sizes_bytes": {"public_key": 3083, "secret_key": 10105, "ciphertext": 3115, "shared_secret": 32},
     })
_add(["BIKE-L5"], family="BIKE", category_floor=256,
     notes="Round-4 BIKE; r=40973, weight per polynomial D=137",
     extras={
         "r_bits": 40973,
         "weight_per_vector": 137,
         "n0": 2,
         "sizes_bytes": {"public_key": 5122, "secret_key": 16494, "ciphertext": 5154, "shared_secret": 32},
     })

# Classic McEliece (code-based Goppa)
_add(["Classic-McEliece-348864f"], family="Classic McEliece", category_floor=128,
     notes="Binary Goppa code; fast (f) variant targeting NIST Cat-1",
     extras={
         "sizes_bytes": {"public_key": 261120, "secret_key": 6492, "ciphertext": 96, "shared_secret": 32},
     })
_add(["Classic-McEliece-460896f"], family="Classic McEliece", category_floor=192,
     notes="Binary Goppa code; fast (f) variant targeting NIST Cat-3",
     extras={
         "sizes_bytes": {"public_key": 524160, "secret_key": 13608, "ciphertext": 156, "shared_secret": 32},
     })
_add(["Classic-McEliece-6688128f"], family="Classic McEliece", category_floor=256,
     notes="Binary Goppa code; fast (f) variant targeting NIST Cat-5",
     extras={
         "sizes_bytes": {"public_key": 1044992, "secret_key": 13932, "ciphertext": 208, "shared_secret": 32},
     })

# FrodoKEM (LWE with large modulus)
_add(["FrodoKEM-640-AES"], family="FrodoKEM", category_floor=128,
     notes="n=640; AES-based sampling; NIST Cat-1",
     extras={
         "sizes_bytes": {"public_key": 9616, "secret_key": 19888, "ciphertext": 9720, "shared_secret": 16},
     })
_add(["FrodoKEM-976-AES"], family="FrodoKEM", category_floor=192,
     notes="n=976; AES-based sampling; NIST Cat-3",
     extras={
         "sizes_bytes": {"public_key": 15632, "secret_key": 31296, "ciphertext": 15744, "shared_secret": 24},
     })
_add(["FrodoKEM-1344-AES"], family="FrodoKEM", category_floor=256,
     notes="n=1344; AES-based sampling; NIST Cat-5",
     extras={
         "sizes_bytes": {"public_key": 21520, "secret_key": 43088, "ciphertext": 21632, "shared_secret": 32},
     })

# NTRU (HPS/HRSS families)
_add(["NTRU-HPS-2048-509"], family="NTRU", category_floor=128,
     notes="HPS Round-3 parameter targeting Cat-1",
     extras={
         "sizes_bytes": {"public_key": 699, "secret_key": 935, "ciphertext": 699, "shared_secret": 32},
     })
_add(["NTRU-HPS-2048-677"], family="NTRU", category_floor=192,
     notes="HPS Round-3 parameter targeting Cat-3",
     extras={
         "sizes_bytes": {"public_key": 930, "secret_key": 1234, "ciphertext": 930, "shared_secret": 32},
     })
_add(["NTRU-HPS-4096-821"], family="NTRU", category_floor=256,
     notes="HPS Round-3 parameter targeting Cat-5",
     extras={
         "sizes_bytes": {"public_key": 1230, "secret_key": 1590, "ciphertext": 1230, "shared_secret": 32},
     })
_add(["NTRU-HRSS-701"], family="NTRU", category_floor=192,
     notes="HRSS alternative Cat-3 parameter",
     extras={
         "sizes_bytes": {"public_key": 1138, "secret_key": 1450, "ciphertext": 1138, "shared_secret": 32},
     })

# NTRU Prime (sntrup family)
_add(["sntrup653"], family="NTRU Prime", category_floor=128,
     notes="sntrup653 (prime-degree NTRU) targeting Cat-1")
_add(["sntrup761"], family="NTRU Prime", category_floor=192,
     notes="sntrup761 (prime-degree NTRU) targeting Cat-3",
     extras={
         "sizes_bytes": {"public_key": 1158, "secret_key": 1763, "ciphertext": 1039, "shared_secret": 32},
     })
_add(["sntrup1277"], family="NTRU Prime", category_floor=256,
     notes="sntrup1277 (prime-degree NTRU) targeting Cat-5")

# SPHINCS+ (hash-based) — many variants; approximate by suffix
_SPHINCS_EXTRAS = {
    "128s": {"n": 16, "full_height": 63, "layers": 7, "fors_height": 12, "fors_trees": 14, "wots_w": 16},
    "128f": {"n": 16, "full_height": 66, "layers": 22, "fors_height": 6, "fors_trees": 33, "wots_w": 16},
    "192s": {"n": 24, "full_height": 63, "layers": 7, "fors_height": 14, "fors_trees": 17, "wots_w": 16},
    "192f": {"n": 24, "full_height": 66, "layers": 22, "fors_height": 8, "fors_trees": 33, "wots_w": 16},
    "256s": {"n": 32, "full_height": 64, "layers": 8, "fors_height": 14, "fors_trees": 22, "wots_w": 16},
    "256f": {"n": 32, "full_height": 68, "layers": 17, "fors_height": 9, "fors_trees": 35, "wots_w": 16},
}

def _sphincs_extras(tag: str) -> Dict[str, Any]:
    return dict(_SPHINCS_EXTRAS.get(tag, {}))


_add(["SPHINCS+-SHA2-128s-simple"], family="SPHINCS+", category_floor=128,
     extras={**_sphincs_extras("128s"), "sizes_bytes": {"public_key": 32, "secret_key": 64, "signature": 7856}})
_add(["SPHINCS+-SHA2-128f-simple"], family="SPHINCS+", category_floor=128,
     extras={**_sphincs_extras("128f"), "sizes_bytes": {"public_key": 32, "secret_key": 64, "signature": 17088}})
_add(["SPHINCS+-SHA2-192s-simple"], family="SPHINCS+", category_floor=192,
     extras={**_sphincs_extras("192s"), "sizes_bytes": {"public_key": 48, "secret_key": 96, "signature": 16224}})
_add(["SPHINCS+-SHA2-192f-simple"], family="SPHINCS+", category_floor=192,
     extras={**_sphincs_extras("192f"), "sizes_bytes": {"public_key": 48, "secret_key": 96, "signature": 35664}})
_add(["SPHINCS+-SHA2-256s-simple"], family="SPHINCS+", category_floor=256,
     extras={**_sphincs_extras("256s"), "sizes_bytes": {"public_key": 64, "secret_key": 128, "signature": 29792}})
_add(["SPHINCS+-SHA2-256f-simple"], family="SPHINCS+", category_floor=256,
     extras={**_sphincs_extras("256f"), "sizes_bytes": {"public_key": 64, "secret_key": 128, "signature": 49856}})
_add(["SPHINCS+-SHAKE-128s-simple"], family="SPHINCS+", category_floor=128,
     extras={**_sphincs_extras("128s"), "sizes_bytes": {"public_key": 32, "secret_key": 64, "signature": 7856}})
_add(["SPHINCS+-SHAKE-128f-simple"], family="SPHINCS+", category_floor=128,
     extras={**_sphincs_extras("128f"), "sizes_bytes": {"public_key": 32, "secret_key": 64, "signature": 17088}})
_add(["SPHINCS+-SHAKE-192s-simple"], family="SPHINCS+", category_floor=192,
     extras={**_sphincs_extras("192s"), "sizes_bytes": {"public_key": 48, "secret_key": 96, "signature": 16224}})
_add(["SPHINCS+-SHAKE-192f-simple"], family="SPHINCS+", category_floor=192,
     extras={**_sphincs_extras("192f"), "sizes_bytes": {"public_key": 48, "secret_key": 96, "signature": 35664}})
_add(["SPHINCS+-SHAKE-256s-simple"], family="SPHINCS+", category_floor=256,
     extras={**_sphincs_extras("256s"), "sizes_bytes": {"public_key": 64, "secret_key": 128, "signature": 29792}})
_add(["SPHINCS+-SHAKE-256f-simple"], family="SPHINCS+", category_floor=256,
     extras={**_sphincs_extras("256f"), "sizes_bytes": {"public_key": 64, "secret_key": 128, "signature": 49856}})
_add(["SPHINCS+-SHA2-128s-robust"], family="SPHINCS+", category_floor=128,
     extras={**_sphincs_extras("128s"), "sizes_bytes": {"public_key": 32, "secret_key": 64, "signature": 8080}})
_add(["SPHINCS+-SHA2-128f-robust"], family="SPHINCS+", category_floor=128,
     extras={**_sphincs_extras("128f"), "sizes_bytes": {"public_key": 32, "secret_key": 64, "signature": 16976}})
_add(["SPHINCS+-SHA2-192s-robust"], family="SPHINCS+", category_floor=192,
     extras={**_sphincs_extras("192s"), "sizes_bytes": {"public_key": 48, "secret_key": 96, "signature": 16256}})
_add(["SPHINCS+-SHA2-192f-robust"], family="SPHINCS+", category_floor=192,
     extras={**_sphincs_extras("192f"), "sizes_bytes": {"public_key": 48, "secret_key": 96, "signature": 35680}})
_add(["SPHINCS+-SHA2-256s-robust"], family="SPHINCS+", category_floor=256,
     extras={**_sphincs_extras("256s"), "sizes_bytes": {"public_key": 64, "secret_key": 128, "signature": 49856}})
_add(["SPHINCS+-SHA2-256f-robust"], family="SPHINCS+", category_floor=256,
     extras={**_sphincs_extras("256f"), "sizes_bytes": {"public_key": 64, "secret_key": 128, "signature": 78112}})
_add(["SPHINCS+-SHAKE-128s-robust"], family="SPHINCS+", category_floor=128,
     extras={**_sphincs_extras("128s"), "sizes_bytes": {"public_key": 32, "secret_key": 64, "signature": 8080}})
_add(["SPHINCS+-SHAKE-128f-robust"], family="SPHINCS+", category_floor=128,
     extras={**_sphincs_extras("128f"), "sizes_bytes": {"public_key": 32, "secret_key": 64, "signature": 16976}})
_add(["SPHINCS+-SHAKE-192s-robust"], family="SPHINCS+", category_floor=192,
     extras={**_sphincs_extras("192s"), "sizes_bytes": {"public_key": 48, "secret_key": 96, "signature": 16256}})
_add(["SPHINCS+-SHAKE-192f-robust"], family="SPHINCS+", category_floor=192,
     extras={**_sphincs_extras("192f"), "sizes_bytes": {"public_key": 48, "secret_key": 96, "signature": 35680}})
_add(["SPHINCS+-SHAKE-256s-robust"], family="SPHINCS+", category_floor=256,
     extras={**_sphincs_extras("256s"), "sizes_bytes": {"public_key": 64, "secret_key": 128, "signature": 49856}})
_add(["SPHINCS+-SHAKE-256f-robust"], family="SPHINCS+", category_floor=256,
     extras={**_sphincs_extras("256f"), "sizes_bytes": {"public_key": 64, "secret_key": 128, "signature": 78112}})

# XMSSMT — security target depends on the parameter set; provide common examples
_add(["XMSSMT-SHA2_20/2_256"], family="XMSSMT", category_floor=128)
_add(["XMSSMT-SHA2_20/4_256"], family="XMSSMT", category_floor=192)
_add(["XMSS-SHA2_20_256"], family="XMSS", category_floor=128)
_add(["XMSSMT-SHAKE_20/2_256"], family="XMSSMT", category_floor=128)
_add(["XMSSMT-SHAKE_20/4_256"], family="XMSSMT", category_floor=192)
_add(["XMSS-SHAKE_20_256"], family="XMSS", category_floor=128)

# MAYO (multivariate signatures) — include structural parameters from liboqs pqmayo
_add(["MAYO-1"], family="MAYO", category_floor=128,
     notes="n=86, m=78, o=8, v=78; k=10; q=16",
     extras={
         "n": 86,
         "m": 78,
         "oil": 8,
         "vinegar": 78,
         "k": 10,
         "q": 16,
         "sizes_bytes": {"public_key": 1420, "secret_key": 24, "signature": 454},
     })
_add(["MAYO-2", "MAYO_two", "MAYO-two"], family="MAYO", category_floor=128,
     notes="n=81, m=64, o=17, v=64; k=4; q=16",
     extras={
         "n": 81,
         "m": 64,
         "oil": 17,
         "vinegar": 64,
         "k": 4,
         "q": 16,
         "sizes_bytes": {"public_key": 4912, "secret_key": 24, "signature": 186},
     })
_add(["MAYO-3"], family="MAYO", category_floor=192,
     notes="n=118, m=108, o=10, v=108; k=11; q=16",
     extras={
         "n": 118,
         "m": 108,
         "oil": 10,
         "vinegar": 108,
         "k": 11,
         "q": 16,
         "sizes_bytes": {"public_key": 2986, "secret_key": 32, "signature": 681},
     })
_add(["MAYO-5"], family="MAYO", category_floor=256,
     notes="n=154, m=142, o=12, v=142; k=12; q=16",
     extras={
         "n": 154,
         "m": 142,
         "oil": 12,
         "vinegar": 142,
         "k": 12,
         "q": 16,
         "sizes_bytes": {"public_key": 5554, "secret_key": 40, "signature": 964},
     })

# CROSS (rank-based signatures)
_add(["cross-rsdpg-128-balanced"], family="CROSS", category_floor=128,
     notes="CROSS RSDPG balanced variant at 128-bit security")
_add(["cross-rsdpg-192-balanced"], family="CROSS", category_floor=192,
     notes="CROSS RSDPG balanced variant at 192-bit security")
_add(["cross-rsdpg-256-balanced"], family="CROSS", category_floor=256,
     notes="CROSS RSDPG balanced variant at 256-bit security")

# SLH-DSA (stateless hash-based signatures)
_add(["SLH_DSA_PURE_SHA2_128S"], family="SLH-DSA", category_floor=128,
     notes="SLH-DSA pure SHA2 128s parameter set (FIPS 205) targeting Cat-1")
_add(["SLH_DSA_PURE_SHA2_192S"], family="SLH-DSA", category_floor=192,
     notes="SLH-DSA pure SHA2 192s parameter set (FIPS 205) targeting Cat-3")
_add(["SLH_DSA_PURE_SHA2_256S"], family="SLH-DSA", category_floor=256,
     notes="SLH-DSA pure SHA2 256s parameter set (FIPS 205) targeting Cat-5")

# SNOVA (structured oil-and-vinegar)
_add(["SNOVA_25_8_3"], family="SNOVA", category_floor=128,
     notes="SNOVA parameter set 25/8/3 targeting Cat-1")
_add(["SNOVA_37_17_2"], family="SNOVA", category_floor=192,
     notes="SNOVA parameter set 37/17/2 targeting Cat-3")
_add(["SNOVA_60_10_4"], family="SNOVA", category_floor=256,
     notes="SNOVA parameter set 60/10/4 targeting Cat-5")

# UOV (Unbalanced Oil and Vinegar)
_add(["OV-Is"], family="UOV", category_floor=128,
     notes="UOV parameter set OV-Is targeting Cat-1")
_add(["OV-III"], family="UOV", category_floor=192,
     notes="UOV parameter set OV-III targeting Cat-3")
_add(["OV-V"], family="UOV", category_floor=256,
     notes="UOV parameter set OV-V targeting Cat-5")


def find(mechanism: Optional[str]) -> Optional[ParamHint]:
    if not mechanism:
        return None
    return _PARAMS.get(mechanism.lower())
