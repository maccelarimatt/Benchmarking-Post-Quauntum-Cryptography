"""Security category mappings for algorithm parameter sets.

This module captures the NIST PQC security floor categories (1, 3, 5) alongside
the concrete mechanism names (or RSA modulus sizes) that should be used for
benchmarks. It provides helpers to resolve environment overrides and the
fallback rules required when an exact category is unavailable.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Mapping, Optional, Sequence, Tuple, Union

SecurityCategory = int  # Expected values: 1, 3, 5


@dataclass(frozen=True)
class AlgorithmVariant:
    """Represents a concrete mechanism (or RSA modulus) for a given category."""

    value: Union[str, int]
    note: Optional[str] = None


@dataclass(frozen=True)
class SecurityOverride:
    """Resolved override for an algorithm at a requested security category."""

    algo: str
    env_var: str
    value: Union[str, int]
    requested_category: SecurityCategory
    applied_category: SecurityCategory
    note: Optional[str] = None

    @property
    def matched(self) -> bool:
        return self.requested_category == self.applied_category


# Canonical security categories supported by the UI / runners
SECURITY_CATEGORIES: Tuple[SecurityCategory, ...] = (1, 3, 5)

# Map algorithm canonical names to their parameter set overrides
_ALGO_VARIANTS: Dict[str, Mapping[SecurityCategory, AlgorithmVariant]] = {
    # KEMs
    "kyber": {
        1: AlgorithmVariant("ML-KEM-512"),
        3: AlgorithmVariant("ML-KEM-768"),
        5: AlgorithmVariant("ML-KEM-1024"),
    },
    "hqc": {
        1: AlgorithmVariant("HQC-128"),
        3: AlgorithmVariant("HQC-192"),
        5: AlgorithmVariant("HQC-256"),
    },
    "rsa-oaep": {
        1: AlgorithmVariant(3072),
        3: AlgorithmVariant(7680),
        5: AlgorithmVariant(15360),
    },
    # Signatures
    "rsa-pss": {
        1: AlgorithmVariant(3072),
        3: AlgorithmVariant(7680),
        5: AlgorithmVariant(15360),
    },
    "dilithium": {
        3: AlgorithmVariant("ML-DSA-65"),
        5: AlgorithmVariant("ML-DSA-87"),
    },
    "falcon": {
        1: AlgorithmVariant("Falcon-512"),
        5: AlgorithmVariant("Falcon-1024"),
    },
    "sphincs+": {
        1: AlgorithmVariant("SPHINCS+-SHAKE-128s-simple", "Using the small-signature (s) SPHINCS+ variants."),
        3: AlgorithmVariant("SPHINCS+-SHAKE-192s-simple", "Using the small-signature (s) SPHINCS+ variants."),
        5: AlgorithmVariant("SPHINCS+-SHAKE-256s-simple", "Using the small-signature (s) SPHINCS+ variants."),
    },
    "xmssmt": {
        5: AlgorithmVariant("XMSSMT-SHA2_20/2_256", "XMSSMT standardized profiles target Cat-5 only."),
    },
    "mayo": {
        1: AlgorithmVariant("MAYO-1"),
        3: AlgorithmVariant("MAYO-3"),
        5: AlgorithmVariant("MAYO-5"),
    },
}

# Provide aliases so callers can refer to liboqs naming variations.
_ALGO_ALIASES: Dict[str, str] = {
    "sphincsplus": "sphincs+",
}

# Mapping from algorithm canonical name to the environment variable used by
# adapters to pick a concrete mechanism.
_ENV_VARS: Dict[str, str] = {
    "kyber": "PQCBENCH_KYBER_ALG",
    "hqc": "PQCBENCH_HQC_ALG",
    "dilithium": "PQCBENCH_DILITHIUM_ALG",
    "falcon": "PQCBENCH_FALCON_ALG",
    "sphincs+": "PQCBENCH_SPHINCS_ALG",
    "sphincsplus": "PQCBENCH_SPHINCS_ALG",  # alias support
    "xmssmt": "PQCBENCH_XMSSMT_ALG",
    "mayo": "PQCBENCH_MAYO_ALG",
    "rsa-oaep": "PQCBENCH_RSA_BITS",
    "rsa-pss": "PQCBENCH_RSA_BITS",
}


def _canonical_algo(algo: str) -> str:
    key = algo.strip().lower()
    if key in _ALGO_VARIANTS:
        return key
    return _ALGO_ALIASES.get(key, key)


def available_categories(algo: str) -> Sequence[SecurityCategory]:
    """Return the security categories explicitly mapped for `algo`."""
    key = _canonical_algo(algo)
    variants = _ALGO_VARIANTS.get(key)
    if not variants:
        return ()
    return tuple(sorted(variants.keys()))


def resolve_security_override(
    algo: str,
    category: Optional[SecurityCategory],
) -> Optional[SecurityOverride]:
    """Compute the environment override for `algo` at the requested category.

    Fallback rules:
    - Prefer an exact match.
    - If unavailable, choose the lowest category above the request.
    - If none are above, choose the highest available category below.

    Returns None when no override information exists for the algorithm or when
    `category` is None.
    """
    if category is None:
        return None

    key = _canonical_algo(algo)
    variants = _ALGO_VARIANTS.get(key)
    if not variants:
        return None

    env_var = _ENV_VARS.get(key) or _ENV_VARS.get(algo)
    if not env_var:
        return None

    defined = sorted(variants.keys())
    if not defined:
        return None

    if category in variants:
        chosen = category
    else:
        higher = [lvl for lvl in defined if lvl >= category]
        if higher:
            chosen = higher[0]
        else:
            chosen = defined[-1]

    variant = variants[chosen]
    note_parts = []
    if variant.note:
        note_parts.append(variant.note)
    if chosen != category:
        direction = "higher" if chosen > category else "lower"
        note_parts.append(
            f"No Category {category} parameter set; using Category {chosen} ({direction} availability)."
        )

    return SecurityOverride(
        algo=algo,
        env_var=env_var,
        value=variant.value,
        requested_category=category,
        applied_category=chosen,
        note=" ".join(note_parts) if note_parts else None,
    )


__all__ = [
    "AlgorithmVariant",
    "SecurityOverride",
    "SecurityCategory",
    "SECURITY_CATEGORIES",
    "available_categories",
    "resolve_security_override",
]
