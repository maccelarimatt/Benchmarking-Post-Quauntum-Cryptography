from __future__ import annotations

"""Helpers for scheme-aware parsing of HQC secret keys.

The native HQC implementations (PQClean/liboqs) store secret keys as a
concatenation of:

- seed (40 bytes) used to derive the constant-weight secret vectors x and y
- sigma (PARAM_K bytes)
- public key (appended to satisfy the NIST API)

Only the constant-weight binary vectors carry the intended secret sampling.
This module reconstructs those vectors so higher-level analyses can operate on
the expected bit distribution instead of the opaque seed+metadata blob.
"""

from dataclasses import dataclass
import hashlib
from typing import Iterable, List, Optional, Sequence


_UINT8_MASK = 0xFF


@dataclass(frozen=True)
class HQCVariant:
    """Parameter bundle describing a concrete HQC parameter set."""

    name: str
    n: int
    w: int
    sigma_bytes: int
    public_key_bytes: int
    m_values: Sequence[int]

    @property
    def seed_bytes(self) -> int:
        # All HQC variants use a 40-byte seed expander input.
        return 40

    @property
    def secret_key_bytes(self) -> int:
        return self.seed_bytes + self.sigma_bytes + self.public_key_bytes

    @property
    def vector_byte_length(self) -> int:
        return (self.n + 7) // 8


# Pre-computed m_val tables taken from PQClean vector.c for each variant.
_HQC_VARIANTS: dict[str, HQCVariant] = {
    "hqc-128": HQCVariant(
        name="HQC-128",
        n=17669,
        w=66,
        sigma_bytes=16,
        public_key_bytes=2249,
        m_values=(
            243079, 243093, 243106, 243120, 243134, 243148, 243161, 243175, 243189,
            243203, 243216, 243230, 243244, 243258, 243272, 243285, 243299, 243313,
            243327, 243340, 243354, 243368, 243382, 243396, 243409, 243423, 243437,
            243451, 243465, 243478, 243492, 243506, 243520, 243534, 243547, 243561,
            243575, 243589, 243603, 243616, 243630, 243644, 243658, 243672, 243686,
            243699, 243713, 243727, 243741, 243755, 243769, 243782, 243796, 243810,
            243824, 243838, 243852, 243865, 243879, 243893, 243907, 243921, 243935,
            243949, 243962, 243976, 243990, 244004, 244018, 244032, 244046, 244059,
            244073, 244087, 244101,
        ),
    ),
    "hqc-128-1-cca2": HQCVariant(
        name="HQC-128-1-CCA2",
        n=17669,
        w=66,
        sigma_bytes=16,
        public_key_bytes=2249,
        m_values=(
            243079, 243093, 243106, 243120, 243134, 243148, 243161, 243175, 243189,
            243203, 243216, 243230, 243244, 243258, 243272, 243285, 243299, 243313,
            243327, 243340, 243354, 243368, 243382, 243396, 243409, 243423, 243437,
            243451, 243465, 243478, 243492, 243506, 243520, 243534, 243547, 243561,
            243575, 243589, 243603, 243616, 243630, 243644, 243658, 243672, 243686,
            243699, 243713, 243727, 243741, 243755, 243769, 243782, 243796, 243810,
            243824, 243838, 243852, 243865, 243879, 243893, 243907, 243921, 243935,
            243949, 243962, 243976, 243990, 244004, 244018, 244032, 244046, 244059,
            244073, 244087, 244101,
        ),
    ),
    "hqc-192": HQCVariant(
        name="HQC-192",
        n=35851,
        w=100,
        sigma_bytes=24,
        public_key_bytes=4522,
        m_values=(
            119800, 119803, 119807, 119810, 119813, 119817, 119820, 119823, 119827,
            119830, 119833, 119837, 119840, 119843, 119847, 119850, 119853, 119857,
            119860, 119864, 119867, 119870, 119874, 119877, 119880, 119884, 119887,
            119890, 119894, 119897, 119900, 119904, 119907, 119910, 119914, 119917,
            119920, 119924, 119927, 119930, 119934, 119937, 119941, 119944, 119947,
            119951, 119954, 119957, 119961, 119964, 119967, 119971, 119974, 119977,
            119981, 119984, 119987, 119991, 119994, 119997, 120001, 120004, 120008,
            120011, 120014, 120018, 120021, 120024, 120028, 120031, 120034, 120038,
            120041, 120044, 120048, 120051, 120054, 120058, 120061, 120065, 120068,
            120071, 120075, 120078, 120081, 120085, 120088, 120091, 120095, 120098,
            120101, 120105, 120108, 120112, 120115, 120118, 120122, 120125, 120128,
            120132, 120135, 120138, 120142, 120145, 120149, 120152, 120155, 120159,
            120162, 120165, 120169, 120172, 120175, 120179,
        ),
    ),
    "hqc-192-1-cca2": HQCVariant(
        name="HQC-192-1-CCA2",
        n=35851,
        w=100,
        sigma_bytes=24,
        public_key_bytes=4522,
        m_values=(
            119800, 119803, 119807, 119810, 119813, 119817, 119820, 119823, 119827,
            119830, 119833, 119837, 119840, 119843, 119847, 119850, 119853, 119857,
            119860, 119864, 119867, 119870, 119874, 119877, 119880, 119884, 119887,
            119890, 119894, 119897, 119900, 119904, 119907, 119910, 119914, 119917,
            119920, 119924, 119927, 119930, 119934, 119937, 119941, 119944, 119947,
            119951, 119954, 119957, 119961, 119964, 119967, 119971, 119974, 119977,
            119981, 119984, 119987, 119991, 119994, 119997, 120001, 120004, 120008,
            120011, 120014, 120018, 120021, 120024, 120028, 120031, 120034, 120038,
            120041, 120044, 120048, 120051, 120054, 120058, 120061, 120065, 120068,
            120071, 120075, 120078, 120081, 120085, 120088, 120091, 120095, 120098,
            120101, 120105, 120108, 120112, 120115, 120118, 120122, 120125, 120128,
            120132, 120135, 120138, 120142, 120145, 120149, 120152, 120155, 120159,
            120162, 120165, 120169, 120172, 120175, 120179,
        ),
    ),
    "hqc-256": HQCVariant(
        name="HQC-256",
        n=57637,
        w=131,
        sigma_bytes=32,
        public_key_bytes=7245,
        m_values=(
            74517, 74518, 74520, 74521, 74522, 74524, 74525, 74526, 74527, 74529,
            74530, 74531, 74533, 74534, 74535, 74536, 74538, 74539, 74540, 74542,
            74543, 74544, 74545, 74547, 74548, 74549, 74551, 74552, 74553, 74555,
            74556, 74557, 74558, 74560, 74561, 74562, 74564, 74565, 74566, 74567,
            74569, 74570, 74571, 74573, 74574, 74575, 74577, 74578, 74579, 74580,
            74582, 74583, 74584, 74586, 74587, 74588, 74590, 74591, 74592, 74593,
            74595, 74596, 74597, 74599, 74600, 74601, 74602, 74604, 74605, 74606,
            74608, 74609, 74610, 74612, 74613, 74614, 74615, 74617, 74618, 74619,
            74621, 74622, 74623, 74625, 74626, 74627, 74628, 74630, 74631, 74632,
            74634, 74635, 74636, 74637, 74639, 74640, 74641, 74643, 74644, 74645,
            74647, 74648, 74649, 74650, 74652, 74653, 74654, 74656, 74657, 74658,
            74660, 74661, 74662, 74663, 74665, 74666, 74667, 74669, 74670, 74671,
            74673, 74674, 74675, 74676, 74678, 74679, 74680, 74682, 74683, 74684,
            74685, 74687, 74688, 74689, 74691, 74692, 74693, 74695, 74696, 74697,
            74698, 74700, 74701, 74702, 74704, 74705, 74706, 74708, 74709,
        ),
    ),
    "hqc-256-1-cca2": HQCVariant(
        name="HQC-256-1-CCA2",
        n=57637,
        w=131,
        sigma_bytes=32,
        public_key_bytes=7245,
        m_values=(
            74517, 74518, 74520, 74521, 74522, 74524, 74525, 74526, 74527, 74529,
            74530, 74531, 74533, 74534, 74535, 74536, 74538, 74539, 74540, 74542,
            74543, 74544, 74545, 74547, 74548, 74549, 74551, 74552, 74553, 74555,
            74556, 74557, 74558, 74560, 74561, 74562, 74564, 74565, 74566, 74567,
            74569, 74570, 74571, 74573, 74574, 74575, 74577, 74578, 74579, 74580,
            74582, 74583, 74584, 74586, 74587, 74588, 74590, 74591, 74592, 74593,
            74595, 74596, 74597, 74599, 74600, 74601, 74602, 74604, 74605, 74606,
            74608, 74609, 74610, 74612, 74613, 74614, 74615, 74617, 74618, 74619,
            74621, 74622, 74623, 74625, 74626, 74627, 74628, 74630, 74631, 74632,
            74634, 74635, 74636, 74637, 74639, 74640, 74641, 74643, 74644, 74645,
            74647, 74648, 74649, 74650, 74652, 74653, 74654, 74656, 74657, 74658,
            74660, 74661, 74662, 74663, 74665, 74666, 74667, 74669, 74670, 74671,
            74673, 74674, 74675, 74676, 74678, 74679, 74680, 74682, 74683, 74684,
            74685, 74687, 74688, 74689, 74691, 74692, 74693, 74695, 74696, 74697,
            74698, 74700, 74701, 74702, 74704, 74705, 74706, 74708, 74709,
        ),
    ),
}


_LENGTH_TO_VARIANT: dict[int, str] = {
    variant.secret_key_bytes: key
    for key, variant in _HQC_VARIANTS.items()
}


@dataclass
class HQCSecretParseResult:
    """Return object for HQC secret parsing."""

    bitstrings: List[bytes]
    parser: str
    context: dict[str, object]
    warnings: List[str]


class _SeedExpander:
    """SHAKE-256 seed expander mirroring PQClean's shake_prng."""

    __slots__ = ("_shake", "_offset")

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 40:
            raise ValueError(f"HQC seed must be 40 bytes, got {len(seed)}")
        self._shake = hashlib.shake_256(seed + bytes([2]))
        self._offset = 0

    def squeeze(self, length: int) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        self._offset += length
        data = self._shake.digest(self._offset)
        return data[self._offset - length : self._offset]


def _reduce(value: int, index: int, n: int, m_values: Sequence[int]) -> int:
    q = (value * m_values[index]) >> 32
    n_i = n - index
    r = value - q * n_i
    if r >= n_i:
        r -= n_i
    if r < 0:
        r += n_i
    return r


def _sample_support(expander: _SeedExpander, weight: int, n: int, m_values: Sequence[int]) -> List[int]:
    raw = expander.squeeze(4 * weight)
    support: List[int] = []
    for i in range(weight):
        chunk = raw[4 * i : 4 * (i + 1)]
        value = int.from_bytes(chunk, "little")
        reduced = _reduce(value, i, n, m_values)
        support.append(i + reduced)

    # Resolve duplicates exactly as PQClean does (replace with index).
    for i in range(weight - 2, -1, -1):
        current = support[i]
        for later in support[i + 1 :]:
            if later == current:
                support[i] = i
                break
    return support


def _support_to_bytes(support: Iterable[int], n: int) -> bytes:
    vec = bytearray((n + 7) // 8)
    for pos in support:
        if pos < 0 or pos >= n:
            raise ValueError(f"support index {pos} out of bounds for n={n}")
        byte_idx = pos // 8
        bit_idx = pos % 8
        vec[byte_idx] |= 1 << bit_idx
    return bytes(vec)


def _popcount(data: bytes) -> int:
    return sum(byte.bit_count() for byte in data)


def resolve_variant(mechanism: Optional[str], secret_key_length: Optional[int]) -> Optional[HQCVariant]:
    if mechanism:
        key = mechanism.lower()
        variant = _HQC_VARIANTS.get(key)
        if variant:
            return variant
    if secret_key_length is not None:
        key = _LENGTH_TO_VARIANT.get(secret_key_length)
        if key:
            return _HQC_VARIANTS[key]
    return None


def parse_secret_keys(
    keys: Sequence[bytes],
    *,
    mechanism: Optional[str],
) -> Optional[HQCSecretParseResult]:
    if not keys:
        return None

    variant = resolve_variant(mechanism, len(keys[0]))
    if not variant:
        return None

    parsed: List[bytes] = []
    warnings: List[str] = []

    for idx, key in enumerate(keys):
        if len(key) != variant.secret_key_bytes:
            warnings.append(
                f"key {idx} length {len(key)} bytes does not match expected {variant.secret_key_bytes}"
            )
            continue
        seed = key[: variant.seed_bytes]
        expander = _SeedExpander(seed)
        x_support = _sample_support(expander, variant.w, variant.n, variant.m_values)
        y_support = _sample_support(expander, variant.w, variant.n, variant.m_values)
        x_vec = _support_to_bytes(x_support, variant.n)
        y_vec = _support_to_bytes(y_support, variant.n)
        for label, vec in (("x", x_vec), ("y", y_vec)):
            hw = _popcount(vec)
            if hw != variant.w:
                warnings.append(
                    f"key {idx} {label}-vector weight {hw} differs from expected {variant.w}"
                )
        parsed.append(x_vec)

    if not parsed:
        return None

    context = {
        "bit_component": "HQC secret vector x",
        "vectors_per_key": 1,
        "variant": variant.name,
    }
    return HQCSecretParseResult(
        bitstrings=parsed,
        parser="hqc_seed_constant_weight_v1",
        context=context,
        warnings=warnings,
    )


__all__ = [
    "HQCSecretParseResult",
    "parse_secret_keys",
    "resolve_variant",
]
