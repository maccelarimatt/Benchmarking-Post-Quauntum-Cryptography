from __future__ import annotations

"""Helpers for interpreting BIKE secret keys.

The liboqs BIKE implementation stores both the sparse index representation
(`wlist`) and the fully expanded binary vectors (`bin`) for the secret
polynomials `h0` and `h1`.  For Hamming analysis we rebuild constant-weight
bitstrings directly from the index lists so the resulting samples exactly
reflect the theoretical weight `D` specified by the parameter set.
"""

from dataclasses import dataclass
import struct
from typing import Dict, Iterable, List, Optional, Sequence


@dataclass
class BikeSecretParseResult:
    bitstrings: List[bytes]
    context: Dict[str, object]
    warnings: List[str]
    parser: str = "bike_constant_weight_v1"


def _set_bit(bytearray_buf: bytearray, position: int) -> None:
    byte_index = position // 8
    bit_index = position % 8
    bytearray_buf[byte_index] |= 1 << bit_index


def _mask_trailing_bits(buf: bytearray, valid_bits: int) -> None:
    total_bits = len(buf) * 8
    excess = total_bits - valid_bits
    if excess <= 0:
        return
    used_bits_last_byte = 8 - excess
    if used_bits_last_byte <= 0:
        buf[-1] = 0
        return
    mask = (1 << used_bits_last_byte) - 1
    buf[-1] &= mask


def parse_bike_secret_keys(
    raw_keys: Sequence[bytes],
    *,
    r_bits: Optional[int],
    weight_per_vector: Optional[int],
    n0: int = 2,
) -> Optional[BikeSecretParseResult]:
    """Extract constant-weight bitstrings from BIKE secret keys.

    Parameters
    ----------
    raw_keys:
        Raw secret key byte strings emitted by liboqs.
    r_bits:
        Degree of the circulant block (length of each secret polynomial).
    weight_per_vector:
        Hamming weight of each secret sparse polynomial (`D` in the spec).
    n0:
        Number of secret polynomials (BIKE uses 2).
    """

    if not raw_keys:
        return None

    if not isinstance(r_bits, int) or not isinstance(weight_per_vector, int):
        return BikeSecretParseResult(
            bitstrings=list(raw_keys),
            context={},
            warnings=["Missing BIKE parameters (r_bits/weight_per_vector); falling back to raw bytes."],
            parser="bike_raw_bytes_passthrough",
        )

    if r_bits <= 0 or weight_per_vector <= 0 or n0 <= 0:
        return BikeSecretParseResult(
            bitstrings=list(raw_keys),
            context={},
            warnings=["Invalid BIKE parameters supplied; falling back to raw bytes."],
            parser="bike_raw_bytes_passthrough",
        )

    r_bytes = (r_bits + 7) // 8
    wlist_entries = n0 * weight_per_vector
    wlist_bytes = wlist_entries * 4  # uint32 little-endian

    bitstrings: List[bytes] = []
    warnings: List[str] = []

    for idx, raw in enumerate(raw_keys):
        if len(raw) < wlist_bytes:
            warnings.append(f"Secret key {idx} shorter than expected wlist segment ({len(raw)} < {wlist_bytes})")
            continue
        if len(raw) < wlist_bytes + (n0 * r_bytes):
            warnings.append(
                f"Secret key {idx} shorter than expected binary segment "
                f"({len(raw)} < {wlist_bytes + n0 * r_bytes})"
            )
            continue

        # Extract index lists (little-endian uint32 entries).
        indices = list(struct.unpack_from(f"<{wlist_entries}I", raw, 0))

        combined = bytearray(r_bytes * n0)
        for vec in range(n0):
            segment = indices[vec * weight_per_vector : (vec + 1) * weight_per_vector]
            arr = bytearray(r_bytes)
            for position in segment:
                if position >= r_bits:
                    warnings.append(f"Secret key {idx} contains out-of-range index {position} (>= {r_bits})")
                    continue
                _set_bit(arr, position)
            _mask_trailing_bits(arr, r_bits)
            offset = vec * r_bytes
            combined[offset : offset + r_bytes] = arr

        bitstrings.append(bytes(combined))

    if not bitstrings:
        return None

    context: Dict[str, object] = {
        "parser": "bike_constant_weight_v1",
        "parsed_components": "h_sparse_vectors",
        "bike": {
            "r_bits": r_bits,
            "weight_per_vector": weight_per_vector,
            "n0": n0,
        },
    }

    return BikeSecretParseResult(
        bitstrings=bitstrings,
        context=context,
        warnings=warnings,
    )
