from __future__ import annotations

"""Parsers for ML-KEM and ML-DSA secret keys extracting lattice coefficients."""

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


# Shared ML-KEM constants (FIPS 203).
_MLKEM_Q = 3329
_MLKEM_POLY_BYTES = 384
_MLKEM_N = 256
_MLKEM_INV_F = pow(1441, -1, _MLKEM_Q)
_MLKEM_ZETAS: Tuple[int, ...] = (
    -1044,
    -758,
    -359,
    -1517,
    1493,
    1422,
    287,
    202,
    -171,
    622,
    1577,
    182,
    962,
    -1202,
    -1474,
    1468,
    573,
    -1325,
    264,
    383,
    -829,
    1458,
    -1602,
    -130,
    -681,
    1017,
    732,
    608,
    -1542,
    411,
    -205,
    -1571,
    1223,
    652,
    -552,
    1015,
    -1293,
    1491,
    -282,
    -1544,
    516,
    -8,
    -320,
    -666,
    -1618,
    -1162,
    126,
    1469,
    -853,
    -90,
    -271,
    830,
    107,
    -1421,
    -247,
    -951,
    -398,
    961,
    -1508,
    -725,
    448,
    -1065,
    677,
    -1275,
    -1103,
    430,
    555,
    843,
    -1251,
    871,
    1550,
    105,
    422,
    587,
    177,
    -235,
    -291,
    -460,
    1574,
    1653,
    -246,
    778,
    1159,
    -147,
    -777,
    1483,
    -602,
    1119,
    -1590,
    644,
    -872,
    349,
    418,
    329,
    -156,
    -75,
    817,
    1097,
    603,
    610,
    1322,
    -1285,
    -1465,
    384,
    -1215,
    -136,
    1218,
    -1335,
    -874,
    220,
    -1187,
    -1659,
    -1185,
    -1530,
    -1278,
    794,
    -1510,
    -854,
    -870,
    478,
    -108,
    -308,
    996,
    991,
    958,
    -1460,
    1522,
    1628,
)


@dataclass
class LatticeSecretParseResult:
    coefficients: List[List[List[int]]]
    parser: str
    context: Dict[str, object]
    warnings: List[str]


def _montgomery_reduce(value: int) -> int:
    qinv = 62209
    t = (value * qinv) & 0xFFFF
    return (value - t * _MLKEM_Q) >> 16


def _fqmul(a: int, b: int) -> int:
    return _montgomery_reduce(a * b)


def _barrett_reduce(a: int) -> int:
    # 20159 == round(2^26 / q).
    t = (20159 * a + (1 << 25)) >> 26
    r = a - t * _MLKEM_Q
    if r >= _MLKEM_Q // 2:
        r -= _MLKEM_Q
    elif r < -_MLKEM_Q // 2:
        r += _MLKEM_Q
    return r


def _mlkem_poly_frombytes(data: bytes) -> List[int]:
    coeffs = [0] * _MLKEM_N
    for i in range(_MLKEM_N // 2):
        t0 = data[3 * i] | ((data[3 * i + 1] & 0x0F) << 8)
        t1 = (data[3 * i + 1] >> 4) | (data[3 * i + 2] << 4)
        coeffs[2 * i] = t0 & 0xFFF
        coeffs[2 * i + 1] = t1 & 0xFFF
    return coeffs


def _mlkem_poly_tobytes(coeffs: Sequence[int]) -> bytes:
    out = bytearray(_MLKEM_POLY_BYTES)
    for i in range(_MLKEM_N // 2):
        t0 = coeffs[2 * i]
        t1 = coeffs[2 * i + 1]
        t0 += (t0 >> 15) & _MLKEM_Q
        t1 += (t1 >> 15) & _MLKEM_Q
        out[3 * i] = t0 & 0xFF
        out[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) & 0xFF
        out[3 * i + 2] = (t1 >> 4) & 0xFF
    return bytes(out)


def _mlkem_ntt(coeffs: Sequence[int]) -> List[int]:
    r = [int(c) for c in coeffs]
    k = 1
    length = _MLKEM_N // 2
    while length >= 2:
        start = 0
        while start < _MLKEM_N:
            zeta = _MLKEM_ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = _fqmul(zeta, r[j + length])
                r[j + length] = r[j] - t
                r[j] = r[j] + t
            start += 2 * length
        length //= 2
    return [_barrett_reduce(x) for x in r]


def _mlkem_invntt(coeffs_ntt: Sequence[int]) -> List[int]:
    r = [int(c) for c in coeffs_ntt]
    # Scale by Montgomery/NTT twist factor.
    f = 1441
    for idx in range(_MLKEM_N):
        r[idx] = _fqmul(r[idx], f)

    length = 2
    k = len(_MLKEM_ZETAS) - 1
    while length <= _MLKEM_N // 2:
        start = 0
        while start < _MLKEM_N:
            zeta = _MLKEM_ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = r[j]
                r[j] = _barrett_reduce(t + r[j + length])
                diff = _barrett_reduce(r[j + length] - t)
                r[j + length] = _fqmul(zeta, diff)
            start += 2 * length
        length *= 2
    for j in range(_MLKEM_N):
        r[j] = _fqmul(r[j], 1441)
    return [_barrett_reduce(x) for x in r]


def _mlkem_center(values: Iterable[int]) -> List[int]:
    centered: List[int] = []
    half_q = _MLKEM_Q // 2
    for val in values:
        v = val
        if v > half_q:
            v -= _MLKEM_Q
        elif v < -half_q:
            v += _MLKEM_Q
        centered.append(int(v))
    return centered


def _mlkem_from_montgomery(values: Sequence[int]) -> List[int]:
    converted: List[int] = []
    for val in values:
        v = (val % _MLKEM_Q) * _MLKEM_INV_F % _MLKEM_Q
        if v > _MLKEM_Q // 2:
            v -= _MLKEM_Q
        converted.append(int(v))
    return converted


def _mlkem_eta_expected_bounds(eta: int) -> Tuple[int, int]:
    return (-eta, eta)


def _dilithium_polyeta_unpack(data: bytes, eta: int) -> List[int]:
    coeffs = [0] * 256
    if eta == 2:
        for i in range(32):
            b0 = data[3 * i]
            b1 = data[3 * i + 1]
            b2 = data[3 * i + 2]
            t0 = (b0 >> 0) & 7
            t1 = (b0 >> 3) & 7
            t2 = ((b0 >> 6) | (b1 << 2)) & 7
            t3 = (b1 >> 1) & 7
            t4 = (b1 >> 4) & 7
            t5 = ((b1 >> 7) | (b2 << 1)) & 7
            t6 = (b2 >> 2) & 7
            t7 = (b2 >> 5) & 7
            base = 8 * i
            coeffs[base + 0] = eta - t0
            coeffs[base + 1] = eta - t1
            coeffs[base + 2] = eta - t2
            coeffs[base + 3] = eta - t3
            coeffs[base + 4] = eta - t4
            coeffs[base + 5] = eta - t5
            coeffs[base + 6] = eta - t6
            coeffs[base + 7] = eta - t7
    elif eta == 4:
        for i in range(128):
            byte = data[i]
            coeffs[2 * i] = eta - (byte & 0x0F)
            coeffs[2 * i + 1] = eta - (byte >> 4)
    else:
        raise ValueError(f"Unsupported Dilithium eta={eta}")
    return coeffs


def _dilithium_polyeta_pack(coeffs: Sequence[int], eta: int) -> bytes:
    if eta == 2:
        out = bytearray(96)
        for i in range(32):
            base = 8 * i
            t = [eta - coeffs[base + j] for j in range(8)]
            out[3 * i] = (t[0] | (t[1] << 3) | (t[2] << 6)) & 0xFF
            out[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)
            out[3 * i + 2] = ((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)) & 0xFF
        return bytes(out)
    if eta == 4:
        out = bytearray(128)
        for i in range(128):
            t0 = eta - coeffs[2 * i]
            t1 = eta - coeffs[2 * i + 1]
            out[i] = (t0 | (t1 << 4)) & 0xFF
        return bytes(out)
    raise ValueError(f"Unsupported Dilithium eta={eta}")


def parse_ml_kem_secret_keys(
    keys: Sequence[bytes],
    *,
    k: Optional[int],
    eta1: Optional[int],
    n: int = _MLKEM_N,
) -> Optional[LatticeSecretParseResult]:
    if not keys:
        return None
    warnings: List[str] = []
    if not isinstance(k, int) or k <= 0:
        warnings.append("ML-KEM parser missing valid 'k' parameter; skipping parse")
        return LatticeSecretParseResult([], "mlkem_eta_coefficients_v1", {}, warnings)
    if not isinstance(eta1, int) or eta1 <= 0:
        warnings.append("ML-KEM parser missing valid 'eta1' parameter; skipping parse")
        return LatticeSecretParseResult([], "mlkem_eta_coefficients_v1", {}, warnings)
    poly_bytes = _MLKEM_POLY_BYTES
    polyvec_bytes = poly_bytes * k
    coefficients: List[List[List[int]]] = []
    for idx, key in enumerate(keys):
        if len(key) < polyvec_bytes:
            warnings.append(
                f"key {idx} shorter than ML-KEM secret vector ({len(key)} < {polyvec_bytes})"
            )
            continue
        secret_part = key[:polyvec_bytes]
        polynomials: List[List[int]] = []
        for pol_idx in range(k):
            segment = secret_part[pol_idx * poly_bytes : (pol_idx + 1) * poly_bytes]
            coeffs_ntt = _mlkem_poly_frombytes(segment)
            coeffs_mont = _mlkem_invntt(coeffs_ntt)
            centered = _mlkem_from_montgomery(coeffs_mont)
            lower, upper = _mlkem_eta_expected_bounds(eta1)
            if any(c < lower or c > upper for c in centered):
                warnings.append(
                    f"ML-KEM key {idx} polynomial {pol_idx} contains values outside ±eta1"
                )
            polynomials.append(centered)
        if polynomials:
            coefficients.append(polynomials)
    context: Dict[str, object] = {
        "eta": eta1,
        "polynomials_per_key": k,
        "coefficients_per_polynomial": n,
        "segments": [
            {
                "name": "secret_vector",
                "count": k,
            }
        ],
        "distribution": "centered_binomial",
    }
    return LatticeSecretParseResult(
        coefficients=coefficients,
        parser="mlkem_eta_coefficients_v1",
        context=context,
        warnings=warnings,
    )


def parse_ml_dsa_secret_keys(
    keys: Sequence[bytes],
    *,
    k: Optional[int],
    l: Optional[int],
    eta: Optional[int],
    seed_bytes: int = 32,
    tr_bytes: int = 64,
) -> Optional[LatticeSecretParseResult]:
    if not keys:
        return None
    warnings: List[str] = []
    if not isinstance(eta, int) or eta <= 0:
        warnings.append("ML-DSA parser missing valid 'eta' parameter; skipping parse")
        return LatticeSecretParseResult([], "mldsa_eta_coefficients_v1", {}, warnings)
    if not isinstance(k, int) or k <= 0 or not isinstance(l, int) or l <= 0:
        warnings.append("ML-DSA parser missing valid 'k' or 'l' parameter; skipping parse")
        return LatticeSecretParseResult([], "mldsa_eta_coefficients_v1", {}, warnings)

    if eta == 2:
        polyeta_bytes = 96
    elif eta == 4:
        polyeta_bytes = 128
    else:
        warnings.append(f"Unsupported ML-DSA eta={eta}; skipping parse")
        return LatticeSecretParseResult([], "mldsa_eta_coefficients_v1", {}, warnings)

    offset_after_headers = seed_bytes + seed_bytes + tr_bytes
    s1_bytes = polyeta_bytes * l
    s2_bytes = polyeta_bytes * k

    coefficients: List[List[List[int]]] = []

    for idx, key in enumerate(keys):
        if len(key) < offset_after_headers + s1_bytes + s2_bytes:
            warnings.append(
                f"key {idx} shorter than ML-DSA secret layout ({len(key)} bytes)"
            )
            continue
        cursor = offset_after_headers
        polynomials: List[List[int]] = []
        for pol_idx in range(l):
            segment = key[cursor : cursor + polyeta_bytes]
            cursor += polyeta_bytes
            polynomials.append(_dilithium_polyeta_unpack(segment, eta))
        for pol_idx in range(k):
            segment = key[cursor : cursor + polyeta_bytes]
            cursor += polyeta_bytes
            polynomials.append(_dilithium_polyeta_unpack(segment, eta))
        coefficients.append(polynomials)

    context: Dict[str, object] = {
        "eta": eta,
        "polynomials_per_key": l + k,
        "coefficients_per_polynomial": 256,
        "segments": [
            {"name": "s1", "count": l},
            {"name": "s2", "count": k},
        ],
        "distribution": "uniform_eta",
    }
    return LatticeSecretParseResult(
        coefficients=coefficients,
        parser="mldsa_eta_coefficients_v1",
        context=context,
        warnings=warnings,
    )


__all__ = [
    "LatticeSecretParseResult",
    "parse_ml_kem_secret_keys",
    "parse_ml_dsa_secret_keys",
    "_mlkem_poly_tobytes",
    "_mlkem_ntt",
    "_dilithium_polyeta_pack",
]
