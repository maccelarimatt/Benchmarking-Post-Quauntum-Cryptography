from __future__ import annotations

import base64
import io
from dataclasses import dataclass
from typing import Dict, Optional

import numpy as np


def decode_base64_buffer(b64_str: str) -> bytes:
    """Decode a base64/data URI payload into raw bytes."""

    payload = b64_str.strip()
    if payload.startswith("data:"):
        _, _, payload = payload.partition(",")
    return base64.b64decode(payload)


@dataclass
class EntropySummary:
    """Container for entropy metrics and supporting histograms."""

    width: int
    height: int
    bits_per_byte_global: float
    bits_per_pixel_rgb: float
    channel_bits: Dict[str, float]
    histograms: Dict[str, np.ndarray]
    block_entropy_rgb: np.ndarray
    include_alpha: bool = False
    bits_per_pixel_rgba: Optional[float] = None


def _entropy_from_counts(counts: np.ndarray) -> float:
    """Compute Shannon entropy (base 2) from a histogram of counts."""

    total = float(counts.sum())
    if total <= 0.0:
        return 0.0
    probabilities = counts / total
    mask = probabilities > 0.0
    if not np.any(mask):
        return 0.0
    return float(-(probabilities[mask] * np.log2(probabilities[mask])).sum())


def channel_hist(channel: np.ndarray) -> np.ndarray:
    """Return a 256-bin histogram for a uint8 image channel."""

    if channel.dtype != np.uint8:
        channel = channel.astype(np.uint8, copy=False)
    return np.bincount(channel.ravel(), minlength=256).astype(np.float64)


def rgba_bytes_to_array(rgba_bytes: bytes, width: int, height: int) -> np.ndarray:
    """View raw RGBA bytes as a (H, W, 4) uint8 array."""

    expected = width * height * 4
    flat = np.frombuffer(rgba_bytes, dtype=np.uint8)
    if flat.size != expected:
        raise ValueError("Byte length does not match width*height*4")
    return flat.reshape((height, width, 4))


def image_entropy_rgba(rgba: np.ndarray, *, include_alpha: bool = False, block: int = 16) -> EntropySummary:
    """Compute global, per-channel, and block entropy metrics for an RGBA image."""

    if rgba.ndim != 3 or rgba.shape[2] != 4:
        raise ValueError("Expected image with shape (H, W, 4)")
    if rgba.dtype != np.uint8:
        rgba = rgba.astype(np.uint8, copy=False)

    height, width, _channels = rgba.shape
    r = rgba[..., 0]
    g = rgba[..., 1]
    b = rgba[..., 2]
    a = rgba[..., 3]

    histograms: Dict[str, np.ndarray] = {
        "R": channel_hist(r),
        "G": channel_hist(g),
        "B": channel_hist(b),
    }
    channel_bits: Dict[str, float] = {
        "R": _entropy_from_counts(histograms["R"]),
        "G": _entropy_from_counts(histograms["G"]),
        "B": _entropy_from_counts(histograms["B"]),
    }
    bits_for_global = [channel_bits["R"], channel_bits["G"], channel_bits["B"]]
    bits_per_pixel_rgb = float(sum(bits_for_global))
    bits_per_pixel_rgba: Optional[float] = None

    if include_alpha:
        histograms["A"] = channel_hist(a)
        channel_bits["A"] = _entropy_from_counts(histograms["A"])
        bits_for_global.append(channel_bits["A"])
        bits_per_pixel_rgba = float(bits_per_pixel_rgb + channel_bits["A"])

    bits_per_byte_global = float(sum(bits_for_global) / len(bits_for_global)) if bits_for_global else 0.0

    tiles_y = (height + block - 1) // block
    tiles_x = (width + block - 1) // block
    block_entropy = np.zeros((tiles_y, tiles_x), dtype=np.float32)

    for ty in range(tiles_y):
        y0 = ty * block
        y1 = min((ty + 1) * block, height)
        for tx in range(tiles_x):
            x0 = tx * block
            x1 = min((tx + 1) * block, width)
            r_block = channel_hist(r[y0:y1, x0:x1])
            g_block = channel_hist(g[y0:y1, x0:x1])
            b_block = channel_hist(b[y0:y1, x0:x1])
            h_r = _entropy_from_counts(r_block)
            h_g = _entropy_from_counts(g_block)
            h_b = _entropy_from_counts(b_block)
            block_entropy[ty, tx] = float((h_r + h_g + h_b) / 3.0)

    return EntropySummary(
        width=width,
        height=height,
        bits_per_byte_global=bits_per_byte_global,
        bits_per_pixel_rgb=bits_per_pixel_rgb,
        channel_bits=channel_bits,
        histograms=histograms,
        block_entropy_rgb=block_entropy,
        include_alpha=include_alpha,
        bits_per_pixel_rgba=bits_per_pixel_rgba,
    )


def summary_to_dict(summary: EntropySummary) -> Dict[str, object]:
    """Convert an EntropySummary to JSON-serializable primitives."""

    out: Dict[str, object] = {
        "width": int(summary.width),
        "height": int(summary.height),
        "bitsPerByteGlobal": float(summary.bits_per_byte_global),
        "bitsPerPixelRGB": float(summary.bits_per_pixel_rgb),
        "channelBits": {k: float(v) for k, v in summary.channel_bits.items()},
        "histograms": {k: [int(x) for x in np.asarray(v, dtype=np.int64)] for k, v in summary.histograms.items()},
        "blockEntropy": summary.block_entropy_rgb.astype(float).tolist(),
        "includeAlpha": bool(summary.include_alpha),
    }
    if summary.bits_per_pixel_rgba is not None:
        out["bitsPerPixelRGBA"] = float(summary.bits_per_pixel_rgba)
    return out


def rgba_from_base64(b64_str: str) -> np.ndarray:
    """Decode a base64-encoded image into an RGBA numpy array."""

    raw = decode_base64_buffer(b64_str)
    try:
        from PIL import Image  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("Pillow is required to decode images.") from exc
    with Image.open(io.BytesIO(raw)) as img:  # type: ignore
        rgba = img.convert("RGBA")
        return np.array(rgba, dtype=np.uint8)

