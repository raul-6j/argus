"""Pure-Python image/byte hashing for the favicon-match signal (Phase 1, A2).

Deliberately dependency-light: MurmurHash3 (x86, 32-bit) is reimplemented
directly rather than adding the ``mmh3`` compiled-extension package — it is
a small, fully-specified algorithm, and the project already keeps
``requirements.txt`` minimal (see CLAUDE.md). :func:`mmh3_32` matches the
conventional "Shodan favicon hash" usage:
``mmh3_32(base64.b64encode(favicon_bytes))``.

:func:`average_hash` computes a lightweight perceptual hash ("aHash") on top
of Pillow (already an installed transitive dependency of matplotlib/shap)
and is used for a *soft* logo/favicon similarity match — a simpler cousin of
true DCT-based pHash, sufficient for the "does this look like the same icon"
signal this module exists to answer, and explicitly documented as such
rather than overclaiming DCT-pHash-grade robustness.
"""

from __future__ import annotations

import io
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_C1 = 0xCC9E2D51
_C2 = 0x1B873593
_MASK32 = 0xFFFFFFFF


def mmh3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit hash of ``data``, as a signed 32-bit int.

    Args:
        data: Bytes to hash.
        seed: Hash seed (``0`` by the conventional favicon-hashing usage).

    Returns:
        A signed 32-bit integer hash. ``mmh3_32(b"", 0) == 0`` always (a
        structural property of the algorithm, not an empirical constant).
    """
    length = len(data)
    h1 = seed
    rounded_end = length & 0xFFFFFFFC

    for i in range(0, rounded_end, 4):
        k1 = (
            (data[i] & 0xFF)
            | ((data[i + 1] & 0xFF) << 8)
            | ((data[i + 2] & 0xFF) << 16)
            | ((data[i + 3] & 0xFF) << 24)
        )
        k1 = (k1 * _C1) & _MASK32
        k1 = ((k1 << 15) | (k1 >> 17)) & _MASK32
        k1 = (k1 * _C2) & _MASK32
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & _MASK32
        h1 = (h1 * 5 + 0xE6546B64) & _MASK32

    k1 = 0
    tail_len = length & 0x03
    tail_start = rounded_end
    if tail_len == 3:
        k1 ^= (data[tail_start + 2] & 0xFF) << 16
    if tail_len >= 2:
        k1 ^= (data[tail_start + 1] & 0xFF) << 8
    if tail_len >= 1:
        k1 ^= data[tail_start] & 0xFF
        k1 = (k1 * _C1) & _MASK32
        k1 = ((k1 << 15) | (k1 >> 17)) & _MASK32
        k1 = (k1 * _C2) & _MASK32
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & _MASK32
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & _MASK32
    h1 ^= h1 >> 16

    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


def average_hash(image_bytes: bytes, hash_size: int = 8) -> Optional[int]:
    """Compute a ``hash_size**2``-bit average hash ("aHash") of an image.

    Never raises (Iron Law #3) — an undecodable image yields ``None``.

    Args:
        image_bytes: Raw image bytes, any Pillow-supported format
            (favicons are commonly ``.ico``, ``.png``, or ``.svg`` — SVG is
            not raster and will fail to decode, yielding ``None``, which the
            caller treats as "no perceptual signal available").
        hash_size: Side length of the reduced grayscale grid (``8`` -> 64
            bits).

    Returns:
        An integer in ``[0, 2**(hash_size**2))``, or ``None`` if the image
        could not be decoded.
    """
    try:
        from PIL import Image

        with Image.open(io.BytesIO(image_bytes)) as img:
            img = img.convert("L").resize((hash_size, hash_size), Image.LANCZOS)
            pixels = list(img.getdata())
    except Exception as exc:  # noqa: BLE001 - undecodable image -> None, never crash
        logger.warning("average_hash: failed to decode image: %s", exc)
        return None

    if not pixels:
        return None
    avg = sum(pixels) / len(pixels)
    bits = 0
    for pixel in pixels:
        bits = (bits << 1) | (1 if pixel > avg else 0)
    return bits


def hamming_distance(a: int, b: int) -> int:
    """Population count of ``a XOR b`` — bit-distance between two hashes."""
    return bin(a ^ b).count("1")
