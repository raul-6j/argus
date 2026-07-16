"""Tests for src.detection.hashing (MurmurHash3 + average-hash)."""

from __future__ import annotations

import io

from src.detection.hashing import average_hash, hamming_distance, mmh3_32


class TestMmh3_32:
    def test_empty_bytes_with_seed_zero_is_zero(self):
        """A structural property of MurmurHash3, not a memorized magic number:
        with no input bytes, the tail/loop stages never execute and the
        avalanche mix of the untouched seed (0) stays 0."""
        assert mmh3_32(b"", 0) == 0

    def test_deterministic(self):
        assert mmh3_32(b"hello world") == mmh3_32(b"hello world")

    def test_different_input_different_hash(self):
        assert mmh3_32(b"hello") != mmh3_32(b"world")

    def test_different_seed_different_hash(self):
        assert mmh3_32(b"hello", seed=0) != mmh3_32(b"hello", seed=1)

    def test_returns_signed_32_bit_int(self):
        h = mmh3_32(b"some arbitrary favicon bytes go here" * 5)
        assert -(2**31) <= h < 2**31

    def test_handles_various_lengths(self):
        """Exercises the tail-byte branches (0/1/2/3 remainder bytes)."""
        for n in range(0, 12):
            data = bytes(range(n))
            h = mmh3_32(data)
            assert isinstance(h, int)


class TestAverageHash:
    def _make_png_bytes(self, color=(10, 20, 30), size=(16, 16)) -> bytes:
        from PIL import Image

        img = Image.new("RGB", size, color=color)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    def test_valid_image_returns_int_hash(self):
        h = average_hash(self._make_png_bytes())
        assert isinstance(h, int)
        assert 0 <= h < 2**64

    def test_identical_images_same_hash(self):
        data = self._make_png_bytes()
        assert average_hash(data) == average_hash(data)

    def test_solid_color_images_hash_consistently(self):
        """A uniform-color image's pixels all equal the average -> hash is
        all-zero bits by the `pixel > avg` convention (no pixel exceeds the
        mean when every pixel equals it)."""
        h = average_hash(self._make_png_bytes(color=(100, 100, 100)))
        assert h == 0

    def test_invalid_bytes_returns_none(self):
        assert average_hash(b"not an image at all") is None

    def test_empty_bytes_returns_none(self):
        assert average_hash(b"") is None

    def test_custom_hash_size(self):
        h = average_hash(self._make_png_bytes(), hash_size=4)
        assert h is not None
        assert h < 2**16


class TestHammingDistance:
    def test_identical_values_zero_distance(self):
        assert hamming_distance(0b1010, 0b1010) == 0

    def test_all_bits_different(self):
        assert hamming_distance(0b0000, 0b1111) == 4

    def test_single_bit_difference(self):
        assert hamming_distance(0b1000, 0b1001) == 1

    def test_symmetric(self):
        assert hamming_distance(123456, 654321) == hamming_distance(654321, 123456)
