"""Tests for src.api.public.keys (Phase 2, C3)."""

from __future__ import annotations

from src.api.public.keys import extract_bearer_key, generate_api_key, hash_api_key


class TestGenerateApiKey:
    def test_raw_key_has_expected_prefix(self):
        raw_key, _key_hash, _prefix = generate_api_key()
        assert raw_key.startswith("argus_")

    def test_hash_is_not_the_raw_key(self):
        raw_key, key_hash, _prefix = generate_api_key()
        assert key_hash != raw_key
        assert len(key_hash) == 64  # sha256 hex digest

    def test_hash_matches_hash_api_key_of_the_raw_value(self):
        raw_key, key_hash, _prefix = generate_api_key()
        assert hash_api_key(raw_key) == key_hash

    def test_prefix_is_a_short_non_secret_slice(self):
        raw_key, _key_hash, prefix = generate_api_key()
        assert raw_key.startswith(prefix)
        assert len(prefix) < len(raw_key)

    def test_two_calls_produce_different_keys(self):
        raw1, _, _ = generate_api_key()
        raw2, _, _ = generate_api_key()
        assert raw1 != raw2


class TestExtractBearerKey:
    def test_valid_bearer_header(self):
        assert extract_bearer_key("Bearer argus_abc123") == "argus_abc123"

    def test_case_insensitive_scheme(self):
        assert extract_bearer_key("bearer argus_abc123") == "argus_abc123"

    def test_none_header_returns_none(self):
        assert extract_bearer_key(None) is None

    def test_empty_header_returns_none(self):
        assert extract_bearer_key("") is None

    def test_malformed_header_returns_none(self):
        assert extract_bearer_key("NotBearer argus_abc123") is None

    def test_bearer_with_no_token_returns_none(self):
        assert extract_bearer_key("Bearer ") is None

    def test_bearer_with_only_whitespace_returns_none(self):
        assert extract_bearer_key("Bearer    ") is None
