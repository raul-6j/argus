"""Tests for src.detection.brand_reference (brand index loader)."""

from __future__ import annotations

import json

from src.detection.brand_reference import Brand, BrandIndex, load_brand_index


class TestLoadBrandIndex:
    def test_missing_file_returns_empty_index(self, tmp_path):
        idx = load_brand_index(tmp_path / "nope.json")
        assert idx.brands == ()

    def test_malformed_json_returns_empty_index(self, tmp_path):
        p = tmp_path / "brands.json"
        p.write_text("{not valid json", encoding="utf-8")
        idx = load_brand_index(p)
        assert idx.brands == ()

    def test_valid_file_loads_brands(self, tmp_path):
        p = tmp_path / "brands.json"
        p.write_text(
            json.dumps(
                {
                    "brands": [
                        {
                            "name": "TestBrand",
                            "domains": ["testbrand.com", "TESTBRAND.NET"],
                            "aliases": ["Test Brand", "TB"],
                            "favicon_mmh3": [12345, -6789],
                            "logo_phash": ["ABCDEF0123456789"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        idx = load_brand_index(p)
        assert len(idx.brands) == 1
        brand = idx.brands[0]
        assert brand.name == "TestBrand"
        # domains/aliases/hashes are lowercased on load.
        assert brand.domains == ("testbrand.com", "testbrand.net")
        assert brand.aliases == ("test brand", "tb")
        assert brand.favicon_mmh3 == (12345, -6789)
        assert brand.logo_phash == ("abcdef0123456789",)

    def test_brand_missing_domains_is_skipped(self, tmp_path):
        p = tmp_path / "brands.json"
        p.write_text(
            json.dumps({"brands": [{"name": "NoDomains", "domains": []}]}), encoding="utf-8"
        )
        idx = load_brand_index(p)
        assert idx.brands == ()

    def test_brands_not_a_list_returns_empty_index(self, tmp_path):
        p = tmp_path / "brands.json"
        p.write_text(json.dumps({"brands": "not-a-list"}), encoding="utf-8")
        idx = load_brand_index(p)
        assert idx.brands == ()

    def test_real_shipped_brands_asset_loads(self):
        """The actual data/reference/brands.json ships with the repo and
        must load cleanly with no path override."""
        idx = load_brand_index()
        assert len(idx.brands) > 0
        names = {b.name for b in idx.brands}
        assert "PayPal" in names


class TestBrandIndexLookup:
    def _index(self) -> BrandIndex:
        brand = Brand(
            name="Acme",
            domains=("acme.com", "acme.net"),
            aliases=("acme",),
            favicon_mmh3=(42, -17),
            logo_phash=("deadbeef",),
        )
        return BrandIndex(brands=(brand,))

    def test_brand_for_domain_hit(self):
        idx = self._index()
        assert idx.brand_for_domain("acme.com").name == "Acme"
        assert idx.brand_for_domain("acme.net").name == "Acme"

    def test_brand_for_domain_is_case_insensitive(self):
        idx = self._index()
        assert idx.brand_for_domain("ACME.COM").name == "Acme"

    def test_brand_for_domain_miss(self):
        idx = self._index()
        assert idx.brand_for_domain("other.com") is None

    def test_brand_for_domain_empty_string(self):
        idx = self._index()
        assert idx.brand_for_domain("") is None

    def test_brand_for_favicon_hash_hit(self):
        idx = self._index()
        assert idx.brand_for_favicon_hash(42).name == "Acme"
        assert idx.brand_for_favicon_hash(-17).name == "Acme"

    def test_brand_for_favicon_hash_miss(self):
        idx = self._index()
        assert idx.brand_for_favicon_hash(999) is None

    def test_empty_index_never_matches(self):
        idx = BrandIndex(brands=())
        assert idx.brand_for_domain("anything.com") is None
        assert idx.brand_for_favicon_hash(0) is None
