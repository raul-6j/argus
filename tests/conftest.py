"""Root-level pytest configuration, loaded before any test module.

src.api.auth.utils.get_secret_key() fails closed (S6) if SECRET_KEY isn't
set in the environment — correct behavior for the real app, but it means
merely *importing* src.api.app (which every tests/api/ module does) would
break the whole suite without a value present. Setting it here, at module
level (not inside a fixture), guarantees it exists before pytest imports
any test module, since pytest loads conftest.py files first during
collection.

This is a fixed *test* secret, not a production one — it must never be used
outside this test run.
"""

from __future__ import annotations

import os

os.environ.setdefault("SECRET_KEY", "test-only-secret-key-do-not-use-in-production-32b")
