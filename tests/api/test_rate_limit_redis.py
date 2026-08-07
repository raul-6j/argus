"""Tests for Redis-backed rate limiting (Phase 2, G2).

Uses ``fakeredis.TcpFakeServer`` — a real TCP server speaking the Redis
protocol, so ``flask-limiter``'s ``storage_uri=redis://...`` resolution
(which creates a real ``redis.Redis`` client, not something mockable at the
Python-object level) works unmodified. No real Redis server is required for
these tests to run in CI.
"""

from __future__ import annotations

import threading
import time

import pytest
import redis
import yaml

from tests.api.conftest import _MODEL_PATH, PROJECT_ROOT

try:
    import fakeredis
except ImportError:  # pragma: no cover - dev dependency, always installed per requirements.txt
    fakeredis = None

pytestmark = pytest.mark.skipif(
    not _MODEL_PATH.is_file(), reason="Run scripts/train.py + scripts/evaluate.py first."
)


@pytest.fixture
def fake_redis_server():
    """A real-protocol, in-process fake Redis server on a free local port."""
    if fakeredis is None:
        pytest.skip("fakeredis not installed")

    address = ("127.0.0.1", 0)
    server = fakeredis.TcpFakeServer(address, server_type="redis")
    port = server.socket.getsockname()[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)
    try:
        yield f"redis://127.0.0.1:{port}/0"
    finally:
        server.shutdown()


def _make_app(config_path: str):
    from src.api.app import create_app

    return create_app(config_path=config_path)


def _write_config(tmp_path_factory, **overrides):
    api_config = yaml.safe_load((PROJECT_ROOT / "configs" / "api_config.yaml").open())
    api_config.update(overrides)
    tmp_dir = tmp_path_factory.mktemp("redis_rate_limit_config")
    config_path = tmp_dir / "api_config.yaml"
    config_path.write_text(yaml.safe_dump(api_config))
    return str(config_path)


_REAL_REDIS_URL = "redis://localhost:6379/0"


@pytest.fixture
def real_redis_url():
    """The core multi-worker enforcement test needs Lua/EVALSHA support for
    `limits`' atomic incr-and-expire script -- fakeredis's Lua emulation is
    flaky for this specific pattern (first-call-only failures observed),
    so this one test prefers a real local Redis over the in-process fake.
    Skips gracefully if no local Redis is running, exactly like the
    project's existing "skip if no trained model" convention.
    """
    try:
        client = redis.Redis.from_url(_REAL_REDIS_URL, socket_connect_timeout=1)
        client.ping()
        client.flushdb()
    except Exception:  # noqa: BLE001
        pytest.skip(f"No local Redis reachable at {_REAL_REDIS_URL} for this test.")
    return _REAL_REDIS_URL


class TestBootTimeConnectivityCheck:
    def test_boots_successfully_when_redis_reachable(self, fake_redis_server, tmp_path_factory):
        config_path = _write_config(tmp_path_factory, rate_limit_storage_uri=fake_redis_server)
        app = _make_app(config_path)
        assert app.extensions["argus"]["redis_client"] is not None
        assert app.extensions["argus"]["redis_client"].ping() is True

    def test_refuses_to_start_when_redis_unreachable(self, tmp_path_factory):
        config_path = _write_config(
            tmp_path_factory, rate_limit_storage_uri="redis://127.0.0.1:1/0"
        )
        with pytest.raises(RuntimeError, match="Redis is unreachable"):
            _make_app(config_path)

    def test_memory_backend_never_touches_redis(self, tmp_path_factory):
        config_path = _write_config(tmp_path_factory, rate_limit_storage_uri="memory://")
        app = _make_app(config_path)
        assert app.extensions["argus"]["redis_client"] is None


class TestMultiWorkerEnforcement:
    def test_rate_limit_shared_across_independent_app_instances(
        self, real_redis_url, tmp_path_factory
    ):
        """The core G2 acceptance test: two INDEPENDENT create_app()
        instances (simulating two separate gunicorn worker processes, each
        with its own in-process Limiter state) must share one rate-limit
        counter via the common Redis backend."""
        config_path = _write_config(
            tmp_path_factory, rate_limit_storage_uri=real_redis_url, rate_limit="5 per minute"
        )
        worker_a = _make_app(config_path)
        worker_b = _make_app(config_path)
        client_a = worker_a.test_client()
        client_b = worker_b.test_client()

        statuses = []
        for i in range(8):
            client = client_a if i % 2 == 0 else client_b
            statuses.append(client.get("/health").status_code)

        assert statuses[:5] == [200] * 5
        assert 429 in statuses[5:]

    def test_independent_apps_without_shared_backend_do_not_share_limit(self, tmp_path_factory):
        """Control case: with memory:// (no shared backend), two independent
        app instances each get their own full quota -- proving the Redis
        test above is measuring real cross-process sharing, not some other
        effect."""
        config_path = _write_config(
            tmp_path_factory, rate_limit_storage_uri="memory://", rate_limit="5 per minute"
        )
        worker_a = _make_app(config_path)
        worker_b = _make_app(config_path)
        client_a = worker_a.test_client()
        client_b = worker_b.test_client()

        # 5 requests to worker A exhausts its own quota...
        statuses_a = [client_a.get("/health").status_code for _ in range(6)]
        assert statuses_a[:5] == [200] * 5
        assert statuses_a[5] == 429

        # ...but worker B, with its own separate in-memory counter, is unaffected.
        assert client_b.get("/health").status_code == 200


class TestMidSessionRedisFailure:
    def test_redis_dying_after_boot_returns_clean_503_not_500(self, tmp_path_factory):
        """The boot-time check (TestBootTimeConnectivityCheck) only catches
        an outage at startup -- this covers Redis dying *after* the app is
        already serving traffic. Must fail closed (never silently allow)
        AND return a clean JSON 503, not an unhandled 500/HTML error."""
        if fakeredis is None:
            pytest.skip("fakeredis not installed")

        address = ("127.0.0.1", 0)
        server = fakeredis.TcpFakeServer(address, server_type="redis")
        port = server.socket.getsockname()[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        config_path = _write_config(
            tmp_path_factory, rate_limit_storage_uri=f"redis://127.0.0.1:{port}/0"
        )
        app = _make_app(config_path)
        client = app.test_client()

        assert client.get("/health").status_code == 200

        server.shutdown()  # Redis "dies" mid-session

        resp = client.get("/health")
        assert resp.status_code == 503
        assert resp.get_json()["error"] == "rate limiting temporarily unavailable"


class TestCacheReusesRedisClient:
    def test_redis_client_available_for_cache_reuse(self, fake_redis_server, tmp_path_factory):
        """G1's verdict cache reuses this same connection (not a second
        one) -- confirm the client is stored where src/serving/cache.py
        expects to find it."""
        config_path = _write_config(tmp_path_factory, rate_limit_storage_uri=fake_redis_server)
        app = _make_app(config_path)
        client = app.extensions["argus"]["redis_client"]
        client.set("cache-reuse-check", "1")
        assert client.get("cache-reuse-check") == b"1"
