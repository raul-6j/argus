"""Tests for the two request-ingress hardening controls in ``create_app()``:
``MAX_CONTENT_LENGTH`` (CWE-770) and proxy-aware client addressing (ProxyFix).

Both need apps built with specific config, so each fixture makes its own
rather than using the shared session app — same pattern as
``tests/api/test_rate_limit.py``. Probe routes are registered inside the
fixtures: Flask refuses ``@app.route`` once an app has handled a request.
"""

from __future__ import annotations

import json

import pytest
import yaml
from flask import request
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from src.api.app import _apply_proxy_fix
from tests.api.conftest import _MODEL_PATH, PROJECT_ROOT


def _build_app(tmp_path_factory, name: str, remove: tuple[str, ...] = (), **overrides):
    if not _MODEL_PATH.is_file():
        pytest.skip("Run scripts/train.py + scripts/evaluate.py first — no trained model available.")

    api_config = yaml.safe_load((PROJECT_ROOT / "configs" / "api_config.yaml").open())
    api_config["database_url"] = "sqlite:///:memory:"
    api_config["rate_limit"] = "10000 per minute"
    api_config.update(overrides)
    for key in remove:
        api_config.pop(key, None)

    config_path = tmp_path_factory.mktemp(name) / "api_config.yaml"
    config_path.write_text(yaml.safe_dump(api_config))

    from src.api.app import create_app

    return create_app(config_path=str(config_path))


def _add_probe_routes(app):
    """Register the introspection routes the assertions below need."""

    @app.route("/_probe/addr")
    def _addr():
        # get_remote_address is flask-limiter's own key function — reporting it
        # here asserts the thing that actually matters (which bucket a request
        # is limited under), not just request.remote_addr.
        return {
            "addr": request.remote_addr,
            "scheme": request.scheme,
            "limiter_key": get_remote_address(),
        }

    @app.route("/_probe/body", methods=["POST"])
    def _body():
        return {"len": len(request.get_data())}

    return app


# --------------------------------------------------------------------------- #
# MAX_CONTENT_LENGTH
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def small_body_app(tmp_path_factory):
    return _add_probe_routes(
        _build_app(tmp_path_factory, "body_limit", max_content_length_bytes=2048)
    )


@pytest.fixture
def small_body_client(small_body_app):
    return small_body_app.test_client()


def test_body_limit_is_configured_on_the_app(small_body_app):
    assert small_body_app.config["MAX_CONTENT_LENGTH"] == 2048


def test_default_body_limit_applies_when_the_config_omits_it(tmp_path_factory):
    """A deployment whose api_config.yaml predates this setting must still get
    a bound rather than Flask's unlimited default."""
    from src.api.app import _DEFAULT_MAX_CONTENT_LENGTH

    app = _build_app(
        tmp_path_factory, "body_limit_default", remove=("max_content_length_bytes",)
    )
    assert _DEFAULT_MAX_CONTENT_LENGTH == 1024 * 1024
    assert app.config["MAX_CONTENT_LENGTH"] == _DEFAULT_MAX_CONTENT_LENGTH


def test_oversize_body_is_rejected_with_413(small_body_client):
    oversize = json.dumps({"url": "https://example.com/" + "a" * 4096})
    response = small_body_client.post(
        "/detect", data=oversize, content_type="application/json"
    )
    assert response.status_code == 413


def test_413_response_is_json_shaped(small_body_client):
    """Every other error path in this API returns JSON; so must this one, or a
    programmatic client gets Werkzeug's HTML page instead."""
    oversize = json.dumps({"url": "https://example.com/" + "a" * 4096})
    response = small_body_client.post(
        "/detect", data=oversize, content_type="application/json"
    )
    assert response.is_json
    assert "error" in response.get_json()


def test_normal_sized_body_still_works(small_body_client):
    response = small_body_client.post("/detect", json={"url": "https://example.com"})
    assert response.status_code == 200


def test_oversize_body_is_never_read_into_memory(small_body_client):
    """The point of the limit. Werkzeug checks Content-Length when the request
    stream is first opened and raises before reading a byte, so the view's own
    ``get_data()`` aborts rather than returning a buffered 4 KiB payload."""
    response = small_body_client.post(
        "/_probe/body", data="a" * 4096, content_type="application/json"
    )
    assert response.status_code == 413
    assert response.get_json().get("len") is None


def test_body_under_the_limit_reaches_the_view_intact(small_body_client):
    response = small_body_client.post(
        "/_probe/body", data="a" * 100, content_type="application/json"
    )
    assert response.status_code == 200
    assert response.get_json()["len"] == 100


def test_oversize_body_on_an_authenticated_endpoint_is_refused(small_body_client):
    """Enforced when the body is *read*, not before routing — so an
    unauthenticated caller hits ``@require_auth``'s 401 first. Either way the
    request is refused and the body is never read; assert that rather than
    over-claiming a specific status code."""
    oversize = json.dumps({"ciphertext": "a" * 4096, "version": 0})
    response = small_body_client.put(
        "/vault", data=oversize, content_type="application/json"
    )
    assert response.status_code in (401, 413)


# --------------------------------------------------------------------------- #
# ProxyFix
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def direct_app(tmp_path_factory):
    return _add_probe_routes(
        _build_app(tmp_path_factory, "proxy_off", trusted_proxy_count=0)
    )


@pytest.fixture(scope="module")
def proxied_app(tmp_path_factory):
    return _add_probe_routes(
        _build_app(tmp_path_factory, "proxy_on", trusted_proxy_count=1)
    )


def test_forwarded_headers_are_ignored_by_default(direct_app):
    """The default must be "trust nothing": enabling ProxyFix without a real
    proxy in front lets any client spoof X-Forwarded-For and choose its own
    rate-limit identity."""
    response = direct_app.test_client().get(
        "/_probe/addr", headers={"X-Forwarded-For": "9.9.9.9"}
    )
    assert response.get_json()["addr"] != "9.9.9.9"


def test_proxy_fix_honours_forwarded_headers_when_enabled(proxied_app):
    response = proxied_app.test_client().get(
        "/_probe/addr",
        headers={"X-Forwarded-For": "203.0.113.7", "X-Forwarded-Proto": "https"},
    )
    body = response.get_json()
    assert body["addr"] == "203.0.113.7"
    assert body["scheme"] == "https"


def test_proxy_fix_trusts_only_the_configured_hop_count(proxied_app):
    """With one trusted proxy, a client that prepends forged entries must not
    get to pick which address it is seen as: ProxyFix takes the last entry —
    the one the real proxy appended — not the client-controlled prefix."""
    response = proxied_app.test_client().get(
        "/_probe/addr", headers={"X-Forwarded-For": "1.1.1.1, 2.2.2.2, 203.0.113.7"}
    )
    assert response.get_json()["addr"] == "203.0.113.7"


def test_rate_limiting_distinguishes_clients_behind_a_proxy(proxied_app, direct_app):
    """Why this matters: flask-limiter keys its per-IP buckets on
    ``get_remote_address()``. Without ProxyFix every client behind the proxy
    resolves to the proxy's own address and shares a single bucket — one noisy
    caller then rate-limits everyone, and the 10/min login limit stops being a
    brute-force control."""
    client = proxied_app.test_client()
    first = client.get("/_probe/addr", headers={"X-Forwarded-For": "198.51.100.4"})
    second = client.get("/_probe/addr", headers={"X-Forwarded-For": "198.51.100.9"})
    assert first.get_json()["limiter_key"] == "198.51.100.4"
    assert second.get_json()["limiter_key"] == "198.51.100.9"

    # Same two callers against a non-proxy-aware app collapse into one bucket.
    unaware = direct_app.test_client()
    third = unaware.get("/_probe/addr", headers={"X-Forwarded-For": "198.51.100.4"})
    fourth = unaware.get("/_probe/addr", headers={"X-Forwarded-For": "198.51.100.9"})
    assert third.get_json()["limiter_key"] == fourth.get_json()["limiter_key"]


def test_apply_proxy_fix_rejects_a_negative_count():
    from flask import Flask

    with pytest.raises(ValueError):
        _apply_proxy_fix(Flask(__name__), -1)


def test_apply_proxy_fix_wraps_only_when_enabled():
    from flask import Flask

    app = Flask(__name__)
    _apply_proxy_fix(app, 0)
    # Identity comparison would be useless: Flask.wsgi_app is a method, so each
    # attribute access yields a fresh bound-method object.
    assert not isinstance(app.wsgi_app, ProxyFix)

    _apply_proxy_fix(app, 1)
    assert isinstance(app.wsgi_app, ProxyFix)
