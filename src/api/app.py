"""ARGUS Flask application factory.

Minimal scaffold exposing a /health endpoint. Feature and ML endpoints
(/detect, /explain) are added in later phases as Blueprints.
"""

from __future__ import annotations

import time

from flask import Flask, jsonify


def create_app() -> Flask:
    """Build and configure the ARGUS Flask application.

    Returns:
        A configured :class:`flask.Flask` instance.
    """
    app = Flask(__name__)

    @app.get("/health")
    def health():
        """Liveness probe. Every endpoint returns latency_ms (Iron Law #4)."""
        start = time.perf_counter()
        latency_ms = round((time.perf_counter() - start) * 1000, 3)
        return jsonify(status="ok", service="argus", latency_ms=latency_ms)

    return app


# `flask --app src/api/app run` discovers this module-level instance.
app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
