"""Serves the self-contained public web app (Phase 2, C1) at ``/app/*``.

Plain static file serving — the webapp has no build step (no bundler,
no CDN dependencies), consistent with the browser extension's own
"no build step needed" MV3 design. Kept as its own tiny blueprint rather
than Flask's default ``/static`` route so the webapp's URL namespace
(``/app/...``) stays clearly distinct from any future internal static
assets.
"""

from __future__ import annotations

from pathlib import Path

from flask import Blueprint, send_from_directory

_WEBAPP_DIR = Path(__file__).resolve().parents[2] / "webapp"

webapp_bp = Blueprint("webapp", __name__, url_prefix="/app")


@webapp_bp.get("/")
@webapp_bp.get("/index.html")
def index():
    return send_from_directory(_WEBAPP_DIR, "index.html")


@webapp_bp.get("/<path:filename>")
def static_file(filename: str):
    return send_from_directory(_WEBAPP_DIR, filename)
