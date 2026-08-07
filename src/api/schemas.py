"""Request schemas for the Flask API (Phase 6, Task 6.1).

marshmallow schemas validate every request body before it reaches a
blueprint's view function. Response bodies are built directly as dicts
in each view function (see ``docs/PHASE_GUIDE.md`` Task 6.1 for the JSON
contract each one must satisfy).
"""

from __future__ import annotations

from marshmallow import Schema, fields, validate


class DetectRequestSchema(Schema):
    """POST /detect request body: ``{"url": "...", "enrich": false}``."""

    url = fields.Str(required=True, validate=validate.Length(min=1))
    enrich = fields.Bool(load_default=False)


class ExplainRequestSchema(Schema):
    """POST /explain request body: ``{"url": "..."}``."""

    url = fields.Str(required=True, validate=validate.Length(min=1))


# --------------------------------------------------------------------------- #
# Phase 2 — C1 (public scan + shareable report)
# --------------------------------------------------------------------------- #


class ScanRequestSchema(Schema):
    """POST /scan request body: ``{"url": "..."}``. Always a full URL, no
    ``enrich`` flag -- /scan always enriches (see src/api/scan/routes.py)."""

    url = fields.Str(required=True, validate=validate.Length(min=1))


# --------------------------------------------------------------------------- #
# Phase 2 — C3 (developer API /v1/*)
# --------------------------------------------------------------------------- #


class V1ScanRequestSchema(Schema):
    """POST /v1/scan request body: ``{"url": "...", "enrich": true}``."""

    url = fields.Str(required=True, validate=validate.Length(min=1))
    enrich = fields.Bool(load_default=False)


class V1ScanBatchRequestSchema(Schema):
    """POST /v1/scan/batch request body: ``{"urls": [...], "enrich": false}``."""

    urls = fields.List(fields.Str(), required=True, validate=validate.Length(min=1, max=50))
    enrich = fields.Bool(load_default=False)


class V1ExplainRequestSchema(Schema):
    """POST /v1/explain request body: ``{"url": "..."}``."""

    url = fields.Str(required=True, validate=validate.Length(min=1))


class V1ScanAsyncRequestSchema(Schema):
    """POST /v1/scan/async request body:
    ``{"url": "...", "enrich": true, "webhook_url": "..."}`` (F19).

    ``webhook_url`` is optional -- with none, the caller is expected to poll
    ``GET /v1/scan/async/<job_id>`` instead.
    """

    url = fields.Str(required=True, validate=validate.Length(min=1))
    enrich = fields.Bool(load_default=False)
    webhook_url = fields.Str(required=False, load_default=None, validate=validate.Length(min=1))
