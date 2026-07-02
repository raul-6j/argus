"""Request/response schemas for the Flask API (Phase 6, Task 6.1).

marshmallow schemas validate every request body before it reaches a
blueprint's view function, and shape every response into the exact JSON
contract documented in ``docs/PHASE_GUIDE.md`` Task 6.1.
"""

from __future__ import annotations

from marshmallow import Schema, fields, validate


class DetectRequestSchema(Schema):
    """POST /detect request body: ``{"url": "...", "enrich": false}``."""

    url = fields.Str(required=True, validate=validate.Length(min=1))
    enrich = fields.Bool(load_default=False)


class DetectResponseSchema(Schema):
    """POST /detect response body."""

    url = fields.Str(required=True)
    label = fields.Str(required=True, validate=validate.OneOf(["phishing", "legitimate"]))
    confidence = fields.Float(required=True)
    verdict = fields.Str(required=True, validate=validate.OneOf(["phishing", "legitimate"]))
    source = fields.Str(required=True)
    latency_ms = fields.Float(required=True)


class ExplainRequestSchema(Schema):
    """POST /explain request body: ``{"url": "..."}``."""

    url = fields.Str(required=True, validate=validate.Length(min=1))


class ShapAttributionSchema(Schema):
    """One entry in /explain's top5_features list."""

    feature = fields.Str(required=True)
    shap_value = fields.Float(required=True)
    feature_value = fields.Raw(required=True)


class ExplainResponseSchema(Schema):
    """POST /explain response body."""

    url = fields.Str(required=True)
    top5_features = fields.List(fields.Nested(ShapAttributionSchema), required=True)
    latency_ms = fields.Float(required=True)


class HealthResponseSchema(Schema):
    """GET /health response body."""

    status = fields.Str(required=True)
    model_loaded = fields.Bool(required=True)
    latency_ms = fields.Float(required=True)


class ErrorResponseSchema(Schema):
    """Shape of every 4xx/5xx error body: ``{"error": "..."}``."""

    error = fields.Str(required=True)
