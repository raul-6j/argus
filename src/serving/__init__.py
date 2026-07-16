"""Model-serving optimizations (Phase 2, G1): optional ONNX inference and a
short-TTL verdict cache. Both are opt-in via ``configs/model_config.yaml``
(``serving.backend``) / ``configs/api_config.yaml`` (``cache.enabled``) --
absent config reproduces the exact pre-Phase-2 sklearn-only, uncached
behavior.
"""
