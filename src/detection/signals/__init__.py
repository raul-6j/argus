"""Individual deterministic detection signals (Phase 1: A1, A2, A3).

Each module exposes a single ``evaluate(...)`` function returning a
:class:`src.detection.types.RiskSignal`, never raising (Iron Law #3).
Combined by :func:`src.detection.run_detection` and
:func:`src.detection.fusion.fuse`.
"""
