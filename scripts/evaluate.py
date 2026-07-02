#!/usr/bin/env python3
# scripts/evaluate.py
# CLI entry point for Phase 5, Task 5.2 — evaluate all candidates on the test
# set (touched exactly once) and promote the winner to models/production/.
# Run: python scripts/evaluate.py --config configs/model_config.yaml

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.models.evaluate import main  # noqa: E402

if __name__ == "__main__":
    main()
