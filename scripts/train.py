#!/usr/bin/env python3
# scripts/train.py
# CLI entry point for Phase 5, Task 5.2 — train the DT/RF/LR/SVM comparison.
# Run: python scripts/train.py --config configs/model_config.yaml

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.models.train import main  # noqa: E402

if __name__ == "__main__":
    main()
