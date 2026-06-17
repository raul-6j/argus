# ARGUS

**A**utomated **R**eal-time **G**uard against **U**RL-based **S**cams — a real-time phishing website detection system using machine learning.

Academic final-year project and production-quality portfolio piece.

## Overview

ARGUS extracts features from a URL (lexical, HTML, WHOIS, and network signals),
runs them through a trained ML classifier, and returns a phishing/benign
verdict with an explanation — exposed over a Flask API for real-time use.

## Stack

| Layer    | Technology                          |
|----------|-------------------------------------|
| Language | Python 3.10+                        |
| ML       | scikit-learn, XGBoost, LightGBM, SHAP |
| API      | Flask 3.0 (Blueprints)              |
| DB       | SQLite (dev), PostgreSQL (prod)     |
| Testing  | pytest + coverage                   |
| Deploy   | Docker + Azure Container Apps       |

## Project Structure

```
argus/
  src/
    features/   # Feature extraction modules
    models/     # Model training, evaluation, serialization
    api/        # Flask API (Blueprints: /detect, /health, /explain)
    data/       # Dataset loading and preprocessing
    utils/      # Logging, config, validators
  tests/        # pytest suite (mirrors src/)
  scripts/      # train.py, evaluate.py, data_prep.py
  configs/      # model_config.yaml, feature_config.yaml
  models/       # Serialized models (git-ignored)
  notebooks/    # Jupyter notebooks for EDA
  docs/         # thesis/ chapter drafts
```

## Setup

```bash
# 1. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. tldextract needs its own writable cache dir
export TLDEXTRACT_CACHE=/tmp/tldextract_cache
```

## Usage

```bash
# Run the API locally
python -m flask --app src/api/app run --debug

# Health check
curl http://127.0.0.1:5000/health

# Run the test suite with coverage
pytest tests/ -v --cov=src --cov-report=html
```

> Feature extractors and ML training are implemented in later phases.
> Commands for those (`train.py`, `evaluate.py`, `extractor`) are documented
> in `CLAUDE.md` and become available as the project grows.

## Conventions

This project follows strict "Iron Laws" (see `CLAUDE.md`), including:
structured logging only (no `print()`), `pathlib`-based paths, reproducible
experiments (`random_state=42`), and `latency_ms` in every API response.

## License

Academic project — license TBD.
