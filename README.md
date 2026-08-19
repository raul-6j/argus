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
| ML       | scikit-learn (Decision Tree, Random Forest, Logistic Regression, SVM), SHAP |
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
  configs/      # model_config.yaml, feature_config.yaml, api_config.yaml, ...
  models/       # Serialized models (git-ignored, Iron Law #5)
  notebooks/    # Jupyter notebooks for EDA
  migrations/   # Alembic schema migrations
  extension/    # MV3 browser extension (Chrome + Firefox, one source tree)
  webapp/       # Public "scan a URL" web app, served at /app/*
  sdk/          # Python + JS clients for the /v1 developer API, plus the CLI
```

> Architecture notes, the decision log, experiment records and the written
> report are kept outside this repository.

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
# A SECRET_KEY is mandatory — the app fails closed without one, by design
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

# Train and evaluate first: the API refuses to start without a model
python scripts/data_prep.py
python scripts/train.py    --config configs/model_config.yaml
python scripts/evaluate.py --config configs/model_config.yaml   # writes models/production/

# Run the API locally
python -m flask --app src/api/app run

# Health check
curl http://127.0.0.1:5000/health

# Run the test suite with coverage
pytest tests/ -v --cov=src --cov-report=html
```

> **Model artefacts are not in this repository.** Serialized models are
> git-ignored on purpose, as are the dataset splits. Until `train.py` and
> `evaluate.py` have been run, `create_app()` will refuse to start and roughly
> a third of the test suite skips itself.

## Database migrations

Schema is managed with Alembic. `create_all()` creates missing *tables* but
never alters an existing one, so a schema change needs a migration or it
silently does nothing and fails later at query time.

```bash
alembic upgrade head      # apply pending migrations
alembic current           # what revision this database is at
alembic upgrade head --sql   # print the SQL without connecting

# After changing a model: register it in src/api/metadata.py FIRST — an
# unregistered model autogenerates as a DROP TABLE — then:
alembic revision --autogenerate -m "describe the change"
```

Always read a generated migration before applying it: autogenerate cannot
detect renames (it emits drop + add, losing data) or data backfills.

## Deployment

```bash
# Production server (never Flask's built-in server)
gunicorn --config gunicorn.conf.py wsgi:application

# Container
docker build -t argus:latest .
docker run --rm -p 5000:5000 -e SECRET_KEY="$(openssl rand -base64 32)" argus:latest
```

Three things to get right in a real deployment:

- **`trusted_proxy_count`** (`configs/api_config.yaml`) must equal the exact
  number of reverse proxies in front of the app. It defaults to `0`. Left at
  `0` behind a proxy, every client shares one rate-limit bucket; set higher
  than reality, clients can forge `X-Forwarded-For` and pick their own bucket.
- **More than one gunicorn worker requires Redis.** Rate-limit counters and
  the verdict cache are per-process, so `memory://` storage silently allows
  N times the configured limit across N workers. See `gunicorn.conf.py`.
- **Run `alembic upgrade head` as a deploy step**, not from the container
  entrypoint — otherwise every replica races the same DDL on startup.

## Continuous integration

`.github/workflows/ci.yml` runs ruff, the test suite across Python 3.9–3.12,
`pip-audit` and `bandit`, the extension's vitest/eslint/web-ext checks, and a
Docker build. The CI job summary reports how many tests were **skipped**,
because a fresh checkout has no model and cannot run the API tests.

## Conventions — Iron Laws

These are referenced by number throughout the codebase (e.g. "Iron Law #5" in
`.gitignore`), so they are recorded here rather than in a contributor's notes:

1. **No `print()` in `src/`** — structured logging only.
2. **No hardcoded paths** — `pathlib.Path` plus config files.
3. **Every feature extractor handles its own exceptions** and returns `None` on
   failure; one bad field never fails a whole extraction.
4. **Every API endpoint returns `latency_ms`** in its JSON response.
5. **Never commit serialized models** (`.pkl`, `.joblib`, `.onnx`).
6. **All ML experiments are reproducible** — `random_state=42` everywhere.
7. **Type hints on all functions**, docstrings on all public functions.
8. **No hardcoded colours, radii, font sizes or spacing** in front-end code —
   use the design tokens in `webapp/style.css` and
   `extension/lib/argus-ui.css`.

## License

Academic project — license TBD.
