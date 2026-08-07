# ARGUS production image (F1).
#
#   docker build -t argus:latest .
#   docker run --rm -p 5000:5000 -e SECRET_KEY="$(openssl rand -base64 32)" argus:latest
#
# python:3.10-slim matches the target this project has documented all along
# (requirements.txt's header, and CLAUDE.md's "Docker target"). The CI matrix
# is what actually verifies which interpreters the code runs on -- see
# .github/workflows/ci.yml. The local venv is 3.9, which is also why
# pyproject.toml pins ruff to py39; that pin has a concrete reason recorded in
# the file (SQLAlchemy evaluates Mapped[...] annotations at runtime, so
# `str | None` would raise TypeError on 3.9 even with postponed annotations).
#
# MODEL ARTEFACTS: create_app() refuses to start without
# models/production/model.joblib. Those files are git-ignored (Iron Law #5),
# so they are NOT in a fresh clone. Either build from a checkout where
# scripts/train.py + scripts/evaluate.py have been run, or omit them from the
# image and mount them at runtime:
#   docker run -v "$PWD/models/production:/app/models/production:ro" ...

# --------------------------------------------------------------------------- #
# Stage 1 -- build wheels in a throwaway image that may carry a compiler
# --------------------------------------------------------------------------- #
FROM python:3.10-slim AS builder

# Most dependencies ship manylinux wheels for cp310, but building in a stage
# that HAS a toolchain means a dependency without one degrades to "slower
# build" rather than "build fails". None of this reaches the runtime image.
RUN apt-get update \
    && apt-get install --no-install-recommends -y build-essential \
    && rm -rf /var/lib/apt/lists/*

# A virtualenv rather than --user or --prefix: it is a single self-contained
# directory that the runtime stage can copy wholesale, with no need to match
# site-packages paths between stages.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copied alone, before the source, so the dependency layer is cached and only
# reinstalls when requirements.txt itself changes -- not on every code edit.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# --------------------------------------------------------------------------- #
# Stage 2 -- runtime
# --------------------------------------------------------------------------- #
FROM python:3.10-slim AS runtime

# PYTHONDONTWRITEBYTECODE: the filesystem is read-mostly and .pyc files would
# just be dirty pages. PYTHONUNBUFFERED: without it, logs sit in a pipe buffer
# and a crashed container appears to have logged nothing at all.
# TLDEXTRACT_CACHE: tldextract writes a public-suffix-list cache at import time
# and fails noisily when its default location is not writable -- a documented
# gotcha in this project, and the container runs as a non-root user below.
# (Kept out of the ENV block: a comment inside a line continuation is not
# reliably parsed across Dockerfile frontends.)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    TLDEXTRACT_CACHE=/tmp/tldextract_cache

# curl is for HEALTHCHECK only; no compiler or headers in the runtime image.
RUN apt-get update \
    && apt-get install --no-install-recommends -y curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv

# Non-root. A phishing scanner fetches attacker-controlled pages by design, so
# the process that parses them should own as little as possible.
RUN useradd --create-home --uid 10001 argus
WORKDIR /app

# Ownership set during COPY rather than with a later `chown -R`, which would
# duplicate every file into a second image layer.
COPY --chown=argus:argus configs/ ./configs/
COPY --chown=argus:argus src/ ./src/
COPY --chown=argus:argus webapp/ ./webapp/
COPY --chown=argus:argus data/ ./data/
COPY --chown=argus:argus models/ ./models/
COPY --chown=argus:argus migrations/ ./migrations/
COPY --chown=argus:argus alembic.ini wsgi.py gunicorn.conf.py ./

USER argus
EXPOSE 5000

# Hits the app's real health endpoint, not just a TCP check: this only passes
# once the model has finished loading, so an orchestrator will not route
# traffic to a still-warming instance.
#
# start-period covers model + SHAP explainer load, which is seconds, not
# milliseconds. Note /health reports model_loaded only -- it does not touch
# the database or Redis (audit M-12), so it is a liveness check, not a full
# readiness probe.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD curl -fsS http://127.0.0.1:5000/health || exit 1

# SECRET_KEY is deliberately NOT given a default. src/api/auth/utils.py fails
# closed without it (S6), and baking one in would hand every deployment the
# same signing key -- the failure mode that design exists to prevent.
#
# Schema migrations are NOT run here. A container entrypoint that migrates on
# boot means N replicas racing the same DDL on startup; run
# `alembic upgrade head` as a separate deploy step (the image contains
# migrations/ and alembic.ini so it can).
CMD ["gunicorn", "--config", "gunicorn.conf.py", "wsgi:application"]
