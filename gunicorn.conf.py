"""Gunicorn configuration for ARGUS (F1).

    gunicorn --config gunicorn.conf.py wsgi:application

Every value is overridable by environment variable so one image can serve
dev, staging and production without a rebuild (Iron Law #2 — nothing
hardcoded that a deployment needs to change).

Read the WORKERS note below before scaling past one worker: ARGUS has two
pieces of process-local state that make multi-worker deployment a
configuration decision rather than a free win.
"""

from __future__ import annotations

import os

# --------------------------------------------------------------------------- #
# Networking
# --------------------------------------------------------------------------- #
bind = os.environ.get("GUNICORN_BIND", "0.0.0.0:5000")

# --------------------------------------------------------------------------- #
# Workers
#
# WARNING -- more than one worker requires configuration changes, because two
# pieces of ARGUS state are per-process:
#
#   1. Rate limiting. `rate_limit_storage_uri: memory://` (the default) gives
#      EACH worker its own independent counter, so N workers silently allow
#      N times the configured limit. Set it to redis://... before scaling up;
#      create_app() already refuses to boot if that URI is set and Redis is
#      unreachable, so the failure is loud rather than silent.
#
#   2. Caches and pools. The verdict cache falls back to in-process when Redis
#      is absent, and the enrichment/job thread pools are per-worker -- so
#      `enrichment_max_workers` and `async_job_max_workers` are per worker,
#      and the real concurrency ceiling is workers x that value. Size them
#      together, not independently.
#
# Each worker also loads its own copy of the model and SHAP explainer, so
# memory scales linearly with worker count. Defaults to 1 deliberately: the
# safe, correct-by-default choice given the above.
# --------------------------------------------------------------------------- #
workers = int(os.environ.get("GUNICORN_WORKERS", "1"))

# Threads, not extra processes, are the cheaper way to add concurrency here:
# this workload is I/O-bound (outbound page fetches, WHOIS, DNS) and threads
# share the one loaded model rather than duplicating it.
threads = int(os.environ.get("GUNICORN_THREADS", "4"))
worker_class = os.environ.get("GUNICORN_WORKER_CLASS", "gthread")

# --------------------------------------------------------------------------- #
# Timeouts
# --------------------------------------------------------------------------- #
# Must exceed the application's own enrichment ceiling (`enrichment_timeout_s`,
# 15s by default, see src/api/verdict.py) with headroom -- otherwise gunicorn
# kills the worker before the app's own bound can fire and return the honest
# 504 it is designed to produce. Raise both together if either changes.
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "60"))
graceful_timeout = int(os.environ.get("GUNICORN_GRACEFUL_TIMEOUT", "30"))

# Slightly above a typical 60s upstream idle timeout, so the proxy closes
# connections rather than gunicorn racing it.
keepalive = int(os.environ.get("GUNICORN_KEEPALIVE", "65"))

# --------------------------------------------------------------------------- #
# Worker recycling
#
# Bounds the blast radius of any slow memory growth in a long-lived worker.
# The jitter stops every worker from restarting on the same request count and
# briefly dropping capacity to zero.
# --------------------------------------------------------------------------- #
max_requests = int(os.environ.get("GUNICORN_MAX_REQUESTS", "1000"))
max_requests_jitter = int(os.environ.get("GUNICORN_MAX_REQUESTS_JITTER", "100"))

# --------------------------------------------------------------------------- #
# Startup
# --------------------------------------------------------------------------- #
# preload_app is deliberately LEFT OFF. It would load the model once in the
# master and fork, saving memory -- but create_app() registers a SIGHUP
# handler for F7's live threat-intel reload, and gunicorn's master uses SIGHUP
# for its own "reload workers" protocol. Preloading runs create_app() in the
# master process, where that handler would then be installed on top of
# gunicorn's, and `kill -HUP <master>` would do one thing or the other
# depending on registration order. Loading per-worker keeps the two signal
# users in separate processes with no ambiguity.
#
# Consequence to know: `kill -HUP` on the gunicorn MASTER restarts workers
# (which picks up a refreshed threat feed anyway, since each new worker reads
# the snapshot at boot). To use F7's in-place reload instead, signal a worker
# PID directly.
preload_app = False

# --------------------------------------------------------------------------- #
# Logging -- to stdout/stderr, for the container runtime to collect.
# --------------------------------------------------------------------------- #
accesslog = os.environ.get("GUNICORN_ACCESS_LOG", "-")
errorlog = os.environ.get("GUNICORN_ERROR_LOG", "-")
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")

# %({X-Forwarded-For}i)s is logged alongside %(h)s on purpose: behind a proxy
# these differ, and seeing both is how you confirm trusted_proxy_count is set
# correctly (see src/api/app.py::_apply_proxy_fix). If they are identical in
# production, ProxyFix is not doing what you think it is.
access_log_format = (
    '%(h)s fwd=%({X-Forwarded-For}i)s "%(r)s" %(s)s %(b)s %(D)sus "%(a)s"'
)
