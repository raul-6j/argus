"""Production WSGI entrypoint (F1).

Used by gunicorn::

    gunicorn --config gunicorn.conf.py wsgi:application

Kept as its own module rather than pointing gunicorn at ``src.api.app``
directly, for one concrete reason: that module already builds an application
at import time (so ``flask --app src/api/app run`` can discover it). Naively
calling ``create_app()`` here would therefore build a *second* one — loading
``model.joblib``, rebuilding the SHAP explainer, re-reading the PhishTank
snapshot and running the warmup prediction all over again, doubling both
startup time and resident memory for an instance nothing would ever serve.
Observed in practice, not hypothesised. So this reuses the instance that
import already produced, and only builds one itself if there wasn't one.

``application`` is gunicorn's default callable name; ``app`` is aliased for
tooling that expects Flask's convention.
"""

from __future__ import annotations

from src.api import app as _app_module

# ``_app_module.app`` is None when the model artefacts are absent, in which
# case create_app() runs and fails loudly with the real reason (a missing
# model file, or S6's missing SECRET_KEY) rather than gunicorn reporting an
# opaque "Failed to find application object".
application = _app_module.app or _app_module.create_app()

# Flask's conventional name, for `flask --app wsgi` and similar tooling.
app = application
