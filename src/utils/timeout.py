"""Bounded execution helper.

Runs a blocking callable on a worker thread with a hard wall-clock timeout, so
that libraries without native timeout support (``python-whois``) or slow network
I/O (HTML fetch) can never block a caller indefinitely.

All callers share **one process-wide, bounded** thread pool. An earlier version
created a fresh single-worker ``ThreadPoolExecutor`` per call and, on timeout,
shut it down with ``wait=False`` — explicitly abandoning the worker thread. That
is called on every hot path (``page_artifacts.fetch`` once per redirect hop,
``pipeline._fetch_html``, ``domain_intel``'s WHOIS lookup, ``favicon_match``),
so a burst of scans against slow/hung hosts created an unbounded number of OS
threads that outlived their own requests — CWE-400, resource exhaustion. With a
shared bounded pool, the same burst *queues* instead of allocating threads, and
each caller still gets control back within its own timeout; the load is shed
(every caller already degrades gracefully on ``TimeoutError``) rather than
converted into thread pressure.
"""

from __future__ import annotations

import atexit
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any, Callable, Optional, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Ceiling on how many blocking calls can be *in flight* at once, process-wide.
# Sized above the API's own enrichment concurrency (``enrichment_max_workers``,
# 8 by default) because one enrichment task issues several bounded calls in
# sequence (page fetch per redirect hop, favicon fetch, WHOIS) and
# ``extract_domain_intel_batch`` additionally fans out across its own pool.
# Overridable for a deployment that has tuned those knobs upwards; not read
# from a config file because this module is imported by offline scripts and
# notebooks that never build a Flask app.
_DEFAULT_MAX_WORKERS = 32
_MAX_WORKERS = int(os.environ.get("ARGUS_TIMEOUT_POOL_WORKERS", _DEFAULT_MAX_WORKERS))

_executor: Optional[ThreadPoolExecutor] = None
_executor_lock = threading.Lock()


def _get_executor() -> ThreadPoolExecutor:
    """Return the shared pool, creating it on first use.

    Built lazily (and only once, under a lock) so that merely importing this
    module — which offline scripts and the test collector both do — never
    spawns threads. ``ThreadPoolExecutor`` itself also grows its worker threads
    on demand, so an idle process holds none.
    """
    global _executor
    if _executor is None:
        with _executor_lock:
            if _executor is None:
                _executor = ThreadPoolExecutor(
                    max_workers=_MAX_WORKERS, thread_name_prefix="argus-timeout"
                )
                logger.debug("Started shared timeout pool with %d workers.", _MAX_WORKERS)
    return _executor


def shutdown_timeout_pool(wait: bool = False) -> None:
    """Tear the shared pool down; the next call rebuilds it.

    Registered with :mod:`atexit` so a process exits cleanly instead of
    blocking on a worker still stuck in someone else's socket read. Also
    useful in tests that want to assert the pool is not leaking threads.

    Args:
        wait: Whether to block until in-flight calls finish. Defaults to
            ``False`` — the whole point of this module is that a hung call
            must never block the caller, and that holds at shutdown too.
    """
    global _executor
    with _executor_lock:
        if _executor is not None:
            _executor.shutdown(wait=wait)
            _executor = None


atexit.register(shutdown_timeout_pool)


def call_with_timeout(
    func: Callable[..., T], timeout: float, *args: Any, **kwargs: Any
) -> T:
    """Run a blocking callable with a hard wall-clock timeout.

    Runs on the shared bounded pool. If every worker is busy the call waits in
    the pool's queue, and ``timeout`` bounds *queue wait plus execution* — so a
    saturated pool sheds load (callers time out and degrade) instead of growing
    without limit. On timeout the future is cancelled, which removes it from
    the queue outright if it had not started yet; a call already running is
    abandoned to finish its own I/O, but it occupies a bounded slot rather than
    a freshly-leaked thread.

    Args:
        func: The blocking callable to run.
        timeout: Maximum seconds to wait for a result.
        *args: Positional arguments forwarded to ``func``.
        **kwargs: Keyword arguments forwarded to ``func``.

    Returns:
        The return value of ``func``.

    Raises:
        concurrent.futures.TimeoutError: If ``func`` does not finish in time.
        Exception: Whatever ``func`` raises is propagated.
    """
    future = _get_executor().submit(func, *args, **kwargs)
    try:
        return future.result(timeout=timeout)
    except FuturesTimeoutError:
        # Cancels only if it hasn't started; a queued-but-timed-out call must
        # not later occupy a worker to produce a result nobody is waiting for.
        future.cancel()
        raise
