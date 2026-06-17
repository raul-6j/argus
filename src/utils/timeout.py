"""Bounded execution helper.

Runs a blocking callable on a worker thread with a hard wall-clock timeout, so
that libraries without native timeout support (``python-whois``) or slow network
I/O (HTML fetch) can never block a caller indefinitely.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, TypeVar

T = TypeVar("T")


def call_with_timeout(
    func: Callable[..., T], timeout: float, *args: Any, **kwargs: Any
) -> T:
    """Run a blocking callable with a hard wall-clock timeout.

    Uses a single-worker thread pool. On timeout the executor is shut down
    without waiting; the abandoned worker may keep running until its own I/O
    completes, but the caller is not blocked.

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
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(func, *args, **kwargs)
    try:
        return future.result(timeout=timeout)
    finally:
        # wait=False: never block on a hung worker thread.
        executor.shutdown(wait=False)
