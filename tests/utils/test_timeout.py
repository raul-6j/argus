"""Tests for src.utils.timeout — the shared bounded-execution helper.

The behavioural contract (return the value, propagate the exception, raise
``TimeoutError`` when slow) predates the shared-pool change and is asserted
here as a regression guard. The thread-accounting tests are new: the helper
used to create a fresh ``ThreadPoolExecutor`` per call and abandon its worker
on timeout with ``shutdown(wait=False)``, so a burst of calls against hung
hosts leaked OS threads without limit (CWE-400).
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import TimeoutError as FuturesTimeoutError

import pytest

from src.utils import timeout as timeout_module
from src.utils.timeout import call_with_timeout, shutdown_timeout_pool


def _argus_thread_count() -> int:
    return sum(1 for t in threading.enumerate() if t.name.startswith("argus-timeout"))


def _await_no_pool_threads(deadline_s: float = 5.0) -> None:
    """Block until every pool worker has actually exited.

    ``shutdown_timeout_pool()`` deliberately does not join (a hung worker must
    never block the caller), so idle workers exit a moment *after* the call
    returns. Without this wait, the thread-counting assertions below would see
    the previous test's dying workers — every pool generation shares the
    ``argus-timeout`` name prefix — and fail intermittently.
    """
    end = time.perf_counter() + deadline_s
    while _argus_thread_count() and time.perf_counter() < end:
        time.sleep(0.01)


@pytest.fixture(autouse=True)
def _fresh_pool():
    """Give each test a pristine pool, and don't leak workers between tests."""
    shutdown_timeout_pool()
    _await_no_pool_threads()
    yield
    shutdown_timeout_pool()
    _await_no_pool_threads()


class TestBehaviour:
    def test_returns_the_callables_value(self):
        assert call_with_timeout(lambda: 42, 5.0) == 42

    def test_forwards_positional_and_keyword_arguments(self):
        def add(a, b, c=0):
            return a + b + c

        assert call_with_timeout(add, 5.0, 1, 2, c=3) == 6

    def test_propagates_the_callables_exception(self):
        def boom():
            raise ValueError("kaboom")

        with pytest.raises(ValueError, match="kaboom"):
            call_with_timeout(boom, 5.0)

    def test_raises_timeout_error_when_too_slow(self):
        # A blocking Event rather than a long time.sleep: the abandoned worker
        # is released the moment the assertion is done, so this test leaves no
        # straggler thread to skew a later test's thread accounting.
        release = threading.Event()
        try:
            with pytest.raises(FuturesTimeoutError):
                call_with_timeout(release.wait, 0.01)
        finally:
            release.set()

    def test_caller_regains_control_promptly_on_timeout(self):
        """A hung callee must not hold the caller past its own timeout — this
        is the whole reason the module exists."""
        release = threading.Event()
        started = time.perf_counter()
        try:
            with pytest.raises(FuturesTimeoutError):
                call_with_timeout(release.wait, 0.05)
            assert time.perf_counter() - started < 5.0
        finally:
            release.set()


class TestBoundedThreadUsage:
    def test_threads_are_reused_across_calls(self):
        for _ in range(50):
            call_with_timeout(lambda: None, 5.0)
        # A per-call executor would have created 50 threads. These calls are
        # strictly sequential, so the shared pool needs one worker; allow a
        # little slack for the window in which a just-finished worker has not
        # yet flagged itself idle and the pool grows by one.
        assert _argus_thread_count() <= 2

    def test_timed_out_calls_do_not_leak_threads_without_limit(self):
        """The regression this module was rewritten for.

        Each of these calls times out while its worker is still blocked, which
        previously abandoned a whole executor (and its thread) per call.
        """
        release = threading.Event()
        try:
            for _ in range(40):
                with pytest.raises(FuturesTimeoutError):
                    call_with_timeout(release.wait, 0.01)
            assert _argus_thread_count() <= timeout_module._MAX_WORKERS
        finally:
            release.set()

    def test_queued_calls_are_cancelled_on_timeout(self):
        """A call that times out while still queued must not later occupy a
        worker to compute a result nobody is waiting for."""
        release = threading.Event()
        ran = threading.Event()

        # Saturate every worker so the call below can only ever be queued.
        blockers = [
            timeout_module._get_executor().submit(release.wait)
            for _ in range(timeout_module._MAX_WORKERS)
        ]
        try:
            with pytest.raises(FuturesTimeoutError):
                call_with_timeout(ran.set, 0.05)
            release.set()
            for future in blockers:
                future.result(timeout=5.0)
            time.sleep(0.05)
            assert not ran.is_set()
        finally:
            release.set()


class TestPoolLifecycle:
    def test_pool_is_created_lazily(self):
        assert timeout_module._executor is None
        call_with_timeout(lambda: None, 5.0)
        assert timeout_module._executor is not None

    def test_shutdown_is_idempotent_and_the_pool_rebuilds(self):
        call_with_timeout(lambda: None, 5.0)
        shutdown_timeout_pool()
        shutdown_timeout_pool()
        assert timeout_module._executor is None
        assert call_with_timeout(lambda: 7, 5.0) == 7
