"""Cooperative cancellation helpers for long-running scans."""

from __future__ import annotations

import signal
from contextlib import contextmanager


class ScanCancelled(Exception):
    """Raised when a scan stops after a cooperative cancellation request."""

    def __init__(self, results):
        super().__init__("Scan cancelled.")
        self.results = dict(results)


class CancellationToken:
    """Small signal-safe flag shared between the CLI and scan workers."""

    def __init__(self):
        self._cancelled = False

    @property
    def cancelled(self):
        return self._cancelled

    def cancel(self):
        self._cancelled = True


@contextmanager
def capture_sigint(token):
    """Turn the first SIGINT into cooperative cancellation.

    A repeated SIGINT is delegated to the previous handler so users can still
    force an immediate shutdown if a request does not finish promptly.
    """
    try:
        previous_handler = signal.getsignal(signal.SIGINT)
        signal.signal(
            signal.SIGINT,
            _make_sigint_handler(token, previous_handler),
        )
    except (AttributeError, OSError, ValueError):
        # Signal handlers can only be installed from the main thread and are
        # not available in every Python runtime. Scanning still works; the
        # platform's normal interrupt behaviour remains in control.
        yield token
        return

    try:
        yield token
    finally:
        try:
            signal.signal(signal.SIGINT, previous_handler)
        except (AttributeError, OSError, ValueError):
            pass


def _make_sigint_handler(token, previous_handler):
    def handle_sigint(signum, frame):
        if not token.cancelled:
            token.cancel()
            return

        if callable(previous_handler):
            previous_handler(signum, frame)
            return

        raise KeyboardInterrupt

    return handle_sigint
