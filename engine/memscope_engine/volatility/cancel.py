"""Interrupt Volatility 3 when a job is cancelled.

Volatility's automagic and layer scanners catch ``Exception`` and keep going.
``JobCancelled`` is a BaseException, and FileLayer.read is patched so cancel
is observed on the next dump access instead of after the current plugin.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from memscope_engine.errors import JobCancelled, job_cancelled_error

_tls = threading.local()
_patch_lock = threading.Lock()
_patch_depth = 0
_orig_file_read: Callable[..., Any] | None = None
_orig_buffer_read: Callable[..., Any] | None = None
# Volatility Threading scan workers do not inherit thread-local cancel state.
_shared_cancelled: Callable[[], bool] | None = None


def raise_if_cancelled() -> None:
    checker = _shared_cancelled
    if checker is None:
        checker = getattr(_tls, "cancelled", None)
    if checker is None:
        return
    if getattr(_tls, "fired", False):
        raise JobCancelled()
    hits = int(getattr(_tls, "hits", 0)) + 1
    _tls.hits = hits
    now = time.monotonic()
    last = float(getattr(_tls, "last_check", 0.0))
    # Time-based only after the first two hits. Checking every N dump reads
    # used to call cancelled() (and Path.exists) hundreds of thousands of times
    # per plugin and stretched Quick Triage / Analyze Process by ~3x.
    if hits > 2 and last > 0 and now - last < 0.1:
        return
    _tls.last_check = now
    try:
        requested = bool(checker())
    except Exception:
        requested = False
    if requested:
        _tls.fired = True
        raise JobCancelled()


def _install_patches() -> None:
    global _patch_depth, _orig_file_read, _orig_buffer_read
    from volatility3.framework.layers.physical import BufferDataLayer, FileLayer

    with _patch_lock:
        if _patch_depth == 0:
            orig_file = FileLayer.read
            orig_buffer = BufferDataLayer.read
            _orig_file_read = orig_file
            _orig_buffer_read = orig_buffer

            def file_read(self: Any, *args: Any, **kwargs: Any) -> Any:
                raise_if_cancelled()
                return orig_file(self, *args, **kwargs)

            def buffer_read(self: Any, *args: Any, **kwargs: Any) -> Any:
                raise_if_cancelled()
                return orig_buffer(self, *args, **kwargs)

            FileLayer.read = file_read  # type: ignore[method-assign]
            BufferDataLayer.read = buffer_read  # type: ignore[method-assign]
        _patch_depth += 1


def _uninstall_patches() -> None:
    global _patch_depth, _orig_file_read, _orig_buffer_read
    from volatility3.framework.layers.physical import BufferDataLayer, FileLayer

    with _patch_lock:
        if _patch_depth <= 0:
            return
        _patch_depth -= 1
        if _patch_depth == 0:
            if _orig_file_read is not None:
                FileLayer.read = _orig_file_read  # type: ignore[method-assign]
            if _orig_buffer_read is not None:
                BufferDataLayer.read = _orig_buffer_read  # type: ignore[method-assign]
            _orig_file_read = None
            _orig_buffer_read = None


@contextmanager
def interrupt_on_cancel(cancelled: Callable[[], bool] | None) -> Iterator[None]:
    """Raise ``AppError(job_cancelled)`` from Volatility dump access when cancelled."""
    if cancelled is None:
        yield
        return
    global _shared_cancelled
    prev = getattr(_tls, "cancelled", None)
    prev_fired = getattr(_tls, "fired", False)
    prev_hits = getattr(_tls, "hits", 0)
    prev_last = getattr(_tls, "last_check", 0.0)
    prev_shared = _shared_cancelled
    _tls.cancelled = cancelled
    _tls.fired = False
    _tls.hits = 0
    _tls.last_check = 0.0
    _shared_cancelled = cancelled
    _install_patches()
    try:
        yield
    except JobCancelled as exc:
        raise job_cancelled_error() from exc
    finally:
        _uninstall_patches()
        _shared_cancelled = prev_shared
        _tls.cancelled = prev
        _tls.fired = prev_fired
        _tls.hits = prev_hits
        _tls.last_check = prev_last
