"""Time-weighted job progress for analysis profiles.

Percents follow typical Volatility wall time (handles dominates), not
equal-sized feature milestones, so the bar does not jump to ~70% and stall.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

# Relative wall-time on a typical Windows dump. Handles is the slow plugin.
STEP_WEIGHTS: dict[str, float] = {
    "processes": 14,
    "session": 6,
    "command_lines": 7,
    "modules": 10,
    "network": 10,
    "handles": 42,
    "findings": 3,
    "iocs": 3,
    "network_artifacts": 3,
    "timeline": 5,
    "recommended": 10,
    "vad": 8,
}

ProgressFn = Callable[..., None]


def step_ranges(step_ids: list[str]) -> dict[str, tuple[float, float]]:
    weights = [STEP_WEIGHTS.get(sid, 6.0) for sid in step_ids]
    total = sum(weights) or 1.0
    ranges: dict[str, tuple[float, float]] = {}
    acc = 0.0
    for sid, weight in zip(step_ids, weights):
        lo = 100.0 * acc / total
        acc += weight
        hi = 100.0 * acc / total
        ranges[sid] = (lo, hi)
    return ranges


def heartbeat_tau(step_id: str, *, step_count: int) -> float:
    """Expected remaining-time constant for the in-step heartbeat.

    Uses typical step wall time (STEP_WEIGHTS), not the percent span. A
    processes-only job still takes about as long as the processes step of
    Complete Analysis; stretching tau with span=100 made Quick Triage crawl
    to ~10% and then jump to 100.
    """
    weight = STEP_WEIGHTS.get(step_id, 6.0)
    tau = 80.0 + weight * 3.2
    if step_count <= 1:
        return min(tau, 50.0)
    return tau


class AnalysisProgress:
    def __init__(
        self,
        progress: ProgressFn,
        step_ids: list[str],
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        self._progress = progress
        self._cancelled = cancelled
        self.ranges = step_ranges(step_ids)

    def _is_cancelled(self) -> bool:
        check = self._cancelled
        if check is None:
            return False
        try:
            return bool(check())
        except Exception:
            return False

    def emit(self, step_id: str, message: str, *, frac: float = 0.0, done: bool = False) -> None:
        if self._is_cancelled():
            return
        lo, hi = self.ranges.get(step_id, (0.0, 100.0))
        span = max(0.0, hi - lo)
        if done:
            pct = hi if hi < 100 else 100.0
        else:
            clamped = min(max(frac, 0.0), 0.97)
            pct = lo + span * clamped
            if span > 0:
                pct = min(pct, hi - 0.25)
        pct = max(0.0, min(100.0, pct))
        try:
            self._progress(message, {"phase": step_id, "percent": round(pct, 1)})
        except TypeError:
            self._progress(message)

    def bind_message(self, step_id: str) -> ProgressFn:
        """Keep nested progress messages, but stay inside this step's percent range."""

        def wrapped(msg: str, extra: dict[str, Any] | None = None) -> None:
            if self._is_cancelled():
                return
            payload = dict(extra or {})
            payload.pop("percent", None)
            payload["phase"] = step_id
            try:
                self._progress(msg, payload)
            except TypeError:
                self._progress(msg)

        return wrapped

    @contextmanager
    def running(self, step_id: str, message: str) -> Iterator[Callable[[float, str | None], None]]:
        lo, hi = self.ranges.get(step_id, (0.0, 100.0))
        span = max(0.0, hi - lo)
        stop = threading.Event()
        lock = threading.Lock()
        best = [lo]
        last_pub = [0.0]
        started = time.monotonic()
        tau = heartbeat_tau(step_id, step_count=len(self.ranges))

        def publish(frac: float, *, force: bool = False) -> None:
            if self._is_cancelled():
                return
            clamped = min(max(frac, 0.0), 0.97)
            pct = lo + span * clamped
            if span > 0:
                pct = min(pct, hi - 0.25)
            now = time.monotonic()
            with lock:
                if not force and pct < best[0] + 0.3 and now - last_pub[0] < 1.0:
                    return
                if pct < best[0]:
                    return
                best[0] = pct
                last_pub[0] = now
            try:
                self._progress(message, {"phase": step_id, "percent": round(pct, 1)})
            except TypeError:
                self._progress(message)

        def vol_cb(vol_pct: float, description: str | None = None) -> None:
            try:
                value = float(vol_pct)
            except (TypeError, ValueError):
                return
            publish(value / 100.0)

        def heartbeat() -> None:
            while not stop.wait(2.0):
                if self._is_cancelled():
                    return
                elapsed = time.monotonic() - started
                publish(0.97 * (1.0 - math.exp(-elapsed / tau)))

        publish(0.0, force=True)
        thread = threading.Thread(target=heartbeat, name=f"progress-{step_id}", daemon=True)
        thread.start()
        try:
            yield vol_cb
        finally:
            stop.set()
            thread.join(timeout=0.6)
            if not self._is_cancelled():
                self.emit(step_id, message, done=True)
