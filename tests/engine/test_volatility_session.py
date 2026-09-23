"""VolatilitySession must raise AppError, never a NameError from a missing import."""

from __future__ import annotations

from pathlib import Path

import pytest

from memscope_engine.errors import AppError, JobCancelled
from memscope_engine.volatility import session as session_mod
from memscope_engine.volatility.cancel import interrupt_on_cancel, raise_if_cancelled
from memscope_engine.volatility.session import VolatilitySession
from memscope_engine.volatility.treegrid import treegrid_to_table


class _Col:
    def __init__(self, name, type_):
        self.name = name
        self.type = type_


class _Node:
    def __init__(self, values, path):
        self.values = values
        self.path = path


class _Grid:
    def __init__(self, columns, nodes):
        self.columns = columns
        self._nodes = nodes

    def populate(self, fn, acc, fail_on_errors=True):
        for node in self._nodes:
            acc = fn(node, acc)
        return None


def test_session_module_exports_app_error() -> None:
    assert getattr(session_mod, "AppError") is AppError


def test_missing_image_raises_app_error(tmp_path: Path) -> None:
    missing = tmp_path / "no-such-image.dmp"
    with pytest.raises(AppError) as exc:
        VolatilitySession(missing)
    assert exc.value.code == "evidence_not_found"
    assert not isinstance(exc.value, NameError)


def test_session_init_applies_volatility_threading(tmp_path: Path) -> None:
    from volatility3.framework import constants

    image = tmp_path / "tiny.dmp"
    image.write_bytes(b"MEMSCOPE-THREADING-SESSION")
    old = constants.PARALLELISM
    try:
        constants.PARALLELISM = constants.Parallelism.Off
        VolatilitySession(image)
        assert constants.PARALLELISM == constants.Parallelism.Threading
        assert constants.PARALLELISM is not constants.Parallelism.Off
        assert constants.PARALLELISM is not constants.Parallelism.Multiprocessing
    finally:
        constants.PARALLELISM = old


def test_treegrid_stops_when_cancelled() -> None:
    visited = []

    class _TrackingGrid(_Grid):
        def populate(self, fn, acc, fail_on_errors=True):
            for node in self._nodes:
                visited.append(node.values[0])
                acc = fn(node, acc)
            return None

    nodes = [_Node([i], ["r"]) for i in range(40)]
    with pytest.raises(AppError) as ei:
        treegrid_to_table(_TrackingGrid([_Col("A", int)], nodes), cancelled=lambda: True)
    assert ei.value.code == "job_cancelled"
    assert visited == [0]


def test_treegrid_cancel_after_partial_populate() -> None:
    class _SlowCancel:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self) -> bool:
            self.calls += 1
            return self.calls >= 2

    nodes = [_Node([i], ["r"]) for i in range(40)]
    with pytest.raises(AppError) as ei:
        treegrid_to_table(_Grid([_Col("A", int)], nodes), cancelled=_SlowCancel())
    assert ei.value.code == "job_cancelled"


def test_job_cancelled_bypasses_volatility_exception_handlers() -> None:
    swallowed = False
    try:
        raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
    except Exception:
        swallowed = True
    assert swallowed

    try:
        try:
            raise JobCancelled()
        except Exception:
            pytest.fail("JobCancelled must not be swallowed as Exception")
    except JobCancelled:
        pass


def test_raise_if_cancelled_does_not_call_checker_on_every_read() -> None:
    from memscope_engine.volatility import cancel as cancel_mod

    n = [0]

    def checker() -> bool:
        n[0] += 1
        return False

    cancel_mod._tls.cancelled = checker
    cancel_mod._tls.fired = False
    cancel_mod._tls.hits = 0
    cancel_mod._tls.last_check = 0.0
    try:
        for _ in range(20_000):
            raise_if_cancelled()
    finally:
        cancel_mod._tls.cancelled = None
        cancel_mod._tls.fired = False
        cancel_mod._tls.hits = 0
        cancel_mod._tls.last_check = 0.0
    # First two hits always check; after that at most ~10/s.
    assert 1 <= n[0] <= 40


def test_raise_if_cancelled_is_visible_to_scan_worker_threads() -> None:
    import threading

    from memscope_engine.errors import JobCancelled

    flag = {"stop": False}
    seen: list[str] = []

    def cancelled() -> bool:
        return flag["stop"]

    def worker() -> None:
        try:
            raise_if_cancelled()
            flag["stop"] = True
            raise_if_cancelled()
        except JobCancelled:
            seen.append("yes")

    with interrupt_on_cancel(cancelled):
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=2)
    assert not thread.is_alive()
    assert seen == ["yes"]


def test_interrupt_on_cancel_converts_to_app_error() -> None:
    with pytest.raises(AppError) as ei:
        with interrupt_on_cancel(lambda: True):
            raise_if_cancelled()
    assert ei.value.code == "job_cancelled"


def test_interrupt_stops_scan_like_loop_immediately() -> None:
    """Volatility scan()/automagic swallow Exception; cancel must still abort."""
    chunks = 0

    def scan_like() -> None:
        nonlocal chunks
        try:
            for _ in range(200):
                raise_if_cancelled()
                chunks += 1
        except Exception:
            return

    with pytest.raises(AppError) as ei:
        with interrupt_on_cancel(lambda: True):
            scan_like()
    assert ei.value.code == "job_cancelled"
    assert chunks == 0


def test_file_layer_read_patch_is_restored() -> None:
    from volatility3.framework.layers.physical import FileLayer

    orig = FileLayer.read
    with interrupt_on_cancel(lambda: False):
        assert FileLayer.read is not orig
    assert FileLayer.read is orig
