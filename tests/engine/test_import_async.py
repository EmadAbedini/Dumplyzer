"""Async memory-image import: streaming hash, job queue, failure cleanup."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

import pytest

from memscope_engine.analysis.workflows import import_evidence, sha256_file
from memscope_engine.errors import AppError
from memscope_engine.jobs.manager import JobManager
from memscope_engine.server import HANDLERS, handle_app_init
from memscope_engine.storage import Database

LARGE_BYTES = 24 * 1024 * 1024


def _write_image(path: Path, nbytes: int) -> None:
    chunk = b"MEMSCOPE-MEMORY-IMAGE-BLOCK" * 32  # 864 bytes
    with path.open("wb") as f:
        written = 0
        while written < nbytes:
            n = min(len(chunk), nbytes - written)
            f.write(chunk[:n])
            written += n


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            block = f.read(1024 * 1024)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _wait_job(job_id: str, timeout: float = 60.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = HANDLERS["jobs.get"]({"job_id": job_id})
        if last["status"] in ("completed", "failed", "cancelled"):
            return last
        time.sleep(0.05)
    raise TimeoutError(f"job {job_id} stuck at {last}")


def test_sha256_streams_large_file(tmp_path: Path) -> None:
    img = tmp_path / "large.raw"
    _write_image(img, LARGE_BYTES)
    progress_events: list[dict] = []

    def progress(msg: str, extra: dict | None = None) -> None:
        progress_events.append({"msg": msg, **(extra or {})})

    digest = sha256_file(img, progress=progress, size=img.stat().st_size)
    assert digest == _sha256(img)
    assert any(e.get("phase") == "hash" for e in progress_events)
    percents = [e["percent"] for e in progress_events if "percent" in e]
    assert percents
    assert percents[-1] == 100 or percents[-1] >= 98


def test_sha256_streams_unaligned_size(tmp_path: Path) -> None:
    img = tmp_path / "odd.raw"
    _write_image(img, (8 * 1024 * 1024) + 17)
    assert sha256_file(img) == _sha256(img)


def test_import_evidence_large_file_registers_once(tmp_path: Path) -> None:
    img = tmp_path / "dump.mem"
    _write_image(img, LARGE_BYTES)
    db = Database(tmp_path / "t.db")
    ev = import_evidence(db, str(img))
    assert ev["size_bytes"] == LARGE_BYTES
    assert ev["sha256"] == _sha256(img)
    again = import_evidence(db, str(img))
    assert again["id"] == ev["id"]
    rows = db.fetchall("SELECT id FROM evidence")
    assert len(rows) == 1
    # Import registers the original path; it must not copy the dump into app data.
    assert Path(ev["path"]).resolve() == img.resolve()
    assert img.is_file()
    db.close()


def test_import_cancel_during_hash_leaves_no_evidence(tmp_path: Path) -> None:
    img = tmp_path / "dump.raw"
    _write_image(img, 4 * 1024 * 1024)
    db = Database(tmp_path / "t.db")
    hits = {"n": 0}

    def cancelled() -> bool:
        hits["n"] += 1
        return hits["n"] > 2

    with pytest.raises(AppError) as exc:
        import_evidence(db, str(img), cancelled=cancelled)
    assert exc.value.code == "job_cancelled"
    assert db.fetchall("SELECT id FROM evidence") == []
    db.close()


def test_import_failure_empty_and_missing_cleanup(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    empty = tmp_path / "empty.raw"
    empty.write_bytes(b"")
    with pytest.raises(AppError) as empty_exc:
        import_evidence(db, str(empty))
    assert empty_exc.value.code == "evidence_empty"

    with pytest.raises(AppError) as missing_exc:
        import_evidence(db, str(tmp_path / "no-such.raw"))
    assert missing_exc.value.code == "evidence_not_found"
    assert db.fetchall("SELECT id FROM evidence") == []
    db.close()


def test_import_job_submit_does_not_block_rpc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """evidence.import must return a queued/running job; health/jobs.get stay responsive."""
    monkeypatch.delenv("MEMSCOPE_DATA_DIR", raising=False)
    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    img = tmp_path / "slow.raw"
    _write_image(img, 1024 * 64)
    gate = {"release": False}
    orig = sha256_file

    def slow_hash(path, *, cancelled=None, progress=None, size=None):
        deadline = time.time() + 2.0
        while time.time() < deadline:
            if cancelled and cancelled():
                raise AppError(code="job_cancelled", message="Import was cancelled.", entity="evidence")
            if progress:
                progress("Hashing memory image", {"phase": "hash", "percent": 10})
            time.sleep(0.05)
        return orig(path, cancelled=cancelled, progress=progress, size=size)

    monkeypatch.setattr("memscope_engine.analysis.workflows.sha256_file", slow_hash)

    t0 = time.perf_counter()
    job = HANDLERS["evidence.import"]({"path": str(img)})
    submit_ms = (time.perf_counter() - t0) * 1000
    assert submit_ms < 1500
    assert job["kind"] == "evidence_import"
    assert job["status"] in ("queued", "running")

    t1 = time.perf_counter()
    health = HANDLERS["health"]({})
    health_ms = (time.perf_counter() - t1) * 1000
    assert health["ok"] is True
    assert health_ms < 500

    t2 = time.perf_counter()
    mid = HANDLERS["jobs.get"]({"job_id": job["id"]})
    get_ms = (time.perf_counter() - t2) * 1000
    assert get_ms < 500
    assert mid["status"] in ("queued", "running", "completed")

    done = _wait_job(job["id"], timeout=15)
    assert done["status"] == "completed"
    evidence = done["result"]["evidence"]
    assert evidence["filename"] == "slow.raw"
    listed = HANDLERS["evidence.list"]({})
    assert any(item["id"] == evidence["id"] for item in listed["items"])
    gate["release"] = True


def test_import_job_cancel_via_handler(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEMSCOPE_DATA_DIR", raising=False)
    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    img = tmp_path / "cancel.raw"
    _write_image(img, 1024 * 32)

    def slow_hash(path, *, cancelled=None, progress=None, size=None):
        for i in range(80):
            if cancelled and cancelled():
                raise AppError(code="job_cancelled", message="Import was cancelled.", entity="evidence")
            if progress:
                progress("Hashing", {"phase": "hash", "percent": i})
            time.sleep(0.05)
        return "0" * 64

    monkeypatch.setattr("memscope_engine.analysis.workflows.sha256_file", slow_hash)
    job = HANDLERS["evidence.import"]({"path": str(img)})
    HANDLERS["jobs.cancel"]({"job_id": job["id"]})
    done = _wait_job(job["id"], timeout=10)
    assert done["status"] == "cancelled"
    listed = HANDLERS["evidence.list"]({})
    assert listed["items"] == []


def test_import_job_rejects_renamed_non_dump(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEMSCOPE_DATA_DIR", raising=False)
    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    fake = tmp_path / "case.dmp"
    fake.write_bytes(b"%PDF-1.4\n% renamed document\n")
    job = HANDLERS["evidence.import"]({"path": str(fake)})
    done = _wait_job(job["id"], timeout=10)
    assert done["status"] == "failed"
    assert done["error"]["code"] == "evidence_not_memory_image"
    assert "not a memory dump" in done["error"]["message"].lower()
    assert HANDLERS["evidence.list"]({})["items"] == []


def test_failed_import_job_leaves_db_usable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEMSCOPE_DATA_DIR", raising=False)
    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    job = HANDLERS["evidence.import"]({"path": str(tmp_path / "missing.mem")})
    done = _wait_job(job["id"], timeout=10)
    assert done["status"] == "failed"
    assert HANDLERS["health"]({})["ok"] is True
    assert HANDLERS["evidence.list"]({})["items"] == []
    good = tmp_path / "ok.raw"
    good.write_bytes(b"MEMSCOPE-TEST-BYTES-0123456789")
    job2 = HANDLERS["evidence.import"]({"path": str(good)})
    done2 = _wait_job(job2["id"], timeout=10)
    assert done2["status"] == "completed"
    assert len(HANDLERS["evidence.list"]({})["items"]) == 1


def test_job_queue_holds_second_job(tmp_path: Path) -> None:
    db = Database(tmp_path / "q.db")
    jobs = JobManager(db)
    running = {"first": False}

    def slow(db_, params, cancelled, progress):
        running["first"] = True
        time.sleep(0.4)
        return {"ok": True}

    jobs.register("slow", slow)
    jobs.start()
    first = jobs.submit("slow", message="one")
    second = jobs.submit("slow", message="two")
    assert second["status"] == "queued"
    deadline = time.time() + 2
    while time.time() < deadline and jobs.get(first["id"])["status"] == "queued":
        time.sleep(0.02)
    assert jobs.get(second["id"])["status"] in ("queued", "running")
    deadline = time.time() + 5
    while time.time() < deadline:
        if jobs.get(first["id"])["status"] == "completed" and jobs.get(second["id"])["status"] == "completed":
            break
        time.sleep(0.05)
    assert jobs.get(first["id"])["status"] == "completed"
    assert jobs.get(second["id"])["status"] == "completed"
    db.close()
