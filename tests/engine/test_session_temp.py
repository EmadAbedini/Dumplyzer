"""Session temp cleanup must not touch evidence, exports, or analysis results."""

from __future__ import annotations

from pathlib import Path

from memscope_engine.analysis.workflows import import_evidence
from memscope_engine.paths import AppPaths
from memscope_engine.server import HANDLERS, handle_app_init, handle_app_shutdown
from memscope_engine.session_temp import cleanup_session_temp
from memscope_engine.storage import Database


def test_import_does_not_copy_evidence_into_data_dir(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "original.dmp"
    img.write_bytes(b"X" * 1024)
    ev = import_evidence(db, str(img))
    assert Path(ev["path"]).resolve() == img.resolve()
    assert img.is_file()
    copied = [
        p
        for p in paths.root.rglob("*")
        if p.is_file() and p.stat().st_size == img.stat().st_size and p.resolve() != img.resolve()
        and p.read_bytes() == img.read_bytes()
    ]
    assert copied == []
    db.close()


def test_cleanup_session_temp_removes_tmp_keeps_exports_and_evidence(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    evidence = tmp_path / "SYSADMIN.dmp"
    evidence.write_bytes(b"ORIGINAL-EVIDENCE")
    scratch = paths.tmp / "plugin_files" / "job1"
    scratch.mkdir(parents=True)
    (scratch / "volat.tmp").write_bytes(b"working")
    dumpfiles = paths.analysis / "pe_extraction" / "run1" / "_dumpfiles_tmp"
    dumpfiles.mkdir(parents=True)
    (dumpfiles / "raw.bin").write_bytes(b"scratch")
    kept_pe = paths.analysis / "pe_extraction" / "run1" / "kept.pe"
    kept_pe.write_bytes(b"pe")
    export = paths.exports / "report.html"
    export.write_text("keep", encoding="utf-8")
    artifact = paths.artifacts / "eid" / "extracted.bin"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"artifact")

    result = cleanup_session_temp(paths)
    assert result["tmp_entries_removed"] >= 1
    assert not (paths.tmp / "plugin_files").exists()
    assert paths.tmp.is_dir()
    assert not dumpfiles.exists()
    assert kept_pe.is_file()
    assert export.is_file()
    assert artifact.is_file()
    assert evidence.is_file()
    assert evidence.read_bytes() == b"ORIGINAL-EVIDENCE"


def test_app_init_and_shutdown_clear_tmp(tmp_path: Path) -> None:
    data = tmp_path / "ipc"
    handle_app_init({"data_dir": str(data)})
    paths = AppPaths(data)
    leftover = paths.tmp / "stale.bin"
    leftover.write_bytes(b"stale")
    dumpfiles = paths.analysis / "pe_extraction" / "r" / "_dumpfiles_tmp"
    dumpfiles.mkdir(parents=True)
    (dumpfiles / "x.bin").write_bytes(b"x")
    closed = handle_app_shutdown({})
    assert closed["ok"] is True
    assert not leftover.exists()
    assert not dumpfiles.exists()
    assert paths.tmp.is_dir()
    # Re-init also clears crash leftovers.
    leftover.write_bytes(b"stale-again")
    handle_app_init({"data_dir": str(data)})
    assert not leftover.exists()
    assert HANDLERS["app.shutdown"]({})["ok"] is True
