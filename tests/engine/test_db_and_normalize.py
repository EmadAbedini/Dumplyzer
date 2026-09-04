"""Database migration and evidence import tests (no memory dump required)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from memscope_engine.analysis.workflows import import_evidence, list_processes, overview
from memscope_engine.paths import AppPaths
from memscope_engine.storage import Database
from memscope_engine.volatility.normalize import normalize_pslist, normalize_windows_info


def test_schema_migrates_to_v1(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    assert db.schema_version() == 4
    db.close()


def test_import_evidence_hashes(tmp_path: Path) -> None:
    img = tmp_path / "sample.raw"
    img.write_bytes(b"MEMSCOPE-TEST-BYTES-0123456789")
    db = Database(tmp_path / "t.db")
    ev = import_evidence(db, str(img))
    assert ev["filename"] == "sample.raw"
    assert ev["size_bytes"] == img.stat().st_size
    assert len(ev["sha256"]) == 64
    again = import_evidence(db, str(img))
    assert again["id"] == ev["id"]
    ov = overview(db, ev["id"])
    assert ov["process_count"] == 0
    procs = list_processes(db, ev["id"])
    assert procs["total"] == 0
    db.close()


def test_normalize_windows_info_fields() -> None:
    cols = ["Variable", "Value"]
    rows = [
        ["Is64Bit", "True"],
        ["NtMajorVersion", "10"],
        ["NtMinorVersion", "0"],
        ["NtProductType", "WinNT"],
        ["Symbols", "file:///symbols/ntkrnlmp.pdb/..."],
    ]
    meta = normalize_windows_info(cols, rows)
    assert meta["architecture"] == "x64"
    assert meta["symbol_status"] == "resolved"
    assert meta["detected_os"] is not None
    assert "10" in meta["detected_os"]


def test_normalize_pslist_rows() -> None:
    cols = [
        "PID",
        "PPID",
        "ImageFileName",
        "Offset(V)",
        "Threads",
        "Handles",
        "SessionId",
        "Wow64",
        "CreateTime",
        "ExitTime",
        "File output",
    ]
    rows = [
        [4, 0, "System", "0x1234", 100, 0, 0, False, None, None, "Disabled"],
        [100, 4, "smss.exe", "0xabcd", 2, 40, 0, False, "2020-01-01T00:00:00", None, "Disabled"],
    ]
    out = normalize_pslist(
        cols,
        rows,
        evidence_id="e1",
        analysis_run_id="a1",
        source_plugin="windows.pslist",
    )
    assert len(out) == 2
    assert out[0]["pid"] == 4
    assert out[1]["name"] == "smss.exe"
    assert out[1]["ppid"] == 4


def test_app_paths_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MEMSCOPE_DATA_DIR", str(tmp_path / "data"))
    paths = AppPaths().ensure()
    assert paths.root == (tmp_path / "data").resolve()
    assert paths.db_path.exists() is False  # only dirs ensured
    assert paths.logs.is_dir()
