"""Tests for VAD indicators, timeline, artifacts, and safe paths."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from memscope_engine.analysis.memory_artifacts import (
    build_timeline,
    enrich_region,
    get_artifact,
    list_artifacts,
    list_memory_regions,
    region_indicators,
)
from memscope_engine.analysis.workflows import import_evidence
from memscope_engine.artifacts import store as artifact_store
from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths
from memscope_engine.storage import Database
import pytest


def test_schema_v4(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    assert db.schema_version() == 7
    db.execute("SELECT COUNT(*) AS c FROM artifacts")
    db.execute("SELECT COUNT(*) AS c FROM timeline_events")
    db.close()


def test_region_indicators_rwx_and_private() -> None:
    r = {
        "protection": "PAGE_EXECUTE_READWRITE",
        "private_memory": 1,
        "file_path": None,
        "tag": "VadS",
        "size_bytes": 4096,
        "start_vpn": "0x1000",
        "end_vpn": "0x2000",
    }
    flags = region_indicators(r)
    codes = {f["code"] for f in flags}
    assert "writable_executable" in codes
    assert "private_executable_unbacked" in codes
    # never claim malware
    assert all("malicious" not in f["label"].lower() for f in flags)

    enriched = enrich_region(
        {
            "start_vpn": "0x1000",
            "end_vpn": "0x3000",
            "protection": "PAGE_READONLY",
            "private_memory": 0,
            "file_path": "C:\\Windows\\System32\\ntdll.dll",
            "tag": "Vad ",
        }
    )
    assert enriched["size_bytes"] == 0x2000
    assert enriched["indicators"] == []


def test_artifact_paths_and_hash(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    eid = str(uuid4())
    d = artifact_store.artifact_dir(paths, eid)
    assert d.is_dir()
    name = artifact_store.build_artifact_filename(
        pid=123, start_vpn="0x1000", end_vpn="0x2000"
    )
    assert "123" in name and name.endswith(".dmp")
    f = d / name
    f.write_bytes(b"MZ\x90\x00" + b"\x00" * 32)
    digest = artifact_store.sha256_file(f)
    assert len(digest) == 64
    assert artifact_store.sniff_file_type(f) == "pe"
    # escape attempt
    with pytest.raises(AppError):
        artifact_store.ensure_within_artifacts(paths, tmp_path / "outside.bin")


def test_timeline_and_artifact_provenance(tmp_path: Path) -> None:
    db = Database(tmp_path / "db.db")
    paths = AppPaths(tmp_path / "data").ensure()
    img = tmp_path / "img.raw"
    img.write_bytes(b"timeline-fixture")
    ev = import_evidence(db, str(img))
    run_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, strategy_json
        ) VALUES (?, ?, 'basic_triage', 'completed', '2020-01-01T00:00:00+00:00', 4, '[]')
        """,
        (run_id, ev["id"]),
    )
    proc_id = str(uuid4())
    db.execute(
        """
        INSERT INTO processes (
          id, evidence_id, analysis_run_id, pid, ppid, name, create_time, source_plugin
        ) VALUES (?, ?, ?, 99, 4, 'demo.exe', '2020-01-02T03:04:05', 'windows.pslist')
        """,
        (proc_id, ev["id"], run_id),
    )
    region_id = str(uuid4())
    db.execute(
        """
        INSERT INTO memory_regions (
          id, evidence_id, analysis_run_id, process_id, pid, start_vpn, end_vpn,
          protection, private_memory, source_plugin, size_bytes, indicators_json
        ) VALUES (?, ?, ?, ?, 99, '0x1000', '0x2000', 'PAGE_EXECUTE_READWRITE', 1,
          'windows.vadinfo', 4096, ?)
        """,
        (
            region_id,
            ev["id"],
            run_id,
            proc_id,
            '[{"code":"writable_executable","label":"W+X","detail":"test"}]',
        ),
    )

    # controlled artifact file
    adir = artifact_store.artifact_dir(paths, ev["id"])
    apath = adir / "pid.99.vad.x1000-x2000.dmp"
    apath.write_bytes(b"\x00" * 16)
    digest = artifact_store.sha256_file(apath)
    art_id = str(uuid4())
    db.execute(
        """
        INSERT INTO artifacts (
          id, evidence_id, process_id, pid, memory_region_id, filename, stored_path,
          sha256, size_bytes, file_type, extraction_method, source_plugin, tool_name,
          tool_version, start_vpn, end_vpn, extracted_at, notes, metadata_json
        ) VALUES (?, ?, ?, 99, ?, ?, ?, ?, 16, 'raw', 'volatility3.windows.vadinfo.vad_dump',
          'windows.vadinfo', 'volatility3', '2.28.0', '0x1000', '0x2000',
          '2020-01-03T00:00:00+00:00', 'test', '{}')
        """,
        (
            art_id,
            ev["id"],
            proc_id,
            region_id,
            apath.name,
            str(apath),
            digest,
        ),
    )

    tl = build_timeline(db, ev["id"])
    kinds = {e["event_kind"] for e in tl["items"]}
    assert "process_create" in kinds
    assert "process_relationship" in kinds
    assert "artifact_extraction" in kinds
    # process create has observed time
    pc = next(e for e in tl["items"] if e["event_kind"] == "process_create")
    assert pc["classification"] == "observed"
    assert pc["event_time"] == "2020-01-02T03:04:05"

    mem = list_memory_regions(db, ev["id"], pid=99)
    assert mem["returned"] == 1
    assert mem["items"][0]["indicators"]

    art = get_artifact(db, art_id)
    assert art["sha256"] == digest
    steps = [s["step"] for s in art["provenance_chain"]]
    assert steps == ["evidence", "process", "memory_region", "artifact"]
    assert list_artifacts(db, ev["id"])["total"] == 1
    db.close()
