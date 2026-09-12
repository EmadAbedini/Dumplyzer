"""Network artifact extraction: provenance, dedup, empty, and job wiring."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from memscope_engine.analysis.network_artifacts import (
    extract_and_store,
    harvest_network_artifacts,
    list_network_artifacts,
    run_network_artifact_job,
)
from memscope_engine.analysis.profiles import FULL_CAPABILITIES, list_profiles
from memscope_engine.analysis.search_iocs import extract_iocs
from memscope_engine.analysis.workflows import import_evidence
from memscope_engine.errors import AppError
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION


def _seed_network(db: Database, evidence_id: str) -> str:
    run_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, strategy_json
        ) VALUES (?, ?, 'basic_triage', 'completed', '2020-01-01T00:00:00+00:00', ?, '[]')
        """,
        (run_id, evidence_id, SCHEMA_VERSION),
    )
    pid = str(uuid4())
    db.execute(
        """
        INSERT INTO processes (
          id, evidence_id, analysis_run_id, pid, ppid, name, command_line, source_plugin
        ) VALUES (?, ?, ?, 4242, 4, 'chrome.exe',
          'chrome.exe http://evil.example.com/a --host 203.0.113.9',
          'windows.pslist')
        """,
        (pid, evidence_id, run_id),
    )
    db.execute(
        """
        INSERT INTO network_connections (
          id, evidence_id, analysis_run_id, process_id, pid, protocol,
          local_address, local_port, remote_address, remote_port, state, offset_hex, source_plugin
        ) VALUES (?, ?, ?, ?, 4242, 'TCPv4', '10.0.0.5', 49152, '203.0.113.10', 443,
          'ESTABLISHED', '0xabc', 'windows.netscan')
        """,
        (str(uuid4()), evidence_id, run_id, pid),
    )
    return pid


def test_schema_includes_network_artifact_tables(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    assert db.schema_version() == SCHEMA_VERSION
    names = {r["name"] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "network_artifacts" in names
    assert "network_artifact_runs" in names
    assert "pcap_reconstructions" in names
    db.close()


def test_profile_catalog_includes_network_artifacts() -> None:
    catalog = list_profiles()
    ids = {c["id"] for c in catalog["capabilities"]}
    assert "network_artifacts" in ids
    assert "network_artifacts" in FULL_CAPABILITIES
    assert "pcap" not in ids


def test_harvest_from_connections_and_cmdline(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    img = tmp_path / "t.raw"
    img.write_bytes(b"network-artifact-seed")
    ev = import_evidence(db, str(img))
    _seed_network(db, ev["id"])
    items = harvest_network_artifacts(db, ev["id"])
    types = {i["artifact_type"] for i in items}
    values = {i["value"] for i in items}
    assert "connection" in types
    assert "ipv4" in types
    assert "tcp_endpoint" in types
    assert "port" in types
    assert "10.0.0.5" in values
    assert "203.0.113.10" in values
    assert "http://evil.example.com/a" in values
    conn = next(i for i in items if i["artifact_type"] == "connection")
    assert conn["source"] == "network_connections"
    assert conn["extraction_method"] == "volatility.netscan"
    assert conn["offset_hex"] == "0xabc"
    assert conn["pid"] == 4242
    db.close()


def test_empty_image_has_no_network_artifacts(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    img = tmp_path / "empty.raw"
    img.write_bytes(b"no-network-here")
    ev = import_evidence(db, str(img))
    result = extract_and_store(db, ev["id"])
    assert result["artifact_count"] == 0
    listed = list_network_artifacts(db, ev["id"])
    assert listed["total"] == 0
    db.close()


def test_dedup_same_connection_ip(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    img = tmp_path / "t.raw"
    img.write_bytes(b"dedup")
    ev = import_evidence(db, str(img))
    _seed_network(db, ev["id"])
    items = harvest_network_artifacts(db, ev["id"])
    ipv4 = [i for i in items if i["artifact_type"] == "ipv4" and i["value"] == "10.0.0.5"]
    assert len(ipv4) == 1
    db.close()


def test_provenance_and_ioc_insert(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    img = tmp_path / "t.raw"
    img.write_bytes(b"prov")
    ev = import_evidence(db, str(img))
    _seed_network(db, ev["id"])
    stored = extract_and_store(db, ev["id"])
    assert stored["artifact_count"] > 0
    listed = list_network_artifacts(db, ev["id"])
    sample = listed["items"][0]
    assert sample["evidence_id"] == ev["id"]
    assert sample["extraction_method"]
    assert sample["source"]
    iocs = db.fetchall(
        "SELECT * FROM iocs WHERE evidence_id = ? AND source = 'network_artifacts'",
        (ev["id"],),
    )
    assert iocs
    db.close()


def test_extract_iocs_keeps_network_artifact_rows(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    img = tmp_path / "t.raw"
    img.write_bytes(b"keep-na")
    ev = import_evidence(db, str(img))
    _seed_network(db, ev["id"])
    extract_and_store(db, ev["id"])
    before = db.fetchall(
        "SELECT value FROM iocs WHERE evidence_id = ? AND source = 'network_artifacts'",
        (ev["id"],),
    )
    extract_iocs(db, ev["id"])
    after = db.fetchall(
        "SELECT value FROM iocs WHERE evidence_id = ? AND source = 'network_artifacts'",
        (ev["id"],),
    )
    assert {r["value"] for r in before} == {r["value"] for r in after}
    db.close()


def test_missing_evidence_and_job(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    with pytest.raises(AppError) as missing:
        harvest_network_artifacts(db, "nope")
    assert missing.value.code == "evidence_missing"
    with pytest.raises(AppError) as required:
        run_network_artifact_job(db, {}, lambda: False, lambda *a, **k: None)
    assert required.value.code == "evidence_required"
    db.close()


def test_job_persists_analysis_run(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    img = tmp_path / "t.raw"
    img.write_bytes(b"job-na")
    ev = import_evidence(db, str(img))
    _seed_network(db, ev["id"])
    percents: list[float] = []

    def progress(msg: str, extra=None) -> None:
        if extra and extra.get("percent") is not None:
            percents.append(float(extra["percent"]))

    result = run_network_artifact_job(
        db,
        {"evidence_id": ev["id"], "job_id": None},
        lambda: False,
        progress,
    )
    assert result["artifact_count"] > 0
    run = db.fetchone(
        "SELECT * FROM analysis_runs WHERE kind = 'network_artifact_extraction'"
    )
    assert run is not None
    assert run["status"] == "completed"
    assert percents
    db.close()


def test_search_finds_network_artifacts(tmp_path: Path) -> None:
    from memscope_engine.analysis.search_iocs import global_search

    db = Database(tmp_path / "t.db")
    img = tmp_path / "t.raw"
    img.write_bytes(b"search-na")
    ev = import_evidence(db, str(img))
    _seed_network(db, ev["id"])
    extract_and_store(db, ev["id"])
    res = global_search(db, ev["id"], "203.0.113.10")
    entities = {i["entity"] for i in res["items"]}
    assert "network_artifact" in entities or "network" in entities
    db.close()
