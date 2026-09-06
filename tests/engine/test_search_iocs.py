"""Search and IOC extraction unit tests (normalized data only)."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from memscope_engine.analysis.search_iocs import extract_iocs, global_search, list_iocs
from memscope_engine.analysis.workflows import import_evidence
from memscope_engine.storage import Database


def _seed(db: Database, evidence_id: str) -> str:
    run_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, strategy_json
        ) VALUES (?, ?, 'basic_triage', 'completed', '2020-01-01T00:00:00+00:00', 3, '[]')
        """,
        (run_id, evidence_id),
    )
    pid = str(uuid4())
    db.execute(
        """
        INSERT INTO processes (
          id, evidence_id, analysis_run_id, pid, ppid, name, command_line, source_plugin
        ) VALUES (?, ?, ?, 4242, 4, 'powershell.exe',
          'powershell.exe -EncodedCommand AQID http://evil.example.com/a',
          'windows.pslist')
        """,
        (pid, evidence_id, run_id),
    )
    db.execute(
        """
        INSERT INTO network_connections (
          id, evidence_id, analysis_run_id, process_id, pid, protocol,
          local_address, local_port, remote_address, remote_port, state, source_plugin
        ) VALUES (?, ?, ?, ?, 4242, 'TCPv4', '10.0.0.5', 49152, '203.0.113.10', 443, 'ESTABLISHED', 'windows.netscan')
        """,
        (str(uuid4()), evidence_id, run_id, pid),
    )
    return pid


def test_global_search_and_iocs(tmp_path: Path) -> None:
    db = Database(tmp_path / "s.db")
    assert db.schema_version() == 6
    img = tmp_path / "t.raw"
    img.write_bytes(b"search-test")
    ev = import_evidence(db, str(img))
    proc_id = _seed(db, ev["id"])

    res = global_search(db, ev["id"], "powershell")
    assert res["total"] >= 1
    assert any(i["entity"] == "process" for i in res["items"])

    res2 = global_search(db, ev["id"], "203.0.113.10")
    assert any(i["entity"] == "network" for i in res2["items"])

    iocs = extract_iocs(db, ev["id"])
    assert iocs["extracted"] >= 1
    types = {i["ioc_type"] for i in iocs["items"]}
    assert "ipv4" in types or "url" in types or "domain" in types

    listed = list_iocs(db, ev["id"])
    assert listed["total"] == iocs["total"]
    assert any(i.get("process_id") == proc_id or i.get("pid") == 4242 for i in listed["items"])
    db.close()
