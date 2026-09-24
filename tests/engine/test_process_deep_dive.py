"""Tests for process deep-dive normalizers, schema v2, and job manager."""

from __future__ import annotations

import time
from pathlib import Path

from memscope_engine.jobs.manager import JobManager
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION
from memscope_engine.volatility.normalize import (
    findings_from_cmdline,
    normalize_cmdline,
    normalize_dlllist,
    normalize_handles,
    normalize_netscan,
    normalize_vadinfo,
)
from memscope_engine.analysis.process_analysis import get_process_deep_dive, list_findings
from memscope_engine.analysis.workflows import import_evidence
from uuid import uuid4


def test_schema_v2(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    assert db.schema_version() == SCHEMA_VERSION
    # tables exist
    db.execute("SELECT COUNT(*) AS c FROM modules")
    db.execute("SELECT COUNT(*) AS c FROM network_connections")
    db.execute("SELECT COUNT(*) AS c FROM handle_entries")
    db.execute("SELECT COUNT(*) AS c FROM memory_regions")
    db.execute("SELECT COUNT(*) AS c FROM findings")
    db.close()


def test_normalize_cmdline_dll_net_handle_vad() -> None:
    cl = normalize_cmdline(
        ["PID", "Process", "Args"],
        [[1234, "notepad.exe", "notepad.exe C:\\a.txt"]],
        pid_filter=1234,
    )
    assert cl[0]["command_line"].startswith("notepad")

    mods = normalize_dlllist(
        ["PID", "Process", "Base", "Size", "Name", "Path", "LoadCount", "LoadTime", "File output"],
        [[1234, "notepad.exe", "0x1000", "0x2000", "ntdll.dll", "C:\\Windows\\System32\\ntdll.dll", 1, None, "Disabled"]],
        evidence_id="e",
        analysis_run_id="a",
        process_id="p",
        pid_filter=1234,
        source_plugin="windows.dlllist",
    )
    assert mods[0]["name"] == "ntdll.dll"

    nets = normalize_netscan(
        ["Offset", "Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID", "Owner", "Created"],
        [["0x1", "TCPv4", "10.0.0.2", 443, "1.2.3.4", 80, "ESTABLISHED", 1234, "notepad.exe", None]],
        evidence_id="e",
        analysis_run_id="a",
        process_id_by_pid={1234: "p"},
        pid_filter=1234,
        source_plugin="windows.netscan",
    )
    assert nets[0]["remote_port"] == 80

    hs = normalize_handles(
        ["PID", "Process", "Offset", "HandleValue", "Type", "GrantedAccess", "Name"],
        [[1234, "notepad.exe", "0x1", "0x4", "File", "0x100", "\\Device\\Harddisk"]],
        evidence_id="e",
        analysis_run_id="a",
        process_id="p",
        pid_filter=1234,
        source_plugin="windows.handles",
    )
    assert hs[0]["handle_type"] == "File"

    vads = normalize_vadinfo(
        ["PID", "Process", "Offset", "Start VPN", "End VPN", "Tag", "Protection", "CommitCharge", "PrivateMemory", "Parent", "File", "File output"],
        [[1234, "notepad.exe", "0x1", "0x1000", "0x2000", "VadS", "PAGE_EXECUTE_READWRITE", 1, 1, None, None, "Disabled"]],
        evidence_id="e",
        analysis_run_id="a",
        process_id="p",
        pid_filter=1234,
        source_plugin="windows.vadinfo",
    )
    assert "EXECUTE" in (vads[0]["protection"] or "").upper()


def test_cmdline_findings_heuristic() -> None:
    fs = findings_from_cmdline(
        evidence_id="e",
        analysis_run_id="a",
        process_id="p",
        pid=1,
        command_line="powershell.exe -EncodedCommand AQID",
    )
    assert any(f["finding_type"] == "encoded_powershell" for f in fs)


def test_job_manager_lifecycle(tmp_path: Path) -> None:
    db = Database(tmp_path / "j.db")
    jm = JobManager(db)

    def handler(_db, params, cancelled, progress):
        progress("working")
        time.sleep(0.05)
        if cancelled():
            return {"cancelled": True}
        return {"ok": True, "n": params.get("n", 0)}

    jm.register("test_job", handler)
    jm.start()
    job = jm.submit("test_job", evidence_id=None, params={"n": 7}, message="test")
    assert job["status"] == "queued"
    # wait for completion
    for _ in range(50):
        j = jm.get(job["id"])
        if j["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.05)
    j = jm.get(job["id"])
    assert j["status"] == "completed"
    assert j["result"]["ok"] is True
    db.close()


def test_process_deep_dive_empty_related(tmp_path: Path) -> None:
    db = Database(tmp_path / "d.db")
    img = tmp_path / "x.raw"
    img.write_bytes(b"abc12345")
    ev = import_evidence(db, str(img))
    run_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, strategy_json
        ) VALUES (?, ?, 'basic_triage', 'completed', '2020-01-01T00:00:00+00:00', 2, '[]')
        """,
        (run_id, ev["id"]),
    )
    pid = str(uuid4())
    db.execute(
        """
        INSERT INTO processes (
          id, evidence_id, analysis_run_id, pid, ppid, name, source_plugin
        ) VALUES (?, ?, ?, 100, 4, 'demo.exe', 'windows.pslist')
        """,
        (pid, ev["id"], run_id),
    )
    dive = get_process_deep_dive(db, pid)
    assert dive["process"]["pid"] == 100
    assert dive["counts"]["modules"] == 0
    assert dive["modules"] == []
    db.close()


def test_list_findings_severity_filter_and_pagination(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    img = tmp_path / "t.raw"
    img.write_bytes(b"findings-page")
    ev = import_evidence(db, str(img))
    now = "2020-01-01T00:00:00+00:00"
    for i, sev in enumerate(("high", "high", "medium", "low", "info", "informational")):
        db.execute(
            """
            INSERT INTO findings (
              id, evidence_id, finding_type, severity, explanation, created_at
            ) VALUES (?, ?, 'encoded_powershell', ?, ?, ?)
            """,
            (str(uuid4()), ev["id"], sev, f"finding {i}", now),
        )
    listed = list_findings(db, ev["id"])
    assert listed["total"] == 6
    assert len(listed["items"]) == 6
    assert listed["severity_counts"]["high"] == 2
    assert listed["severity_counts"]["medium"] == 1
    assert listed["severity_counts"]["low"] == 1
    assert listed["severity_counts"]["info"] == 2
    page = list_findings(db, ev["id"], limit=1, offset=0)
    assert len(page["items"]) == 1
    assert page["total"] == 6
    next_page = list_findings(db, ev["id"], limit=1, offset=1)
    assert len(next_page["items"]) == 1
    assert page["items"][0]["id"] != next_page["items"][0]["id"]
    high = list_findings(db, ev["id"], severity="high")
    assert high["total"] == 2
    assert len(high["items"]) == 2
    assert all(i["severity"] == "high" for i in high["items"])
    info = list_findings(db, ev["id"], severity="info")
    assert info["total"] == 2
    assert {i["severity"] for i in info["items"]} == {"info", "informational"}
    db.close()

