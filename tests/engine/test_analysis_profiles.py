"""Analysis profiles: mapping, persistence, Select All / Full Analysis."""

from __future__ import annotations

import json
import time
from pathlib import Path
from uuid import uuid4

import pytest

from memscope_engine.analysis import profiles, process_analysis
from memscope_engine.analysis.profiles import (
    EVIDENCE_IDS,
    FULL_CAPABILITIES,
    RECOMMENDED_CAPABILITIES,
    list_profiles,
    resolve_selection,
    run_analysis_profile_job,
)
from memscope_engine.analysis.workflows import import_evidence, overview
from memscope_engine.errors import AppError
from memscope_engine.server import HANDLERS, handle_app_init
from memscope_engine.storage import Database


def _import(tmp_path: Path) -> tuple[Database, dict]:
    img = tmp_path / "sample.raw"
    img.write_bytes(b"MEMSCOPE-TEST-BYTES-0123456789")
    db = Database(tmp_path / "t.db")
    ev = import_evidence(db, str(img))
    return db, ev


def test_list_profiles_matches_implemented_capabilities() -> None:
    catalog = list_profiles()
    ids = {c["id"] for c in catalog["capabilities"]}
    assert set(EVIDENCE_IDS) <= ids
    labels = {c["label"] for c in catalog["capabilities"]}
    assert "Processes" in labels
    assert "Network Connections" in labels
    assert "Modules / DLLs" in labels
    assert "IOC Extraction" in labels
    full = next(p for p in catalog["profiles"] if p["id"] == "full")
    assert full["capabilities"] == list(FULL_CAPABILITIES)
    assert "pe_extraction" not in full["capabilities"]
    assert "bulk_extractor" not in full["capabilities"]
    assert "complete supported Dumplyzer analysis workflow" in catalog["full_analysis"]
    assert "PE reconstruction" in catalog["full_analysis"]
    assert "Run them from Carved Data" in catalog["full_analysis"]
    assert "Extracted files" in labels
    assert "Carved artifacts" in labels
    assert catalog["select_all_evidence"] == list(EVIDENCE_IDS)


def test_resolve_full_recommended_custom_and_empty() -> None:
    full = resolve_selection("full")
    assert full["profile"] == "full"
    assert full["capabilities"] == list(FULL_CAPABILITIES)
    rec = resolve_selection("recommended")
    assert rec["capabilities"] == list(RECOMMENDED_CAPABILITIES)
    custom = resolve_selection("custom", ["processes", "network", "processes"])
    assert custom["profile"] == "custom"
    assert custom["capabilities"] == ["processes", "network"]
    with pytest.raises(AppError) as empty:
        resolve_selection("custom", [])
    assert empty.value.code == "empty_selection"
    with pytest.raises(AppError) as unknown:
        resolve_selection("mystery")
    assert unknown.value.code == "invalid_profile"


def test_select_all_and_clear_all_semantics() -> None:
    catalog = list_profiles()
    select_all = catalog["select_all_evidence"]
    assert select_all == list(EVIDENCE_IDS)
    assert set(select_all) == set(c["id"] for c in catalog["capabilities"] if c["scope"] == "evidence")
    with pytest.raises(AppError):
        resolve_selection("custom", [])


def test_full_analysis_is_defined_profile_not_checkbox_union() -> None:
    full = resolve_selection("full", selected=["artifacts", "memory_vad"])
    assert "artifacts" not in full["capabilities"]
    assert full["capabilities"] == list(FULL_CAPABILITIES)


def _fake_triage(db: Database, params, cancelled, progress):
    progress("fake triage")
    run_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at, error_json,
          volatility_version, schema_version, notes, process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'basic_triage', 'completed', datetime('now'), datetime('now'), NULL, 'test', 9, 'fake', NULL, NULL, NULL, '[]')
        """,
        (run_id, params["evidence_id"]),
    )
    return {"analysis_run_id": run_id, "process_count": 0}


class _FakeSession:
    volatility_version = "test-vol"

    def __init__(self, path) -> None:  # noqa: ANN001
        self.path = path


def test_analysis_run_persists_full_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db, ev = _import(tmp_path)
    monkeypatch.setattr(process_analysis, "run_basic_triage_job", _fake_triage)
    monkeypatch.setattr(profiles, "VolatilitySession", _FakeSession)
    monkeypatch.setattr(
        profiles,
        "_run_cmdline",
        lambda *a, **k: {"id": "command_lines", "status": "completed", "rows": 0},
    )
    monkeypatch.setattr(
        profiles, "_run_dlllist", lambda *a, **k: {"id": "modules", "status": "completed", "rows": 0}
    )
    monkeypatch.setattr(
        profiles, "_run_netscan", lambda *a, **k: {"id": "network", "status": "completed", "rows": 0}
    )
    monkeypatch.setattr(
        profiles, "_run_handles", lambda *a, **k: {"id": "handles", "status": "completed", "rows": 0}
    )

    result = run_analysis_profile_job(
        db,
        {"evidence_id": ev["id"], "profile": "full", "job_id": None},
        lambda: False,
        lambda *a, **k: None,
    )
    assert result["profile"] == "full"
    assert result["capabilities"] == list(FULL_CAPABILITIES)
    row = db.fetchone("SELECT * FROM analysis_runs WHERE id = ?", (result["analysis_run_id"],))
    assert row is not None
    assert row["kind"] == "analysis_profile"
    assert row["status"] == "completed"
    strategy = json.loads(row["strategy_json"])
    assert strategy["profile"] == "full"
    assert strategy["capabilities"] == list(FULL_CAPABILITIES)
    items = overview(db, ev["id"])["coverage"]["items"]
    for cid in FULL_CAPABILITIES:
        if cid == "command_lines":
            assert items[cid]["state"] == "not_analyzed", cid
            assert items[cid]["count"] is None
            continue
        assert items[cid]["state"] == "analyzed_zero", cid
        assert items[cid]["count"] == 0
    assert items["memory_vad"]["state"] == "not_analyzed"
    assert items["artifacts"]["state"] == "not_analyzed"
    assert items["recommended"]["state"] == "not_analyzed"
    db.close()


def test_full_profile_progress_includes_live_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db, ev = _import(tmp_path)
    monkeypatch.setattr(process_analysis, "run_basic_triage_job", _fake_triage)
    monkeypatch.setattr(profiles, "VolatilitySession", _FakeSession)
    monkeypatch.setattr(
        profiles,
        "_run_cmdline",
        lambda *a, **k: {"id": "command_lines", "status": "completed", "rows": 0},
    )
    monkeypatch.setattr(
        profiles, "_run_dlllist", lambda *a, **k: {"id": "modules", "status": "completed", "rows": 0}
    )
    monkeypatch.setattr(
        profiles, "_run_netscan", lambda *a, **k: {"id": "network", "status": "completed", "rows": 0}
    )
    monkeypatch.setattr(
        profiles, "_run_handles", lambda *a, **k: {"id": "handles", "status": "completed", "rows": 0}
    )
    extras: list[dict] = []

    def progress(_msg: str, extra=None) -> None:
        extras.append(dict(extra or {}))

    run_analysis_profile_job(
        db,
        {"evidence_id": ev["id"], "profile": "full", "job_id": None},
        lambda: False,
        progress,
    )
    covered = [e["coverage"] for e in extras if e.get("coverage")]
    assert covered
    last = covered[-1]
    assert "processes" in last["items"]
    assert last["items"]["processes"]["state"] in ("analyzed", "analyzed_zero")
    db.close()


def test_dlllist_cancel_does_not_persist_or_swallow(tmp_path: Path) -> None:
    db, ev = _import(tmp_path)
    run_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, notes
        ) VALUES (?, ?, 'analysis_profile', 'running', datetime('now'), 9, 'test')
        """,
        (run_id, ev["id"]),
    )
    pe = process_analysis._record_plugin_start(
        db, run_id=run_id, evidence_id=ev["id"], plugin="windows.dlllist", parameters={}
    )
    with pytest.raises(AppError) as ei:
        profiles._finish_plugin_error(
            db,
            pe,
            AppError(code="job_cancelled", message="Job was cancelled.", entity="job"),
            "modules",
        )
    assert ei.value.code == "job_cancelled"
    counted = db.fetchone(
        "SELECT COUNT(*) AS c FROM modules WHERE evidence_id = ?", (ev["id"],)
    )
    assert counted is not None and int(counted["c"] or 0) == 0
    row = db.fetchone("SELECT status FROM plugin_executions WHERE id = ?", (pe,))
    assert row is not None and row["status"] == "cancelled"
    db.close()


def test_custom_selected_analysis_persists(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db, ev = _import(tmp_path)
    monkeypatch.setattr(process_analysis, "run_basic_triage_job", _fake_triage)
    result = run_analysis_profile_job(
        db,
        {
            "evidence_id": ev["id"],
            "profile": "custom",
            "capabilities": ["processes", "iocs", "timeline"],
            "job_id": None,
        },
        lambda: False,
        lambda *a, **k: None,
    )
    row = db.fetchone("SELECT * FROM analysis_runs WHERE id = ?", (result["analysis_run_id"],))
    strategy = json.loads(row["strategy_json"])
    assert strategy["profile"] == "custom"
    assert strategy["capabilities"] == ["processes", "iocs", "timeline"]
    assert result["skipped"] == []
    db.close()


def test_rerun_resets_stale_coverage_counts(tmp_path: Path) -> None:
    from memscope_engine.analysis.coverage import coverage_for_evidence

    db, ev = _import(tmp_path)
    old_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at,
          schema_version, notes, strategy_json
        ) VALUES (?, ?, 'analysis_profile', 'completed', datetime('now'), datetime('now'), 9, 'old', ?)
        """,
        (
            old_id,
            ev["id"],
            json.dumps(
                {
                    "profile": "full",
                    "capabilities": ["processes", "modules", "network"],
                    "evidence_capabilities": ["processes", "modules", "network"],
                    "steps": [
                        {"id": "processes", "status": "completed"},
                        {"id": "modules", "status": "completed"},
                        {"id": "network", "status": "completed"},
                    ],
                }
            ),
        ),
    )
    proc_id = str(uuid4())
    db.execute(
        """
        INSERT INTO processes (
          id, evidence_id, analysis_run_id, pid, ppid, name, username,
          image_path, command_line, create_time, exit_time, offset_hex,
          threads, handles, session_id, wow64, source_plugin
        ) VALUES (?, ?, ?, 4, 0, 'System', NULL, NULL, NULL, NULL, NULL, '0x1', 1, 1, 0, 0, 'windows.pslist')
        """,
        (proc_id, ev["id"], old_id),
    )
    db.execute(
        """
        INSERT INTO modules (
          id, evidence_id, analysis_run_id, process_id, pid, name, path,
          base_address, size, load_count, load_time, source_plugin
        ) VALUES (?, ?, ?, ?, 4, 'ntdll.dll', 'C:\\ntdll.dll', '0x1', '100', 1, NULL, 'windows.dlllist')
        """,
        (str(uuid4()), ev["id"], old_id, proc_id),
    )
    db.execute(
        """
        INSERT INTO network_connections (
          id, evidence_id, analysis_run_id, process_id, pid, protocol,
          local_address, local_port, remote_address, remote_port, state, owner,
          created, offset_hex, source_plugin
        ) VALUES (?, ?, ?, ?, 4, 'TCP', '1.1.1.1', 1, '2.2.2.2', 2, 'ESTABLISHED', NULL, NULL, '0x2', 'windows.netscan')
        """,
        (str(uuid4()), ev["id"], old_id, proc_id),
    )
    before = coverage_for_evidence(db, ev["id"])["items"]
    assert before["processes"]["state"] == "analyzed"
    assert before["processes"]["count"] == 1
    assert before["modules"]["count"] == 1
    assert before["network"]["count"] == 1

    running_id = str(uuid4())
    rerun_strategy = {
        "profile": "full",
        "capabilities": ["processes", "modules", "network"],
        "evidence_capabilities": ["processes", "modules", "network"],
        "steps": [],
    }
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, notes, strategy_json
        ) VALUES (?, ?, 'analysis_profile', 'running', datetime('now'), 9, 'rerun', ?)
        """,
        (running_id, ev["id"], json.dumps(rerun_strategy)),
    )
    profiles._reset_capability_results(db, ev["id"], ["processes", "modules", "network"])
    mid = coverage_for_evidence(db, ev["id"])["items"]
    assert mid["processes"]["state"] == "not_analyzed"
    assert mid["processes"]["count"] == 0
    assert mid["modules"]["state"] == "not_analyzed"
    assert mid["modules"]["count"] == 0
    assert mid["network"]["count"] == 0

    db.execute(
        """
        INSERT INTO processes (
          id, evidence_id, analysis_run_id, pid, ppid, name, username,
          image_path, command_line, create_time, exit_time, offset_hex,
          threads, handles, session_id, wow64, source_plugin
        ) VALUES (?, ?, ?, 4, 0, 'System', NULL, NULL, NULL, NULL, NULL, '0x1', 1, 1, 0, 0, 'windows.pslist')
        """,
        (str(uuid4()), ev["id"], running_id),
    )
    rerun_strategy["steps"] = [{"id": "processes", "status": "completed"}]
    db.execute(
        "UPDATE analysis_runs SET strategy_json = ? WHERE id = ?",
        (json.dumps(rerun_strategy), running_id),
    )
    after = coverage_for_evidence(db, ev["id"])["items"]
    assert after["processes"]["state"] == "analyzed"
    assert after["processes"]["count"] == 1
    assert after["modules"]["state"] == "not_analyzed"
    assert after["modules"]["count"] == 0
    db.close()


def test_process_scoped_skipped_without_pid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db, ev = _import(tmp_path)
    monkeypatch.setattr(process_analysis, "run_basic_triage_job", _fake_triage)
    result = run_analysis_profile_job(
        db,
        {
            "evidence_id": ev["id"],
            "profile": "custom",
            "capabilities": ["processes", "memory_vad", "artifacts"],
            "job_id": None,
        },
        lambda: False,
        lambda *a, **k: None,
    )
    skipped_ids = {s["id"] for s in result["skipped"]}
    assert skipped_ids == {"memory_vad", "artifacts"}
    db.close()


def test_analysis_run_handler_queues_job(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEMSCOPE_DATA_DIR", raising=False)
    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    img = tmp_path / "sample.raw"
    img.write_bytes(b"MEMSCOPE-TEST-BYTES-0123456789")
    imported = HANDLERS["evidence.import"]({"path": str(img)})
    deadline = time.time() + 10
    done = imported
    while time.time() < deadline:
        done = HANDLERS["jobs.get"]({"job_id": imported["id"]})
        if done["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)
    assert done["status"] == "completed"
    evidence_id = done["result"]["evidence"]["id"]

    catalog = HANDLERS["analysis.profiles"]({})
    assert catalog["profiles"][0]["id"] == "full"

    monkeypatch.setattr(process_analysis, "run_basic_triage_job", _fake_triage)
    job = HANDLERS["analysis.run"](
        {"evidence_id": evidence_id, "profile": "recommended", "capabilities": []}
    )
    assert job["kind"] == "analysis_profile"
    assert job["status"] in ("queued", "running", "completed")
    deadline = time.time() + 10
    while time.time() < deadline:
        job = HANDLERS["jobs.get"]({"job_id": job["id"]})
        if job["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.05)
    assert job["status"] == "completed"
    assert job["analysis_run_id"]
    ov = HANDLERS["overview.get"]({"evidence_id": evidence_id})
    kinds = [r["kind"] for r in ov["recent_runs"]]
    assert "analysis_profile" in kinds
    run = next(r for r in ov["recent_runs"] if r["kind"] == "analysis_profile")
    assert run["status"] == "completed"


def test_analysis_run_rejects_empty_custom_before_queue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MEMSCOPE_DATA_DIR", raising=False)
    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    img = tmp_path / "sample.raw"
    img.write_bytes(b"MEMSCOPE-TEST-BYTES-0123456789")
    imported = HANDLERS["evidence.import"]({"path": str(img)})
    deadline = time.time() + 10
    done = imported
    while time.time() < deadline:
        done = HANDLERS["jobs.get"]({"job_id": imported["id"]})
        if done["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)
    evidence_id = done["result"]["evidence"]["id"]
    with pytest.raises(AppError) as exc:
        HANDLERS["analysis.run"](
            {"evidence_id": evidence_id, "profile": "custom", "capabilities": []}
        )
    assert exc.value.code == "empty_selection"


def test_unexpected_error_marks_analysis_run_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db, ev = _import(tmp_path)

    def boom(*_a, **_k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(process_analysis, "run_basic_triage_job", boom)
    with pytest.raises(RuntimeError, match="kaboom"):
        run_analysis_profile_job(
            db,
            {"evidence_id": ev["id"], "profile": "recommended", "job_id": None},
            lambda: False,
            lambda *_a, **_k: None,
        )
    row = db.fetchone(
        "SELECT status, error_json FROM analysis_runs WHERE kind = 'analysis_profile'"
    )
    assert row is not None
    assert row["status"] == "failed"
    err = json.loads(row["error_json"])
    assert err["code"] == "analysis_profile_failed"
    assert "RuntimeError: kaboom" in err["details"]
    db.close()


def test_overview_coverage_import_is_not_analyzed(tmp_path: Path) -> None:
    db, ev = _import(tmp_path)
    items = overview(db, ev["id"])["coverage"]["items"]
    assert items["processes"]["state"] == "not_analyzed"
    assert items["network"]["state"] == "not_analyzed"
    assert items["modules"]["state"] == "not_analyzed"
    assert items["findings"]["state"] == "not_analyzed"
    assert items["iocs"]["state"] == "not_analyzed"
    db.close()


def test_overview_coverage_recommended_only_processes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db, ev = _import(tmp_path)
    monkeypatch.setattr(process_analysis, "run_basic_triage_job", _fake_triage)
    run_analysis_profile_job(
        db,
        {"evidence_id": ev["id"], "profile": "recommended", "job_id": None},
        lambda: False,
        lambda *_a, **_k: None,
    )
    items = overview(db, ev["id"])["coverage"]["items"]
    assert items["processes"]["state"] == "analyzed_zero"
    assert items["processes"]["count"] == 0
    assert items["command_lines"]["state"] == "not_analyzed"
    assert items["network"]["state"] == "not_analyzed"
    assert items["modules"]["state"] == "not_analyzed"
    assert items["findings"]["state"] == "not_analyzed"
    assert items["iocs"]["state"] == "not_analyzed"
    assert items["timeline"]["state"] == "not_analyzed"
    db.close()


def test_overview_coverage_custom_subset_and_zero_iocs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db, ev = _import(tmp_path)
    monkeypatch.setattr(process_analysis, "run_basic_triage_job", _fake_triage)
    run_analysis_profile_job(
        db,
        {
            "evidence_id": ev["id"],
            "profile": "custom",
            "capabilities": ["processes", "iocs"],
            "job_id": None,
        },
        lambda: False,
        lambda *_a, **_k: None,
    )
    items = overview(db, ev["id"])["coverage"]["items"]
    assert items["processes"]["state"] == "analyzed_zero"
    assert items["iocs"]["state"] == "analyzed_zero"
    assert items["network"]["state"] == "not_analyzed"
    assert items["modules"]["state"] == "not_analyzed"
    db.close()


def test_overview_coverage_failed_plugin_step_not_counted_as_analyzed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db, ev = _import(tmp_path)
    monkeypatch.setattr(process_analysis, "run_basic_triage_job", _fake_triage)

    def failed_net(*_a, **_k):
        return {"id": "network", "status": "failed", "error": "unsatisfied"}

    monkeypatch.setattr(profiles, "VolatilitySession", _FakeSession)
    monkeypatch.setattr(profiles, "_run_netscan", failed_net)
    run_analysis_profile_job(
        db,
        {
            "evidence_id": ev["id"],
            "profile": "custom",
            "capabilities": ["processes", "network"],
            "job_id": None,
        },
        lambda: False,
        lambda *_a, **_k: None,
    )
    items = overview(db, ev["id"])["coverage"]["items"]
    assert items["processes"]["state"] == "analyzed_zero"
    assert items["network"]["state"] == "failed"
    db.close()


def test_cancelled_profile_does_not_mark_modules_failed(tmp_path: Path) -> None:
    from memscope_engine.analysis.coverage import coverage_for_evidence

    db, ev = _import(tmp_path)
    old_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at,
          schema_version, notes, strategy_json
        ) VALUES (?, ?, 'analysis_profile', 'completed', datetime('now'), datetime('now'), 9, 'old', ?)
        """,
        (
            old_id,
            ev["id"],
            json.dumps(
                {
                    "profile": "full",
                    "evidence_capabilities": ["processes", "modules"],
                    "steps": [
                        {"id": "processes", "status": "completed"},
                        {"id": "modules", "status": "completed"},
                    ],
                }
            ),
        ),
    )
    cancelled_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at,
          schema_version, notes, strategy_json
        ) VALUES (?, ?, 'analysis_profile', 'cancelled', datetime('now'), datetime('now'), 9, 'cancel', ?)
        """,
        (
            cancelled_id,
            ev["id"],
            json.dumps(
                {
                    "profile": "full",
                    "evidence_capabilities": ["processes", "modules"],
                    "steps": [
                        {"id": "processes", "status": "completed"},
                        {"id": "modules", "status": "failed", "error": "Job was cancelled."},
                    ],
                }
            ),
        ),
    )
    items = coverage_for_evidence(db, ev["id"])["items"]
    assert items["modules"]["state"] == "not_analyzed"
    assert items["modules"]["count"] is None
    assert items["processes"]["state"] in ("analyzed", "analyzed_zero")
    db.close()


def test_overview_coverage_live_rows_show_count_before_executed(tmp_path: Path) -> None:
    db, ev = _import(tmp_path)
    run_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at, error_json,
          volatility_version, schema_version, notes, process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'analysis_profile', 'running', datetime('now'), NULL, NULL, NULL, 9, 'live', NULL, NULL, NULL, '{}')
        """,
        (run_id, ev["id"]),
    )
    db.execute(
        """
        INSERT INTO processes (
          id, evidence_id, analysis_run_id, pid, ppid, name, username,
          image_path, command_line, create_time, exit_time, offset_hex,
          threads, handles, session_id, wow64, source_plugin
        ) VALUES (?, ?, ?, 4, 0, 'test.exe', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'windows.pslist')
        """,
        (str(uuid4()), ev["id"], run_id),
    )
    items = overview(db, ev["id"])["coverage"]["items"]
    assert items["processes"]["state"] == "not_analyzed"
    assert items["processes"]["count"] == 1
    assert items["modules"]["state"] == "not_analyzed"
    assert items["modules"]["count"] is None
    db.close()


def test_nested_triage_keeps_full_analysis_pending(tmp_path: Path) -> None:
    """Complete Analysis nested windows.pslist must not hide Findings/Timeline as skipped."""
    from memscope_engine.analysis.coverage import coverage_for_evidence

    db, ev = _import(tmp_path)
    profile_id = str(uuid4())
    strategy = {
        "profile": "full",
        "capabilities": list(FULL_CAPABILITIES),
        "evidence_capabilities": list(FULL_CAPABILITIES),
        "steps": [{"id": "processes", "status": "completed"}],
    }
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at, error_json,
          volatility_version, schema_version, notes, process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'analysis_profile', 'running', datetime('now'), NULL, NULL, NULL, 9, 'full', NULL, NULL, NULL, ?)
        """,
        (profile_id, ev["id"], json.dumps(strategy)),
    )
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at, error_json,
          volatility_version, schema_version, notes, process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'basic_triage', 'completed', datetime('now', '+1 second'), datetime('now', '+1 second'), NULL, 'test', 9, 'nested', NULL, NULL, NULL, '[]')
        """,
        (str(uuid4()), ev["id"]),
    )
    items = coverage_for_evidence(db, ev["id"])["items"]
    assert items["processes"]["state"] in ("analyzed", "analyzed_zero")
    for cid in ("findings", "iocs", "timeline", "modules", "network", "handles", "network_artifacts"):
        assert items[cid]["state"] == "not_analyzed", cid
        assert items[cid]["count"] == 0, cid
    db.close()


def test_recommended_running_does_not_mark_unselected_pending(tmp_path: Path) -> None:
    from memscope_engine.analysis.coverage import coverage_for_evidence

    db, ev = _import(tmp_path)
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at, error_json,
          volatility_version, schema_version, notes, process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'analysis_profile', 'running', datetime('now'), NULL, NULL, NULL, 9, 'rec', NULL, NULL, NULL, ?)
        """,
        (
            str(uuid4()),
            ev["id"],
            json.dumps(
                {
                    "profile": "recommended",
                    "capabilities": list(RECOMMENDED_CAPABILITIES),
                    "evidence_capabilities": list(RECOMMENDED_CAPABILITIES),
                    "steps": [],
                }
            ),
        ),
    )
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at, error_json,
          volatility_version, schema_version, notes, process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'basic_triage', 'running', datetime('now', '+1 second'), NULL, NULL, NULL, 9, 'nested', NULL, NULL, NULL, '[]')
        """,
        (str(uuid4()), ev["id"]),
    )
    items = coverage_for_evidence(db, ev["id"])["items"]
    assert items["processes"]["count"] == 0
    assert items["findings"]["count"] is None
    assert items["timeline"]["count"] is None
    assert items["iocs"]["count"] is None
    db.close()


def test_reimport_same_hash_clears_previous_analysis(tmp_path: Path) -> None:
    db, ev = _import(tmp_path)
    img = Path(ev["path"])
    run_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at, error_json,
          volatility_version, schema_version, notes, process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'basic_triage', 'completed', datetime('now'), datetime('now'), NULL, 'test', 9, 'prev', NULL, NULL, NULL, '[]')
        """,
        (run_id, ev["id"]),
    )
    db.execute(
        """
        INSERT INTO processes (
          id, evidence_id, analysis_run_id, pid, ppid, name, username,
          image_path, command_line, create_time, exit_time, offset_hex,
          threads, handles, session_id, wow64, source_plugin
        ) VALUES (?, ?, ?, 4, 0, 'test.exe', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'windows.pslist')
        """,
        (str(uuid4()), ev["id"], run_id),
    )
    items = overview(db, ev["id"])["coverage"]["items"]
    assert items["processes"]["state"] == "analyzed"
    assert items["processes"]["count"] == 1
    again = import_evidence(db, str(img))
    assert again["id"] == ev["id"]
    assert again["symbol_status"] == "unknown"
    assert again["detected_os"] is None
    items = overview(db, again["id"])["coverage"]["items"]
    assert items["processes"]["state"] == "not_analyzed"
    assert items["processes"]["count"] is None
    assert overview(db, again["id"])["process_count"] == 0
    db.close()


def test_overview_coverage_stale_rows_hidden_without_running_job(tmp_path: Path) -> None:
    db, ev = _import(tmp_path)
    run_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at, error_json,
          volatility_version, schema_version, notes, process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'analysis_profile', 'completed', datetime('now'), datetime('now'), NULL, NULL, 9, 'stale', NULL, NULL, NULL, '{}')
        """,
        (run_id, ev["id"]),
    )
    db.execute(
        """
        INSERT INTO processes (
          id, evidence_id, analysis_run_id, pid, ppid, name, username,
          image_path, command_line, create_time, exit_time, offset_hex,
          threads, handles, session_id, wow64, source_plugin
        ) VALUES (?, ?, ?, 8, 0, 'stale.exe', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'windows.pslist')
        """,
        (str(uuid4()), ev["id"], run_id),
    )
    items = overview(db, ev["id"])["coverage"]["items"]
    assert items["processes"]["state"] == "not_analyzed"
    assert items["processes"]["count"] is None
    db.close()


def test_process_recommended_running_spins_process_caps_not_iocs(tmp_path: Path) -> None:
    from memscope_engine.analysis.coverage import coverage_for_evidence

    db, ev = _import(tmp_path)
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at, error_json,
          volatility_version, schema_version, notes, process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'process_recommended', 'running', datetime('now'), NULL, NULL, NULL, 9, 'pid 4', NULL, 4, NULL, '[]')
        """,
        (str(uuid4()), ev["id"]),
    )
    items = coverage_for_evidence(db, ev["id"])["items"]
    assert items["modules"]["state"] == "not_analyzed"
    assert items["modules"]["count"] == 0
    assert items["modules"]["updating"] is True
    assert items["network"]["updating"] is True
    assert items["memory_vad"]["updating"] is True
    assert items["iocs"]["count"] is None
    assert items["iocs"]["updating"] is False
    assert items["timeline"]["count"] is None
    assert items["artifacts"]["updating"] is False
    db.close()


def test_process_recommended_completed_keeps_module_counts(tmp_path: Path) -> None:
    from memscope_engine.analysis.coverage import coverage_for_evidence

    db, ev = _import(tmp_path)
    run_id = str(uuid4())
    proc_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at, error_json,
          volatility_version, schema_version, notes, process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'process_recommended', 'completed', datetime('now'), datetime('now'), NULL, NULL, 9, 'pid 4', ?, 4, NULL, '[]')
        """,
        (run_id, ev["id"], proc_id),
    )
    db.execute(
        """
        INSERT INTO processes (
          id, evidence_id, analysis_run_id, pid, ppid, name, username,
          image_path, command_line, create_time, exit_time, offset_hex,
          threads, handles, session_id, wow64, source_plugin
        ) VALUES (?, ?, ?, 4, 0, 'test.exe', NULL, NULL, 'whoami', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'windows.pslist')
        """,
        (proc_id, ev["id"], run_id),
    )
    db.execute(
        """
        INSERT INTO modules (
          id, evidence_id, analysis_run_id, process_id, pid, name, path,
          base_address, size, load_count, load_time, source_plugin
        ) VALUES (?, ?, ?, ?, 4, 'ntdll.dll', 'C:\\ntdll.dll', '0x1', '100', 1, NULL, 'windows.dlllist')
        """,
        (str(uuid4()), ev["id"], run_id, proc_id),
    )
    items = coverage_for_evidence(db, ev["id"])["items"]
    assert items["modules"]["state"] == "not_analyzed"
    assert items["modules"]["count"] == 1
    assert items["modules"]["updating"] is False
    assert items["command_lines"]["state"] == "not_analyzed"
    assert items["command_lines"]["count"] == 1
    assert items["iocs"]["count"] is None
    db.close()


def test_signatures_coverage_sums_both_yara_tabs(tmp_path: Path) -> None:
    from memscope_engine.analysis.coverage import coverage_for_evidence

    db, ev = _import(tmp_path)
    items = coverage_for_evidence(db, ev["id"])["items"]
    assert items["signatures"]["state"] == "not_analyzed"
    assert items["signatures"]["count"] is None

    db.execute(
        """
        INSERT INTO yara_scans (
          id, evidence_id, artifact_id, target_kind, process_id, pid, memory_region_id,
          analysis_run_id, job_id, status, match_count, yara_version, ruleset_json,
          error_json, started_at, finished_at
        ) VALUES (?, ?, NULL, 'memory', NULL, NULL, NULL, NULL, NULL, 'completed', 3, NULL, '{}', NULL, datetime('now'), datetime('now'))
        """,
        (str(uuid4()), ev["id"]),
    )
    db.execute(
        """
        INSERT INTO yara_scans (
          id, evidence_id, artifact_id, target_kind, process_id, pid, memory_region_id,
          analysis_run_id, job_id, status, match_count, yara_version, ruleset_json,
          error_json, started_at, finished_at
        ) VALUES (?, ?, NULL, 'artifact', NULL, NULL, NULL, NULL, NULL, 'completed', 5, NULL, '{}', NULL, datetime('now'), datetime('now'))
        """,
        (str(uuid4()), ev["id"]),
    )
    items = coverage_for_evidence(db, ev["id"])["items"]
    assert items["signatures"]["count"] == 8
    db.close()

