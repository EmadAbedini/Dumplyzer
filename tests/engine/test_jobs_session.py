"""Jobs list is session/case scoped, not a permanent history."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from memscope_engine.errors import AppError
from memscope_engine.jobs.manager import JobManager
from memscope_engine.server import HANDLERS, handle_app_init
from memscope_engine.storage import Database


def test_jobs_list_empty_on_new_manager_with_historical_rows(tmp_path: Path) -> None:
    db = Database(tmp_path / "j.db")
    first = JobManager(db)

    def handler(_db, params, cancelled, progress):
        return {"ok": True}

    first.register("test_job", handler)
    first.start()
    job = first.submit("test_job", message="old")
    for _ in range(50):
        if first.get(job["id"])["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.02)
    assert first.list_jobs()
    # Simulate application restart: new JobManager on the same SQLite file.
    restarted = JobManager(db)
    assert restarted.list_jobs() == []
    assert db.fetchone("SELECT id FROM jobs WHERE id = ?", (job["id"],)) is not None
    db.close()


def test_jobs_reset_on_new_evidence_import(tmp_path: Path) -> None:
    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    img = tmp_path / "a.raw"
    img.write_bytes(b"MEMSCOPE-SYNTHETIC-JOB-SESSION")
    first = HANDLERS["evidence.import"]({"path": str(img)})
    deadline = time.time() + 20
    while time.time() < deadline:
        done = HANDLERS["jobs.get"]({"job_id": first["id"]})
        if done["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.05)
    listed = HANDLERS["jobs.list"]({"limit": 50})
    item = next(j for j in listed["items"] if j["id"] == first["id"])
    assert item["evidence_filename"] == "a.raw"

    img2 = tmp_path / "b.raw"
    img2.write_bytes(b"MEMSCOPE-SYNTHETIC-JOB-SESSION-2")
    second = HANDLERS["evidence.import"]({"path": str(img2)})
    listed2 = HANDLERS["jobs.list"]({"limit": 50})
    ids = {j["id"] for j in listed2["items"]}
    assert first["id"] not in ids
    assert second["id"] in ids
    # Historical row remains in SQLite; it is not used for the active Jobs view.
    db = Database(tmp_path / "ipc" / "memscope.db")
    assert db.fetchone("SELECT id FROM jobs WHERE id = ?", (first["id"],)) is not None
    db.close()


def test_cancel_active_unblocks_the_worker_for_the_next_job(tmp_path: Path) -> None:
    db = Database(tmp_path / "j.db")
    jobs = JobManager(db)
    started = threading.Event()
    imported = threading.Event()

    def blocker(_db, params, cancelled, progress):
        started.set()
        while not cancelled():
            time.sleep(0.02)
        return {"stopped": True}

    def importer(_db, params, cancelled, progress):
        imported.set()
        return {"imported": True}

    jobs.register("block", blocker)
    jobs.register("evidence_import", importer)
    jobs.start()
    stuck = jobs.submit("block")
    assert started.wait(timeout=2)
    jobs.cancel_active()
    jobs.reset_visible_jobs()
    incoming = jobs.submit("evidence_import", message="Importing memory image…")
    deadline = time.time() + 5
    while time.time() < deadline:
        if jobs.get(incoming["id"])["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.02)
    assert jobs.get(incoming["id"])["status"] == "completed"
    assert imported.is_set()
    assert jobs.get(stuck["id"])["status"] in ("cancelled", "completed")
    db.close()


def test_list_jobs_includes_evidence_filename(tmp_path: Path) -> None:
    db = Database(tmp_path / "j.db")
    eid = "ev-filename"
    db.execute(
        """
        INSERT INTO evidence (
          id, path, filename, size_bytes, sha256,
          symbol_status, import_status, import_timestamp
        ) VALUES (?, ?, ?, 8, ?, 'unknown', 'imported', ?)
        """,
        (eid, str(tmp_path / "case.dmp"), "case.dmp", "sha-filename-1", "2020-01-01T00:00:00+00:00"),
    )
    jobs = JobManager(db)

    def handler(_db, params, cancelled, progress):
        return {"ok": True}

    jobs.register("test_job", handler)
    jobs.start()
    job = jobs.submit("test_job", evidence_id=eid, message="Quick Triage")
    for _ in range(80):
        if jobs.get(job["id"])["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.02)
    listed = jobs.list_jobs(evidence_id=eid)
    assert listed
    assert listed[0]["evidence_filename"] == "case.dmp"
    db.close()


def test_cancel_marker_stops_running_job_without_rpc(tmp_path: Path) -> None:
    db = Database(tmp_path / "j.db")
    jobs = JobManager(db)
    started = threading.Event()

    def handler(_db, params, cancelled, progress):
        started.set()
        progress("working", {"percent": 40})
        while not cancelled():
            time.sleep(0.02)
        raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")

    jobs.register("test_job", handler)
    jobs.start()
    job = jobs.submit("test_job")
    assert started.wait(timeout=2)
    marker = tmp_path / "tmp" / "job-cancel" / job["id"]
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("1", encoding="utf-8")
    deadline = time.time() + 3
    status = None
    while time.time() < deadline:
        got = jobs.get(job["id"])
        status = got["status"]
        if status in ("cancelled", "failed", "completed"):
            break
        time.sleep(0.05)
    assert status == "cancelled"
    assert jobs.get(job["id"])["message"] == "Cancelled"
    assert not marker.exists()
    db.close()


def test_cancel_does_not_mark_completed_after_handler_returns(tmp_path: Path) -> None:
    db = Database(tmp_path / "j.db")
    jobs = JobManager(db)
    started = threading.Event()
    release = threading.Event()

    def handler(_db, params, cancelled, progress):
        started.set()
        release.wait(timeout=2)
        progress("almost done", {"percent": 99})
        return {"ok": True}

    jobs.register("test_job", handler)
    jobs.start()
    job = jobs.submit("test_job")
    assert started.wait(timeout=2)
    jobs.cancel(job["id"])
    release.set()
    deadline = time.time() + 3
    status = None
    while time.time() < deadline:
        status = jobs.get(job["id"])["status"]
        if status in ("cancelled", "failed", "completed"):
            break
        time.sleep(0.05)
    assert status == "cancelled"
    db.close()


def test_progress_without_percent_keeps_last_percent(tmp_path: Path) -> None:
    db = Database(tmp_path / "j.db")
    jobs = JobManager(db)
    after_nested = threading.Event()
    release = threading.Event()

    def handler(_db, params, cancelled, progress):
        progress("Processes (basic triage)", {"phase": "processes", "percent": 5})
        progress("Running windows.info")
        after_nested.set()
        release.wait(timeout=2)
        progress("Command lines", {"phase": "command_lines", "percent": 30})
        return {"ok": True}

    jobs.register("test_job", handler)
    jobs.start()
    job = jobs.submit("test_job")
    assert after_nested.wait(timeout=2)
    mid = jobs.get(job["id"])
    assert mid["result"]["percent"] == 5
    assert mid["result"]["phase"] == "processes"
    assert mid["progress_kind"] == "determinate"
    release.set()
    deadline = time.time() + 3
    while time.time() < deadline:
        if jobs.get(job["id"])["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.02)
    done = jobs.get(job["id"])
    assert done["status"] == "completed"
    db.close()


def test_frontend_jobs_view_progress_and_cancel_copy() -> None:
    root = Path(__file__).resolve().parents[2]
    view = (root / "app" / "frontend" / "src" / "components" / "JobsView.tsx").read_text(
        encoding="utf-8"
    )
    helpers = (root / "app" / "frontend" / "src" / "lib" / "analysisOptions.ts").read_text(
        encoding="utf-8"
    )
    display = (root / "app" / "frontend" / "src" / "lib" / "jobDisplay.ts").read_text(
        encoding="utf-8"
    )
    css = (root / "app" / "frontend" / "src" / "styles.css").read_text(encoding="utf-8")
    toast = (root / "app" / "frontend" / "src" / "components" / "StatusToast.tsx").read_text(
        encoding="utf-8"
    )
    coverage = (root / "app" / "frontend" / "src" / "components" / "CoverageStatus.tsx").read_text(
        encoding="utf-8"
    )
    sidebar = (root / "app" / "frontend" / "src" / "components" / "Sidebar.tsx").read_text(
        encoding="utf-8"
    )
    coverage_lib = (root / "app" / "frontend" / "src" / "lib" / "analysisCoverage.ts").read_text(
        encoding="utf-8"
    )
    scope = (root / "app" / "frontend" / "src" / "lib" / "analysisScope.ts").read_text(
        encoding="utf-8"
    )
    app = (root / "app" / "frontend" / "src" / "App.tsx").read_text(encoding="utf-8")
    assert "jobTableMessage" in view
    assert "jobFileName" in view
    assert "evidenceFilename" in view
    assert "Jobs updated" in view
    assert "Refreshing…" in toast
    assert "app-toast" in toast
    assert "notMemoryImageToast" in helpers
    assert "isNotMemoryImageError" in helpers
    assert "notMemoryImageToast" in app
    assert "evidence_not_memory_image" in helpers
    assert "File name" in view
    assert "Cancelling…" in view
    assert ">Kind<" not in view
    assert ">PID<" not in view
    assert "Analysis" in view
    assert ">Action<" in view
    assert "Math.round" in helpers
    assert "toFixed(2)" not in helpers
    assert "Complete Analysis" in helpers
    assert "Quick Triage" in helpers
    assert "Waiting to start" in helpers
    assert "Custom Analysis" in helpers
    assert "Memory Image Import" in display
    assert "Modules / DLLs" in helpers
    assert "ANALYSIS_PROFILE_COPY" in display
    assert "windows.dlllist" not in view
    assert "analysis_profile" not in view
    assert "table-layout: fixed" in css
    assert "jobs-created" not in css
    assert "Created" not in view
    assert "colSpan={5}" in view
    assert "jobs-message" in css
    assert "16rem" in css
    assert "width: 100%" in css
    assert "jobs-file" in css
    assert "jobs-action-col" in css
    assert "nth-child(even)" in css
    assert "h-full min-h-0 flex-col" not in coverage
    assert "so far" in coverage
    assert "Updating…" in coverage
    assert "Analysis in progress" in coverage
    assert "Results will appear here automatically when available." in coverage
    assert "This data was not collected in the analysis you ran." in coverage
    assert "Quick Triage only collects processes." in coverage
    assert "AnalysisScopeNote" in coverage
    assert "SortableTh" in view
    assert "jobFileName" in display
    assert "jobsRunning" in sidebar
    assert "jobsPercent" in sidebar
    assert "animate-spin" in sidebar
    assert "jobProgressPercentText" in display
    assert "frozenPercent" in display
    assert "Analysis views are available after the memory image import finishes." in sidebar
    assert 'NAV_OPEN_DURING_IMPORT = new Set<NavId>(["jobs"])' in sidebar
    assert '["overview", "jobs"' not in sidebar
    assert "navLockedDuringImport" in sidebar
    assert "navOpenDuringJobs" in sidebar
    assert "PLUGIN_JOB_BUSY_HINT" in sidebar
    assert "EXPORT_JOB_BUSY_HINT" in sidebar
    assert "navStartsConcurrentJob" in sidebar
    assert "This section will be available when its analysis completes." not in sidebar
    assert "onJobsRunningNav" not in sidebar
    assert "coverageLiveKind" in coverage_lib
    assert "has_results" in coverage_lib
    assert "item.updating" in coverage_lib
    assert "coverageRefreshKey" in coverage_lib
    assert "coverageHasSearchableData" in coverage_lib
    assert "coverageProcessListReady" in coverage_lib
    assert "coverageCanExport" in coverage_lib
    assert "STORED_ACTION_TITLE" in scope
    assert "limitedResultsNote" in scope
    assert "analysisCoverage={coverage}" in app
    assert "analysisBusy" in app
    assert "IMPORTING_NAV_HINT" in app
    assert "navLockedDuringImport(id)" in app
    assert "A job is running" not in sidebar
    assert "A job is running" not in app
    for label in ("cancelling", "cancelled", "completed", "failed", "running"):
        assert label in view or label in helpers or label in display
