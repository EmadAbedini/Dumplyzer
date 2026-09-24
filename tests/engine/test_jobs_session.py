"""Jobs list is session/case scoped, not a permanent history."""

from __future__ import annotations

import inspect
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
    assert HANDLERS["jobs.reset_visible"]({}) == {"ok": True}
    assert HANDLERS["jobs.list"]({"limit": 50})["items"] == []

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


def test_list_jobs_omits_bulky_result_payload(tmp_path: Path) -> None:
    db = Database(tmp_path / "j.db")
    jobs = JobManager(db)
    started = threading.Event()
    release = threading.Event()

    def handler(_db, params, cancelled, progress):
        progress("working", {"percent": 12, "phase": "scan"})
        started.set()
        release.wait(timeout=2)
        return {"ok": True, "items": ["x" * 4000], "blob": "y" * 8000}

    jobs.register("test_job", handler)
    jobs.start()
    job = jobs.submit(
        "test_job",
        params={"profile": "full", "filename": "case.dmp", "extra": "z" * 4000},
    )
    assert started.wait(timeout=2)
    mid = jobs.list_jobs()[0]
    assert mid["result"]["percent"] == 12
    assert mid["result"]["phase"] == "scan"
    assert "items" not in (mid.get("result") or {})
    assert "blob" not in (mid.get("result") or {})
    assert mid["params"]["profile"] == "full"
    assert mid["params"]["filename"] == "case.dmp"
    assert "extra" not in mid["params"]
    release.set()
    deadline = time.time() + 3
    while time.time() < deadline:
        if jobs.get(job["id"])["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.02)
    full = jobs.get(job["id"])
    listed = jobs.list_jobs()[0]
    assert full["result"]["items"]
    assert full["params"]["extra"]
    assert "items" not in (listed.get("result") or {})
    assert "blob" not in (listed.get("result") or {})
    assert "extra" not in listed["params"]
    db.close()


def test_list_jobs_hides_kernel_symbols_fetch(tmp_path: Path) -> None:
    db = Database(tmp_path / "j.db")
    jobs = JobManager(db)

    def handler(_db, params, cancelled, progress):
        progress("downloading", {"percent": 10, "phase": "kernel_symbols"})
        return {"ok": True}

    jobs.register("kernel_symbols_fetch", handler)
    jobs.register("test_job", handler)
    jobs.start()
    hidden = jobs.submit("kernel_symbols_fetch", message="Downloading kernel symbols")
    shown = jobs.submit("test_job", message="Quick Triage")
    deadline = time.time() + 3
    while time.time() < deadline:
        hidden_status = jobs.get(hidden["id"])["status"]
        shown_status = jobs.get(shown["id"])["status"]
        if hidden_status in ("completed", "failed", "cancelled") and shown_status in (
            "completed",
            "failed",
            "cancelled",
        ):
            break
        time.sleep(0.02)
    listed_ids = {item["id"] for item in jobs.list_jobs()}
    assert hidden["id"] not in listed_ids
    assert shown["id"] in listed_ids
    assert jobs.get(hidden["id"])["kind"] == "kernel_symbols_fetch"
    db.close()


def test_list_jobs_hides_kernel_symbols_required_failure(tmp_path: Path) -> None:
    db = Database(tmp_path / "j.db")
    jobs = JobManager(db)

    def need_symbols(_db, params, cancelled, progress):
        raise AppError(
            code="kernel_symbols_required",
            message="This Windows dump needs kernel symbol tables before analysis can continue.",
            entity="volatility",
        )

    def ok(_db, params, cancelled, progress):
        return {"ok": True}

    jobs.register("analysis_profile", need_symbols)
    jobs.register("test_job", ok)
    jobs.start()
    blocked = jobs.submit("analysis_profile", message="Quick Triage")
    shown = jobs.submit("test_job", message="Importing memory image…")
    deadline = time.time() + 3
    while time.time() < deadline:
        blocked_status = jobs.get(blocked["id"])["status"]
        shown_status = jobs.get(shown["id"])["status"]
        if blocked_status in ("completed", "failed", "cancelled") and shown_status in (
            "completed",
            "failed",
            "cancelled",
        ):
            break
        time.sleep(0.02)
    listed_ids = {item["id"] for item in jobs.list_jobs()}
    assert blocked["id"] not in listed_ids
    assert shown["id"] in listed_ids
    assert jobs.get(blocked["id"])["status"] == "failed"
    assert jobs.get(blocked["id"])["error"]["code"] == "kernel_symbols_required"
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


def test_orphaned_running_jobs_do_not_block_new_work(tmp_path: Path) -> None:
    db = Database(tmp_path / "j.db")
    db.execute(
        """
        INSERT INTO jobs (
          id, kind, status, evidence_id, process_id, pid, analysis_run_id,
          created_at, started_at, finished_at, progress_kind, message,
          error_json, result_json, params_json, cancel_requested
        ) VALUES (?, 'analysis_profile', 'running', NULL, NULL, NULL, NULL,
                  ?, ?, NULL, 'indeterminate', 'Cancel requested', NULL, NULL, '{}', 1)
        """,
        (
            "orphan-running",
            "2026-09-14T16:28:14+00:00",
            "2026-09-14T16:28:15+00:00",
        ),
    )
    jobs = JobManager(db)
    ran = threading.Event()

    def handler(_db, params, cancelled, progress):
        ran.set()
        return {"ok": True}

    jobs.register("test_job", handler)
    jobs.start()
    orphan = db.fetchone("SELECT status, message FROM jobs WHERE id = ?", ("orphan-running",))
    assert orphan["status"] == "cancelled"
    assert "Abandoned" in orphan["message"]
    job = jobs.submit("test_job")
    deadline = time.time() + 3
    while time.time() < deadline:
        if jobs.get(job["id"])["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.02)
    assert jobs.get(job["id"])["status"] == "completed"
    assert ran.is_set()
    db.close()


def test_vol_init_health_does_not_import_framework() -> None:
    from memscope_engine.server import _vol_init, _vol_init_full

    src = inspect.getsource(_vol_init)
    assert "from volatility3.framework" not in src
    assert "import volatility3" not in src
    assert "find_spec" not in src
    full = inspect.getsource(_vol_init_full)
    assert "from volatility3.framework import automagic" in full
    init_src = inspect.getsource(handle_app_init)
    assert "discover_plugins" not in init_src
    assert "warmup_plugin_catalog" not in init_src


def test_capabilities_status_skips_heavy_work_during_live_job(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("MEMSCOPE_DATA_DIR", raising=False)
    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    img = tmp_path / "slow.raw"
    img.write_bytes(b"MEMSCOPE-MEMORY-IMAGE-BLOCK" * 64)
    started = threading.Event()
    release = threading.Event()

    def slow_hash(path, *, cancelled=None, progress=None, size=None):
        del path, cancelled, progress, size
        started.set()
        release.wait(timeout=8)
        return "a" * 64

    monkeypatch.setattr("memscope_engine.analysis.workflows.sha256_file", slow_hash)
    vol_calls = {"n": 0}

    def boom():
        vol_calls["n"] += 1
        time.sleep(20)
        return {"ok": True}

    monkeypatch.setattr("memscope_engine.server._vol_init", boom)
    job = HANDLERS["evidence.import"]({"path": str(img)})
    assert started.wait(timeout=3)
    t0 = time.perf_counter()
    caps = HANDLERS["capabilities.status"]({})
    assert time.perf_counter() - t0 < 1.0
    assert caps.get("checking") is True
    assert vol_calls["n"] == 0
    mid = HANDLERS["jobs.get"]({"job_id": job["id"]})
    assert mid["status"] in ("queued", "running")
    release.set()
    deadline = time.time() + 5
    while time.time() < deadline:
        if HANDLERS["jobs.get"]({"job_id": job["id"]})["status"] in (
            "completed",
            "failed",
            "cancelled",
        ):
            break
        time.sleep(0.02)


def test_keep_alive_app_init_preserves_tmp_during_job(tmp_path: Path) -> None:
    from memscope_engine.paths import AppPaths
    from memscope_engine.server import _STATE

    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    jobs = _STATE["jobs"]
    started = threading.Event()
    release = threading.Event()

    def blocker(_db, params, cancelled, progress):
        started.set()
        release.wait(timeout=5)
        return {"ok": True}

    jobs.register("block", blocker)
    jobs.submit("block")
    assert started.wait(timeout=2)
    leftover = AppPaths(tmp_path / "ipc").tmp / "keep.bin"
    leftover.write_bytes(b"keep")
    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    assert leftover.is_file()
    assert _STATE["jobs"] is jobs
    release.set()
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
    memory_view = (
        root / "app" / "frontend" / "src" / "components" / "MemoryExplorerView.tsx"
    ).read_text(encoding="utf-8")
    scope = (root / "app" / "frontend" / "src" / "lib" / "analysisScope.ts").read_text(
        encoding="utf-8"
    )
    app = (root / "app" / "frontend" / "src" / "App.tsx").read_text(encoding="utf-8")
    dive = (
        root / "app" / "frontend" / "src" / "components" / "ProcessDeepDiveView.tsx"
    ).read_text(encoding="utf-8")
    capability = (root / "app" / "frontend" / "src" / "lib" / "capabilityStatus.ts").read_text(
        encoding="utf-8"
    )
    assert "jobTableMessage" in view
    assert "jobFileName" in view
    assert "evidenceFilename" in view
    assert "Jobs updated" in view
    assert "Loading jobs…" in view
    assert "startTransition" in view
    assert "jobPollBusyRef" in app
    assert "coverageFromJobResult" in app
    assert "lastProcessCountRef" in app
    assert "fast ? 500 : 1500" in app
    assert "setInterval(() => void poll(), 500)" in app
    assert "setInterval(() => void load(), 2000)" in view
    assert "setInterval(() => void poll(), 500)" in dive
    assert 'refreshToken={`${coverageTick}:${jobTick}`}' in app
    assert "pcapPending" in (
        root / "app" / "frontend" / "src" / "components" / "NetworkView.tsx"
    ).read_text(encoding="utf-8")
    network_view = (
        root / "app" / "frontend" / "src" / "components" / "NetworkView.tsx"
    ).read_text(encoding="utf-8")
    assert 'recon.limitations.join(" ")' in network_view
    assert 'jobs.list"' in view or "jobs.list" in view
    assert "evidence_id: evidenceId" not in view
    assert "startCapabilityChecks" not in app
    assert "plugins.warmup" in app
    explorer = (
        root / "app" / "frontend" / "src" / "components" / "PluginExplorerView.tsx"
    ).read_text(encoding="utf-8")
    assert "Loading plugins…" in explorer
    assert "Loading plugin catalog…" in explorer
    assert "BUNDLED_TOOL" in capability
    assert "result.checking" in capability
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
    assert "items-center" in coverage
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
    assert "waiting_for_pdb" in coverage_lib
    assert "coverageWaitingForPdb" in coverage_lib
    assert "Waiting for PDB" in coverage
    assert "item.updating" in coverage_lib
    assert "coverageFromJobResult" in coverage_lib
    assert "coverageRefreshKey" in coverage_lib
    assert "coverageShownInView" in coverage_lib
    assert "onShownCountChange" in memory_view
    timeline_view = (
        root / "app" / "frontend" / "src" / "components" / "TimelineArtifactsViews.tsx"
    ).read_text(encoding="utf-8")
    artifacts_view = (
        root / "app" / "frontend" / "src" / "components" / "ArtifactsView.tsx"
    ).read_text(encoding="utf-8")
    be_view = (
        root / "app" / "frontend" / "src" / "components" / "BulkExtractorResults.tsx"
    ).read_text(encoding="utf-8")
    assert "onShownCountChange" in timeline_view
    assert "onShownCountChange" in artifacts_view
    assert "onCoverageRefresh" in timeline_view
    assert "Artifact extraction ${scan.ui_state || scan.status}." not in be_view
    assert "sidebarCoverage" in app
    assert "coverageHasSearchableData" in coverage_lib
    assert "coverageProcessListReady" in coverage_lib
    assert "coverageCanExport" in coverage_lib
    assert "STORED_ACTION_TITLE" in scope
    assert "limitedResultsNote" in scope
    assert "findingsScopeNote" in scope
    assert "iocsScopeNote" in scope
    assert "searchScopeNote" in scope
    assert "jobProgressPercentText" in dive
    assert 'Analysing ${analyzePercentText ?? "0%"}' in dive
    assert "nowMs={nowMs}" in app
    assert "activeJobs={activeJobs}" in app
    assert "Rebuild From Extracted Records" in (
        root / "app" / "frontend" / "src" / "components" / "TimelineArtifactsViews.tsx"
    ).read_text(encoding="utf-8")
    assert "analysisCoverage={coverage}" in app
    assert "analysisBusy" in app
    assert "IMPORTING_NAV_HINT" in app
    assert "navLockedDuringImport(id)" in app
    assert "A job is running" not in sidebar
    assert "A job is running" not in app
    dialog = (
        root / "app" / "frontend" / "src" / "components" / "KernelSymbolsDialog.tsx"
    ).read_text(encoding="utf-8")
    assert "Downloading Symbol..." in dialog
    assert "Downloading symbol..." not in dialog
    assert "kernel_symbols_required" in view
    assert "coverageWaitingForPdb" in app
    assert "waitingForPdb={waitingForPdb}" in app
    assert "setNav(\"overview\")" in app
    for label in ("cancelling", "cancelled", "completed", "failed", "running"):
        assert label in view or label in helpers or label in display
