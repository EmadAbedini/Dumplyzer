"""Export / reporting tests. Fixtures are labeled synthetic unit-test data only."""

from __future__ import annotations

import csv
import json
import time
from io import StringIO
from pathlib import Path
from uuid import uuid4

import pytest

from memscope_engine.analysis.workflows import import_evidence
from memscope_engine.errors import AppError
from memscope_engine.export.collect import collect_investigation, normalize_sections
from memscope_engine.export.constants import (
    HTML_MAX_ROWS,
    REPORT_FORMAT,
    REPORT_SCHEMA_VERSION,
)
from memscope_engine.export.csv_export import csv_cell, write_csv_file
from memscope_engine.export.html_report import render_html
from memscope_engine.export.json_export import write_json_file
from memscope_engine.export.safe_paths import (
    allocate_export_dir,
    parse_optional_basename,
    reject_user_destination,
    sanitize_filename,
)
from memscope_engine.export.workflows import generate_export, list_exports
from memscope_engine.jobs.manager import JobManager
from memscope_engine.paths import AppPaths
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION


def _seed_empty(tmp_path: Path) -> tuple[AppPaths, Database, dict]:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "synth.raw"
    img.write_bytes(b"MEMSCOPE-SYNTHETIC-EXPORT-TEST")
    ev = import_evidence(db, str(img))
    return paths, db, ev


def _run(db: Database, evidence_id: str, kind: str = "basic_triage") -> str:
    run_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, strategy_json,
          volatility_version
        ) VALUES (?, ?, ?, 'completed', '2020-01-01T00:00:00+00:00', ?, '[]', '2.28.0-test')
        """,
        (run_id, evidence_id, kind, SCHEMA_VERSION),
    )
    return run_id


def _process(
    db: Database,
    evidence_id: str,
    run_id: str,
    pid: int,
    ppid: int,
    name: str,
    cmdline: str | None = None,
) -> str:
    pid_id = str(uuid4())
    db.execute(
        """
        INSERT INTO processes (
          id, evidence_id, analysis_run_id, pid, ppid, name, image_path, command_line,
          source_plugin
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'windows.pslist')
        """,
        (pid_id, evidence_id, run_id, pid, ppid, name, f"C:\\{name}", cmdline),
    )
    return pid_id


def test_schema_v9_exports_table(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    assert db.schema_version() == SCHEMA_VERSION
    assert SCHEMA_VERSION == 9
    db.execute("SELECT COUNT(*) AS c FROM exports")
    db.close()


def test_json_schema_version_and_determinism(tmp_path: Path) -> None:
    paths, db, ev = _seed_empty(tmp_path)
    rec = generate_export(db, paths, evidence_id=ev["id"], fmt="json", scope="complete")
    assert rec["report_schema_version"] == REPORT_SCHEMA_VERSION
    path = Path(rec["primary_path"])
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["format"] == REPORT_FORMAT
    assert data["report_schema_version"] == 1
    assert data["analysis_schema_version"] == SCHEMA_VERSION
    assert "provenance" in data
    a = json.dumps(data, sort_keys=True, ensure_ascii=False)
    b = json.dumps(json.loads(path.read_text(encoding="utf-8")), sort_keys=True, ensure_ascii=False)
    assert a == b
    out = tmp_path / "round.json"
    write_json_file(out, data)
    write_json_file(tmp_path / "round2.json", data)
    assert (tmp_path / "round.json").read_text(encoding="utf-8") == (
        tmp_path / "round2.json"
    ).read_text(encoding="utf-8")
    db.close()


def test_csv_nulls_and_structured_values(tmp_path: Path) -> None:
    assert csv_cell(None) == ""
    assert csv_cell({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    assert csv_cell([1, None]) == "[1,null]"
    path = tmp_path / "findings.csv"
    write_csv_file(
        path,
        "findings",
        [
            {
                "id": "f1",
                "title": "t",
                "severity": None,
                "explanation": 'say "hi", please',
                "plugin": None,
            }
        ],
    )
    text = path.read_text(encoding="utf-8")
    reader = csv.reader(StringIO(text))
    rows = list(reader)
    assert rows[0][0] == "id"
    assert rows[1][2] == ""  # null severity
    assert 'say "hi", please' in rows[1][3]


def test_html_escapes_malicious_strings(tmp_path: Path) -> None:
    paths, db, ev = _seed_empty(tmp_path)
    run_id = _run(db, ev["id"])
    proc = _process(
        db,
        ev["id"],
        run_id,
        4242,
        4,
        "evil.exe",
        "<script>alert(1)</script>",
    )
    db.execute(
        """
        INSERT INTO findings (
          id, evidence_id, analysis_run_id, process_id, pid, finding_type, severity,
          explanation, field_name, field_value, plugin, created_at
        ) VALUES (?, ?, ?, ?, 4242, 'synthetic_html', 'low',
          '<script>alert("xss")</script><img src=x onerror=alert(1)>',
          'command_line', '<script>alert(1)</script>', 'windows.pslist',
          '2020-01-01T00:00:00+00:00')
        """,
        (str(uuid4()), ev["id"], run_id, proc),
    )
    rec = generate_export(db, paths, evidence_id=ev["id"], fmt="html", scope="complete")
    html = Path(rec["primary_path"]).read_text(encoding="utf-8")
    assert "<script>alert" not in html
    assert "<img src=x onerror" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    db.close()


def test_observed_vs_inferred_timeline(tmp_path: Path) -> None:
    paths, db, ev = _seed_empty(tmp_path)
    db.execute(
        """
        INSERT INTO timeline_events (
          id, evidence_id, event_time, classification, event_kind, summary,
          source_plugin, provenance_json, created_at
        ) VALUES
          (?, ?, '2020-01-01T00:00:00+00:00', 'observed', 'process_start',
           'synthetic observed start', 'windows.pslist', '{}', '2020-01-01T00:00:00+00:00'),
          (?, ?, NULL, 'inferred', 'process_relation',
           'synthetic inferred parent link', 'memscope.timeline', '{}', '2020-01-01T00:00:00+00:00')
        """,
        (str(uuid4()), ev["id"], str(uuid4()), ev["id"]),
    )
    rec = generate_export(db, paths, evidence_id=ev["id"], fmt="html", scope="complete")
    html = Path(rec["primary_path"]).read_text(encoding="utf-8")
    assert "observed" in html
    assert "inferred" in html
    assert "synthetic observed start" in html
    assert "synthetic inferred parent link" in html
    doc = collect_investigation(db, ev["id"], fmt="json", sections=["metadata", "timeline"])
    classes = {i["classification"] for i in doc["timeline"]["items"]}
    assert classes == {"observed", "inferred"}
    inferred = [i for i in doc["timeline"]["items"] if i["classification"] == "inferred"][0]
    assert inferred["event_time"] is None
    db.close()


def test_provenance_preserved(tmp_path: Path) -> None:
    paths, db, ev = _seed_empty(tmp_path)
    run_id = _run(db, ev["id"])
    proc = _process(db, ev["id"], run_id, 7, 4, "demo.exe")
    art_id = str(uuid4())
    db.execute(
        """
        INSERT INTO artifacts (
          id, evidence_id, process_id, pid, filename, stored_path, sha256, size_bytes,
          file_type, extraction_method, source_plugin, extracted_at, metadata_json
        ) VALUES (?, ?, ?, 7, 'pid.7.synth.dmp', 'C:\\synth\\pid.7.synth.dmp',
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 16,
          'raw', 'vad_extract', 'windows.vadinfo', '2020-01-01T00:00:00+00:00', '{}')
        """,
        (art_id, ev["id"], proc),
    )
    rec = generate_export(db, paths, evidence_id=ev["id"], fmt="json", scope="complete")
    data = json.loads(Path(rec["primary_path"]).read_text(encoding="utf-8"))
    assert data["provenance"]["chain"][0] == "evidence"
    art = data["artifacts"]["items"][0]
    assert art["provenance"]["evidence_id"] == ev["id"]
    assert art["provenance"]["process_id"] == proc
    assert art["sha256"].startswith("aaaa")
    db.close()


def test_empty_investigation_all_formats(tmp_path: Path) -> None:
    paths, db, ev = _seed_empty(tmp_path)
    html_rec = generate_export(db, paths, evidence_id=ev["id"], fmt="html")
    json_rec = generate_export(db, paths, evidence_id=ev["id"], fmt="json")
    csv_rec = generate_export(db, paths, evidence_id=ev["id"], fmt="csv")
    html = Path(html_rec["primary_path"]).read_text(encoding="utf-8")
    assert "No malware or risk score" in html
    data = json.loads(Path(json_rec["primary_path"]).read_text(encoding="utf-8"))
    assert data["summary"]["process_count"] == 0
    assert data["summary"]["no_risk_score"] is True
    assert data["malware"]["yara_matches"]["total"] == 0
    names = {f["name"] for f in csv_rec["files"]}
    assert "processes.csv" in names
    assert "manifest.json" in names
    db.close()


def test_large_section_html_truncates(tmp_path: Path) -> None:
    paths, db, ev = _seed_empty(tmp_path)
    run_id = _run(db, ev["id"])
    n = HTML_MAX_ROWS + 50
    for i in range(n):
        _process(db, ev["id"], run_id, 1000 + i, 4, f"p{i}.exe")
    rec = generate_export(db, paths, evidence_id=ev["id"], fmt="html", scope="complete")
    html = Path(rec["primary_path"]).read_text(encoding="utf-8")
    assert "Remaining rows are in the JSON/CSV export" in html
    assert html.count("<tr>") < HTML_MAX_ROWS + 80
    db.close()


def test_missing_optional_providers_and_failed_cache_plugins(tmp_path: Path) -> None:
    paths, db, ev = _seed_empty(tmp_path)
    run_id = _run(db, ev["id"], kind="plugin_advanced")
    failed_id = str(uuid4())
    hit_id = str(uuid4())
    db.execute(
        """
        INSERT INTO plugin_executions (
          id, analysis_run_id, evidence_id, plugin, parameters_json, status,
          started_at, finished_at, error_json, row_count, cache_hit, plugin_id
        ) VALUES (?, ?, ?, 'windows.pslist.PsList', '{"pid":4}', 'failed',
          '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:01+00:00',
          '{"message":"synthetic failure"}', 0, 0, 'windows.pslist.PsList')
        """,
        (failed_id, run_id, ev["id"]),
    )
    db.execute(
        """
        INSERT INTO plugin_executions (
          id, analysis_run_id, evidence_id, plugin, parameters_json, status,
          started_at, finished_at, row_count, cache_hit, plugin_id
        ) VALUES (?, ?, ?, 'frameworkinfo.FrameworkInfo', '{}', 'completed',
          '2020-01-01T00:00:02+00:00', '2020-01-01T00:00:03+00:00',
          3, 1, 'frameworkinfo.FrameworkInfo')
        """,
        (hit_id, run_id, ev["id"]),
    )
    db.execute(
        """
        INSERT INTO plugin_results (
          id, evidence_id, analysis_run_id, plugin_execution_id, plugin_id,
          row_count, columns_json, from_cache, created_at
        ) VALUES (?, ?, ?, ?, 'frameworkinfo.FrameworkInfo', 3, '["Module"]', 1,
          '2020-01-01T00:00:03+00:00')
        """,
        (str(uuid4()), ev["id"], run_id, hit_id),
    )
    rec = generate_export(db, paths, evidence_id=ev["id"], fmt="json", scope="complete")
    data = json.loads(Path(rec["primary_path"]).read_text(encoding="utf-8"))
    statuses = {i["status"] for i in data["advanced"]["items"]}
    assert "failed" in statuses
    hits = [i for i in data["advanced"]["items"] if i["cache_hit"]]
    assert hits and hits[0]["result_summary"]["raw_output_omitted"] is True
    assert data["malware"]["pe_sieve"]["total"] == 0
    assert data["malware"]["mal_unpack"]["total"] == 0
    html_rec = generate_export(db, paths, evidence_id=ev["id"], fmt="html")
    html = Path(html_rec["primary_path"]).read_text(encoding="utf-8")
    assert "TreeGrid" in html
    assert "synthetic failure" in html
    db.close()


def test_safe_paths_and_filename_sanitization(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    img = tmp_path / "evidence.raw"
    img.write_bytes(b"x")
    with pytest.raises(AppError) as exc:
        reject_user_destination(str(img))
    assert exc.value.code == "export_path_rejected"
    with pytest.raises(AppError):
        parse_optional_basename("..\\..\\Windows\\evil.html")
    with pytest.raises(AppError):
        parse_optional_basename("/tmp/x.html")
    with pytest.raises(AppError):
        parse_optional_basename("a/b.html")
    assert "<script>" not in sanitize_filename("<script>alert(1)</script>.html")
    dest = allocate_export_dir(
        paths,
        evidence_filename="case.raw",
        export_id="abcd1234-ffff",
        evidence_path=str(img),
    )
    assert dest.is_dir()
    dest.relative_to(paths.exports)
    with pytest.raises(AppError) as exc2:
        generate_export(
            Database(paths.db_path),
            paths,
            evidence_id="missing",
            fmt="html",
            destination=str(img),
        )
    assert exc2.value.code in {"export_path_rejected", "evidence_missing"}


def test_path_traversal_rejected_before_write(tmp_path: Path) -> None:
    paths, db, ev = _seed_empty(tmp_path)
    with pytest.raises(AppError) as exc:
        generate_export(
            db,
            paths,
            evidence_id=ev["id"],
            fmt="html",
            filename_hint="..\\..\\escape",
        )
    assert exc.value.code == "export_path_rejected"
    db.close()


def test_selected_json_and_csv_sections(tmp_path: Path) -> None:
    paths, db, ev = _seed_empty(tmp_path)
    rec = generate_export(
        db,
        paths,
        evidence_id=ev["id"],
        fmt="json",
        scope="selected",
        sections=["iocs", "findings"],
    )
    names = {f["name"] for f in rec["files"]}
    assert "iocs.json" in names
    assert "findings.json" in names
    assert "investigation.json" not in names
    csv_rec = generate_export(
        db,
        paths,
        evidence_id=ev["id"],
        fmt="csv",
        scope="selected",
        sections=["processes", "summary"],
    )
    csv_names = {f["name"] for f in csv_rec["files"]}
    assert "processes.csv" in csv_names
    with pytest.raises(AppError) as exc:
        generate_export(
            db,
            paths,
            evidence_id=ev["id"],
            fmt="csv",
            scope="selected",
            sections=["summary", "malware"],
        )
    assert exc.value.code == "export_csv_empty"
    db.close()


def test_unknown_section_and_normalize() -> None:
    with pytest.raises(AppError):
        normalize_sections("selected", ["not_a_section"])
    secs = normalize_sections("selected", ["findings"])
    assert secs[0] == "metadata"
    assert "findings" in secs


def test_ipc_round_trip(tmp_path: Path) -> None:
    from memscope_engine.server import HANDLERS, handle_app_init

    init = handle_app_init({"data_dir": str(tmp_path / "ipcdata")})
    assert init["schema_version"] == 9
    opts = HANDLERS["export.options"]({})
    assert "html" in opts["formats"]
    assert opts["pdf"] is False
    from memscope_engine import server as srv

    engine_db = srv._db()
    img = tmp_path / "ipc.raw"
    img.write_bytes(b"ipc-export")
    ev = import_evidence(engine_db, str(img))
    job = HANDLERS["export.generate"](
        {"evidence_id": ev["id"], "format": "html", "scope": "complete"}
    )
    assert job["kind"] == "export_report"
    got = None
    for _ in range(80):
        got = HANDLERS["jobs.get"]({"job_id": job["id"]})
        if got["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.1)
    assert got is not None
    assert got["status"] == "completed"
    listed = HANDLERS["export.list"]({"evidence_id": ev["id"]})
    assert listed["total"] >= 1
    rec = HANDLERS["export.get"]({"export_id": listed["items"][0]["id"]})
    assert Path(rec["primary_path"]).is_file()
    html = Path(rec["primary_path"]).read_text(encoding="utf-8")
    assert "MemScope investigation report" in html


def test_job_cancel_queued(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "c.raw"
    img.write_bytes(b"cancel")
    ev = import_evidence(db, str(img))
    jobs = JobManager(db)

    def _hang(db_, params, cancelled, progress):
        while not cancelled():
            time.sleep(0.05)
        raise AppError(code="export_cancelled", message="Export cancelled.", entity="export")

    jobs.register("export_report", _hang)
    jobs.start()
    job = jobs.submit("export_report", evidence_id=ev["id"], params={"evidence_id": ev["id"]})
    jobs.cancel(job["id"])
    deadline = time.time() + 3
    status = None
    while time.time() < deadline:
        status = jobs.get(job["id"])["status"]
        if status in ("cancelled", "failed", "completed"):
            break
        time.sleep(0.05)
    assert status == "cancelled"
    db.close()


def test_frontend_export_states_present() -> None:
    root = Path(__file__).resolve().parents[2]
    view = (root / "app" / "frontend" / "src" / "components" / "ExportView.tsx").read_text(
        encoding="utf-8"
    )
    for state in ("idle", "queued", "running", "completed", "failed", "cancelled"):
        assert state in view
    types = (root / "app" / "frontend" / "src" / "lib" / "types.ts").read_text(encoding="utf-8")
    assert "ExportUiState" in types


def test_html_report_has_no_cdn_or_javascript_payload(tmp_path: Path) -> None:
    paths, db, ev = _seed_empty(tmp_path)
    rec = generate_export(db, paths, evidence_id=ev["id"], fmt="html")
    html = Path(rec["primary_path"]).read_text(encoding="utf-8")
    assert "cdn." not in html.lower()
    assert "<script" not in html.lower()
    listed = list_exports(db, ev["id"])
    assert listed["total"] >= 1
    db.close()
