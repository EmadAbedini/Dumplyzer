"""bulk_extractor provider, workflow, schema, parsing, and IPC tests."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from uuid import uuid4

import pytest

from memscope_engine.analysis import bulk_extractor_workflows
from memscope_engine.analysis.workflows import import_evidence
from memscope_engine.errors import AppError
from memscope_engine.export.collect import collect_investigation
from memscope_engine.paths import AppPaths
from memscope_engine.providers.bulk_extractor import (
    VERIFIED_RELEASE,
    BulkExtractorProvider,
    ProcessRun,
    build_scan_argv,
    build_version_argv,
    compute_ui_state,
    discover_executable,
    feature_kind_for_stem,
    is_feature_filename,
    normalize_bulk_extractor_output,
    parse_feature_file,
    parse_version_output,
    validate_executable_path,
    validate_output_dir,
)
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION


def _mz_stub() -> bytes:
    return b"MZ" + b"\x00" * 64


def _write_dummy_exe(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_mz_stub())
    return path


def _write_feature_fixture(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "email.txt").write_text(
        "0\talice@example.com\tctx alice@example.com\n"
        "# comment\n"
        "16\tbob@example.org\tctx\n"
        "24\tpkiadmin@trustcentre.co.za0\tcert\n",
        encoding="utf-8",
    )
    (output_dir / "url.txt").write_text(
        "100\thttp://example.test/login\tctx http://example.test/login\n",
        encoding="utf-8",
    )
    (output_dir / "domain.txt").write_text(
        "200\texample.test\tctx example.test\n",
        encoding="utf-8",
    )
    (output_dir / "ip.txt").write_text(
        "300\t203.0.113.10\tctx 203.0.113.10\n"
        "400\t2001:db8::1\tctx 2001:db8::1\n",
        encoding="utf-8",
    )
    (output_dir / "telephone.txt").write_text(
        "500\t+1-202-555-0100\tctx\n"
        "508\tDSN:                   \tnoise\n"
        "516\t09914277158\tSupport 1: 09914277158\n",
        encoding="utf-8",
    )
    (output_dir / "ccn.txt").write_text(
        "600\t4111111111111111\tctx\n",
        encoding="utf-8",
    )
    (output_dir / "httplogs.txt").write_text(
        "700\tGET /index.html HTTP/1.1\tctx\n",
        encoding="utf-8",
    )
    (output_dir / "aes_keys.txt").write_text(
        "10\t0e f2 72 0a 06 54 f2 81 22 7a 3e f5 d5 b3 e2 3a 0f 31 bd 48 43 a8 34 f9 28 73 db b4 3c fd a7 d1\tAES256\n"
        "20\t00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f\tAES256\n"
        "30\t00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\tAES128\n",
        encoding="utf-8",
    )
    (output_dir / "winlnk.txt").write_text(
        "40\tNO_LINKINFO\t<lnk><atime>2024-02-26T11:23:49Z</atime><ctime>2018-04-11T21:04:33Z</ctime>"
        "<local_base_path>C:\\134Windows\\134System32</local_base_path>"
        "<net_name>\\\\134\\\\134192.168.20.20\\\\134REPORT</net_name></lnk>\n",
        encoding="utf-8",
    )
    (output_dir / "sqlite_carved.txt").write_text(
        "50\tsqlite_carved/000/50.sqlite3\t"
        "<fileobject><filename>sqlite_carved/000/50.sqlite3</filename>"
        "<filesize>4096</filesize><hashdigest type='sha1'>abc123</hashdigest></fileobject>\n",
        encoding="utf-8",
    )
    (output_dir / "ntfsmft_carved.txt").write_text(
        "60\t$MFT\t<fileobject><filename>$MFT</filename></fileobject>\n",
        encoding="utf-8",
    )
    (output_dir / "url_histogram.txt").write_text("2\texample.test\n", encoding="utf-8")
    (output_dir / "report.xml").write_text(
        '<?xml version="1.0"?>\n'
        "<dfxml><creator><version>2.2.0</version></creator>"
        '<scanner name="email"/><scanner name="url"/><scanner name="ip"/>'
        "</dfxml>\n",
        encoding="utf-8",
    )


def _seed_evidence(tmp_path: Path) -> tuple[AppPaths, Database, dict, Path]:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "synth.raw"
    img.write_bytes(b"DUMPLYZER-SYNTHETIC-BULK-EXTRACTOR-IMAGE")
    ev = import_evidence(db, str(img))
    return paths, db, ev, img


def _version_runner(version: str = VERIFIED_RELEASE):
    def runner(argv, *, cwd=None, timeout_secs=30, cancelled=None):
        if "-V" in argv:
            return ProcessRun(returncode=0, stdout=f"bulk_extractor {version}\n", stderr="")
        raise AssertionError(f"unexpected argv {argv}")

    return runner


def _scan_runner(
    *,
    version: str = VERIFIED_RELEASE,
    timed_out: bool = False,
    hang_until_cancel: bool = False,
    mutate_image: bool = False,
    write_features: bool = True,
    exit_code: int = 0,
):
    def runner(argv, *, cwd=None, timeout_secs=30, cancelled=None):
        if "-V" in argv:
            return ProcessRun(returncode=0, stdout=f"bulk_extractor {version}\n", stderr="")
        if hang_until_cancel:
            if cancelled and cancelled():
                return ProcessRun(returncode=-1, stdout="", stderr="", cancelled=True)
            return ProcessRun(returncode=-1, stdout="", stderr="", cancelled=True)
        if timed_out:
            return ProcessRun(returncode=-1, stdout="", stderr="", timed_out=True)
        out = Path(argv[argv.index("-o") + 1])
        image = Path(argv[-1])
        if mutate_image:
            image.write_bytes(image.read_bytes() + b"X")
        if write_features:
            _write_feature_fixture(out)
        else:
            out.mkdir(parents=True, exist_ok=True)
        return ProcessRun(returncode=exit_code, stdout="scan ok\n", stderr="")

    return runner


def test_schema_v10_has_bulk_extractor_tables(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    assert db.schema_version() == SCHEMA_VERSION
    assert SCHEMA_VERSION == 14
    db.execute("SELECT COUNT(*) AS c FROM bulk_extractor_scans")
    db.execute("SELECT COUNT(*) AS c FROM bulk_extractor_outputs")
    db.execute("SELECT COUNT(*) AS c FROM bulk_extractor_features")
    db.close()


def test_availability_unavailable(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    p = BulkExtractorProvider(
        tools_dir=paths.tools,
        analysis_dir=paths.analysis,
        artifacts_dir=paths.artifacts,
    )
    info = p.availability()
    assert info["available"] is False
    assert info["supported_target_kinds"] == ["memory_image"]
    assert info["verified_release"] == VERIFIED_RELEASE
    assert info["license"]["bundled_in_memscope"] is True
    assert info["license"]["name"] == "GPL-3.0-or-later"
    assert "reinstall" in (info["suggestion"] or "").lower() or "bulk_extractor64" in (
        info["suggestion"] or ""
    )


def test_availability_and_version_detection(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    exe = _write_dummy_exe(paths.tools / "bulk_extractor" / "bulk_extractor64.exe")
    p = BulkExtractorProvider(
        tools_dir=paths.tools,
        analysis_dir=paths.analysis,
        artifacts_dir=paths.artifacts,
        runner=_version_runner("2.2.0"),
    )
    info = p.availability()
    assert info["available"] is True
    assert info["bulk_extractor_version"] == "2.2.0"
    assert info["source"] == "user-supplied"
    assert Path(info["executable_path"]) == exe.resolve()
    assert p.detect_version() == "2.2.0"
    assert discover_executable([paths.tools]) == exe.resolve()


def test_bundled_root_preferred_over_user_tools(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    bundled = tmp_path / "resources" / "tools" / "bulk_extractor"
    user = _write_dummy_exe(paths.tools / "bulk_extractor64.exe")
    shipped = _write_dummy_exe(bundled / "bulk_extractor64.exe")
    p = BulkExtractorProvider(
        tools_dir=paths.tools,
        analysis_dir=paths.analysis,
        artifacts_dir=paths.artifacts,
        extra_tool_roots=[bundled],
        runner=_version_runner("2.2.0"),
    )
    info = p.availability()
    assert info["available"] is True
    assert info["source"] == "bundled"
    assert Path(info["executable_path"]) == shipped.resolve()
    assert Path(info["executable_path"]) != user.resolve()


def test_parse_version_output() -> None:
    assert parse_version_output("bulk_extractor 2.2.0\n") == "2.2.0"
    assert parse_version_output("bulk_extractor version 2.1.1") == "2.1.1"
    assert parse_version_output("bulk_extractor v2.0.0") == "2.0.0"
    assert parse_version_output("no version here") is None


def test_missing_and_invalid_executable(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    p = BulkExtractorProvider(
        tools_dir=paths.tools,
        analysis_dir=paths.analysis,
        artifacts_dir=paths.artifacts,
    )
    missing = paths.tools / "bulk_extractor64.exe"
    with pytest.raises(AppError) as ei:
        validate_executable_path(missing, [paths.tools])
    assert ei.value.code == "bulk_extractor_exe_missing"

    bad_name = _write_dummy_exe(paths.tools / "notepad.exe")
    with pytest.raises(AppError) as ei:
        validate_executable_path(bad_name, [paths.tools])
    assert ei.value.code == "bulk_extractor_exe_invalid"

    not_mz = paths.tools / "bulk_extractor.exe"
    not_mz.write_bytes(b"PK\x03\x04")
    with pytest.raises(AppError) as ei:
        validate_executable_path(not_mz, [paths.tools])
    assert ei.value.code == "bulk_extractor_exe_invalid"

    outside = _write_dummy_exe(tmp_path / "bulk_extractor64.exe")
    with pytest.raises(AppError) as ei:
        p.configure({"executable_path": str(outside)})
    assert ei.value.code == "bulk_extractor_exe_path_denied"

    evil = paths.artifacts / "bulk_extractor64.exe"
    _write_dummy_exe(evil)
    with pytest.raises(AppError) as ei:
        validate_executable_path(evil, [paths.tools, paths.artifacts], deny_roots=[paths.artifacts])
    assert ei.value.code == "bulk_extractor_exe_denied"


def test_configuration_rejects_extra_args(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    exe = _write_dummy_exe(paths.tools / "bulk_extractor64.exe")
    p = BulkExtractorProvider(
        tools_dir=paths.tools,
        analysis_dir=paths.analysis,
        artifacts_dir=paths.artifacts,
        runner=_version_runner(),
    )
    with pytest.raises(AppError) as ei:
        p.configure({"timeout_secs": 0})
    assert ei.value.code == "bulk_extractor_invalid_timeout"
    with pytest.raises(AppError) as ei:
        p.configure({"extra_args": ["-x", "foo"]})
    assert ei.value.code == "bulk_extractor_invalid_config"
    out = p.configure({"timeout_secs": 60, "executable_path": str(exe)})
    assert out["available"] is True
    assert p.timeout_secs == 60


def test_command_construction(tmp_path: Path) -> None:
    exe = tmp_path / "bulk_extractor64.exe"
    image = tmp_path / "img.raw"
    out = tmp_path / "analysis" / "run1"
    argv = build_scan_argv(exe, image, out)
    assert argv == [str(exe), "-o", str(out), str(image)]
    assert build_version_argv(exe) == [str(exe), "-V"]
    assert "-e" not in argv
    assert "/pid" not in argv


def test_output_directory_rules(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    existing = paths.analysis / "bulk_extractor" / "exists"
    existing.mkdir(parents=True)
    with pytest.raises(AppError) as ei:
        validate_output_dir(existing, [paths.analysis], must_not_exist=True)
    assert ei.value.code == "bulk_extractor_output_exists"

    outside = tmp_path / "not-analysis" / "out"
    with pytest.raises(AppError) as ei:
        validate_output_dir(outside, [paths.analysis])
    assert ei.value.code == "bulk_extractor_output_denied"

    fresh = paths.analysis / "bulk_extractor" / str(uuid4())
    got = validate_output_dir(fresh, [paths.analysis])
    assert got == fresh.resolve()
    assert not got.exists()
    assert fresh.parent.is_dir()


def test_parse_representative_feature_files(tmp_path: Path) -> None:
    out = tmp_path / "be-out"
    _write_feature_fixture(out)
    rows = parse_feature_file(out / "email.txt")
    assert [r["feature"] for r in rows] == [
        "alice@example.com",
        "bob@example.org",
        "pkiadmin@trustcentre.co.za0",
    ]
    assert is_feature_filename("email.txt")
    assert is_feature_filename("aes_keys.txt")
    assert is_feature_filename("sqlite_carved.txt")
    assert not is_feature_filename("url_histogram.txt")
    assert not is_feature_filename("report.xml")
    assert not is_feature_filename("ntfsmft_carved.txt")
    assert feature_kind_for_stem("url") == ("url", "url")
    assert feature_kind_for_stem("ccn")[0] == "ccn"
    assert feature_kind_for_stem("aes_keys") == ("crypto", "aes_key_candidate")
    normalized = normalize_bulk_extractor_output(
        out,
        bulk_extractor_version="2.2.0",
        exit_code=0,
        stdout="",
        stderr="",
    )
    kinds = {f["ioc_type"] for f in normalized["features"]}
    assert {"email", "url", "domain", "ip", "telephone", "ccn", "crypto", "shortcut", "sqlite"}.issubset(kinds)
    assert normalized["feature_count"] >= 6
    emails = [f["value"] for f in normalized["features"] if f["ioc_type"] == "email"]
    assert "alice@example.com" in emails
    assert "pkiadmin@trustcentre.co.za" in emails
    phones = [f["value"] for f in normalized["features"] if f["ioc_type"] == "telephone"]
    assert "+1-202-555-0100" in phones
    assert "09914277158" in phones
    assert not any("DSN" in str(f["value"]) for f in normalized["features"] if f["ioc_type"] == "telephone")
    aes = [f for f in normalized["features"] if f["category"] == "aes_keys"]
    assert aes
    assert any(f["extra"].get("weak") for f in aes)
    assert any(not f["extra"].get("weak") for f in aes)
    lnk = [f for f in normalized["features"] if f["category"] == "winlnk"]
    assert lnk
    assert "Windows" in str(lnk[0]["value"]) or "Windows" in str(lnk[0]["extra"].get("path"))
    sqlite = [f for f in normalized["features"] if f["category"] == "sqlite"]
    assert sqlite and sqlite[0]["extra"].get("size_bytes") == 4096
    assert all(f["scanner"] != "ntfsmft_carved" for f in normalized["features"])
    cat_ids = {c["id"] for c in normalized["categories"]}
    assert {"email", "telephone", "aes_keys", "winlnk", "sqlite"}.issubset(cat_ids)
    assert normalized["interpretation"]["kind"] == "extracted_artifact"
    assert "not" in normalized["interpretation"]["notes"].lower()
    scanners = set(normalized["scanners"])
    assert "email" in scanners
    assert "url" in scanners


def test_scan_normalizes_iocs_and_preserves_raw_output(tmp_path: Path) -> None:
    paths, db, ev, img = _seed_evidence(tmp_path)
    exe = _write_dummy_exe(paths.tools / "bulk_extractor64.exe")
    p = BulkExtractorProvider(
        tools_dir=paths.tools,
        analysis_dir=paths.analysis,
        artifacts_dir=paths.artifacts,
        runner=_scan_runner(),
        executable_path=exe,
    )
    before = img.read_bytes()
    mtime = img.stat().st_mtime_ns
    out = paths.analysis / "bulk_extractor" / str(uuid4())
    result = p.scan_image(img, output_dir=out)
    assert result["invoked"] is True
    assert result["feature_count"] >= 6
    assert (out / "email.txt").is_file()
    assert (out / "report.xml").is_file()
    assert (out / "dumplyzer-stdout.txt").is_file()
    assert img.read_bytes() == before
    assert img.stat().st_mtime_ns == mtime
    assert result["observed"]["feature_file_count"] >= 1
    assert result["interpretation"]["kind"] == "extracted_artifact"
    db.close()


def test_job_persists_iocs_findings_timeline_provenance(tmp_path: Path, monkeypatch) -> None:
    paths, db, ev, img = _seed_evidence(tmp_path)
    exe = _write_dummy_exe(paths.tools / "bulk_extractor64.exe")

    def _provider(_paths, _db):
        return BulkExtractorProvider(
            tools_dir=paths.tools,
            analysis_dir=paths.analysis,
            artifacts_dir=paths.artifacts,
            runner=_scan_runner(),
            executable_path=exe,
        )

    monkeypatch.setattr(bulk_extractor_workflows, "get_or_create_provider", _provider)
    percents: list[float] = []

    def progress(_msg: str, extra=None) -> None:
        if extra and extra.get("percent") is not None:
            percents.append(float(extra["percent"]))

    # persist_bulk_extractor_result updates plugin_executions; the job inserts those rows.
    bundle = bulk_extractor_workflows.run_bulk_extractor_scan_job(
        db,
        {"evidence_id": ev["id"]},
        lambda: False,
        progress,
        paths=paths,
    )
    scan = bundle["scan"]
    assert scan["status"] == "completed"
    assert scan["invoked"] is True
    assert scan["ui_state"] == "completed_features"
    assert scan["feature_count"] >= 6
    assert Path(scan["output_dir"]).is_dir()
    assert (Path(scan["output_dir"]) / "email.txt").is_file()
    assert percents
    assert percents[-1] == 100

    iocs = db.fetchall("SELECT * FROM iocs WHERE evidence_id = ?", (ev["id"],))
    assert iocs
    assert all(i["source"] == "bulk_extractor" for i in iocs)
    values = {i["value"] for i in iocs}
    assert "alice@example.com" in values
    assert "http://example.test/login" in values
    types = {i["ioc_type"] for i in iocs}
    assert "email" in types
    assert "telephone" in types
    assert "crypto" in types

    stored = db.fetchall("SELECT * FROM bulk_extractor_features WHERE evidence_id = ?", (ev["id"],))
    assert stored
    cats = {r["category"] for r in stored}
    assert {"email", "telephone", "aes_keys"}.issubset(cats)

    page = bulk_extractor_workflows.list_bulk_extractor_features(
        db, scan["id"], category="email"
    )
    assert page["total"] >= 2
    assert any(i["value"] == "alice@example.com" for i in page["items"])
    aes_page = bulk_extractor_workflows.list_bulk_extractor_features(
        db, scan["id"], category="aes_keys", hide_weak=True
    )
    assert aes_page["items"]
    assert all(not (i.get("extra") or {}).get("weak") for i in aes_page["items"])

    findings = db.fetchall("SELECT * FROM findings WHERE evidence_id = ?", (ev["id"],))
    assert findings
    assert all(f["plugin"] == "provider.bulk_extractor" for f in findings)
    assert all(f["severity"] == "info" for f in findings)
    assert all(f["confidence"] == "extracted" for f in findings)
    assert all("not a confirmed malicious" in (f["explanation"] or "").lower() for f in findings)

    events = db.fetchall(
        "SELECT * FROM timeline_events WHERE evidence_id = ? AND event_kind = 'bulk_extractor'",
        (ev["id"],),
    )
    assert len(events) == 1
    prov = json.loads(events[0]["provenance_json"])
    assert prov["provider"] == "bulk_extractor"
    assert prov["kind"] == "extracted_artifact"

    doc = collect_investigation(
        db,
        ev["id"],
        fmt="json",
        sections=["malware", "summary", "iocs", "findings"],
    )
    be = doc["malware"]["bulk_extractor"]
    assert be["total"] == 1
    assert "Extracted Artifact" in be["note"]
    assert doc["summary"]["bulk_extractor_scan_count"] == 1
    assert img.read_bytes() == b"DUMPLYZER-SYNTHETIC-BULK-EXTRACTOR-IMAGE"
    db.close()


def test_timeout_and_cancellation(tmp_path: Path) -> None:
    paths, db, ev, img = _seed_evidence(tmp_path)
    exe = _write_dummy_exe(paths.tools / "bulk_extractor64.exe")
    p = BulkExtractorProvider(
        tools_dir=paths.tools,
        analysis_dir=paths.analysis,
        artifacts_dir=paths.artifacts,
        runner=_scan_runner(timed_out=True),
        executable_path=exe,
        timeout_secs=1,
    )
    with pytest.raises(AppError) as ei:
        p.scan_image(img, output_dir=paths.analysis / "bulk_extractor" / "to")
    assert ei.value.code == "bulk_extractor_timeout"

    p2 = BulkExtractorProvider(
        tools_dir=paths.tools,
        analysis_dir=paths.analysis,
        artifacts_dir=paths.artifacts,
        runner=_scan_runner(hang_until_cancel=True),
        executable_path=exe,
    )
    with pytest.raises(AppError) as ei:
        p2.scan_image(
            img,
            output_dir=paths.analysis / "bulk_extractor" / "cancel",
            cancelled=lambda: True,
        )
    assert ei.value.code == "job_cancelled"
    db.close()


def test_unavailable_job(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DUMPLYZER_BUNDLE_TOOLS", raising=False)
    isolated = tmp_path / "isolated-python.exe"
    isolated.write_bytes(b"")
    monkeypatch.setattr(sys, "executable", str(isolated))
    paths, db, ev, _img = _seed_evidence(tmp_path)
    with pytest.raises(AppError) as ei:
        bulk_extractor_workflows.run_bulk_extractor_scan_job(
            db,
            {"evidence_id": ev["id"]},
            lambda: False,
            lambda *_a, **_k: None,
            paths=paths,
        )
    assert ei.value.code == "bulk_extractor_unavailable"
    row = db.fetchone("SELECT * FROM bulk_extractor_scans WHERE evidence_id = ?", (ev["id"],))
    assert row is not None
    assert row["status"] == "unavailable"
    db.close()


def test_evidence_immutability_detected(tmp_path: Path) -> None:
    paths, db, ev, img = _seed_evidence(tmp_path)
    exe = _write_dummy_exe(paths.tools / "bulk_extractor64.exe")
    p = BulkExtractorProvider(
        tools_dir=paths.tools,
        analysis_dir=paths.analysis,
        artifacts_dir=paths.artifacts,
        runner=_scan_runner(mutate_image=True),
        executable_path=exe,
    )
    with pytest.raises(AppError) as ei:
        p.scan_image(img, output_dir=paths.analysis / "bulk_extractor" / "mut")
    assert ei.value.code == "bulk_extractor_evidence_mutated"
    db.close()


def test_ui_state_transitions() -> None:
    assert compute_ui_state(available=False) == "unavailable"
    assert compute_ui_state(available=True) == "idle"
    assert compute_ui_state(available=True, scan_status="running") == "running"
    assert (
        compute_ui_state(available=True, scan_status="completed", feature_count=3)
        == "completed_features"
    )
    assert (
        compute_ui_state(available=True, scan_status="completed", feature_count=0)
        == "completed_no_features"
    )


def test_ipc_round_trip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MEMSCOPE_DATA_DIR", str(tmp_path / "ipcdata"))
    monkeypatch.delenv("DUMPLYZER_BUNDLE_TOOLS", raising=False)
    isolated = tmp_path / "isolated-python.exe"
    isolated.write_bytes(b"")
    monkeypatch.setattr(sys, "executable", str(isolated))
    from memscope_engine.server import HANDLERS, handle_app_init

    init = handle_app_init({"data_dir": str(tmp_path / "ipcdata")})
    assert init["schema_version"] == SCHEMA_VERSION
    assert "bulk_extractor" in init
    status = HANDLERS["bulk_extractor.status"]({})
    assert status["available"] is False
    assert status["ui_state"] == "unavailable"
    with pytest.raises(AppError):
        HANDLERS["bulk_extractor.configure"](
            {"executable_path": str(tmp_path / "bulk_extractor64.exe")}
        )
    from memscope_engine import server as srv

    engine_db = srv._db()
    img = tmp_path / "ipc.raw"
    img.write_bytes(b"ipc-img")
    ev = import_evidence(engine_db, str(img))
    job = HANDLERS["bulk_extractor.scan"]({"evidence_id": ev["id"]})
    assert job["kind"] == "bulk_extractor_scan"
    for _ in range(100):
        got = HANDLERS["jobs.get"]({"job_id": job["id"]})
        if got["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.05)
    got = HANDLERS["jobs.get"]({"job_id": job["id"]})
    assert got["status"] == "failed"
    listed = HANDLERS["bulk_extractor.scans"]({"evidence_id": ev["id"]})
    assert listed["total"] >= 1
    scan_id = listed["items"][0]["scan"]["id"]
    fetched = HANDLERS["bulk_extractor.scan_get"]({"scan_id": scan_id})
    assert fetched["scan"]["id"] == scan_id


def test_real_bulk_extractor_version_if_installed() -> None:
    """Only runs -V against a real EXE. Does not scan a memory dump."""
    roots = [
        Path(__file__).resolve().parents[2]
        / "app"
        / "desktop"
        / "resources"
        / "tools"
        / "bulk_extractor",
    ]
    local = os.environ.get("LOCALAPPDATA")
    if local:
        roots.append(Path(local) / "Dumplyzer" / "tools")
    found = None
    for root in roots:
        for name in ("bulk_extractor64.exe", "bulk_extractor.exe", "bulk_extractor32.exe"):
            cand = root / name
            if cand.is_file():
                found = cand
                break
            cand = root / "bulk_extractor" / name
            if cand.is_file():
                found = cand
                break
        if found:
            break
    if found is None:
        pytest.skip("bulk_extractor is not installed on this machine")
    from memscope_engine.providers.process_run import default_subprocess_runner

    p = BulkExtractorProvider(runner=default_subprocess_runner)
    version = p.detect_version(found)
    assert version
    assert version.startswith("2.")
    assert parse_version_output(f"bulk_extractor {version}") == version
    import pefile

    pe = pefile.PE(str(found), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    dlls = []
    if getattr(pe, "DIRECTORY_ENTRY_IMPORT", None):
        dlls = [e.dll.decode("ascii", "replace").lower() for e in pe.DIRECTORY_ENTRY_IMPORT]
    forbidden = ("libgcc", "libstdc++", "libwinpthread", "libgcc_s", "libre2", "libabsl", "libexpat", "zlib1", "libcrypto")
    assert not any(any(f in d for f in forbidden) for d in dlls), dlls


def test_real_scan_synthetic_if_bundled(tmp_path: Path) -> None:
    exe = (
        Path(__file__).resolve().parents[2]
        / "app"
        / "desktop"
        / "resources"
        / "tools"
        / "bulk_extractor"
        / "bulk_extractor64.exe"
    )
    if not exe.is_file():
        pytest.skip("bundled bulk_extractor64.exe is not prepared")
    from memscope_engine.providers.process_run import default_subprocess_runner

    paths, db, ev, img = _seed_evidence(tmp_path)
    before = img.read_bytes()
    mtime = img.stat().st_mtime_ns
    p = BulkExtractorProvider(
        tools_dir=paths.tools,
        analysis_dir=paths.analysis,
        artifacts_dir=paths.artifacts,
        extra_tool_roots=[exe.parent],
        executable_path=exe,
        runner=default_subprocess_runner,
        timeout_secs=180,
    )
    out = paths.analysis / "bulk_extractor" / "real-synth"
    result = p.scan_image(img, output_dir=out)
    assert result["invoked"] is True
    assert result["exit_code"] == 0
    assert Path(result["output_dir"]).is_dir()
    assert (out / "report.xml").is_file() or list(out.glob("*.txt"))
    assert img.read_bytes() == before
    assert img.stat().st_mtime_ns == mtime
    db.close()


def test_high_value_scanners_not_starved_by_domains(tmp_path: Path) -> None:
    out = tmp_path / "be-flood"
    out.mkdir()
    domain_lines = [f"{i}\tflood{i}.example.test\tctx\n" for i in range(6000)]
    (out / "domain.txt").write_text("".join(domain_lines), encoding="utf-8")
    (out / "email.txt").write_text("1\tkeepme@case.test\tctx\n", encoding="utf-8")
    (out / "telephone.txt").write_text("2\t+1-202-555-0199\tctx\n", encoding="utf-8")
    (out / "aes_keys.txt").write_text(
        "3\taa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99\tAES128\n",
        encoding="utf-8",
    )
    normalized = normalize_bulk_extractor_output(
        out, bulk_extractor_version="2.2.0", exit_code=0, stdout="", stderr=""
    )
    values = {f["value"] for f in normalized["features"]}
    assert "keepme@case.test" in values
    assert "+1-202-555-0199" in values
    assert any(f["category"] == "aes_keys" for f in normalized["features"])
    cat_ids = {c["id"] for c in normalized["categories"]}
    assert {"email", "telephone", "aes_keys", "domain"}.issubset(cat_ids)


def test_user_bulk_extractor_output_if_present() -> None:
    """Parse a real bulk_extractor directory when the analyst left one on disk."""
    root = Path(r"F:\Case\Bulk-Extractor_Output")
    if not root.is_dir() or not (root / "email.txt").is_file():
        pytest.skip("analyst bulk_extractor output is not present")
    normalized = normalize_bulk_extractor_output(
        root, bulk_extractor_version="2.2.0", exit_code=0, stdout="", stderr=""
    )
    cat_ids = {c["id"] for c in normalized["categories"]}
    assert {"email", "telephone", "aes_keys"}.issubset(cat_ids)
    assert any(f["ioc_type"] == "email" for f in normalized["features"])
    assert any(f["ioc_type"] == "telephone" for f in normalized["features"])
    assert any(f["category"] == "aes_keys" and not f["extra"].get("weak") for f in normalized["features"])
    assert any(f["category"] == "winlnk" for f in normalized["features"])
