"""PE-sieve provider, workflow, schema, and IPC tests."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from uuid import uuid4

import pytest

from memscope_engine.analysis import pe_sieve_workflows
from memscope_engine.analysis.memory_artifacts import get_artifact
from memscope_engine.analysis.workflows import import_evidence
from memscope_engine.artifacts import store as artifact_store
from memscope_engine.errors import AppError
from memscope_engine.jobs.manager import JobManager
from memscope_engine.paths import AppPaths
from memscope_engine.providers.pe_sieve import (
    TARGET_ARTIFACT,
    TARGET_LIVE_PROCESS,
    PeSieveProvider,
    ProcessRun,
    VERIFIED_RELEASE,
    build_scan_argv,
    build_version_argv,
    compute_ui_state,
    describe_target,
    interpret_exit_code,
    normalize_pe_sieve_output,
    parse_version_output,
    validate_executable_path,
    validate_live_pid,
    validate_output_dir,
)
from memscope_engine.storage import Database

# Documented v0.4.1.1 scan_report / dump_report shape (wiki + ResultsDumper).
_SCAN_REPORT = {
    "pid": 684,
    "is_64_bit": 1,
    "is_managed": 0,
    "main_image_path": "",
    "used_reflection": 0,
    "scanned": {
        "total": 48,
        "skipped": 0,
        "modified": {
            "total": 2,
            "patched": 0,
            "iat_hooked": 0,
            "replaced": 1,
            "hdr_modified": 0,
            "implanted_pe": 0,
            "implanted_shc": 0,
            "unreachable_file": 0,
            "other": 1,
        },
        "errors": 0,
    },
    "scans": [
        {
            "mapping_scan": {
                "module": "7ff6bc950000",
                "module_file": r"C:\Windows\notepad.exe",
                "mapped_file": "",
                "status": 1,
            }
        },
        {
            "headers_scan": {
                "module": "7ff6bc950000",
                "module_file": r"C:\Windows\notepad.exe",
                "status": 1,
                "is_pe_replaced": 1,
            }
        },
    ],
}

_DUMP_REPORT = {
    "pid": 684,
    "output_dir": "process_684",
    "dumped": {"total": 1, "dumped": 1},
    "dumps": [
        {
            "module": "7ff6bc950000",
            "module_size": "e4000",
            "dump_file": "7ff6bc950000.notepad.exe",
            "dump_mode": "UNMAPPED",
            "is_shellcode": 0,
            "status": 1,
        }
    ],
}


def _mz_stub() -> bytes:
    return b"MZ" + b"\x00" * 64


def _write_dummy_exe(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_mz_stub())
    return path


def _seed_artifact(tmp_path: Path) -> tuple[AppPaths, Database, dict, str]:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "img.raw"
    img.write_bytes(b"pesieve-img")
    ev = import_evidence(db, str(img))
    adir = artifact_store.artifact_dir(paths, ev["id"])
    apath = adir / "pid.1.vad.x1000-x2000.dmp"
    apath.write_bytes(_mz_stub())
    digest = artifact_store.sha256_file(apath)
    art_id = str(uuid4())
    db.execute(
        """
        INSERT INTO artifacts (
          id, evidence_id, process_id, pid, memory_region_id, filename, stored_path,
          sha256, size_bytes, file_type, extraction_method, source_plugin, tool_name,
          tool_version, start_vpn, end_vpn, extracted_at, notes, metadata_json
        ) VALUES (?, ?, NULL, 1, NULL, ?, ?, ?, ?, 'pe', 'test', 'test', 'test', '0',
          '0x1000', '0x2000', '2020-01-01T00:00:00+00:00', 'fixture', '{}')
        """,
        (art_id, ev["id"], apath.name, str(apath), digest, apath.stat().st_size),
    )
    return paths, db, ev, art_id


def _version_runner(version: str = VERIFIED_RELEASE):
    def runner(argv, *, cwd=None, timeout_secs=30, cancelled=None):
        if "/version" in argv:
            return ProcessRun(returncode=0, stdout=f"{version}\n", stderr="")
        raise AssertionError(f"unexpected argv {argv}")

    return runner


def _scan_runner(
    *,
    version: str = VERIFIED_RELEASE,
    scan_report: dict | None = None,
    dump_report: dict | None = None,
    dump_bytes: bytes = b"MZDUMP",
    exit_code: int = 2,
    sleep_secs: float = 0,
    hang_until_cancel: bool = False,
    write_reports: bool = True,
    malformed: bool = False,
):
    def runner(argv, *, cwd=None, timeout_secs=30, cancelled=None):
        if "/version" in argv:
            return ProcessRun(returncode=0, stdout=f"{version}\n", stderr="")
        if hang_until_cancel:
            deadline = time.time() + max(timeout_secs, 1)
            while time.time() < deadline:
                if cancelled and cancelled():
                    return ProcessRun(returncode=-1, stdout="", stderr="", cancelled=True)
                time.sleep(0.05)
            return ProcessRun(returncode=-1, stdout="", stderr="", timed_out=True)
        if sleep_secs:
            time.sleep(sleep_secs)
            if time.time() and sleep_secs > timeout_secs:
                return ProcessRun(returncode=-1, stdout="", stderr="", timed_out=True)
            if sleep_secs > timeout_secs:
                return ProcessRun(returncode=-1, stdout="", stderr="", timed_out=True)
        out_dir = None
        if "/dir" in argv:
            out_dir = Path(argv[argv.index("/dir") + 1])
        if write_reports and out_dir is not None:
            proc_dir = out_dir / "process_684"
            proc_dir.mkdir(parents=True, exist_ok=True)
            if malformed:
                (proc_dir / "scan_report.json").write_text("{not-json", encoding="utf-8")
            else:
                sr = scan_report if scan_report is not None else _SCAN_REPORT
                dr = dump_report if dump_report is not None else _DUMP_REPORT
                (proc_dir / "scan_report.json").write_text(json.dumps(sr), encoding="utf-8")
                (proc_dir / "dump_report.json").write_text(json.dumps(dr), encoding="utf-8")
                dump_name = (dr.get("dumps") or [{}])[0].get("dump_file") or "module.bin"
                (proc_dir / Path(str(dump_name)).name).write_bytes(dump_bytes)
        return ProcessRun(returncode=exit_code, stdout="", stderr="")

    return runner


def test_schema_v7_includes_v6(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    assert db.schema_version() == 8
    db.execute("SELECT COUNT(*) AS c FROM pe_sieve_scans")
    db.execute("SELECT COUNT(*) AS c FROM pe_sieve_outputs")
    db.execute("SELECT parent_artifact_id FROM artifacts LIMIT 1")
    db.close()


def test_availability_unavailable(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    p = PeSieveProvider(tools_dir=paths.tools, tmp_dir=paths.tmp, artifacts_dir=paths.artifacts)
    info = p.availability()
    assert info["available"] is False
    assert info["memscope_artifact_targets_supported"] is False
    assert info["supported_target_kinds"] == ["live_process"]
    assert info["verified_release"] == VERIFIED_RELEASE
    assert info["license"]["bundled_in_memscope"] is False


def test_availability_and_version_detection(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    exe = _write_dummy_exe(paths.tools / "pe-sieve" / "pe-sieve64.exe")
    p = PeSieveProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_version_runner("0.4.1.1"),
    )
    info = p.availability()
    assert info["available"] is True
    assert info["pe_sieve_version"] == "0.4.1.1"
    assert Path(info["executable_path"]) == exe.resolve()
    assert p.detect_version() == "0.4.1.1"


def test_parse_version_output() -> None:
    assert parse_version_output("0.4.1.1\n") == "0.4.1.1"
    assert parse_version_output("Version:  0.4.1.1 (x64)") == "0.4.1.1"
    assert parse_version_output("no version here") is None


def test_configuration_validation(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    exe = _write_dummy_exe(paths.tools / "pe-sieve64.exe")
    p = PeSieveProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_version_runner(),
    )
    with pytest.raises(AppError) as ei:
        p.configure({"timeout_secs": 0})
    assert ei.value.code == "pe_sieve_invalid_timeout"
    with pytest.raises(AppError) as ei:
        p.configure({"extra_args": ["/pid", "1"]})
    assert ei.value.code == "pe_sieve_invalid_config"
    out = p.configure({"timeout_secs": 30, "executable_path": str(exe)})
    assert out["available"] is True
    assert p.timeout_secs == 30


def test_executable_path_allow_list(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    outside = _write_dummy_exe(tmp_path / "pe-sieve64.exe")
    p = PeSieveProvider(tools_dir=paths.tools, tmp_dir=paths.tmp, artifacts_dir=paths.artifacts)
    with pytest.raises(AppError) as ei:
        validate_executable_path(outside, [paths.tools], deny_roots=[paths.artifacts])
    assert ei.value.code == "pe_sieve_exe_path_denied"
    with pytest.raises(AppError) as ei:
        p.configure({"executable_path": str(outside)})
    assert ei.value.code == "pe_sieve_exe_path_denied"

    # Artifact must never become the executed program.
    evil = artifact_store.artifact_dir(paths, "ev1") / "pe-sieve64.exe"
    _write_dummy_exe(evil)
    with pytest.raises(AppError) as ei:
        validate_executable_path(evil, [paths.tools, paths.artifacts], deny_roots=[paths.artifacts])
    assert ei.value.code == "pe_sieve_exe_denied"

    not_pe = paths.tools / "pe-sieve64.exe"
    not_pe.write_bytes(b"NO")
    with pytest.raises(AppError) as ei:
        validate_executable_path(not_pe, [paths.tools])
    assert ei.value.code == "pe_sieve_exe_invalid"


def test_target_validation_and_unsupported() -> None:
    art = describe_target(TARGET_ARTIFACT)
    assert art["supported"] is False
    live = describe_target(TARGET_LIVE_PROCESS)
    assert live["supported"] is True
    p = PeSieveProvider()
    with pytest.raises(AppError) as ei:
        p.assert_target_supported(TARGET_ARTIFACT)
    assert ei.value.code == "pe_sieve_unsupported_target"
    with pytest.raises(AppError):
        validate_live_pid(0)
    with pytest.raises(AppError):
        validate_live_pid("nope")
    assert validate_live_pid(684) == 684
    assert validate_live_pid("0x2ac") == 0x2AC


def test_command_construction(tmp_path: Path) -> None:
    exe = tmp_path / "pe-sieve64.exe"
    out = tmp_path / "out"
    argv = build_scan_argv(exe, 684, out)
    assert argv[0] == str(exe)
    assert argv[1:5] == ["/pid", "684", "/dir", str(out)]
    assert "/json" in argv and "/quiet" in argv
    assert "/minidmp" not in argv
    assert argv[0] != str(tmp_path / "artifact.exe")
    ver = build_version_argv(exe)
    assert ver == [str(exe), "/version"]


def test_timeout(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    _write_dummy_exe(paths.tools / "pe-sieve64.exe")

    def runner(argv, *, cwd=None, timeout_secs=30, cancelled=None):
        if "/version" in argv:
            return ProcessRun(returncode=0, stdout="0.4.1.1\n", stderr="")
        return ProcessRun(returncode=-1, stdout="", stderr="", timed_out=True)

    p = PeSieveProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=runner,
        timeout_secs=1,
    )
    with pytest.raises(AppError) as ei:
        p.scan_live_process(4, output_dir=paths.tmp / "pe_sieve" / "t")
    assert ei.value.code == "pe_sieve_timeout"


def test_cancellation(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    _write_dummy_exe(paths.tools / "pe-sieve64.exe")
    p = PeSieveProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_scan_runner(hang_until_cancel=True),
        timeout_secs=5,
    )
    flag = {"c": False}

    def cancelled() -> bool:
        return flag["c"]

    flag["c"] = True
    with pytest.raises(AppError) as ei:
        p.scan_live_process(4, output_dir=paths.tmp / "pe_sieve" / "t", cancelled=cancelled)
    assert ei.value.code == "job_cancelled"


def test_provider_unavailable_scan(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    p = PeSieveProvider(tools_dir=paths.tools, tmp_dir=paths.tmp, artifacts_dir=paths.artifacts)
    with pytest.raises(AppError) as ei:
        p.scan_live_process(4)
    assert ei.value.code == "pe_sieve_unavailable"


def test_malformed_output(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    _write_dummy_exe(paths.tools / "pe-sieve64.exe")
    p = PeSieveProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_scan_runner(malformed=True, exit_code=1),
    )
    with pytest.raises(AppError) as ei:
        p.scan_live_process(684, output_dir=paths.tmp / "pe_sieve" / "bad")
    assert ei.value.code == "pe_sieve_output_invalid"


def test_missing_output(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    _write_dummy_exe(paths.tools / "pe-sieve64.exe")
    p = PeSieveProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_scan_runner(write_reports=False, exit_code=1),
    )
    with pytest.raises(AppError) as ei:
        p.scan_live_process(684, output_dir=paths.tmp / "pe_sieve" / "empty")
    assert ei.value.code == "pe_sieve_output_invalid"


def test_valid_output_normalization(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    _write_dummy_exe(paths.tools / "pe-sieve64.exe")
    p = PeSieveProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_scan_runner(exit_code=2),
    )
    result = p.scan_live_process(684, output_dir=paths.tmp / "pe_sieve" / "ok")
    assert result["status"] == "completed"
    assert result["pesieve_result"] == "detected"
    assert result["observed"]["scan_report"]["modified"]["replaced"] == 1
    assert result["observed"]["scan_report"]["module_scans"]
    assert result["interpretation"]["source"] == "memscope"
    assert "malware" not in result["interpretation"]["summary"].lower()
    assert result["interpretation"]["has_indicators"] is True
    assert result["ui_state"] == "completed_indicators"
    # no-findings path
    empty = dict(_SCAN_REPORT)
    empty["scanned"] = {
        "total": 10,
        "skipped": 0,
        "modified": {"total": 0, "patched": 0, "iat_hooked": 0, "replaced": 0,
                     "hdr_modified": 0, "implanted_pe": 0, "implanted_shc": 0,
                     "unreachable_file": 0, "other": 0},
        "errors": 0,
    }
    empty["scans"] = []
    p.runner = _scan_runner(scan_report=empty, dump_report={"pid": 684, "dumps": []}, exit_code=1)
    result2 = p.scan_live_process(684, output_dir=paths.tmp / "pe_sieve" / "none")
    assert result2["pesieve_result"] == "not_detected"
    assert result2["ui_state"] == "completed_no_findings"


def test_normalize_malformed_types() -> None:
    out = normalize_pe_sieve_output(
        scan_report={"pid": 1, "scanned": "nope"},
        dump_report={"dumps": "nope"},
        error_report=None,
        exit_code=1,
        pe_sieve_version="0.4.1.1",
        executable_path="pe-sieve64.exe",
        output_dir="x",
        live_pid=1,
        argv=["pe-sieve64.exe", "/pid", "1"],
    )
    assert out["pesieve_result"] == "not_detected"
    assert out["observed"]["scan_report"]["modified"]["total"] is None


def test_artifact_creation_sha256_provenance(tmp_path: Path) -> None:
    paths, db, ev, art_id = _seed_artifact(tmp_path)
    _write_dummy_exe(paths.tools / "pe-sieve64.exe")
    p = PeSieveProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_scan_runner(exit_code=2, dump_bytes=b"MZPE-SIEVE-DUMP"),
    )
    result = p.scan_live_process(684, output_dir=paths.tmp / "pe_sieve" / "ing")
    parent = db.fetchone("SELECT * FROM artifacts WHERE id = ?", (art_id,))
    bundle = pe_sieve_workflows.persist_pe_sieve_result(
        db,
        paths,
        evidence_id=ev["id"],
        result=result,
        artifact_id=art_id,
        process_id=parent["process_id"],
        pid=parent["pid"],
        memory_region_id=parent["memory_region_id"],
    )
    assert bundle["scan"]["ui_state"] == "completed_indicators"
    assert bundle["outputs"]
    dump = next(o for o in bundle["outputs"] if o["role"] == "dump_file")
    assert dump["sha256"]
    assert len(dump["sha256"]) == 64
    stored = Path(dump["stored_path"])
    assert stored.is_file()
    assert artifact_store.sha256_file(stored) == dump["sha256"]
    assert stored.read_bytes() == b"MZPE-SIEVE-DUMP"
    # source artifact untouched
    src = Path(parent["stored_path"])
    assert src.read_bytes().startswith(b"MZ")
    assert src.read_bytes() != b"MZPE-SIEVE-DUMP"
    child = get_artifact(db, dump["artifact_id"])
    assert child["parent_artifact_id"] == art_id
    assert child["tool_name"] == "pe-sieve"
    assert any(s.get("step") == "source_artifact" for s in child["provenance_chain"])
    assert any(s.get("step") == "pe_sieve_output" for s in child["provenance_chain"])
    db.close()


def test_output_dir_must_be_under_tmp(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    with pytest.raises(AppError) as ei:
        validate_output_dir(tmp_path / "outside", [paths.tmp])
    assert ei.value.code == "pe_sieve_output_denied"


def test_unsupported_artifact_job(tmp_path: Path) -> None:
    paths, db, ev, art_id = _seed_artifact(tmp_path)
    _write_dummy_exe(paths.tools / "pe-sieve64.exe")
    provider = pe_sieve_workflows.get_or_create_provider(paths, db)
    provider.runner = _version_runner()
    pe_sieve_workflows.save_pe_sieve_settings(db, provider)

    jm = JobManager(db)

    def handler(db_, params, cancelled, progress):
        return pe_sieve_workflows.run_pe_sieve_artifact_scan_job(
            db_, params, cancelled, progress, paths=paths
        )

    jm.register("pe_sieve_artifact_scan", handler)
    jm.start()
    job = jm.submit(
        "pe_sieve_artifact_scan",
        evidence_id=ev["id"],
        params={"artifact_id": art_id},
        message="test pe-sieve",
    )
    for _ in range(100):
        j = jm.get(job["id"])
        if j["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.05)
    j = jm.get(job["id"])
    assert j["status"] == "completed", j
    assert j["result"]["scan"]["status"] == "unsupported_target"
    assert j["result"]["scan"]["ui_state"] == "unsupported_target"
    assert j["result"]["scan"]["observed"]["invoked"] is False
    db.close()


def test_unavailable_artifact_job(tmp_path: Path) -> None:
    paths, db, ev, art_id = _seed_artifact(tmp_path)
    jm = JobManager(db)

    def handler(db_, params, cancelled, progress):
        return pe_sieve_workflows.run_pe_sieve_artifact_scan_job(
            db_, params, cancelled, progress, paths=paths
        )

    jm.register("pe_sieve_artifact_scan", handler)
    jm.start()
    job = jm.submit(
        "pe_sieve_artifact_scan",
        evidence_id=ev["id"],
        params={"artifact_id": art_id},
    )
    for _ in range(100):
        j = jm.get(job["id"])
        if j["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.05)
    j = jm.get(job["id"])
    assert j["status"] == "failed"
    scans = pe_sieve_workflows.list_pe_sieve_scans_for_artifact(db, art_id)
    assert scans["items"][0]["scan"]["ui_state"] == "unavailable"
    db.close()


def test_ui_state_transitions() -> None:
    assert compute_ui_state(available=False) == "unavailable"
    assert compute_ui_state(available=True, target_kind=TARGET_ARTIFACT) == "unsupported_target"
    assert compute_ui_state(available=True, scan_status="queued") == "queued"
    assert compute_ui_state(available=True, scan_status="running") == "running"
    assert compute_ui_state(available=True, scan_status="failed") == "failed"
    assert compute_ui_state(available=True, scan_status="cancelled") == "cancelled"
    assert (
        compute_ui_state(available=True, scan_status="completed", pesieve_result="not_detected", modified_total=0)
        == "completed_no_findings"
    )
    assert (
        compute_ui_state(available=True, scan_status="completed", pesieve_result="detected", modified_total=2)
        == "completed_indicators"
    )


def test_exit_code_mapping() -> None:
    assert interpret_exit_code(-1) == "error"
    assert interpret_exit_code(0) == "info"
    assert interpret_exit_code(1) == "not_detected"
    assert interpret_exit_code(2) == "detected"
    assert interpret_exit_code(4294967295) == "error"


def test_ipc_round_trip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MEMSCOPE_DATA_DIR", str(tmp_path / "ipcdata"))
    from memscope_engine.server import HANDLERS, handle_app_init

    init = handle_app_init({"data_dir": str(tmp_path / "ipcdata")})
    assert init["schema_version"] == 8
    assert "pe_sieve" in init
    status = HANDLERS["pe_sieve.status"]({})
    assert status["available"] is False
    assert status["ui_state"] == "unavailable"
    with pytest.raises(AppError):
        HANDLERS["pe_sieve.configure"]({"executable_path": str(tmp_path / "pe-sieve64.exe")})
    from memscope_engine import server as srv

    engine_db = srv._db()
    engine_paths = srv._paths()
    img = tmp_path / "ipc.raw"
    img.write_bytes(b"ipc-img")
    ev = import_evidence(engine_db, str(img))
    adir = artifact_store.artifact_dir(engine_paths, ev["id"])
    apath = adir / "a.dmp"
    apath.write_bytes(_mz_stub())
    art_id = str(uuid4())
    engine_db.execute(
        """
        INSERT INTO artifacts (
          id, evidence_id, process_id, pid, memory_region_id, filename, stored_path,
          sha256, size_bytes, file_type, extraction_method, source_plugin, tool_name,
          tool_version, extracted_at, notes, metadata_json
        ) VALUES (?, ?, NULL, 1, NULL, ?, ?, ?, ?, 'pe', 'test', 'test', 'test', '0',
          '2020-01-01T00:00:00+00:00', 'fixture', '{}')
        """,
        (art_id, ev["id"], apath.name, str(apath), artifact_store.sha256_file(apath), apath.stat().st_size),
    )
    job = HANDLERS["pe_sieve.scan_artifact"]({"artifact_id": art_id, "evidence_id": ev["id"]})
    assert job["kind"] == "pe_sieve_artifact_scan"
    for _ in range(100):
        got = HANDLERS["jobs.get"]({"job_id": job["id"]})
        if got["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.05)
    got = HANDLERS["jobs.get"]({"job_id": job["id"]})
    assert got["status"] == "failed"  # unavailable on this machine
    listed = HANDLERS["pe_sieve.scans_for_artifact"]({"artifact_id": art_id})
    assert listed["total"] >= 1
    scan_id = listed["items"][0]["scan"]["id"]
    fetched = HANDLERS["pe_sieve.scan_get"]({"scan_id": scan_id})
    assert fetched["scan"]["id"] == scan_id
    art = HANDLERS["artifacts.get"]({"artifact_id": art_id})
    assert "pe_sieve_status" in art
    assert "pe_sieve_scans" in art


def test_real_pe_sieve_version_if_installed() -> None:
    """Only runs /version against a real EXE. Does not scan live processes."""
    roots = []
    local = os.environ.get("LOCALAPPDATA")
    if local:
        roots.append(Path(local) / "MemScope" / "tools")
    found = None
    for root in roots:
        for name in ("pe-sieve64.exe", "pe-sieve.exe", "pe-sieve32.exe"):
            cand = root / name
            if cand.is_file():
                found = cand
                break
            cand = root / "pe-sieve" / name
            if cand.is_file():
                found = cand
                break
        if found:
            break
    if found is None:
        pytest.skip("PE-sieve is not installed on this machine")
    from memscope_engine.providers.pe_sieve import default_subprocess_runner

    run = default_subprocess_runner(build_version_argv(found), cwd=found.parent, timeout_secs=15)
    ver = parse_version_output(run.stdout + "\n" + run.stderr)
    assert ver  # real tool responded; do not invent findings
