"""mal_unpack provider, workflow, schema, and IPC tests."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from uuid import uuid4

import pytest

from memscope_engine.analysis import mal_unpack_workflows
from memscope_engine.analysis.memory_artifacts import get_artifact
from memscope_engine.analysis.workflows import import_evidence
from memscope_engine.artifacts import store as artifact_store
from memscope_engine.errors import AppError
from memscope_engine.jobs.manager import JobManager
from memscope_engine.paths import AppPaths
from memscope_engine.providers.mal_unpack import (
    TARGET_ARTIFACT,
    TARGET_EXECUTABLE_FILE,
    TARGET_LIVE_PROCESS,
    TARGET_MEMORY_DUMP,
    TARGET_MEMORY_REGION,
    VERIFIED_RELEASE,
    VERIFIED_VERSION_STR,
    MalUnpackProvider,
    ProcessRun,
    build_unpack_argv,
    build_version_argv,
    compute_ui_state,
    describe_target,
    parse_mal_unpack_version,
    validate_executable_path,
    validate_output_dir,
)
from memscope_engine.storage import Database

# PE-sieve dump reports emitted under mal_unpack's scan_{ts}/ tree (verified 1.0 layout).
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
    "scans": [],
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
    img.write_bytes(b"malunpack-img")
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


def _version_runner(version: str = VERIFIED_VERSION_STR):
    def runner(argv, *, cwd=None, timeout_secs=30, cancelled=None):
        if "/version" in argv:
            return ProcessRun(returncode=0, stdout=f"MalUnpack: v.{version}\n", stderr="")
        raise AssertionError(f"unexpected argv {argv}")

    return runner


def _unpack_runner(
    *,
    version: str = VERIFIED_VERSION_STR,
    scan_report: dict | None = None,
    dump_report: dict | None = None,
    dump_bytes: bytes = b"MZUNPACK",
    exit_code: int = 2,
    hang_until_cancel: bool = False,
    write_reports: bool = True,
    malformed: bool = False,
    timed_out: bool = False,
):
    def runner(argv, *, cwd=None, timeout_secs=30, cancelled=None):
        if "/version" in argv:
            return ProcessRun(returncode=0, stdout=f"MalUnpack: v.{version}\n", stderr="")
        if hang_until_cancel:
            deadline = time.time() + max(timeout_secs, 1)
            while time.time() < deadline:
                if cancelled and cancelled():
                    return ProcessRun(returncode=-1, stdout="", stderr="", cancelled=True)
                time.sleep(0.05)
            return ProcessRun(returncode=-1, stdout="", stderr="", timed_out=True)
        if timed_out:
            return ProcessRun(returncode=-1, stdout="", stderr="", timed_out=True)
        out_dir = None
        sample = None
        if "/dir" in argv:
            out_dir = Path(argv[argv.index("/dir") + 1])
        if "/exe" in argv:
            sample = Path(argv[argv.index("/exe") + 1])
        if write_reports and out_dir is not None:
            scan_root = out_dir / f"{(sample.name if sample else 'sample.exe')}.out" / "scan_1700000000"
            proc_dir = scan_root / "process_684"
            proc_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "unpack.log").write_text("unpack fixture log\n", encoding="utf-8")
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


def test_schema_v7(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    assert db.schema_version() == 9
    db.execute("SELECT COUNT(*) AS c FROM mal_unpack_scans")
    db.execute("SELECT COUNT(*) AS c FROM mal_unpack_outputs")
    db.execute("SELECT invoked FROM mal_unpack_scans LIMIT 1")
    db.close()


def test_availability_unavailable(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    p = MalUnpackProvider(tools_dir=paths.tools, tmp_dir=paths.tmp, artifacts_dir=paths.artifacts)
    info = p.availability()
    assert info["available"] is False
    assert info["memscope_artifact_targets_supported"] is False
    assert info["supported_target_kinds"] == []
    assert info["native_target_kinds"] == ["executable_file"]
    assert info["verified_release"] == VERIFIED_RELEASE
    assert info["verified_version_str"] == VERIFIED_VERSION_STR
    assert info["executes_sample"] is True
    assert info["license"]["bundled_in_memscope"] is False
    assert info["license"]["name"] == "BSD-2-Clause"


def test_availability_and_version_detection(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    exe = _write_dummy_exe(paths.tools / "mal_unpack" / "mal_unpack.exe")
    p = MalUnpackProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_version_runner("1.0.0.1"),
    )
    info = p.availability()
    assert info["available"] is True
    assert info["mal_unpack_version"] == "1.0.0.1"
    assert Path(info["executable_path"]) == exe.resolve()
    assert p.detect_version() == "1.0.0.1"


def test_parse_version_output() -> None:
    assert parse_mal_unpack_version("MalUnpack: v.1.0.0.1\n") == "1.0.0.1"
    assert parse_mal_unpack_version("MalUnpack: v1.0") == "1.0"
    assert parse_mal_unpack_version("no version here") is None


def test_configuration_validation(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    exe = _write_dummy_exe(paths.tools / "mal_unpack.exe")
    p = MalUnpackProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_version_runner(),
    )
    with pytest.raises(AppError) as ei:
        p.configure({"timeout_secs": 0})
    assert ei.value.code == "mal_unpack_invalid_timeout"
    with pytest.raises(AppError) as ei:
        p.configure({"extra_args": ["/exe", "x"]})
    assert ei.value.code == "mal_unpack_invalid_config"
    with pytest.raises(AppError) as ei:
        p.configure({"cmd": "whoami"})
    assert ei.value.code == "mal_unpack_invalid_config"
    out = p.configure({"timeout_secs": 30, "executable_path": str(exe)})
    assert out["available"] is True
    assert p.timeout_secs == 30
    assert p.timeout_ms() == 30_000


def test_executable_path_allow_list(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    outside = _write_dummy_exe(tmp_path / "mal_unpack.exe")
    p = MalUnpackProvider(tools_dir=paths.tools, tmp_dir=paths.tmp, artifacts_dir=paths.artifacts)
    with pytest.raises(AppError) as ei:
        validate_executable_path(outside, [paths.tools], deny_roots=[paths.artifacts])
    assert ei.value.code == "mal_unpack_exe_path_denied"
    with pytest.raises(AppError) as ei:
        p.configure({"executable_path": str(outside)})
    assert ei.value.code == "mal_unpack_exe_path_denied"

    evil = artifact_store.artifact_dir(paths, "ev1") / "mal_unpack.exe"
    _write_dummy_exe(evil)
    with pytest.raises(AppError) as ei:
        validate_executable_path(evil, [paths.tools, paths.artifacts], deny_roots=[paths.artifacts])
    assert ei.value.code == "mal_unpack_exe_denied"

    not_pe = paths.tools / "mal_unpack.exe"
    not_pe.write_bytes(b"NO")
    with pytest.raises(AppError) as ei:
        validate_executable_path(not_pe, [paths.tools])
    assert ei.value.code == "mal_unpack_exe_invalid"

    wrong_name = paths.tools / "unpacker.exe"
    _write_dummy_exe(wrong_name)
    with pytest.raises(AppError) as ei:
        validate_executable_path(wrong_name, [paths.tools])
    assert ei.value.code == "mal_unpack_exe_invalid"


def test_target_validation_and_unsupported() -> None:
    for kind in (
        TARGET_ARTIFACT,
        TARGET_EXECUTABLE_FILE,
        TARGET_LIVE_PROCESS,
        TARGET_MEMORY_REGION,
        TARGET_MEMORY_DUMP,
    ):
        info = describe_target(kind)
        assert info["supported"] is False
        assert info["memscope_safe"] is False
        assert info["executes_sample"] is True
    native = describe_target(TARGET_EXECUTABLE_FILE)
    assert native["native_tool_target"] is True
    p = MalUnpackProvider()
    with pytest.raises(AppError) as ei:
        p.assert_target_supported(TARGET_ARTIFACT)
    assert ei.value.code == "mal_unpack_unsupported_target"
    with pytest.raises(AppError) as ei:
        p.assert_target_supported(TARGET_EXECUTABLE_FILE)
    assert ei.value.code == "mal_unpack_unsupported_target"


def test_command_construction(tmp_path: Path) -> None:
    exe = tmp_path / "mal_unpack.exe"
    sample = tmp_path / "packed.exe"
    out = tmp_path / "out"
    argv = build_unpack_argv(exe, sample, 5000, out)
    assert argv[0] == str(exe)
    assert argv[1:7] == ["/exe", str(sample), "/timeout", "5000", "/dir", str(out)]
    assert "/cmd" not in argv
    assert argv[0] != str(sample)
    ver = build_version_argv(exe)
    assert ver == [str(exe), "/version"]
    with pytest.raises(AppError) as ei:
        build_unpack_argv(exe, exe, 1000, out)
    assert ei.value.code == "mal_unpack_exe_denied"


def test_execution_forbidden_without_confirm(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    _write_dummy_exe(paths.tools / "mal_unpack.exe")
    sample = tmp_path / "packed.exe"
    sample.write_bytes(_mz_stub())
    called = {"n": 0}

    def runner(argv, *, cwd=None, timeout_secs=30, cancelled=None):
        called["n"] += 1
        raise AssertionError("mal_unpack must not be invoked without confirm")

    p = MalUnpackProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=runner,
    )
    with pytest.raises(AppError) as ei:
        p.run_unpack(sample)
    assert ei.value.code == "mal_unpack_execution_forbidden"
    assert called["n"] == 0


def test_refuse_artifact_store_as_exe(tmp_path: Path) -> None:
    paths, db, ev, art_id = _seed_artifact(tmp_path)
    _write_dummy_exe(paths.tools / "mal_unpack.exe")
    parent = db.fetchone("SELECT * FROM artifacts WHERE id = ?", (art_id,))
    p = MalUnpackProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_unpack_runner(),
    )
    with pytest.raises(AppError) as ei:
        p.run_unpack(Path(parent["stored_path"]), confirm_sample_execution=True)
    assert ei.value.code == "mal_unpack_execution_forbidden"
    db.close()


def test_timeout(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    _write_dummy_exe(paths.tools / "mal_unpack.exe")
    sample = tmp_path / "packed.exe"
    sample.write_bytes(_mz_stub())
    p = MalUnpackProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_unpack_runner(timed_out=True),
        timeout_secs=1,
    )
    with pytest.raises(AppError) as ei:
        p.run_unpack(
            sample,
            output_dir=paths.tmp / "mal_unpack" / "t",
            confirm_sample_execution=True,
        )
    assert ei.value.code == "mal_unpack_timeout"


def test_cancellation(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    _write_dummy_exe(paths.tools / "mal_unpack.exe")
    sample = tmp_path / "packed.exe"
    sample.write_bytes(_mz_stub())
    p = MalUnpackProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_unpack_runner(hang_until_cancel=True),
        timeout_secs=5,
    )
    with pytest.raises(AppError) as ei:
        p.run_unpack(
            sample,
            output_dir=paths.tmp / "mal_unpack" / "t",
            cancelled=lambda: True,
            confirm_sample_execution=True,
        )
    assert ei.value.code == "job_cancelled"


def test_provider_unavailable_unpack(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    sample = tmp_path / "packed.exe"
    sample.write_bytes(_mz_stub())
    p = MalUnpackProvider(tools_dir=paths.tools, tmp_dir=paths.tmp, artifacts_dir=paths.artifacts)
    with pytest.raises(AppError) as ei:
        p.run_unpack(sample, confirm_sample_execution=True)
    assert ei.value.code == "mal_unpack_unavailable"


def test_malformed_output(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    _write_dummy_exe(paths.tools / "mal_unpack.exe")
    sample = tmp_path / "packed.exe"
    sample.write_bytes(_mz_stub())
    p = MalUnpackProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_unpack_runner(malformed=True, exit_code=1),
    )
    with pytest.raises(AppError) as ei:
        p.run_unpack(
            sample,
            output_dir=paths.tmp / "mal_unpack" / "bad",
            confirm_sample_execution=True,
        )
    assert ei.value.code == "mal_unpack_output_invalid"


def test_missing_output(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    _write_dummy_exe(paths.tools / "mal_unpack.exe")
    sample = tmp_path / "packed.exe"
    sample.write_bytes(_mz_stub())
    p = MalUnpackProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_unpack_runner(write_reports=False, exit_code=1),
    )
    with pytest.raises(AppError) as ei:
        p.run_unpack(
            sample,
            output_dir=paths.tmp / "mal_unpack" / "empty",
            confirm_sample_execution=True,
        )
    assert ei.value.code == "mal_unpack_output_invalid"


def test_valid_output_normalization(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    _write_dummy_exe(paths.tools / "mal_unpack.exe")
    sample = tmp_path / "packed.exe"
    sample.write_bytes(_mz_stub())
    p = MalUnpackProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_unpack_runner(exit_code=2),
    )
    result = p.run_unpack(
        sample,
        output_dir=paths.tmp / "mal_unpack" / "ok",
        confirm_sample_execution=True,
    )
    assert result["status"] == "completed"
    assert result["invoked"] is True
    assert result["unpack_result"] == "detected"
    assert result["observed"]["source"] == "mal_unpack"
    assert result["observed"]["executes_sample"] is True
    assert result["interpretation"]["source"] == "memscope"
    assert "malware" not in result["interpretation"]["summary"].lower()
    assert result["ui_state"] == "completed_output_generated"
    assert "/cmd" not in result["observed"]["argv"]
    empty_dump = {"pid": 684, "dumps": []}
    p.runner = _unpack_runner(scan_report=_SCAN_REPORT, dump_report=empty_dump, exit_code=1)
    result2 = p.run_unpack(
        sample,
        output_dir=paths.tmp / "mal_unpack" / "none",
        confirm_sample_execution=True,
    )
    assert result2["unpack_result"] == "not_detected"
    assert result2["ui_state"] == "completed_no_output"


def test_artifact_creation_sha256_provenance(tmp_path: Path) -> None:
    paths, db, ev, art_id = _seed_artifact(tmp_path)
    _write_dummy_exe(paths.tools / "mal_unpack.exe")
    sample = tmp_path / "packed.exe"
    sample.write_bytes(_mz_stub())
    p = MalUnpackProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
        runner=_unpack_runner(exit_code=2, dump_bytes=b"MZMAL-UNPACK-DUMP"),
    )
    result = p.run_unpack(
        sample,
        output_dir=paths.tmp / "mal_unpack" / "ing",
        confirm_sample_execution=True,
    )
    parent = db.fetchone("SELECT * FROM artifacts WHERE id = ?", (art_id,))
    bundle = mal_unpack_workflows.persist_mal_unpack_result(
        db,
        paths,
        evidence_id=ev["id"],
        result=result,
        artifact_id=art_id,
        process_id=parent["process_id"],
        pid=parent["pid"],
        memory_region_id=parent["memory_region_id"],
    )
    assert bundle["scan"]["ui_state"] == "completed_output_generated"
    assert bundle["scan"]["invoked"] is True
    assert bundle["outputs"]
    dump = next(o for o in bundle["outputs"] if o["role"] == "dump_file")
    assert dump["sha256"]
    assert len(dump["sha256"]) == 64
    stored = Path(dump["stored_path"])
    assert stored.is_file()
    assert artifact_store.sha256_file(stored) == dump["sha256"]
    assert stored.read_bytes() == b"MZMAL-UNPACK-DUMP"
    src = Path(parent["stored_path"])
    assert src.read_bytes().startswith(b"MZ")
    assert src.read_bytes() != b"MZMAL-UNPACK-DUMP"
    child = get_artifact(db, dump["artifact_id"])
    assert child["parent_artifact_id"] == art_id
    assert child["tool_name"] == "mal_unpack"
    assert child["extraction_method"] == "mal_unpack_dump"
    assert any(s.get("step") == "source_artifact" for s in child["provenance_chain"])
    assert any(s.get("step") == "mal_unpack_output" for s in child["provenance_chain"])
    db.close()


def test_output_dir_must_be_under_tmp(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    with pytest.raises(AppError) as ei:
        validate_output_dir(tmp_path / "outside", [paths.tmp])
    assert ei.value.code == "mal_unpack_output_denied"


def test_unsupported_artifact_job(tmp_path: Path) -> None:
    paths, db, ev, art_id = _seed_artifact(tmp_path)
    _write_dummy_exe(paths.tools / "mal_unpack.exe")
    provider = mal_unpack_workflows.get_or_create_provider(paths, db)
    provider.runner = _version_runner()
    mal_unpack_workflows.save_mal_unpack_settings(db, provider)

    # Restore a runner-less provider from settings would lose the mock; inject via job path
    # by placing the dummy EXE so availability is true without invoking unpack.
    jm = JobManager(db)

    def handler(db_, params, cancelled, progress):
        return mal_unpack_workflows.run_mal_unpack_artifact_job(
            db_, params, cancelled, progress, paths=paths
        )

    jm.register("mal_unpack_artifact", handler)
    jm.start()
    job = jm.submit(
        "mal_unpack_artifact",
        evidence_id=ev["id"],
        params={"artifact_id": art_id},
        message="test mal_unpack",
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
    assert j["result"]["scan"]["invoked"] is False
    db.close()


def test_unavailable_artifact_job(tmp_path: Path) -> None:
    paths, db, ev, art_id = _seed_artifact(tmp_path)
    jm = JobManager(db)

    def handler(db_, params, cancelled, progress):
        return mal_unpack_workflows.run_mal_unpack_artifact_job(
            db_, params, cancelled, progress, paths=paths
        )

    jm.register("mal_unpack_artifact", handler)
    jm.start()
    job = jm.submit(
        "mal_unpack_artifact",
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
    scans = mal_unpack_workflows.list_mal_unpack_scans_for_artifact(db, art_id)
    assert scans["items"][0]["scan"]["ui_state"] == "unavailable"
    assert scans["items"][0]["scan"]["invoked"] is False
    db.close()


def test_ui_state_transitions() -> None:
    assert compute_ui_state(available=False) == "unavailable"
    assert compute_ui_state(available=True, target_kind=TARGET_ARTIFACT) == "unsupported_target"
    assert compute_ui_state(available=True, scan_status="queued") == "queued"
    assert compute_ui_state(available=True, scan_status="running") == "running"
    assert compute_ui_state(available=True, scan_status="failed") == "failed"
    assert compute_ui_state(available=True, scan_status="cancelled") == "cancelled"
    assert (
        compute_ui_state(available=True, scan_status="completed", unpack_result="not_detected", output_count=0)
        == "completed_no_output"
    )
    assert (
        compute_ui_state(available=True, scan_status="completed", unpack_result="detected", output_count=1)
        == "completed_output_generated"
    )


def test_ipc_round_trip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MEMSCOPE_DATA_DIR", str(tmp_path / "ipcdata"))
    from memscope_engine.server import HANDLERS, handle_app_init

    init = handle_app_init({"data_dir": str(tmp_path / "ipcdata")})
    assert init["schema_version"] == 9
    assert "mal_unpack" in init
    status = HANDLERS["mal_unpack.status"]({})
    assert status["available"] is False
    assert status["ui_state"] == "unavailable"
    with pytest.raises(AppError):
        HANDLERS["mal_unpack.configure"]({"executable_path": str(tmp_path / "mal_unpack.exe")})
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
    job = HANDLERS["mal_unpack.unpack_artifact"]({"artifact_id": art_id, "evidence_id": ev["id"]})
    assert job["kind"] == "mal_unpack_artifact"
    for _ in range(100):
        got = HANDLERS["jobs.get"]({"job_id": job["id"]})
        if got["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.05)
    got = HANDLERS["jobs.get"]({"job_id": job["id"]})
    assert got["status"] == "failed"
    listed = HANDLERS["mal_unpack.scans_for_artifact"]({"artifact_id": art_id})
    assert listed["total"] >= 1
    scan_id = listed["items"][0]["scan"]["id"]
    fetched = HANDLERS["mal_unpack.scan_get"]({"scan_id": scan_id})
    assert fetched["scan"]["id"] == scan_id
    assert fetched["scan"]["invoked"] is False
    art = HANDLERS["artifacts.get"]({"artifact_id": art_id})
    assert "mal_unpack_status" in art
    assert "mal_unpack_scans" in art


def test_real_mal_unpack_version_if_installed() -> None:
    """Only runs /version against a real EXE. Does not execute a sample."""
    roots = []
    local = os.environ.get("LOCALAPPDATA")
    if local:
        roots.append(Path(local) / "MemScope" / "tools")
    found = None
    for root in roots:
        for name in ("mal_unpack.exe", "mal_unpack64.exe", "mal_unpack32.exe"):
            cand = root / name
            if cand.is_file():
                found = cand
                break
            cand = root / "mal_unpack" / name
            if cand.is_file():
                found = cand
                break
        if found:
            break
    if found is None:
        pytest.skip("mal_unpack is not installed on this machine")
    from memscope_engine.providers.pe_sieve import default_subprocess_runner

    run = default_subprocess_runner(build_version_argv(found), cwd=found.parent, timeout_secs=15)
    ver = parse_mal_unpack_version(run.stdout + "\n" + run.stderr)
    assert ver  # real tool responded; do not invent unpack findings
