"""FLOSS provider, command construction, parsing, and provenance tests."""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

import pytest

from memscope_engine.analysis import floss_workflows
from memscope_engine.analysis.workflows import import_evidence
from memscope_engine.artifacts import store as artifact_store
from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths
from memscope_engine.providers.floss import (
    FlossProvider,
    VERIFIED_RELEASE,
    build_scan_argv,
    build_version_argv,
    normalize_floss_json,
    parse_version_output,
)
from memscope_engine.providers.process_run import ProcessRun
from memscope_engine.server import HANDLERS, handle_app_init
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION


def _write_dummy_exe(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"MZ" + b"\x00" * 256)
    return path


def test_schema_floss(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    assert db.schema_version() == SCHEMA_VERSION
    db.execute("SELECT COUNT(*) AS c FROM floss_scans")
    db.execute("SELECT COUNT(*) AS c FROM floss_strings")
    db.close()


def test_availability_missing(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    p = FlossProvider(tools_dir=paths.tools, artifacts_dir=paths.artifacts)
    avail = p.availability()
    assert avail["available"] is False
    assert avail["license"]["bundled_in_memscope"] is True


def test_availability_bundled_skips_version_spawn(tmp_path: Path) -> None:
    bundled = tmp_path / "resources" / "tools" / "floss"
    exe = _write_dummy_exe(bundled / "floss.exe")
    called: list[int] = []

    def runner(*_a, **_k):
        called.append(1)
        return ProcessRun(returncode=0, stdout="floss 3.1.1\n", stderr="")

    p = FlossProvider(
        tools_dir=tmp_path / "tools",
        artifacts_dir=tmp_path / "artifacts",
        extra_tool_roots=[bundled],
        runner=runner,
    )
    info = p.availability()
    assert info["available"] is True
    assert info["source"] == "bundled"
    assert info["floss_version"] == VERIFIED_RELEASE
    assert Path(info["executable_path"]) == exe.resolve()
    assert called == []


def test_version_and_argv(tmp_path: Path) -> None:
    assert parse_version_output("floss 3.1.1") == "3.1.1"
    exe = _write_dummy_exe(tmp_path / "floss.exe")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64)
    argv = build_scan_argv(exe, sample)
    assert argv[0] == str(exe)
    assert "-j" in argv
    assert str(sample) in argv
    assert build_version_argv(exe) == [str(exe), "--version"]


def test_missing_executable_analyze(tmp_path: Path) -> None:
    p = FlossProvider(tools_dir=tmp_path / "tools")
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 32)
    with pytest.raises(AppError) as ei:
        p.analyze_pe(sample)
    assert ei.value.code == "floss_unavailable"


def test_parse_strings() -> None:
    doc = {
        "metadata": {"version": "3.1.1"},
        "strings": {
            "static_strings": [{"string": "hello", "offset": 16}],
            "decoded_strings": [{"string": "http://example", "encoding": "ascii"}],
            "stack_strings": ["stack"],
            "tight_strings": [],
        },
    }
    out = normalize_floss_json(doc)
    assert out["string_count"] == 3
    kinds = {s["kind"] for s in out["strings"]}
    assert "static" in kinds
    assert "decoded" in kinds
    assert out["interpretation"]["kind"] == "extracted_string"


def test_analyze_known_pe_with_mock_runner(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    _write_dummy_exe(paths.tools / "floss" / "floss.exe")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 80)
    payload = {
        "metadata": {"version": "3.1.1"},
        "strings": {"decoded_strings": [{"string": "cmd.exe", "encoding": "ascii"}]},
    }

    def runner(argv, **_k):
        if "--version" in argv:
            return ProcessRun(returncode=0, stdout="floss 3.1.1\n", stderr="")
        return ProcessRun(returncode=0, stdout=__import__("json").dumps(payload), stderr="")

    p = FlossProvider(tools_dir=paths.tools, artifacts_dir=paths.artifacts, runner=runner)
    result = p.analyze_pe(sample)
    assert result["string_count"] == 1
    assert result["strings"][0]["value"] == "cmd.exe"


def test_failure_invalid_json(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    _write_dummy_exe(paths.tools / "floss.exe")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 80)

    def runner(argv, **_k):
        if "--version" in argv:
            return ProcessRun(returncode=0, stdout="floss 3.1.1\n", stderr="")
        return ProcessRun(returncode=1, stdout="nope", stderr="")

    p = FlossProvider(tools_dir=paths.tools, artifacts_dir=paths.artifacts, runner=runner)
    with pytest.raises(AppError) as ei:
        p.analyze_pe(sample)
    assert ei.value.code == "floss_exec_failed"
    assert "non-zero exit code" in ei.value.message


def test_timeout_returns_structured_error(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    _write_dummy_exe(paths.tools / "floss.exe")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 80)

    def runner(argv, **_k):
        if "--version" in argv:
            return ProcessRun(returncode=0, stdout="floss 3.1.1\n", stderr="")
        return ProcessRun(returncode=-1, stdout="", stderr="busy", timed_out=True, tree_terminated=True)

    p = FlossProvider(tools_dir=paths.tools, artifacts_dir=paths.artifacts, runner=runner)
    with pytest.raises(AppError) as ei:
        p.analyze_pe(sample)
    assert ei.value.code == "floss_timeout"
    assert "timed out after 900 seconds" in ei.value.message
    assert "process tree terminated" in ei.value.message


def test_job_provenance(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "img.raw"
    img.write_bytes(b"dump")
    ev = import_evidence(db, str(img))
    adir = artifact_store.artifact_dir(paths, ev["id"])
    apath = adir / "pid100_loaded_module_mod_7fff0000.dll"
    apath.write_bytes(b"MZ" + b"\x00" * 80)
    art_id = str(uuid4())
    db.execute(
        """
        INSERT INTO artifacts (
          id, evidence_id, process_id, pid, memory_region_id, filename, stored_path,
          sha256, size_bytes, file_type, extraction_method, source_plugin, tool_name,
          tool_version, start_vpn, end_vpn, extracted_at, notes, metadata_json
        ) VALUES (?, ?, NULL, 100, NULL, ?, ?, ?, ?, 'pe', 'volatility3.windows.pedump.loaded_module',
          'windows.pedump', 'volatility3', '2.28.0', '0x7fff0000', NULL, '2020-01-01T00:00:00+00:00',
          'Extracted PE artifact', ?)
        """,
        (
            art_id,
            ev["id"],
            apath.name,
            str(apath),
            artifact_store.sha256_file(apath),
            apath.stat().st_size,
            '{"pe_extraction_run_id": "run-2", "label": "extracted_pe_artifact"}',
        ),
    )
    _write_dummy_exe(paths.tools / "floss.exe")
    payload = {
        "metadata": {"version": "3.1.1"},
        "strings": {"static_strings": [{"string": "kernel32", "offset": 10}]},
    }

    def runner(argv, **_k):
        if "--version" in argv:
            return ProcessRun(returncode=0, stdout="floss 3.1.1\n", stderr="")
        return ProcessRun(returncode=0, stdout=__import__("json").dumps(payload), stderr="")

    orig = floss_workflows.get_or_create_provider

    def patched(paths_, db_):
        p = orig(paths_, db_)
        p.runner = runner
        return p

    floss_workflows.get_or_create_provider = patched  # type: ignore[method-assign]
    try:
        result = floss_workflows.run_floss_artifact_job(
            db,
            {"artifact_id": art_id, "evidence_id": ev["id"]},
            lambda: False,
            lambda _m: None,
            paths=paths,
        )
        assert result["scan"]["pe_extraction_run_id"] == "run-2"
        assert result["scan"]["status"] == "completed"
        assert result["strings"][0]["value"] == "kernel32"
        scans = floss_workflows.list_floss_scans_for_artifact(db, art_id)
        assert scans["total"] == 1
    finally:
        floss_workflows.get_or_create_provider = orig  # type: ignore[method-assign]
    db.close()


def test_ipc_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DUMPLYZER_BUNDLE_TOOLS", raising=False)
    isolated = tmp_path / "isolated-python.exe"
    isolated.write_bytes(b"")
    monkeypatch.setattr(sys, "executable", str(isolated))
    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    status = HANDLERS["floss.status"]({})
    assert status["available"] is False
    assert "floss.scan_artifact" in HANDLERS
