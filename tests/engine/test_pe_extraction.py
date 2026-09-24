"""PE Extraction identification, workflow, provenance, and failure tests."""

from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from memscope_engine.analysis import pe_extraction_workflows
from memscope_engine.analysis.workflows import import_evidence
from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths
from memscope_engine.providers.pe_extraction import (
    METHOD_LOADED_MODULE,
    METHOD_PROCESS_IMAGE,
    PeExtractionProvider,
    build_pe_filename,
    classify_pe_bytes,
    identify_pe_candidates,
    unique_pe_path,
)
from memscope_engine.server import HANDLERS, handle_app_init
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION


def _minimal_pe(*, dll: bool) -> bytes:
    chars = 0x0102 | (0x2000 if dll else 0)
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (64).to_bytes(4, "little")
    pe = bytearray(b"PE\x00\x00")
    pe += (0x14C).to_bytes(2, "little")
    pe += (1).to_bytes(2, "little")
    pe += (0).to_bytes(4, "little") * 3
    pe += (0xE0).to_bytes(2, "little")
    pe += chars.to_bytes(2, "little")
    pe += b"\x0b\x01"  # magic PE32
    pe += b"\x00" * (0xE0 - 2)
    section = b".text\x00\x00\x00" + b"\x00" * 32
    return bytes(dos) + bytes(pe) + section + b"\x00" * 64


def test_schema_v11_pe_extraction(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    assert db.schema_version() == SCHEMA_VERSION
    db.execute("SELECT COUNT(*) AS c FROM pe_extraction_runs")
    db.execute("SELECT COUNT(*) AS c FROM pe_extraction_items")
    db.close()


def test_provider_discovery() -> None:
    avail = PeExtractionProvider().availability()
    assert avail["provider"] == "pe_extraction"
    assert "available" in avail
    assert avail["produces"] == "extracted_pe_artifact"
    assert avail["not_a_malware_verdict"] is True
    assert METHOD_PROCESS_IMAGE in avail["methods"]
    assert avail.get("dumpfiles_default") is False
    assert "volatility3.windows.dumpfiles.pe" in (avail.get("optional_methods") or [])
    src = inspect.getsource(PeExtractionProvider.availability)
    assert "from volatility3" not in src
    assert "PEDump" not in src
    assert "find_spec" not in src


def test_identify_exe_and_dll_and_mapped() -> None:
    cands = identify_pe_candidates(
        processes=[{"pid": 100, "name": "app.exe", "image_path": r"C:\app.exe", "image_base": 0x400000}],
        modules=[
            {"pid": 100, "name": "kernel32.dll", "path": r"C:\Windows\System32\kernel32.dll", "base_address": "0x7fff0000"},
            {"pid": 100, "name": "app.exe", "path": r"C:\app.exe", "base_address": 0x400000},
        ],
        vads=[
            {
                "pid": 100,
                "process_name": "app.exe",
                "start_vpn": "0x200000",
                "end_vpn": "0x210000",
                "file_path": r"C:\mapped.dll",
                "has_mz": True,
                "tag": "VadImageMap",
            },
            {
                "pid": 100,
                "start_vpn": "0x300000",
                "end_vpn": "0x310000",
                "private_memory": True,
                "protection": "PAGE_EXECUTE_READWRITE",
                "has_mz": True,
            },
        ],
        cached_files=[{"name": "deleted.exe", "is_pe": True, "pid": 100}],
    )
    kinds = {c["kind"] for c in cands}
    assert "process_image" in kinds
    assert "loaded_module" in kinds
    assert "mapped_pe" in kinds
    assert "unlinked_mapped" in kinds
    assert "cached_file" in kinds
    dlls = [c for c in cands if c["kind"] == "loaded_module"]
    assert dlls[0]["pe_kind_hint"] == "dll"
    assert all(c["kind"] != "loaded_module" or "app.exe" not in (c.get("original_path") or "") for c in cands)


def test_classify_exe_and_dll() -> None:
    exe = classify_pe_bytes(_minimal_pe(dll=False))
    dll = classify_pe_bytes(_minimal_pe(dll=True))
    assert exe["is_pe"] is True
    assert dll["is_pe"] is True
    if exe.get("parse_ok"):
        assert exe["pe_kind"] == "exe"
        assert exe.get("architecture") == "x86"
    if dll.get("parse_ok"):
        assert dll["pe_kind"] == "dll"
    assert classify_pe_bytes(b"notpe")["is_pe"] is False
    mz_only = b"MZ" + b"\x00" * 62
    mz_info = classify_pe_bytes(mz_only)
    assert mz_info["is_pe"] is False
    assert mz_info["parse_ok"] is False


def test_filename_collision_handling(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    name = build_pe_filename(
        pid=4, pe_kind="exe", original_name="smss.exe", base_address=0x400000, method="process_image"
    )
    first = unique_pe_path(
        out, pid=4, pe_kind="exe", original_name="smss.exe", base_address=0x400000, method="process_image"
    )
    first.write_bytes(b"MZ")
    second = unique_pe_path(
        out, pid=4, pe_kind="exe", original_name="smss.exe", base_address=0x400000, method="process_image"
    )
    assert first.name == name
    assert second != first
    assert second.name.startswith(first.stem)


def test_missing_evidence(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    with pytest.raises(AppError) as ei:
        pe_extraction_workflows.run_pe_extraction_job(
            db, {"evidence_id": "missing"}, lambda: False, lambda _m: None, paths=paths
        )
    assert ei.value.code == "evidence_missing"
    db.close()


def test_invalid_evidence_path(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "gone.raw"
    img.write_bytes(b"dump")
    ev = import_evidence(db, str(img))
    img.unlink()
    with pytest.raises(AppError) as ei:
        pe_extraction_workflows.run_pe_extraction_job(
            db, {"evidence_id": ev["id"]}, lambda: False, lambda _m: None, paths=paths
        )
    assert ei.value.code == "evidence_not_found"
    db.close()


def _fake_extract(image, output_dir, *, pid_filter=None, cancelled=None, progress=None, include_dumpfiles=False, **_k):
    exe = _minimal_pe(dll=False)
    dll = _minimal_pe(dll=True)
    p1 = unique_pe_path(
        output_dir, pid=100, pe_kind="exe", original_name="app.exe", base_address=0x400000, method="process_image"
    )
    p2 = unique_pe_path(
        output_dir, pid=100, pe_kind="dll", original_name="mod.dll", base_address=0x7fff0000, method="loaded_module"
    )
    p1.write_bytes(exe)
    p2.write_bytes(dll)
    items = [
        SimpleNamespace(
            pid=100,
            process_name="app.exe",
            original_path=r"C:\app.exe",
            pe_kind="exe",
            kind="process_image",
            extraction_method=METHOD_PROCESS_IMAGE,
            source_plugin="windows.pslist+windows.pedump",
            start_vpn="0x400000",
            end_vpn=None,
            memory_region="0x400000",
            path=p1,
            sha256=__import__("hashlib").sha256(exe).hexdigest(),
            size_bytes=len(exe),
            notes="Extracted PE artifact; not executed; not classified as malware.",
            metadata={"pe_kind": "exe"},
        ),
        SimpleNamespace(
            pid=100,
            process_name="app.exe",
            original_path=r"C:\mod.dll",
            pe_kind="dll",
            kind="loaded_module",
            extraction_method=METHOD_LOADED_MODULE,
            source_plugin="windows.dlllist+windows.pedump",
            start_vpn="0x7fff0000",
            end_vpn=None,
            memory_region="0x7fff0000",
            path=p2,
            sha256=__import__("hashlib").sha256(dll).hexdigest(),
            size_bytes=len(dll),
            notes="Extracted PE artifact; not executed; not classified as malware.",
            metadata={"pe_kind": "dll"},
        ),
    ]
    return {
        "items": items,
        "skipped": [],
        "errors": [],
        "methods_used": [METHOD_PROCESS_IMAGE, METHOD_LOADED_MODULE],
        "volatility_version": "2.28.0",
        "extracted_count": 2,
        "exe_count": 1,
        "dll_count": 1,
        "skipped_count": 0,
    }


def test_extraction_job_provenance_and_multiple_pe(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "img.raw"
    img.write_bytes(b"memory-dump-bytes")
    before = img.read_bytes()
    ev = import_evidence(db, str(img))
    result = pe_extraction_workflows.run_pe_extraction_job(
        db,
        {"evidence_id": ev["id"]},
        lambda: False,
        lambda _m: None,
        paths=paths,
        extract_fn=_fake_extract,
    )
    assert result["run"]["extracted_count"] == 2
    assert result["run"]["exe_count"] == 1
    assert result["run"]["dll_count"] == 1
    assert img.read_bytes() == before
    arts = pe_extraction_workflows.list_extracted_pe_artifacts(db, ev["id"])
    assert arts["total"] == 2
    from memscope_engine.analysis.memory_artifacts import get_artifact

    art = get_artifact(db, result["items"][0]["artifact_id"])
    steps = [s["step"] for s in art["provenance_chain"]]
    assert "evidence" in steps
    assert "pe_extraction" in steps
    assert art["metadata"]["label"] == "extracted_pe_artifact"
    assert "malware" not in (art.get("notes") or "").lower() or "not" in (art.get("notes") or "").lower()
    db.close()


def test_extraction_job_emits_percent(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "img.raw"
    img.write_bytes(b"memory-dump-bytes")
    ev = import_evidence(db, str(img))
    percents: list[float] = []

    def progress(msg: str, extra=None) -> None:
        if extra and extra.get("percent") is not None:
            percents.append(float(extra["percent"]))

    pe_extraction_workflows.run_pe_extraction_job(
        db,
        {"evidence_id": ev["id"]},
        lambda: False,
        progress,
        paths=paths,
        extract_fn=_fake_extract,
    )
    assert percents
    assert percents[0] < 50
    assert percents[-1] == 100
    db.close()


def test_extraction_failure_handling(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "img.raw"
    img.write_bytes(b"dump")
    ev = import_evidence(db, str(img))

    def _boom(*_a, **_k):
        raise RuntimeError("reconstruct exploded")

    with pytest.raises(AppError) as ei:
        pe_extraction_workflows.run_pe_extraction_job(
            db, {"evidence_id": ev["id"]}, lambda: False, lambda _m: None, paths=paths, extract_fn=_boom
        )
    assert ei.value.code == "pe_extraction_failed"
    row = db.fetchone("SELECT status FROM pe_extraction_runs ORDER BY started_at DESC")
    assert row["status"] == "failed"
    db.close()


def test_evidence_immutability(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "img.raw"
    img.write_bytes(b"orig")
    ev = import_evidence(db, str(img))

    def _mutate(image, output_dir, **_k):
        Path(image).write_bytes(b"changed")
        return {
            "items": [],
            "skipped": [],
            "errors": [],
            "methods_used": [],
            "volatility_version": "test",
            "extracted_count": 0,
            "exe_count": 0,
            "dll_count": 0,
            "skipped_count": 0,
        }

    with pytest.raises(AppError) as ei:
        pe_extraction_workflows.run_pe_extraction_job(
            db, {"evidence_id": ev["id"]}, lambda: False, lambda _m: None, paths=paths, extract_fn=_mutate
        )
    assert ei.value.code == "evidence_mutated"
    db.close()


def test_ipc_handlers(tmp_path: Path) -> None:
    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    status = HANDLERS["pe_extraction.status"]({})
    assert status["provider"] == "pe_extraction"
    assert "pe_extraction.run" in HANDLERS
    assert "pe_extraction.runs" in HANDLERS
    assert "pe_extraction.artifacts" in HANDLERS


def test_list_extracted_pe_artifacts_includes_vad_dump(tmp_path: Path) -> None:
    from uuid import uuid4

    from memscope_engine.artifacts import store as artifact_store

    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "img.raw"
    img.write_bytes(b"dump")
    ev = import_evidence(db, str(img))
    adir = artifact_store.artifact_dir(paths, ev["id"])
    apath = adir / "pid.4.vad.x1000-x2000.dmp"
    apath.write_bytes(b"\x00" * 32)
    digest = artifact_store.sha256_file(apath)
    art_id = str(uuid4())
    db.execute(
        """
        INSERT INTO artifacts (
          id, evidence_id, process_id, pid, memory_region_id, filename, stored_path,
          sha256, size_bytes, file_type, extraction_method, source_plugin, tool_name,
          tool_version, start_vpn, end_vpn, extracted_at, notes, metadata_json
        ) VALUES (?, ?, NULL, 4, NULL, ?, ?, ?, ?, 'raw', 'volatility3.windows.vadinfo.vad_dump',
          'windows.vadinfo', 'volatility3', '0', '0x1000', '0x2000',
          '2020-01-01T00:00:00+00:00', 'fixture', '{}')
        """,
        (art_id, ev["id"], apath.name, str(apath), digest, apath.stat().st_size),
    )
    listed = pe_extraction_workflows.list_extracted_pe_artifacts(db, ev["id"])
    assert listed["total"] == 1
    assert listed["items"][0]["id"] == art_id
    db.close()


def test_yara_jail_allows_pe_extraction_store(tmp_path: Path) -> None:
    from memscope_engine.artifacts.store import ensure_within_controlled_data

    paths = AppPaths(tmp_path / "data").ensure()
    stored = paths.analysis / "pe_extraction" / "run-x" / "pid4_process_image_smss_400000.exe"
    stored.parent.mkdir(parents=True)
    stored.write_bytes(b"MZ")
    got = ensure_within_controlled_data(paths, stored)
    assert got == stored.resolve()
    outside = tmp_path / "evil.exe"
    outside.write_bytes(b"MZ")
    with pytest.raises(AppError) as ei:
        ensure_within_controlled_data(paths, outside)
    assert ei.value.code == "artifact_path_invalid"


def test_default_extraction_does_not_enable_dumpfiles() -> None:
    from memscope_engine.volatility.pe_dump import _extract_pe_images_impl, extract_pe_images

    sig = inspect.signature(extract_pe_images)
    assert sig.parameters["include_dumpfiles"].default is False
    src = inspect.getsource(_extract_pe_images_impl)
    assert "if include_dumpfiles:" in src
    assert src.index("if include_dumpfiles:") < src.index("_extract_dumpfiles_pe")


def test_workflow_does_not_invoke_dumpfiles_by_default(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "img.raw"
    img.write_bytes(b"memory-dump-bytes")
    ev = import_evidence(db, str(img))
    captured: dict = {}

    def _extract(image, output_dir, **kwargs):
        captured.update(kwargs)
        if kwargs.get("include_dumpfiles"):
            raise AssertionError("normal PE extraction must not enable dumpfiles")
        return _fake_extract(image, output_dir, **kwargs)

    pe_extraction_workflows.run_pe_extraction_job(
        db,
        {"evidence_id": ev["id"]},
        lambda: False,
        lambda _m: None,
        paths=paths,
        extract_fn=_extract,
    )
    assert captured.get("include_dumpfiles") is False
    db.close()


def test_explicit_dumpfiles_flag_is_forwarded(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "img.raw"
    img.write_bytes(b"memory-dump-bytes")
    ev = import_evidence(db, str(img))
    captured: dict = {}

    def _extract(image, output_dir, **kwargs):
        captured.update(kwargs)
        return _fake_extract(image, output_dir, **kwargs)

    pe_extraction_workflows.run_pe_extraction_job(
        db,
        {"evidence_id": ev["id"], "include_dumpfiles": True},
        lambda: False,
        lambda _m: None,
        paths=paths,
        extract_fn=_extract,
    )
    assert captured.get("include_dumpfiles") is True
    db.close()


def test_dumpfiles_temp_cleanup_preserves_committed_pes(tmp_path: Path) -> None:
    from memscope_engine.volatility.pe_dump import cleanup_dumpfiles_temp

    out = tmp_path / "out"
    out.mkdir()
    pe = out / "pid4_process_image_smss_400000.exe"
    pe.write_bytes(_minimal_pe(dll=False))
    tmp = out / "_dumpfiles_tmp"
    tmp.mkdir()
    (tmp / "huge.bin").write_bytes(b"x" * 32)
    dump = tmp_path / "SYSADMIN.dmp"
    dump.write_bytes(b"PAGEDU64")
    cleanup_dumpfiles_temp(out)
    assert pe.is_file()
    assert dump.is_file()
    assert not tmp.exists()
