"""Signature Detection (YARA) provider and workflow tests."""

from __future__ import annotations

import time
from pathlib import Path
from uuid import uuid4

import pytest

from memscope_engine.analysis import yara_workflows
from memscope_engine.analysis.workflows import import_evidence
from memscope_engine.artifacts import store as artifact_store
from memscope_engine.errors import AppError
from memscope_engine.jobs.manager import JobManager
from memscope_engine.paths import AppPaths, sync_bundled_yara_rules
from memscope_engine.providers.yara_provider import (
    KIND_ARTIFACT,
    KIND_MEMORY,
    YaraProvider,
    classify_rule_kinds,
    classify_rule_source,
    detect_yara,
    discover_rule_files,
)
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION


def _require_yara() -> None:
    info = detect_yara()
    if not info["available"]:
        pytest.fail("yara-python 4.5.4 must be installed in the engine environment")


def _provider(paths: AppPaths) -> YaraProvider:
    return YaraProvider(
        default_rules_dir=paths.yara_rules,
        bundled_dir=paths.yara_rules_bundled,
        custom_dir=paths.yara_rules_custom,
    )


def _wait_job(jm: JobManager, job_id: str, timeout: float = 20.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        j = jm.get(job_id)
        if j["status"] in ("completed", "failed", "cancelled"):
            return j
        time.sleep(0.05)
    return jm.get(job_id)


def test_schema_yara_tables(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    assert db.schema_version() == SCHEMA_VERSION
    db.execute("SELECT COUNT(*) AS c FROM yara_scans")
    db.execute("SELECT COUNT(*) AS c FROM yara_matches")
    row = db.fetchone("PRAGMA table_info(yara_scans)")
    assert row is not None
    cols = {r["name"] for r in db.fetchall("PRAGMA table_info(yara_scans)")}
    assert "target_kind" in cols
    db.close()


def test_yara_python_import() -> None:
    _require_yara()
    import yara

    assert yara.__version__ == "4.5.4"
    info = detect_yara()
    assert info["available"] is True
    assert info["yara_version"] == "4.5.4"


def test_bundled_rule_discovery(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    files = discover_rule_files([paths.yara_rules_bundled])
    suffixes = {p.suffix.lower() for p in files}
    assert files
    assert suffixes <= {".yar", ".yara"}
    memory = [p for p in files if "memory" in p.parts]
    artifact = [p for p in files if "artifact" in p.parts]
    assert memory
    assert artifact
    assert (paths.yara_rules_bundled / "README.md").is_file()


def test_custom_yar_and_yara_discovery(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    (paths.yara_rules_custom / "company_rules.yara").write_text(
        "rule CustomYaraExt { condition: true }\n",
        encoding="utf-8",
    )
    (paths.yara_rules_custom / "my_rule.yar").write_text(
        "rule CustomYarExt { condition: true }\n",
        encoding="utf-8",
    )
    p = _provider(paths)
    names = {path.name for path in p.list_rule_sources()}
    assert "company_rules.yara" in names
    assert "my_rule.yar" in names


def test_status_distinguishes_bundled_and_empty_custom(tmp_path: Path) -> None:
    _require_yara()
    paths = AppPaths(tmp_path / "data").ensure()
    bundled = discover_rule_files([paths.yara_rules_bundled])
    custom = discover_rule_files([paths.yara_rules_custom])
    assert bundled
    assert custom == []
    p = _provider(paths)
    avail = p.availability()
    assert Path(avail["custom_dir"]) == paths.yara_rules_custom
    assert Path(avail["bundled_dir"]) == paths.yara_rules_bundled
    assert avail["bundled_rule_file_count"] == len(bundled)
    assert avail["custom_rule_file_count"] == 0
    assert avail["valid_rule_file_count"] == len(bundled)
    assert avail["loaded_rule_count"] == avail["bundled_rule_count"]
    summary = avail["status_summary"] or ""
    assert "bundled rule file" in summary
    assert "0 custom rule files" in summary


def test_custom_rules_increase_status_counts(tmp_path: Path) -> None:
    _require_yara()
    paths = AppPaths(tmp_path / "data").ensure()
    p = _provider(paths)
    before = p.availability()
    (paths.yara_rules_custom / "user.yar").write_text(
        "rule UserYar { condition: true }\n",
        encoding="utf-8",
    )
    (paths.yara_rules_custom / "user.yara").write_text(
        "rule UserYara { condition: true }\n",
        encoding="utf-8",
    )
    after = p.availability()
    assert after["bundled_rule_file_count"] == before["bundled_rule_file_count"]
    assert after["custom_rule_file_count"] == 2
    assert after["custom_rule_count"] == 2
    assert after["valid_rule_file_count"] == before["valid_rule_file_count"] + 2
    assert after["loaded_rule_count"] == before["loaded_rule_count"] + 2
    summary = after["status_summary"] or ""
    assert "2 custom rule files" in summary
    assert classify_rule_source(
        paths.yara_rules_custom / "user.yar",
        bundled_dir=paths.yara_rules_bundled,
        custom_dir=paths.yara_rules_custom,
    ) == "custom"


def test_invalid_rule_skipped_when_others_valid(tmp_path: Path) -> None:
    _require_yara()
    paths = AppPaths(tmp_path / "data").ensure()
    bad = paths.yara_rules_custom / "bad.yar"
    bad.write_text("rule broken { condition: not_a_thing }\n", encoding="utf-8")
    p = _provider(paths)
    _rules, meta = p.compile_rules(kind=KIND_MEMORY)
    skipped_names = [Path(item["path"]).name for item in meta["skipped"]]
    assert "bad.yar" in skipped_names
    avail = p.availability()
    assert "syntax error" in avail["status_summary"] or "skipped" in avail["status_summary"]
    assert "Traceback" not in (avail["status_summary"] or "")


def test_all_invalid_rules_fail(tmp_path: Path) -> None:
    _require_yara()
    bundled = tmp_path / "bundled"
    custom = tmp_path / "custom"
    bundled.mkdir()
    custom.mkdir()
    (custom / "bad.yar").write_text("rule broken { condition: not_a_thing }\n", encoding="utf-8")
    p = YaraProvider(default_rules_dir=tmp_path, bundled_dir=bundled, custom_dir=custom)
    with pytest.raises(AppError) as ei:
        p.compile_rules()
    assert ei.value.code == "yara_compile_failed"
    assert "bad.yar" in (ei.value.details or "")
    assert "Traceback" not in (ei.value.message or "")


def test_compile_and_scan_match_and_nomatch(tmp_path: Path) -> None:
    _require_yara()
    bundled = tmp_path / "bundled"
    custom = tmp_path / "custom"
    bundled.mkdir()
    custom.mkdir()
    (custom / "demo.yar").write_text(
        """
rule MemScopeDemoMZ
{
    meta:
        description = "fixture PE header"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}
""",
        encoding="utf-8",
    )
    p = YaraProvider(default_rules_dir=tmp_path, bundled_dir=bundled, custom_dir=custom)
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ" + b"\x00" * 32)
    res = p.scan_file(target)
    assert res["status"] == "completed"
    assert res["match_count"] >= 1
    assert res["matches"][0]["rule_name"] == "MemScopeDemoMZ"
    assert res["matches"][0]["strings"]

    target2 = tmp_path / "empty.bin"
    target2.write_bytes(b"\x00" * 64)
    res2 = p.scan_file(target2)
    assert res2["match_count"] == 0


def test_rule_path_outside_denied(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    outside = tmp_path / "outside.yar"
    outside.write_text("rule t { condition: true }\n", encoding="utf-8")
    p = _provider(paths)
    with pytest.raises(AppError) as ei:
        p.configure({"extra_rule_paths": [str(outside)]})
    assert ei.value.code == "yara_rule_path_denied"


def test_memory_vs_artifact_rule_classification(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    mem = paths.yara_rules_bundled / "memory" / "x.yar"
    art = paths.yara_rules_bundled / "artifact" / "x.yar"
    custom = paths.yara_rules_custom / "both.yar"
    custom.write_text("rule Both { condition: true }\n", encoding="utf-8")
    assert classify_rule_kinds(mem, bundled_dir=paths.yara_rules_bundled, custom_dir=paths.yara_rules_custom) == {
        KIND_MEMORY
    }
    assert classify_rule_kinds(art, bundled_dir=paths.yara_rules_bundled, custom_dir=paths.yara_rules_custom) == {
        KIND_ARTIFACT
    }
    assert classify_rule_kinds(
        custom, bundled_dir=paths.yara_rules_bundled, custom_dir=paths.yara_rules_custom
    ) == {KIND_MEMORY, KIND_ARTIFACT}


def test_yara_workflow_job_and_provenance(tmp_path: Path) -> None:
    _require_yara()
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "img.raw"
    img.write_bytes(b"yara-img")
    ev = import_evidence(db, str(img))
    adir = artifact_store.artifact_dir(paths, ev["id"])
    apath = adir / "pid.1.vad.x1000-x2000.dmp"
    apath.write_bytes(b"MZ" + b"\x00" * 40 + b"mimikatz sekurlsa::logonpasswords")
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

    jm = JobManager(db)

    def handler(db_, params, cancelled, progress):
        return yara_workflows.run_yara_artifact_scan_job(
            db_, params, cancelled, progress, paths=paths
        )

    jm.register("yara_artifact_scan", handler)
    jm.start()
    job = jm.submit(
        "yara_artifact_scan",
        evidence_id=ev["id"],
        params={"artifact_id": art_id},
        message="test yara",
    )
    j = _wait_job(jm, job["id"])
    assert j["status"] == "completed", j
    assert j["result"]["scan"]["match_count"] >= 1
    assert j["result"]["scan"]["target_kind"] == KIND_ARTIFACT
    bundles = yara_workflows.list_yara_scans_for_artifact(db, art_id)
    assert bundles["total"] >= 1
    m = bundles["items"][0]["matches"][0]
    assert m["artifact_id"] == art_id
    assert m["evidence_id"] == ev["id"]
    findings = db.fetchall(
        "SELECT * FROM findings WHERE evidence_id = ? AND finding_type = 'signature_detection'",
        (ev["id"],),
    )
    assert findings
    assert "Signature Detection" in findings[0]["explanation"]
    assert "Extracted PE Artifact" in findings[0]["explanation"]
    db.close()


def test_memory_scan_findings_and_custom_rule(tmp_path: Path) -> None:
    _require_yara()
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    marker = b"DUMPLYZER_CUSTOM_MEMORY_TOKEN"
    img = tmp_path / "mem.raw"
    img.write_bytes(
        b"padding-"
        + b"System.Management.Automation.AmsiUtils\x00amsiInitFailed\x00NonPublic,Static\x00"
        + marker
        + b"-end"
    )
    ev = import_evidence(db, str(img))
    (paths.yara_rules_custom / "custom_token.yar").write_text(
        'rule CustomDumpToken { strings: $a = "DUMPLYZER_CUSTOM_MEMORY_TOKEN" ascii condition: $a }\n',
        encoding="utf-8",
    )
    result = yara_workflows.run_yara_memory_scan_job(
        db,
        {"evidence_id": ev["id"]},
        cancelled=lambda: False,
        progress=lambda _m: None,
        paths=paths,
    )
    assert result["scan"]["status"] == "completed"
    assert result["scan"]["target_kind"] == KIND_MEMORY
    names = {m["rule_name"] for m in result["matches"]}
    assert "CustomDumpToken" in names
    assert "dumplyzer_script_amsi_bypass_memory" in names
    findings = db.fetchall(
        "SELECT * FROM findings WHERE evidence_id = ? AND finding_type = 'signature_detection'",
        (ev["id"],),
    )
    assert any("Memory Dump" in (row["explanation"] or "") for row in findings)
    listed = yara_workflows.list_yara_scans_for_evidence(db, ev["id"])
    assert listed["total"] >= 1
    db.close()


def test_memory_scan_does_not_modify_dump(tmp_path: Path) -> None:
    _require_yara()
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "readonly.raw"
    original = b"\x00\x01DUMP" + b"\x00" * 64 + b"mimikatz gentilkiwi"
    img.write_bytes(original)
    digest = artifact_store.sha256_file(img)
    ev = import_evidence(db, str(img))
    yara_workflows.run_yara_memory_scan_job(
        db,
        {"evidence_id": ev["id"]},
        cancelled=lambda: False,
        progress=lambda _m: None,
        paths=paths,
    )
    assert img.read_bytes() == original
    assert artifact_store.sha256_file(img) == digest
    db.close()


def test_cancellation_before_scan(tmp_path: Path) -> None:
    _require_yara()
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "c.raw"
    img.write_bytes(b"cancel-me")
    ev = import_evidence(db, str(img))
    with pytest.raises(AppError) as ei:
        yara_workflows.run_yara_memory_scan_job(
            db,
            {"evidence_id": ev["id"]},
            cancelled=lambda: True,
            progress=lambda _m: None,
            paths=paths,
        )
    assert ei.value.code == "job_cancelled"
    db.close()


def test_chunked_large_file_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _require_yara()
    monkeypatch.setenv("DUMPLYZER_YARA_CHUNK_THRESHOLD", "64")
    monkeypatch.setenv("DUMPLYZER_YARA_CHUNK_BYTES", "64")
    bundled = tmp_path / "bundled"
    custom = tmp_path / "custom"
    bundled.mkdir()
    custom.mkdir()
    (custom / "tok.yar").write_text(
        'rule ChunkToken { strings: $a = "CHUNKTOKENXYZ" ascii condition: $a }\n',
        encoding="utf-8",
    )
    p = YaraProvider(default_rules_dir=tmp_path, bundled_dir=bundled, custom_dir=custom)
    target = tmp_path / "big.bin"
    target.write_bytes((b"\x00" * 80) + b"CHUNKTOKENXYZ" + (b"\x00" * 80))
    res = p.scan_memory_image(target)
    assert res["ruleset"]["scan_mode"] == "chunked"
    assert res["match_count"] >= 1
    assert res["matches"][0]["rule_name"] == "ChunkToken"


def test_custom_rules_survive_bundled_refresh(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    custom = paths.yara_rules_custom / "keep_me.yar"
    custom.write_text("rule KeepMe { condition: true }\n", encoding="utf-8")
    body = custom.read_text(encoding="utf-8")
    sync_bundled_yara_rules(paths.yara_rules_bundled)
    paths.ensure()
    assert custom.is_file()
    assert custom.read_text(encoding="utf-8") == body
    assert custom.exists()


def test_yara_unavailable_path(monkeypatch, tmp_path: Path) -> None:
    import memscope_engine.providers.yara_provider as yp

    monkeypatch.setattr(
        yp,
        "detect_yara",
        lambda: {
            "available": False,
            "reason": "Signature Detection is not available in this runtime.",
            "suggestion": "Use the bundled Dumplyzer analysis runtime.",
            "yara_version": None,
            "binding": None,
        },
    )
    p = YaraProvider(default_rules_dir=tmp_path)
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    with pytest.raises(AppError) as ei:
        p.scan_file(f)
    assert ei.value.code == "yara_unavailable"
    assert "pip" not in (ei.value.message or "").lower()
    assert "yara-python" not in (ei.value.message or "").lower()


def test_yara_status_counts_without_compiling_invalid_custom(tmp_path: Path) -> None:
    _require_yara()
    from memscope_engine.server import HANDLERS, handle_app_init

    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    custom = AppPaths(tmp_path / "ipc").yara_rules_custom
    (custom / "bad.yar").write_text(
        "rule broken { condition: not_a_thing }\n",
        encoding="utf-8",
    )
    status = HANDLERS["yara.status"]({})
    assert status["available"] is True
    assert int(status.get("custom_rule_count") or 0) == 1
    assert int(status.get("skipped_rule_file_count") or 0) == 0
    reloaded = HANDLERS["yara.reload"]({})
    assert int(reloaded.get("skipped_rule_file_count") or 0) >= 1


def test_yara_reload_rpc(tmp_path: Path) -> None:
    from memscope_engine.server import HANDLERS, handle_app_init

    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    assert "yara.reload" in HANDLERS
    assert "yara.scan_extracted" in HANDLERS
    status = HANDLERS["yara.reload"]({})
    assert "available" in status
    assert status.get("provider") == "yara" or "status_summary" in status
    assert Path(status["custom_dir"]) == AppPaths(tmp_path / "ipc").yara_rules_custom
    if status.get("available"):
        assert int(status.get("bundled_rule_file_count") or 0) >= 1
        assert int(status.get("custom_rule_file_count") or 0) == 0
        assert "0 custom rule files" in (status.get("status_summary") or "")


def test_yara_reload_picks_up_added_and_removed_custom_rule(tmp_path: Path) -> None:
    _require_yara()
    from memscope_engine.server import HANDLERS, handle_app_init

    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    custom = AppPaths(tmp_path / "ipc").yara_rules_custom
    probe = custom / "_reload_probe.yar"
    before = HANDLERS["yara.reload"]({})
    assert int(before.get("custom_rule_count") or 0) == 0
    bundled = int(before.get("bundled_rule_count") or 0)
    total = int(before.get("loaded_rule_count") or 0)
    probe.write_text("rule ReloadProbe { condition: true }\n", encoding="utf-8")
    try:
        added = HANDLERS["yara.reload"]({})
        assert added.get("custom_dir") == before.get("custom_dir")
        assert int(added.get("bundled_rule_count") or 0) == bundled
        assert int(added.get("custom_rule_count") or 0) == 1
        assert int(added.get("loaded_rule_count") or 0) == total + 1
    finally:
        probe.unlink(missing_ok=True)
    after = HANDLERS["yara.reload"]({})
    assert int(after.get("custom_rule_count") or 0) == 0
    assert int(after.get("bundled_rule_count") or 0) == bundled
    assert int(after.get("loaded_rule_count") or 0) == total


def test_extracted_files_scan_requires_pe(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "mem.raw"
    img.write_bytes(b"padding" * 32)
    ev = import_evidence(db, str(img))
    with pytest.raises(AppError) as ei:
        yara_workflows.run_yara_extracted_files_job(
            db,
            {"evidence_id": ev["id"]},
            cancelled=lambda: False,
            progress=lambda _m: None,
            paths=paths,
        )
    assert ei.value.code == "extracted_pe_missing"
    db.close()


def test_extracted_files_scan_covers_pe_artifacts(tmp_path: Path) -> None:
    _require_yara()
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "mem.raw"
    img.write_bytes(b"\x00\x01DUMPLYZER-YARA-IMAGE\x00")
    ev = import_evidence(db, str(img))
    adir = artifact_store.artifact_dir(paths, ev["id"])
    apath = adir / "pid.1.extracted.exe"
    apath.write_bytes(b"MZ" + b"\x00" * 40 + b"mimikatz sekurlsa::logonpasswords")
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
    result = yara_workflows.run_yara_extracted_files_job(
        db,
        {"evidence_id": ev["id"]},
        cancelled=lambda: False,
        progress=lambda _m: None,
        paths=paths,
    )
    assert result["scanned"] == 1
    listed = yara_workflows.list_yara_scans_for_evidence(db, ev["id"])
    assert listed["total"] >= 1
    assert listed["items"][0]["scan"]["artifact_id"] == art_id
    db.close()
