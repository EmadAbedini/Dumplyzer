"""YARA provider and workflow tests."""

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
from memscope_engine.paths import AppPaths
from memscope_engine.providers.yara_provider import (
    YaraProvider,
    detect_yara,
    normalize_match,
)
from memscope_engine.storage import Database


def test_schema_v5(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    assert db.schema_version() == 8
    db.execute("SELECT COUNT(*) AS c FROM yara_scans")
    db.execute("SELECT COUNT(*) AS c FROM yara_matches")
    db.close()


def test_yara_available_on_this_machine() -> None:
    info = detect_yara()
    # Document reality: this environment has yara-python 4.5.4
    assert info["available"] is True
    assert info["yara_version"]


def test_compile_invalid_rule(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    bad = paths.yara_rules / "bad.yar"
    bad.write_text("rule broken { condition: not_a_thing }\n", encoding="utf-8")
    p = YaraProvider(default_rules_dir=paths.yara_rules)
    with pytest.raises(AppError) as ei:
        p.compile_rules()
    assert ei.value.code == "yara_compile_failed"


def test_compile_and_scan_match_and_nomatch(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    rule = paths.yara_rules / "demo.yar"
    rule.write_text(
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
    p = YaraProvider(default_rules_dir=paths.yara_rules)
    # positive
    target = paths.tmp / "sample.bin"
    target.write_bytes(b"MZ" + b"\x00" * 32)
    res = p.scan_file(target)
    assert res["status"] == "completed"
    assert res["match_count"] >= 1
    assert res["matches"][0]["rule_name"] == "MemScopeDemoMZ"
    assert res["matches"][0]["strings"]

    # no match
    target2 = paths.tmp / "empty.bin"
    target2.write_bytes(b"\x00" * 64)
    res2 = p.scan_file(target2)
    assert res2["match_count"] == 0


def test_rule_path_outside_denied(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    outside = tmp_path / "outside.yar"
    outside.write_text("rule t { condition: true }\n", encoding="utf-8")
    p = YaraProvider(default_rules_dir=paths.yara_rules)
    with pytest.raises(AppError) as ei:
        p.configure({"extra_rule_paths": [str(outside)]})
    assert ei.value.code == "yara_rule_path_denied"


def test_yara_workflow_job_and_provenance(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    # seed evidence + artifact
    img = tmp_path / "img.raw"
    img.write_bytes(b"yara-img")
    ev = import_evidence(db, str(img))
    adir = artifact_store.artifact_dir(paths, ev["id"])
    apath = adir / "pid.1.vad.x1000-x2000.dmp"
    apath.write_bytes(b"MZ" + b"\x00" * 40)
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
    rule = paths.yara_rules / "mz.yar"
    rule.write_text(
        "rule FixtureMZ { strings: $a = { 4D 5A } condition: $a at 0 }\n",
        encoding="utf-8",
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
    for _ in range(100):
        j = jm.get(job["id"])
        if j["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.05)
    j = jm.get(job["id"])
    assert j["status"] == "completed", j
    assert j["result"]["scan"]["match_count"] >= 1
    bundles = yara_workflows.list_yara_scans_for_artifact(db, art_id)
    assert bundles["total"] >= 1
    assert bundles["items"][0]["matches"][0]["rule_name"] == "FixtureMZ"
    # provenance fields present
    m = bundles["items"][0]["matches"][0]
    assert m["artifact_id"] == art_id
    assert m["evidence_id"] == ev["id"]
    db.close()


def test_yara_unavailable_path(monkeypatch, tmp_path: Path) -> None:
    import memscope_engine.providers.yara_provider as yp

    def _no():
        raise ImportError("no yara")

    monkeypatch.setattr(yp, "detect_yara", lambda: {
        "available": False,
        "reason": "yara-python is not installed",
        "suggestion": "install",
        "yara_version": None,
        "binding": None,
    })
    # force scan_file to use detect
    p = YaraProvider(default_rules_dir=tmp_path)
    with pytest.raises(AppError) as ei:
        p.scan_file(tmp_path / "x.bin")
    # file missing may raise first — create file
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    with pytest.raises(AppError) as ei:
        p.scan_file(f)
    assert ei.value.code == "yara_unavailable"
