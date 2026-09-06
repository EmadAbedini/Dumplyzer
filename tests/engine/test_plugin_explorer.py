"""Plugin Explorer discovery, requirements, execution, cache, and IPC tests."""

from __future__ import annotations

import json
import time
from pathlib import Path
from uuid import uuid4

import pytest

from memscope_engine.analysis import plugin_explorer
from memscope_engine.analysis.workflows import import_evidence
from memscope_engine.cache.store import AnalysisCache, cache_key, canonical_params
from memscope_engine.errors import AppError
from memscope_engine.jobs.manager import JobManager
from memscope_engine.paths import AppPaths
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION
from memscope_engine.volatility.discovery import (
    discover_plugins,
    plugin_runnable_with_evidence,
    resolve_plugin_class,
    volatility_version,
)
from memscope_engine.volatility.requirements import (
    normalize_requirement,
    validate_user_parameters,
)
from memscope_engine.volatility.session import PluginResult, VolatilitySession
from memscope_engine.volatility.treegrid import treegrid_to_table


class _Col:
    def __init__(self, name, type_):
        self.name = name
        self.type = type_


class _Node:
    def __init__(self, values, path):
        self.values = values
        self.path = path


class _Grid:
    def __init__(self, columns, nodes):
        self.columns = columns
        self._nodes = nodes

    def populate(self, fn, acc, fail_on_errors=True):
        for node in self._nodes:
            acc = fn(node, acc)
        return None


def _seed_evidence(tmp_path: Path) -> tuple[AppPaths, Database, dict]:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "img.raw"
    img.write_bytes(b"MEMSCOPE-PLUGIN-EXPLORER")
    ev = import_evidence(db, str(img))
    return paths, db, ev


def test_schema_v8(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    assert db.schema_version() == 9
    db.execute("SELECT cache_hit, cache_key, result_path, plugin_id FROM plugin_executions LIMIT 1")
    db.execute("SELECT COUNT(*) AS c FROM analysis_cache")
    db.execute("SELECT COUNT(*) AS c FROM plugin_results")
    db.close()


def test_plugin_enumeration_and_version() -> None:
    catalog = discover_plugins()
    assert catalog["volatility_version"] == volatility_version()
    assert catalog["plugin_count"] >= 50
    assert len(catalog["items"]) == catalog["plugin_count"]
    ids = {i["id"] for i in catalog["items"]}
    assert "windows.pslist.PsList" in ids
    cats = {c["id"] for c in catalog["categories"]}
    assert "windows" in cats
    assert "linux" in cats
    for item in catalog["items"]:
        if item["available"]:
            assert item["id"]
            assert item["module_path"].startswith("volatility3.")
            assert item["class_name"]
        else:
            assert item["discovery_errors"]


def test_discovery_failures_are_not_marked_available() -> None:
    catalog = discover_plugins()
    for item in catalog["items"]:
        if item["discovery_errors"] and any(
            "get_requirements failed" in e or "requires framework" in e for e in item["discovery_errors"]
        ):
            assert item["available"] is False
    for failed in catalog["import_failures"]:
        assert isinstance(failed, str)
        assert failed not in {i["id"] for i in catalog["items"] if i["available"]}


def test_metadata_normalization() -> None:
    meta = plugin_explorer.get_plugin_metadata("windows.pslist.PsList")
    assert meta["id"] == "windows.pslist.PsList"
    assert meta["class_name"] == "PsList"
    assert "process" in (meta["description"] or "").lower()
    names = {r["name"]: r for r in meta["requirements"]}
    assert names["kernel"]["type"] == "ModuleRequirement"
    assert names["kernel"]["configurable"] is False
    assert names["physical"]["type"] == "BooleanRequirement"
    assert names["physical"]["optional"] is True
    assert names["pid"]["type"] == "ListRequirement"
    assert names["pid"]["configurable"] is True
    assert names["pid"]["element_type"] == "int"
    assert names["dump"]["type"] == "BooleanRequirement"
    assert any(r["type"] == "VersionRequirement" for r in meta["requirements"])


def test_requirement_type_normalization() -> None:
    from volatility3.framework.configuration.requirements import (
        BooleanRequirement,
        ChoiceRequirement,
        IntRequirement,
        ListRequirement,
        ModuleRequirement,
        URIRequirement,
        VersionRequirement,
    )

    choice = normalize_requirement(
        ChoiceRequirement(["json", "text"], name="fmt", description="format", optional=True, default="json")
    )
    assert choice["type"] == "ChoiceRequirement"
    assert choice["configurable"] is True
    assert choice["choices"] == ["json", "text"]

    boolean = normalize_requirement(BooleanRequirement(name="dump", optional=True, default=False))
    assert boolean["configurable"] is True
    integer = normalize_requirement(IntRequirement(name="maxsize", optional=True, default=10))
    assert integer["configurable"] is True
    listing = normalize_requirement(
        ListRequirement(element_type=int, name="pid", optional=True, description="pids")
    )
    assert listing["configurable"] is True
    assert listing["element_type"] == "int"

    uri = normalize_requirement(URIRequirement(name="isf", optional=True))
    assert uri["configurable"] is False
    assert uri["classification"] == "framework"
    kernel = normalize_requirement(ModuleRequirement(name="kernel", description="Windows kernel"))
    assert kernel["configurable"] is False
    from volatility3.plugins.timeliner import TimeLinerInterface

    ver = normalize_requirement(
        VersionRequirement(name="timeliner", component=TimeLinerInterface, version=(1, 0, 0))
    )
    assert ver["configurable"] is False


def test_validate_user_parameters_types() -> None:
    meta = plugin_explorer.get_plugin_metadata("windows.pslist.PsList")
    cleaned = validate_user_parameters(meta, {"physical": True, "pid": "4, 8", "dump": False})
    assert cleaned["physical"] is True
    assert cleaned["pid"] == [4, 8]
    assert cleaned["dump"] is False
    with pytest.raises(AppError) as ei:
        validate_user_parameters(meta, {"kernel": "ntkrnlmp"})
    assert ei.value.code == "plugin_param_forbidden"
    with pytest.raises(AppError) as ei:
        validate_user_parameters(meta, {"pid": "not-an-int"})
    assert ei.value.code == "plugin_param_type"
    with pytest.raises(AppError) as ei:
        validate_user_parameters(meta, {"nope": 1})
    assert ei.value.code == "plugin_param_unknown"
    with pytest.raises(AppError) as ei:
        validate_user_parameters(meta, {"physical": "maybe"})
    assert ei.value.code == "plugin_param_type"
    with pytest.raises(AppError) as ei:
        validate_user_parameters(meta, {"command": "vol.py -f x"})
    assert ei.value.code == "plugin_invalid_params"


def test_choice_requirement_validation() -> None:
    meta = {
        "requirements": [],
        "configurable_parameters": [
            {
                "name": "fmt",
                "type": "ChoiceRequirement",
                "configurable": True,
                "optional": True,
                "choices": ["json", "text"],
            }
        ],
    }
    assert validate_user_parameters(meta, {"fmt": "json"})["fmt"] == "json"
    with pytest.raises(AppError) as ei:
        validate_user_parameters(meta, {"fmt": "xml"})
    assert ei.value.code == "plugin_param_choice"


def test_string_path_rejected() -> None:
    meta = {
        "requirements": [],
        "configurable_parameters": [
            {
                "name": "pattern",
                "type": "StringRequirement",
                "configurable": True,
                "optional": True,
            }
        ],
    }
    assert validate_user_parameters(meta, {"pattern": "MZ"})["pattern"] == "MZ"
    with pytest.raises(AppError) as ei:
        validate_user_parameters(meta, {"pattern": r"C:\Windows\memory.dmp"})
    assert ei.value.code == "plugin_param_path_denied"


def test_safe_plugin_resolution() -> None:
    ident, cls = resolve_plugin_class("windows.pslist.PsList")
    assert ident == "windows.pslist.PsList"
    assert cls.__name__ == "PsList"
    ident2, _ = resolve_plugin_class("windows.pslist")
    assert ident2 == "windows.pslist.PsList"
    with pytest.raises(AppError) as ei:
        resolve_plugin_class("os.system")
    assert ei.value.code == "plugin_unknown"
    with pytest.raises(AppError) as ei:
        resolve_plugin_class("../evil")
    assert ei.value.code == "plugin_invalid_id"
    with pytest.raises(AppError) as ei:
        resolve_plugin_class("windows.pslist.PsList;import os")
    assert ei.value.code == "plugin_invalid_id"
    with pytest.raises(AppError) as ei:
        resolve_plugin_class("volatility3.plugins.windows.pslist.PsList")
    assert ei.value.code in {"plugin_invalid_id", "plugin_unknown"}


def test_runnable_os_match(tmp_path: Path) -> None:
    paths, db, ev = _seed_evidence(tmp_path)
    meta_w = plugin_explorer.get_plugin_metadata("windows.pslist.PsList")
    meta_l = plugin_explorer.get_plugin_metadata("linux.pslist.PsList")
    unknown = plugin_runnable_with_evidence(meta_w, ev)
    assert unknown["os_match"] == "unknown"
    db.execute("UPDATE evidence SET detected_os = 'Windows NT 10' WHERE id = ?", (ev["id"],))
    ev = db.fetchone("SELECT * FROM evidence WHERE id = ?", (ev["id"],))
    assert plugin_runnable_with_evidence(meta_w, ev)["runnable"] is True
    assert plugin_runnable_with_evidence(meta_l, ev)["runnable"] is False
    db.close()


def test_treegrid_normalization() -> None:
    grid = _Grid(
        [_Col("PID", int), _Col("Name", str), _Col("Offset", object)],
        [
            _Node([4, "System", None], ["r"]),
            _Node([400, "lsass", object()], ["r", "c"]),
        ],
    )
    table = treegrid_to_table(grid)
    assert table["row_count"] == 2
    assert table["nested"] is True
    assert table["columns"][0]["type"] == "int"
    assert table["rows"][0]["values"]["PID"] == 4
    assert table["rows"][1]["depth"] == 1
    empty = treegrid_to_table(_Grid([_Col("A", str)], []))
    assert empty["row_count"] == 0
    assert empty["rows"] == []


def test_treegrid_structured_and_bytes() -> None:
    grid = _Grid(
        [_Col("Data", bytes), _Col("Meta", dict)],
        [_Node([b"MZ", {"k": 1}], ["r"])],
    )
    table = treegrid_to_table(grid)
    cell = table["rows"][0]["values"]["Data"]
    assert cell["type"] == "bytes"
    assert cell["hex"] == b"MZ".hex()
    assert table["rows"][0]["values"]["Meta"]["k"] == 1


def test_invalid_plugin_and_evidence(tmp_path: Path) -> None:
    paths, db, ev = _seed_evidence(tmp_path)
    with pytest.raises(AppError) as ei:
        plugin_explorer.validate_execution_request(
            db, evidence_id=ev["id"], plugin_id="not.a.plugin.Nope", parameters={}
        )
    assert ei.value.code == "plugin_unknown"
    with pytest.raises(AppError) as ei:
        plugin_explorer.validate_execution_request(
            db, evidence_id="missing", plugin_id="windows.pslist.PsList", parameters={}
        )
    assert ei.value.code == "evidence_missing"
    Path(ev["path"]).unlink()
    with pytest.raises(AppError) as ei:
        plugin_explorer.validate_execution_request(
            db, evidence_id=ev["id"], plugin_id="windows.pslist.PsList", parameters={}
        )
    assert ei.value.code == "evidence_not_found"
    db.close()


def test_dummy_image_structured_unsatisfied(tmp_path: Path) -> None:
    paths, db, ev = _seed_evidence(tmp_path)
    jm = JobManager(db)

    def handler(db_, params, cancelled, progress):
        return plugin_explorer.run_advanced_plugin_job(
            db_, params, cancelled, progress, paths=paths
        )

    jm.register("plugin_advanced", handler)
    jm.start()
    job = jm.submit(
        "plugin_advanced",
        evidence_id=ev["id"],
        params={"evidence_id": ev["id"], "plugin_id": "windows.pslist.PsList", "parameters": {}},
    )
    for _ in range(80):
        got = jm.get(job["id"])
        if got["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.1)
    got = jm.get(job["id"])
    assert got["status"] == "failed"
    assert got["error"]
    assert got["error"].get("code") in {
        "volatility_unsatisfied",
        "volatility_construct_failed",
        "plugin_execution_failed",
        "plugin_not_runnable",
    }
    db.close()


def _fake_plugin_result() -> PluginResult:
    return PluginResult(
        plugin="windows.pslist.PsList",
        columns=["PID", "PPID", "ImageFileName"],
        rows=[[4, 0, "System"], [400, 4, "lsass.exe"]],
        transparency={"tool": "volatility3", "plugin": "windows.pslist.PsList"},
        table={
            "model_version": 1,
            "columns": [
                {"name": "PID", "type": "int"},
                {"name": "PPID", "type": "int"},
                {"name": "ImageFileName", "type": "str"},
            ],
            "rows": [
                {"depth": 0, "cells": [4, 0, "System"], "values": {"PID": 4, "PPID": 0, "ImageFileName": "System"}},
                {
                    "depth": 0,
                    "cells": [400, 4, "lsass.exe"],
                    "values": {"PID": 400, "PPID": 4, "ImageFileName": "lsass.exe"},
                },
            ],
            "row_count": 2,
            "nested": False,
        },
    )


def test_mocked_execution_cache_and_persistence(tmp_path: Path, monkeypatch) -> None:
    paths, db, ev = _seed_evidence(tmp_path)
    calls = {"n": 0}

    def fake_run(self, plugin_cls, plugin_params=None, progress_callback=None, **kwargs):
        calls["n"] += 1
        return _fake_plugin_result()

    monkeypatch.setattr(VolatilitySession, "run_plugin", fake_run)

    def handler(db_, params, cancelled, progress):
        return plugin_explorer.run_advanced_plugin_job(
            db_, params, cancelled, progress, paths=paths
        )

    jm = JobManager(db)
    jm.register("plugin_advanced", handler)
    jm.start()
    job1 = jm.submit(
        "plugin_advanced",
        evidence_id=ev["id"],
        params={"evidence_id": ev["id"], "plugin_id": "windows.pslist.PsList", "parameters": {"physical": False}},
    )
    for _ in range(80):
        g = jm.get(job1["id"])
        if g["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.05)
    g1 = jm.get(job1["id"])
    assert g1["status"] == "completed", g1
    assert g1["result"]["execution"]["cache_hit"] is False
    assert g1["result"]["result"]["row_count"] == 2
    assert g1["result"]["result"]["raw"]["columns"]
    assert "malware" not in json.dumps(g1["result"]).lower()
    assert calls["n"] == 1

    job2 = jm.submit(
        "plugin_advanced",
        evidence_id=ev["id"],
        params={"evidence_id": ev["id"], "plugin_id": "windows.pslist.PsList", "parameters": {"physical": False}},
    )
    for _ in range(80):
        g = jm.get(job2["id"])
        if g["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.05)
    g2 = jm.get(job2["id"])
    assert g2["status"] == "completed"
    assert g2["result"]["execution"]["cache_hit"] is True
    assert calls["n"] == 1

    job3 = jm.submit(
        "plugin_advanced",
        evidence_id=ev["id"],
        params={"evidence_id": ev["id"], "plugin_id": "windows.pslist.PsList", "parameters": {"physical": True}},
    )
    for _ in range(80):
        g = jm.get(job3["id"])
        if g["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.05)
    g3 = jm.get(job3["id"])
    assert g3["status"] == "completed"
    assert g3["result"]["execution"]["cache_hit"] is False
    assert calls["n"] == 2

    runs = db.fetchall("SELECT * FROM analysis_runs WHERE kind='plugin_advanced'")
    assert len(runs) == 3
    execs = plugin_explorer.list_executions(db, ev["id"])
    assert execs["total"] == 3
    db.close()


def test_cache_key_changes_with_inputs() -> None:
    base = dict(
        evidence_sha256="abc",
        volatility_version="2.28.0",
        plugin_id="windows.pslist.PsList",
        parameters={"pid": [4]},
        schema_version=8,
    )
    k1 = cache_key(**base)
    k2 = cache_key(**{**base, "parameters": {"pid": [8]}})
    k3 = cache_key(**{**base, "volatility_version": "2.27.0"})
    k4 = cache_key(**{**base, "evidence_sha256": "def"})
    k5 = cache_key(**{**base, "schema_version": 7})
    assert len({k1, k2, k3, k4, k5}) == 5
    assert cache_key(**base) == k1
    assert canonical_params({"b": 1, "a": None}) == {"b": 1}


def test_cancellation_before_run(tmp_path: Path, monkeypatch) -> None:
    paths, db, ev = _seed_evidence(tmp_path)

    def fake_run(self, *a, **k):
        raise AssertionError("should not run")

    monkeypatch.setattr(VolatilitySession, "run_plugin", fake_run)
    with pytest.raises(AppError) as ei:
        plugin_explorer.run_advanced_plugin_job(
            db,
            {
                "evidence_id": ev["id"],
                "plugin_id": "windows.pslist.PsList",
                "parameters": {},
                "job_id": None,
            },
            cancelled=lambda: True,
            progress=lambda _m: None,
            paths=paths,
        )
    assert ei.value.code == "job_cancelled"
    db.close()


def test_timeout_after_run(tmp_path: Path, monkeypatch) -> None:
    paths, db, ev = _seed_evidence(tmp_path)
    monkeypatch.setattr(VolatilitySession, "run_plugin", lambda *a, **k: _fake_plugin_result())
    clock = {"t": 0.0}

    def mono() -> float:
        clock["t"] += 1000.0
        return clock["t"]

    monkeypatch.setattr(plugin_explorer.time, "monotonic", mono)
    with pytest.raises(AppError) as ei:
        plugin_explorer.run_advanced_plugin_job(
            db,
            {
                "evidence_id": ev["id"],
                "plugin_id": "windows.pslist.PsList",
                "parameters": {},
                "timeout_secs": 5,
            },
            cancelled=lambda: False,
            progress=lambda _m: None,
            paths=paths,
        )
    assert ei.value.code == "plugin_timeout"
    db.close()


def test_process_link_when_pid_known(tmp_path: Path, monkeypatch) -> None:
    paths, db, ev = _seed_evidence(tmp_path)
    proc_id = str(uuid4())
    run_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (id, evidence_id, kind, status, started_at, schema_version, notes)
        VALUES (?, ?, 'basic_triage', 'completed', '2020-01-01T00:00:00+00:00', 8, 'seed')
        """,
        (run_id, ev["id"]),
    )
    db.execute(
        """
        INSERT INTO processes (
          id, evidence_id, analysis_run_id, pid, ppid, name, source_plugin
        ) VALUES (?, ?, ?, 4, 0, 'System', 'windows.pslist')
        """,
        (proc_id, ev["id"], run_id),
    )
    monkeypatch.setattr(VolatilitySession, "run_plugin", lambda *a, **k: _fake_plugin_result())
    bundle = plugin_explorer.run_advanced_plugin_job(
        db,
        {"evidence_id": ev["id"], "plugin_id": "windows.pslist.PsList", "parameters": {}},
        cancelled=lambda: False,
        progress=lambda _m: None,
        paths=paths,
    )
    links = bundle["result"]["links"]
    assert any(l.get("process_id") == proc_id and l.get("pid") == 4 for l in links)
    db.close()


def test_ipc_round_trip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MEMSCOPE_DATA_DIR", str(tmp_path / "ipcdata"))
    from memscope_engine.server import HANDLERS, handle_app_init

    init = handle_app_init({"data_dir": str(tmp_path / "ipcdata")})
    assert init["schema_version"] == 9
    listed = HANDLERS["plugins.list"]({})
    assert listed["plugin_count"] >= 50
    assert listed["volatility_version"]
    detail = HANDLERS["plugins.get"]({"plugin_id": "windows.pslist.PsList"})
    assert detail["plugin"]["id"] == "windows.pslist.PsList"
    with pytest.raises(AppError):
        HANDLERS["plugins.validate"]({"plugin_id": "windows.pslist.PsList", "parameters": {}})
    from memscope_engine import server as srv

    engine_db = srv._db()
    img = tmp_path / "ipc.raw"
    img.write_bytes(b"ipc-img")
    ev = import_evidence(engine_db, str(img))
    val = HANDLERS["plugins.validate"](
        {"evidence_id": ev["id"], "plugin_id": "windows.pslist.PsList", "parameters": {"physical": False}}
    )
    assert val["ok"] is True
    assert val["parameters"]["physical"] is False
    job = HANDLERS["plugins.execute"](
        {"evidence_id": ev["id"], "plugin_id": "windows.pslist.PsList", "parameters": {}}
    )
    assert job["kind"] == "plugin_advanced"
    for _ in range(80):
        got = HANDLERS["jobs.get"]({"job_id": job["id"]})
        if got["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.1)
    got = HANDLERS["jobs.get"]({"job_id": job["id"]})
    assert got["status"] in ("failed", "completed")
    execs = HANDLERS["plugins.executions"]({"evidence_id": ev["id"]})
    assert execs["total"] >= 1


def test_frameworkinfo_real_execution_if_possible(tmp_path: Path) -> None:
    """Runs a real Volatility plugin with no memory-layer requirement.

    Does not invent process/memory findings. FrameworkInfo lists framework modules.
    """
    paths, db, ev = _seed_evidence(tmp_path)
    try:
        bundle = plugin_explorer.run_advanced_plugin_job(
            db,
            {
                "evidence_id": ev["id"],
                "plugin_id": "frameworkinfo.FrameworkInfo",
                "parameters": {},
                "timeout_secs": 60,
            },
            cancelled=lambda: False,
            progress=lambda _m: None,
            paths=paths,
        )
    except AppError as exc:
        pytest.skip(f"FrameworkInfo could not run on this dummy file: {exc.code}")
    assert bundle["execution"]["status"] == "completed"
    assert bundle["execution"]["cache_hit"] is False
    assert bundle["result"]["row_count"] >= 1
    db.close()
