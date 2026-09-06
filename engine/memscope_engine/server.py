"""NDJSON JSON-RPC 2.0 server over stdio."""

from __future__ import annotations

import json
import sys
import traceback
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Callable

from memscope_engine.analysis import (
    mal_unpack_workflows,
    memory_artifacts,
    pe_sieve_workflows,
    plugin_explorer,
    process_analysis,
    search_iocs,
    workflows,
    yara_workflows,
)
from memscope_engine.errors import AppError, rpc_error_payload
from memscope_engine.jobs.manager import JobManager
from memscope_engine.logging_setup import get_logger, setup_logging
from memscope_engine.paths import AppPaths
from memscope_engine.storage import Database

log = get_logger("app")

_STATE: dict[str, Any] = {
    "paths": None,
    "db": None,
    "jobs": None,
}


def _vol_init() -> dict[str, Any]:
    import volatility3
    from volatility3.framework import automagic, constants, contexts, plugins

    try:
        vol_ver = version("volatility3")
    except PackageNotFoundError:
        vol_ver = getattr(constants, "PACKAGE_VERSION", "unknown")

    _ = contexts.Context
    _ = automagic
    _ = plugins

    return {
        "ok": True,
        "engine_version": "0.1.0-dev",
        "python_version": sys.version.split()[0],
        "volatility3_version": vol_ver,
        "volatility3_path": getattr(volatility3, "__file__", None),
        "framework_package_version": getattr(constants, "PACKAGE_VERSION", None),
    }


def _db() -> Database:
    db = _STATE.get("db")
    if db is None:
        raise AppError(
            code="engine_not_initialized",
            message="Analysis engine is not initialized.",
            suggestion="Call app.init before other methods.",
        )
    return db


def _paths() -> AppPaths:
    paths = _STATE.get("paths")
    if paths is None:
        raise AppError(
            code="engine_not_initialized",
            message="Analysis engine is not initialized.",
            suggestion="Call app.init before other methods.",
        )
    return paths


def _jobs() -> JobManager:
    jobs = _STATE.get("jobs")
    if jobs is None:
        raise AppError(
            code="engine_not_initialized",
            message="Job manager is not initialized.",
            suggestion="Call app.init before other methods.",
        )
    return jobs


def handle_app_init(params: dict[str, Any]) -> dict[str, Any]:
    data_dir = params.get("data_dir")
    paths = AppPaths(data_dir).ensure() if data_dir else AppPaths().ensure()
    setup_logging(paths.logs)
    if _STATE.get("db") is not None:
        try:
            _STATE["db"].close()
        except Exception:  # noqa: BLE001
            pass
    db = Database(paths.db_path)
    jobs = JobManager(db)
    jobs.register("basic_triage", process_analysis.run_basic_triage_job)
    jobs.register("process_recommended", process_analysis.run_process_recommended_job)
    jobs.register("vad_scan", memory_artifacts.run_vad_scan_job)

    def _vad_extract(db_, params, cancelled, progress):
        return memory_artifacts.run_vad_extract_job(
            db_, params, cancelled, progress, paths=paths
        )

    def _yara_scan(db_, params, cancelled, progress):
        return yara_workflows.run_yara_artifact_scan_job(
            db_, params, cancelled, progress, paths=paths
        )

    def _pe_sieve_scan(db_, params, cancelled, progress):
        return pe_sieve_workflows.run_pe_sieve_artifact_scan_job(
            db_, params, cancelled, progress, paths=paths
        )

    def _mal_unpack(db_, params, cancelled, progress):
        return mal_unpack_workflows.run_mal_unpack_artifact_job(
            db_, params, cancelled, progress, paths=paths
        )

    def _plugin_advanced(db_, params, cancelled, progress):
        return plugin_explorer.run_advanced_plugin_job(
            db_, params, cancelled, progress, paths=paths
        )

    jobs.register("vad_extract", _vad_extract)
    jobs.register("yara_artifact_scan", _yara_scan)
    jobs.register("pe_sieve_artifact_scan", _pe_sieve_scan)
    jobs.register("mal_unpack_artifact", _mal_unpack)
    jobs.register("plugin_advanced", _plugin_advanced)
    jobs.start()
    _STATE["paths"] = paths
    _STATE["db"] = db
    _STATE["jobs"] = jobs
    log.info("engine initialized", extra={"channel": "app"})
    return {
        "ok": True,
        "paths": paths.as_dict(),
        "schema_version": db.schema_version(),
        "volatility": _vol_init(),
        "yara": yara_workflows.yara_status(paths, db),
        "pe_sieve": pe_sieve_workflows.pe_sieve_status(paths, db),
        "mal_unpack": mal_unpack_workflows.mal_unpack_status(paths, db),
        "plugins": {
            "volatility_version": plugin_explorer.volatility_version(),
            "model_version": 1,
        },
    }


def handle_health(_params: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": True,
        "service": "memscope_engine",
        "version": "0.1.0-dev",
        "initialized": _STATE.get("db") is not None,
    }


def handle_job_submit(params: dict[str, Any]) -> dict[str, Any]:
    kind = params.get("kind")
    if not kind:
        raise AppError(code="invalid_params", message="kind is required", entity="job")
    return _jobs().submit(
        kind,
        evidence_id=params.get("evidence_id"),
        process_id=params.get("process_id"),
        pid=params.get("pid"),
        params=params.get("params") or {},
        message=params.get("message"),
    )


def _artifact_get(artifact_id: str) -> dict[str, Any]:
    dto = memory_artifacts.get_artifact(_db(), artifact_id)
    yara = yara_workflows.list_yara_scans_for_artifact(_db(), artifact_id)
    dto["yara_scans"] = yara["items"]
    dto["yara_status"] = yara_workflows.yara_status(_paths(), _db())
    pe = pe_sieve_workflows.list_pe_sieve_scans_for_artifact(_db(), artifact_id)
    dto["pe_sieve_scans"] = pe["items"]
    dto["pe_sieve_status"] = pe_sieve_workflows.pe_sieve_status(_paths(), _db())
    mu = mal_unpack_workflows.list_mal_unpack_scans_for_artifact(_db(), artifact_id)
    dto["mal_unpack_scans"] = mu["items"]
    dto["mal_unpack_status"] = mal_unpack_workflows.mal_unpack_status(_paths(), _db())
    return dto


HANDLERS: dict[str, Callable[[dict[str, Any]], Any]] = {
    "health": handle_health,
    "app.init": handle_app_init,
    "app.paths": lambda _p: _paths().as_dict(),
    "volatility.init": lambda _p: _vol_init(),
    "smoke.e2e": lambda _p: {
        "ok": True,
        "health": handle_health({}),
        "volatility": _vol_init(),
    },
    "evidence.import": lambda p: workflows.import_evidence(_db(), p["path"]),
    "evidence.list": lambda _p: {"items": workflows.list_evidence(_db())},
    "evidence.get": lambda p: workflows.get_evidence(_db(), p["evidence_id"]),
    # Prefer async jobs; keep sync alias that only queues
    "evidence.analyze_basic": lambda p: _jobs().submit(
        "basic_triage",
        evidence_id=p["evidence_id"],
        message="Basic triage (info + pslist)",
    ),
    "processes.list": lambda p: workflows.list_processes(
        _db(),
        p["evidence_id"],
        search=p.get("search"),
        limit=int(p.get("limit", 5000)),
        offset=int(p.get("offset", 0)),
    ),
    "process.get": lambda p: process_analysis.get_process_deep_dive(_db(), p["process_id"]),
    "process.analyze_recommended": lambda p: _jobs().submit(
        "process_recommended",
        evidence_id=p["evidence_id"],
        process_id=p.get("process_id"),
        pid=p.get("pid"),
        params={"evidence_id": p["evidence_id"], "process_id": p.get("process_id"), "pid": p.get("pid")},
        message=f"Recommended analysis PID {p.get('pid')}",
    ),
    "overview.get": lambda p: workflows.overview(_db(), p["evidence_id"]),
    "network.list": lambda p: process_analysis.list_network(_db(), p["evidence_id"]),
    "modules.list": lambda p: process_analysis.list_modules(
        _db(), p["evidence_id"], pid=p.get("pid")
    ),
    "findings.list": lambda p: process_analysis.list_findings(_db(), p["evidence_id"]),
    "search.query": lambda p: search_iocs.global_search(
        _db(),
        p["evidence_id"],
        p["query"],
        limit=int(p.get("limit", 200)),
    ),
    "iocs.extract": lambda p: search_iocs.extract_iocs(_db(), p["evidence_id"]),
    "iocs.list": lambda p: search_iocs.list_iocs(
        _db(), p["evidence_id"], ioc_type=p.get("ioc_type")
    ),
    "iocs.export_json": lambda p: search_iocs.export_iocs_json(_db(), p["evidence_id"]),
    "iocs.export_csv": lambda p: {
        "csv": search_iocs.export_iocs_csv(_db(), p["evidence_id"])
    },
    "memory.list": lambda p: memory_artifacts.list_memory_regions(
        _db(),
        p["evidence_id"],
        pid=p.get("pid"),
        process_id=p.get("process_id"),
        suspicious_only=bool(p.get("suspicious_only", False)),
        limit=int(p.get("limit", 10000)),
        offset=int(p.get("offset", 0)),
    ),
    "memory.get": lambda p: memory_artifacts.get_memory_region(_db(), p["region_id"]),
    "memory.scan": lambda p: _jobs().submit(
        "vad_scan",
        evidence_id=p["evidence_id"],
        process_id=p.get("process_id"),
        pid=p.get("pid"),
        params={
            "evidence_id": p["evidence_id"],
            "process_id": p.get("process_id"),
            "pid": p.get("pid"),
        },
        message=f"VAD scan PID {p.get('pid')}",
    ),
    "memory.extract": lambda p: _jobs().submit(
        "vad_extract",
        evidence_id=p["evidence_id"],
        process_id=p.get("process_id"),
        pid=p.get("pid"),
        params={
            "evidence_id": p["evidence_id"],
            "memory_region_id": p["memory_region_id"],
            "maxsize": p.get("maxsize"),
        },
        message="Extract VAD region",
    ),
    "timeline.build": lambda p: memory_artifacts.build_timeline(_db(), p["evidence_id"]),
    "timeline.list": lambda p: memory_artifacts.list_timeline(_db(), p["evidence_id"]),
    "artifacts.list": lambda p: memory_artifacts.list_artifacts(_db(), p["evidence_id"]),
    "artifacts.get": lambda p: _artifact_get(p["artifact_id"]),
    "yara.status": lambda _p: yara_workflows.yara_status(_paths(), _db()),
    "yara.configure": lambda p: yara_workflows.configure_yara(
        _paths(), _db(), p.get("settings") or p
    ),
    "yara.scan_artifact": lambda p: _jobs().submit(
        "yara_artifact_scan",
        evidence_id=p.get("evidence_id"),
        process_id=p.get("process_id"),
        pid=p.get("pid"),
        params={"artifact_id": p["artifact_id"], "evidence_id": p.get("evidence_id")},
        message=f"YARA scan artifact {p.get('artifact_id')}",
    ),
    "yara.scans_for_artifact": lambda p: yara_workflows.list_yara_scans_for_artifact(
        _db(), p["artifact_id"]
    ),
    "yara.scan_get": lambda p: yara_workflows.get_yara_scan(_db(), p["scan_id"]),
    "yara.matches_for_evidence": lambda p: yara_workflows.list_yara_matches_for_evidence(
        _db(), p["evidence_id"]
    ),
    "pe_sieve.status": lambda _p: pe_sieve_workflows.pe_sieve_status(_paths(), _db()),
    "pe_sieve.configure": lambda p: pe_sieve_workflows.configure_pe_sieve(
        _paths(), _db(), p.get("settings") or p
    ),
    "pe_sieve.scan_artifact": lambda p: _jobs().submit(
        "pe_sieve_artifact_scan",
        evidence_id=p.get("evidence_id"),
        process_id=p.get("process_id"),
        pid=p.get("pid"),
        params={"artifact_id": p["artifact_id"], "evidence_id": p.get("evidence_id")},
        message=f"PE-sieve workflow artifact {p.get('artifact_id')}",
    ),
    "pe_sieve.scans_for_artifact": lambda p: pe_sieve_workflows.list_pe_sieve_scans_for_artifact(
        _db(), p["artifact_id"]
    ),
    "pe_sieve.scan_get": lambda p: pe_sieve_workflows.get_pe_sieve_scan(_db(), p["scan_id"]),
    "mal_unpack.status": lambda _p: mal_unpack_workflows.mal_unpack_status(_paths(), _db()),
    "mal_unpack.configure": lambda p: mal_unpack_workflows.configure_mal_unpack(
        _paths(), _db(), p.get("settings") or p
    ),
    "mal_unpack.unpack_artifact": lambda p: _jobs().submit(
        "mal_unpack_artifact",
        evidence_id=p.get("evidence_id"),
        process_id=p.get("process_id"),
        pid=p.get("pid"),
        params={"artifact_id": p["artifact_id"], "evidence_id": p.get("evidence_id")},
        message=f"mal_unpack workflow artifact {p.get('artifact_id')}",
    ),
    "mal_unpack.scans_for_artifact": lambda p: mal_unpack_workflows.list_mal_unpack_scans_for_artifact(
        _db(), p["artifact_id"]
    ),
    "mal_unpack.scan_get": lambda p: mal_unpack_workflows.get_mal_unpack_scan(_db(), p["scan_id"]),
    "plugins.list": lambda p: plugin_explorer.list_plugins_for_ui(
        _db(), p.get("evidence_id")
    ),
    "plugins.get": lambda p: plugin_explorer.get_plugin_for_ui(
        _db(), p["plugin_id"], p.get("evidence_id")
    ),
    "plugins.validate": lambda p: {
        "ok": True,
        **{
            k: v
            for k, v in plugin_explorer.validate_execution_request(
                _db(),
                evidence_id=p.get("evidence_id"),
                plugin_id=p["plugin_id"],
                parameters=p.get("parameters") or {},
            ).items()
            if k != "evidence"
        },
        "evidence_id": p.get("evidence_id"),
    },
    "plugins.execute": lambda p: _jobs().submit(
        "plugin_advanced",
        evidence_id=p["evidence_id"],
        params={
            "evidence_id": p["evidence_id"],
            "plugin_id": p["plugin_id"],
            "parameters": p.get("parameters") or {},
            "timeout_secs": p.get("timeout_secs"),
        },
        message=f"Advanced plugin {p.get('plugin_id')}",
    ),
    "plugins.execution_get": lambda p: plugin_explorer.get_execution_bundle(
        _db(),
        p["execution_id"],
        preview_limit=int(p.get("limit", 500)),
        offset=int(p.get("offset", 0)),
    ),
    "plugins.executions": lambda p: plugin_explorer.list_executions(
        _db(), p["evidence_id"], limit=int(p.get("limit", 50))
    ),
    "jobs.submit": handle_job_submit,
    "jobs.get": lambda p: _jobs().get(p["job_id"]),
    "jobs.list": lambda p: {
        "items": _jobs().list_jobs(
            evidence_id=p.get("evidence_id"), limit=int(p.get("limit", 50))
        )
    },
    "jobs.cancel": lambda p: _jobs().cancel(p["job_id"]),
}


def _write(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":"), default=str) + "\n")
    sys.stdout.flush()


def _error(req_id: Any, payload: dict[str, Any]) -> None:
    _write({"jsonrpc": "2.0", "id": req_id, "error": payload})


def handle_line(line: str) -> None:
    line = line.strip()
    if not line:
        return
    try:
        req = json.loads(line)
    except json.JSONDecodeError as exc:
        _error(None, {"code": -32700, "message": "Parse error", "data": str(exc)})
        return

    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params") or {}
    if not isinstance(params, dict):
        params = {}

    if req.get("jsonrpc") != "2.0" or not isinstance(method, str):
        _error(req_id, {"code": -32600, "message": "Invalid Request"})
        return

    handler = HANDLERS.get(method)
    if handler is None:
        _error(req_id, {"code": -32601, "message": f"Method not found: {method}"})
        return

    try:
        result = handler(params)
        if req_id is not None:
            _write({"jsonrpc": "2.0", "id": req_id, "result": result})
    except Exception as exc:  # noqa: BLE001
        payload = rpc_error_payload(exc)
        if not isinstance(exc, AppError):
            payload.setdefault("data", {})
            if isinstance(payload["data"], dict):
                payload["data"]["traceback"] = traceback.format_exc()
        _error(req_id, payload)


def main() -> None:
    try:
        handle_app_init({})
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"engine bootstrap failed: {exc}\n")
        raise
    for line in sys.stdin:
        handle_line(line)


if __name__ == "__main__":
    main()
