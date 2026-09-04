"""NDJSON JSON-RPC 2.0 server over stdio."""

from __future__ import annotations

import json
import sys
import traceback
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Callable

from memscope_engine.analysis import process_analysis, search_iocs, workflows
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
