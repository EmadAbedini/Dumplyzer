"""Plugin Explorer and Advanced Volatility execution workflows."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from memscope_engine.artifacts import store as artifact_store
from memscope_engine.cache.store import AnalysisCache, cache_key, canonical_params
from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION
from memscope_engine.volatility.discovery import (
    discover_plugins,
    get_plugin_metadata,
    plugin_runnable_with_evidence,
    resolve_plugin_class,
    volatility_version,
)
from memscope_engine.volatility.files import make_file_handler_class
from memscope_engine.volatility.requirements import validate_user_parameters
from memscope_engine.volatility.session import VolatilitySession
from memscope_engine.volatility.treegrid import RESULT_MODEL_VERSION

log = logging.getLogger("memscope.analysis")

DEFAULT_TIMEOUT_SECS = 300.0
PREVIEW_ROW_LIMIT = 500


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _evidence_or_raise(db: Database, evidence_id: str | None) -> dict[str, Any]:
    if not evidence_id:
        raise AppError(
            code="evidence_required",
            message="Select imported evidence before running a plugin.",
            entity="evidence",
        )
    row = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    if not row:
        raise AppError(code="evidence_missing", message="Evidence record not found.", entity="evidence")
    path = Path(row["path"])
    if not path.is_file():
        raise AppError(
            code="evidence_not_found",
            message="Memory image file was not found.",
            details=str(path),
            suggestion="Re-import the evidence; Advanced Execution cannot use arbitrary paths.",
            entity="evidence",
        )
    return row


def list_plugins_for_ui(db: Database | None = None, evidence_id: str | None = None) -> dict[str, Any]:
    catalog = discover_plugins()
    evidence = None
    if db is not None and evidence_id:
        evidence = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    items = []
    for meta in catalog["items"]:
        runnable = plugin_runnable_with_evidence(meta, evidence)
        items.append(
            {
                **{k: meta[k] for k in (
                    "id",
                    "name",
                    "module_path",
                    "class_name",
                    "category",
                    "description",
                    "available",
                    "version",
                    "oses",
                    "architectures",
                    "discovery_errors",
                )},
                "configurable_parameter_count": len(meta.get("configurable_parameters") or []),
                "runnable": runnable["runnable"],
                "runnable_reason": runnable["reason"],
                "os_match": runnable["os_match"],
            }
        )
    return {
        "model_version": catalog["model_version"],
        "volatility_version": catalog["volatility_version"],
        "framework_interface_version": catalog["framework_interface_version"],
        "plugin_count": catalog["plugin_count"],
        "import_failures": catalog["import_failures"],
        "categories": catalog["categories"],
        "items": items,
        "evidence_id": evidence_id,
    }


def get_plugin_for_ui(
    db: Database | None,
    plugin_id: str,
    evidence_id: str | None = None,
) -> dict[str, Any]:
    meta = get_plugin_metadata(plugin_id)
    evidence = None
    if db is not None and evidence_id:
        evidence = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    runnable = plugin_runnable_with_evidence(meta, evidence)
    return {
        "plugin": {
            **meta,
            "runnable": runnable["runnable"],
            "runnable_reason": runnable["reason"],
            "os_match": runnable["os_match"],
        },
        "runnable": runnable,
        "volatility_version": volatility_version(),
        "evidence_id": evidence_id,
        "notes": (
            "Framework requirements (kernel, layers, symbols, image URI) are filled from "
            "the selected MemScope evidence. This is generic plugin execution, not a dedicated forensic view."
        ),
    }


def validate_execution_request(
    db: Database,
    *,
    evidence_id: str | None,
    plugin_id: str,
    parameters: dict[str, Any] | None,
) -> dict[str, Any]:
    evidence = _evidence_or_raise(db, evidence_id)
    ident, _cls = resolve_plugin_class(plugin_id)
    meta = get_plugin_metadata(ident)
    if not meta.get("available"):
        raise AppError(
            code="plugin_unavailable",
            message=f"Plugin {ident} is not available.",
            details="; ".join(meta.get("discovery_errors") or []),
            entity="plugin",
        )
    runnable = plugin_runnable_with_evidence(meta, evidence)
    params = validate_user_parameters(meta, parameters)
    return {
        "evidence": evidence,
        "plugin_id": ident,
        "meta": meta,
        "parameters": params,
        "runnable": runnable,
    }


def run_advanced_plugin_job(
    db: Database,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: Callable[[str], None],
    *,
    paths: AppPaths,
) -> dict[str, Any]:
    evidence_id = params.get("evidence_id")
    plugin_id = params.get("plugin_id")
    user_params = params.get("parameters") or {}
    timeout_secs = float(params.get("timeout_secs") or DEFAULT_TIMEOUT_SECS)
    if timeout_secs < 5 or timeout_secs > 3600:
        raise AppError(
            code="plugin_invalid_timeout",
            message="timeout_secs must be between 5 and 3600.",
            entity="plugin",
        )
    job_id = params.get("job_id")
    validated = validate_execution_request(
        db, evidence_id=evidence_id, plugin_id=plugin_id, parameters=user_params
    )
    evidence = validated["evidence"]
    ident = validated["plugin_id"]
    meta = validated["meta"]
    plugin_params = validated["parameters"]
    runnable = validated["runnable"]

    if cancelled():
        raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")

    vol_ver = volatility_version()
    key = cache_key(
        evidence_sha256=evidence["sha256"],
        volatility_version=vol_ver,
        plugin_id=ident,
        parameters=plugin_params,
        schema_version=SCHEMA_VERSION,
        model_version=RESULT_MODEL_VERSION,
    )
    cache = AnalysisCache(db, paths)
    hit = cache.get(key)

    run_id = str(uuid4())
    started = _utcnow()
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, notes,
          process_id, pid, job_id, strategy_json, volatility_version
        ) VALUES (?, ?, 'plugin_advanced', 'running', ?, ?, ?, NULL, NULL, ?, ?, ?)
        """,
        (
            run_id,
            evidence["id"],
            started,
            SCHEMA_VERSION,
            f"Advanced execution {ident}",
            job_id,
            json.dumps([{"plugin": ident, "parameters": canonical_params(plugin_params)}]),
            vol_ver,
        ),
    )
    if job_id:
        db.execute("UPDATE jobs SET analysis_run_id = ? WHERE id = ?", (run_id, job_id))

    exec_id = str(uuid4())
    db.execute(
        """
        INSERT INTO plugin_executions (
          id, analysis_run_id, evidence_id, plugin, parameters_json,
          status, started_at, transparency_json, cache_hit, cache_key, plugin_id
        ) VALUES (?, ?, ?, ?, ?, 'running', ?, '{}', ?, ?, ?)
        """,
        (
            exec_id,
            run_id,
            evidence["id"],
            ident,
            json.dumps(canonical_params(plugin_params)),
            started,
            1 if hit else 0,
            key,
            ident,
        ),
    )

    if hit:
        progress(f"Cache hit for {ident}")
        payload = hit["payload"]
        payload.setdefault("execution", {})
        payload["execution"]["from_cache"] = True
        payload["execution"]["cache_key"] = key
        payload["execution"]["analysis_run_id"] = run_id
        payload["execution"]["plugin_execution_id"] = exec_id
        payload["execution"]["job_id"] = job_id
        result_row = _persist_result_row(
            db,
            evidence_id=evidence["id"],
            analysis_run_id=run_id,
            plugin_execution_id=exec_id,
            job_id=job_id,
            plugin_id=ident,
            cache_key=key,
            result_path=hit["result_path"],
            payload=payload,
            from_cache=True,
        )
        db.execute(
            """
            UPDATE plugin_executions SET status='completed', finished_at=?, row_count=?,
              result_path=?, cache_hit=1, transparency_json=? WHERE id=?
            """,
            (
                _utcnow(),
                payload.get("table", {}).get("row_count", 0),
                hit["result_path"],
                json.dumps(
                    {
                        "tool": "volatility3",
                        "tool_version": vol_ver,
                        "plugin": ident,
                        "from_cache": True,
                        "cache_key": key,
                    }
                ),
                exec_id,
            ),
        )
        db.execute(
            "UPDATE analysis_runs SET status='completed', finished_at=? WHERE id=?",
            (_utcnow(), run_id),
        )
        return get_execution_bundle(db, exec_id, preview_limit=PREVIEW_ROW_LIMIT)

    if not runnable["runnable"]:
        err = AppError(
            code="plugin_not_runnable",
            message="This plugin is not runnable with the selected evidence.",
            details=runnable["reason"],
            entity="plugin",
        )
        _fail_exec(db, exec_id, run_id, err)
        raise err

    progress(f"Constructing {ident} via Volatility 3 APIs")
    ident, plugin_cls = resolve_plugin_class(ident)
    collected_files: list[dict[str, Any]] = []
    file_dir = paths.tmp / "plugin_files" / (job_id or exec_id)
    handler_cls = make_file_handler_class(file_dir, collected_files)

    def _progress(pct: float, description: str | None = None) -> None:
        if description:
            progress(str(description)[:200])

    started_exec = time.monotonic()
    try:
        session = VolatilitySession(Path(evidence["path"]))
        if cancelled():
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
        plugin_result = session.run_plugin(
            plugin_cls,
            plugin_params,
            progress_callback=_progress,
            cancelled=cancelled,
            open_method=handler_cls,
        )
        elapsed = time.monotonic() - started_exec
        if elapsed > timeout_secs:
            raise AppError(
                code="plugin_timeout",
                message="Volatility plugin execution exceeded the configured timeout.",
                details=f"elapsed={elapsed:.1f}s timeout={timeout_secs:.0f}s",
                suggestion="Increase timeout_secs. Cancellation during run() is cooperative; Volatility may finish the current plugin first.",
                entity="plugin",
            )
        table = plugin_result.table or _table_from_plugin_result(plugin_result)
    except AppError as exc:
        if cancelled() or exc.code == "job_cancelled":
            _fail_exec(
                db,
                exec_id,
                run_id,
                AppError(code="job_cancelled", message="Job was cancelled.", entity="job"),
                status="cancelled",
            )
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job") from exc
        _fail_exec(db, exec_id, run_id, exc)
        raise
    except Exception as exc:  # noqa: BLE001
        err = AppError(
            code="plugin_execution_failed",
            message=f"Plugin {ident} failed.",
            details=f"{type(exc).__name__}: {exc}",
            entity="plugin",
        )
        _fail_exec(db, exec_id, run_id, err)
        raise err from exc

    if cancelled():
        _fail_exec(
            db,
            exec_id,
            run_id,
            AppError(code="job_cancelled", message="Job was cancelled.", entity="job"),
            status="cancelled",
        )
        raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")

    ingested = _ingest_plugin_files(
        db, paths, evidence=evidence, files=collected_files, exec_id=exec_id, plugin_id=ident
    )
    payload = {
        "model_version": RESULT_MODEL_VERSION,
        "plugin_id": ident,
        "plugin": {
            "id": ident,
            "module_path": meta.get("module_path"),
            "class_name": meta.get("class_name"),
            "version": meta.get("version"),
            "category": meta.get("category"),
        },
        "parameters": canonical_params(plugin_params),
        "table": table,
        "files": ingested,
        "execution": {
            "from_cache": False,
            "cache_key": key,
            "volatility_version": vol_ver,
            "schema_version": SCHEMA_VERSION,
            "started_at": started,
            "finished_at": _utcnow(),
            "timeout_secs": timeout_secs,
            "cancellation": "cooperative",
            "source_evidence_sha256": evidence["sha256"],
            "source_evidence_id": evidence["id"],
            "analysis_run_id": run_id,
            "plugin_execution_id": exec_id,
            "job_id": job_id,
            "transparency": plugin_result.transparency,
        },
        "links": _entity_links(db, evidence["id"], table),
    }
    stored = cache.put(
        key=key,
        evidence_id=evidence["id"],
        evidence_sha256=evidence["sha256"],
        volatility_version=vol_ver,
        plugin_id=ident,
        parameters=plugin_params,
        payload=payload,
        analysis_run_id=run_id,
        plugin_execution_id=exec_id,
    )
    _persist_result_row(
        db,
        evidence_id=evidence["id"],
        analysis_run_id=run_id,
        plugin_execution_id=exec_id,
        job_id=job_id,
        plugin_id=ident,
        cache_key=key,
        result_path=stored["result_path"],
        payload=payload,
        from_cache=False,
    )
    db.execute(
        """
        UPDATE plugin_executions SET status='completed', finished_at=?, row_count=?,
          result_path=?, cache_hit=0, transparency_json=? WHERE id=?
        """,
        (
            _utcnow(),
            table.get("row_count", 0),
            stored["result_path"],
            json.dumps(plugin_result.transparency),
            exec_id,
        ),
    )
    db.execute(
        "UPDATE analysis_runs SET status='completed', finished_at=?, volatility_version=? WHERE id=?",
        (_utcnow(), vol_ver, run_id),
    )
    log.info("advanced plugin completed", extra={"channel": "analysis", "plugin": ident})
    return get_execution_bundle(db, exec_id, preview_limit=PREVIEW_ROW_LIMIT)


def _table_from_plugin_result(plugin_result: Any) -> dict[str, Any]:
    columns = [{"name": str(c), "type": "object"} for c in plugin_result.columns]
    rows = []
    for raw in plugin_result.rows:
        cells = list(raw)
        named = {}
        for i, col in enumerate(columns):
            named[col["name"]] = cells[i] if i < len(cells) else None
        rows.append({"depth": 0, "cells": cells, "values": named})
    return {
        "model_version": RESULT_MODEL_VERSION,
        "columns": columns,
        "rows": rows,
        "row_count": len(rows),
        "nested": False,
    }


def _ingest_plugin_files(
    db: Database,
    paths: AppPaths,
    *,
    evidence: dict[str, Any],
    files: list[dict[str, Any]],
    exec_id: str,
    plugin_id: str,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    dest_dir = artifact_store.artifact_dir(paths, evidence["id"])
    for item in files:
        src = Path(item["path"])
        if not src.is_file():
            continue
        dest_name = artifact_store.sanitize_component(
            f"plugin.{plugin_id.split('.')[0]}.{src.name}", max_len=120
        )
        dest = dest_dir / dest_name
        if dest.exists():
            dest = dest_dir / artifact_store.sanitize_component(
                f"plugin.{uuid4().hex[:8]}.{src.name}", max_len=120
            )
        dest.write_bytes(src.read_bytes())
        dest = artifact_store.ensure_within_artifacts(paths, dest)
        digest = artifact_store.sha256_file(dest)
        ftype = artifact_store.sniff_file_type(dest)
        art_id = str(uuid4())
        db.execute(
            """
            INSERT INTO artifacts (
              id, evidence_id, process_id, pid, memory_region_id, filename, stored_path,
              sha256, size_bytes, file_type, extraction_method, source_plugin, tool_name,
              tool_version, extracted_at, notes, metadata_json
            ) VALUES (?, ?, NULL, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                art_id,
                evidence["id"],
                dest.name,
                str(dest),
                digest,
                dest.stat().st_size,
                ftype,
                "plugin_file_handler",
                plugin_id,
                "volatility3",
                volatility_version(),
                _utcnow(),
                f"File emitted by {plugin_id}; never executed.",
                json.dumps(
                    {
                        "plugin_execution_id": exec_id,
                        "preferred_filename": item.get("preferred_filename"),
                    }
                ),
            ),
        )
        out.append(
            {
                "artifact_id": art_id,
                "filename": dest.name,
                "sha256": digest,
                "size_bytes": dest.stat().st_size,
                "file_type": ftype,
            }
        )
    return out


def _entity_links(db: Database, evidence_id: str, table: dict[str, Any]) -> list[dict[str, Any]]:
    """Link result rows to known processes only when a PID column matches stored processes."""
    cols = [c.get("name") for c in (table.get("columns") or [])]
    pid_col = next((c for c in cols if c and str(c).lower() == "pid"), None)
    if not pid_col:
        return []
    proc_rows = db.fetchall(
        """
        SELECT id, pid, name FROM processes
        WHERE evidence_id = ?
        ORDER BY rowid DESC
        """,
        (evidence_id,),
    )
    by_pid: dict[int, dict[str, Any]] = {}
    for row in proc_rows:
        pid = row.get("pid")
        if pid is None:
            continue
        by_pid.setdefault(int(pid), {"process_id": row["id"], "pid": int(pid), "name": row.get("name")})
    links = []
    seen: set[int] = set()
    for row in table.get("rows") or []:
        values = row.get("values") or {}
        raw = values.get(pid_col)
        try:
            pid = int(raw)
        except (TypeError, ValueError):
            continue
        if pid in seen:
            continue
        seen.add(pid)
        match = by_pid.get(pid)
        if match:
            links.append(
                {
                    "kind": "process",
                    "pid": pid,
                    "process_id": match["process_id"],
                    "name": match.get("name"),
                    "reliable": True,
                }
            )
    return links


def _persist_result_row(
    db: Database,
    *,
    evidence_id: str,
    analysis_run_id: str,
    plugin_execution_id: str,
    job_id: str | None,
    plugin_id: str,
    cache_key: str,
    result_path: str,
    payload: dict[str, Any],
    from_cache: bool,
) -> str:
    result_id = str(uuid4())
    table = payload.get("table") or {}
    db.execute(
        """
        INSERT INTO plugin_results (
          id, evidence_id, analysis_run_id, plugin_execution_id, job_id, plugin_id,
          cache_key, result_path, row_count, columns_json, from_cache, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result_id,
            evidence_id,
            analysis_run_id,
            plugin_execution_id,
            job_id,
            plugin_id,
            cache_key,
            result_path,
            int(table.get("row_count") or 0),
            json.dumps(table.get("columns") or []),
            1 if from_cache else 0,
            _utcnow(),
        ),
    )
    return result_id


def _fail_exec(
    db: Database,
    exec_id: str,
    run_id: str,
    error: AppError,
    *,
    status: str = "failed",
) -> None:
    payload = json.dumps(error.to_dict())
    now = _utcnow()
    db.execute(
        "UPDATE plugin_executions SET status=?, finished_at=?, error_json=? WHERE id=?",
        (status, now, payload, exec_id),
    )
    db.execute(
        "UPDATE analysis_runs SET status=?, finished_at=?, error_json=? WHERE id=?",
        (status, now, payload, run_id),
    )


def get_execution_bundle(
    db: Database,
    plugin_execution_id: str,
    *,
    preview_limit: int = PREVIEW_ROW_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    exec_row = db.fetchone("SELECT * FROM plugin_executions WHERE id = ?", (plugin_execution_id,))
    if not exec_row:
        raise AppError(code="plugin_execution_missing", message="Plugin execution not found.", entity="plugin")
    result_row = db.fetchone(
        """
        SELECT * FROM plugin_results WHERE plugin_execution_id = ?
        ORDER BY created_at DESC LIMIT 1
        """,
        (plugin_execution_id,),
    )
    payload = None
    if result_row and result_row.get("result_path"):
        path = Path(result_row["result_path"])
        if path.is_file():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = None
    table = (payload or {}).get("table") or {"columns": [], "rows": [], "row_count": 0}
    rows = table.get("rows") or []
    preview = rows[offset : offset + preview_limit]
    err = None
    if exec_row.get("error_json"):
        try:
            err = json.loads(exec_row["error_json"])
        except json.JSONDecodeError:
            err = {"message": exec_row["error_json"]}
    return {
        "execution": {
            "id": exec_row["id"],
            "analysis_run_id": exec_row["analysis_run_id"],
            "evidence_id": exec_row["evidence_id"],
            "plugin": exec_row["plugin"],
            "plugin_id": exec_row.get("plugin_id") or exec_row["plugin"],
            "parameters": json.loads(exec_row["parameters_json"] or "{}"),
            "status": exec_row["status"],
            "started_at": exec_row["started_at"],
            "finished_at": exec_row["finished_at"],
            "row_count": exec_row.get("row_count"),
            "cache_hit": bool(exec_row.get("cache_hit")),
            "cache_key": exec_row.get("cache_key"),
            "result_path": exec_row.get("result_path"),
            "error": err,
            "transparency": json.loads(exec_row["transparency_json"] or "{}"),
        },
        "result": {
            "model_version": (payload or {}).get("model_version"),
            "plugin_id": (payload or {}).get("plugin_id"),
            "plugin": (payload or {}).get("plugin"),
            "parameters": (payload or {}).get("parameters"),
            "columns": table.get("columns") or [],
            "row_count": table.get("row_count") or 0,
            "nested": table.get("nested"),
            "offset": offset,
            "limit": preview_limit,
            "rows": preview,
            "files": (payload or {}).get("files") or [],
            "links": (payload or {}).get("links") or [],
            "execution": (payload or {}).get("execution"),
            "raw": {
                "columns": table.get("columns") or [],
                "rows": preview,
                "files": (payload or {}).get("files") or [],
                "transparency": (payload or {}).get("execution", {}).get("transparency")
                if payload
                else exec_row.get("transparency_json"),
            },
            "truncated": (table.get("row_count") or 0) > offset + len(preview),
        },
    }


def list_executions(db: Database, evidence_id: str, *, limit: int = 50) -> dict[str, Any]:
    rows = db.fetchall(
        """
        SELECT pe.* FROM plugin_executions pe
        JOIN analysis_runs ar ON ar.id = pe.analysis_run_id
        WHERE pe.evidence_id = ? AND ar.kind = 'plugin_advanced'
        ORDER BY pe.started_at DESC LIMIT ?
        """,
        (evidence_id, limit),
    )
    items = []
    for row in rows:
        items.append(
            {
                "id": row["id"],
                "plugin": row.get("plugin_id") or row["plugin"],
                "status": row["status"],
                "started_at": row["started_at"],
                "finished_at": row["finished_at"],
                "row_count": row.get("row_count"),
                "cache_hit": bool(row.get("cache_hit")),
                "analysis_run_id": row["analysis_run_id"],
            }
        )
    return {"evidence_id": evidence_id, "total": len(items), "items": items}
