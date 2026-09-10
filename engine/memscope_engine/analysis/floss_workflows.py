"""FLOSS workflows against extracted PE artifacts."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from memscope_engine.artifacts import store as artifact_store
from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths
from memscope_engine.providers.floss import FlossProvider, bundled_floss_roots
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION

log = logging.getLogger("memscope.analysis")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_or_create_provider(paths: AppPaths, db: Database) -> FlossProvider:
    provider = FlossProvider(
        tools_dir=paths.tools,
        analysis_dir=paths.analysis,
        artifacts_dir=paths.artifacts,
        extra_tool_roots=bundled_floss_roots(),
    )
    row = db.fetchone("SELECT value_json FROM app_settings WHERE key = 'floss'")
    if row:
        try:
            settings = json.loads(row["value_json"])
            if isinstance(settings, dict):
                if "timeout_secs" in settings:
                    try:
                        provider.timeout_secs = float(settings["timeout_secs"])
                    except (TypeError, ValueError):
                        pass
                exe = settings.get("executable_path")
                if exe:
                    p = Path(str(exe))
                    if p.exists():
                        provider.executable_path = p
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    return provider


def save_floss_settings(db: Database, provider: FlossProvider) -> dict[str, Any]:
    payload = {
        "timeout_secs": provider.timeout_secs,
        "executable_path": str(provider.executable_path) if provider.executable_path else None,
        "tools_dir": str(provider.tools_dir) if provider.tools_dir else None,
    }
    db.execute(
        """
        INSERT INTO app_settings(key, value_json, updated_at) VALUES('floss', ?, ?)
        ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
        """,
        (json.dumps(payload), _utcnow()),
    )
    return provider.availability()


def floss_status(paths: AppPaths, db: Database) -> dict[str, Any]:
    return get_or_create_provider(paths, db).availability()


def configure_floss(paths: AppPaths, db: Database, settings: dict[str, Any]) -> dict[str, Any]:
    provider = get_or_create_provider(paths, db)
    provider.configure(settings)
    return save_floss_settings(db, provider)


def run_floss_artifact_job(
    db: Database,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: Callable[[str], None],
    *,
    paths: AppPaths,
) -> dict[str, Any]:
    artifact_id = params.get("artifact_id")
    if not artifact_id:
        raise AppError(code="artifact_required", message="artifact_id is required for FLOSS.", entity="floss")
    art = db.fetchone("SELECT * FROM artifacts WHERE id = ?", (artifact_id,))
    if not art:
        raise AppError(code="artifact_missing", message="Artifact not found.", entity="artifact")
    evidence_id = art["evidence_id"]
    stored = artifact_store.ensure_within_controlled_data(paths, Path(art["stored_path"]))
    if not stored.is_file():
        raise AppError(
            code="artifact_file_missing",
            message="Artifact file is missing from the controlled store.",
            details=str(stored),
            entity="artifact",
        )

    provider = get_or_create_provider(paths, db)
    avail = provider.availability()
    if not avail.get("available"):
        raise AppError(
            code="floss_unavailable",
            message="FLOSS is not available on this system.",
            details=avail.get("reason"),
            suggestion=avail.get("suggestion"),
            entity="floss",
        )

    job_id = params.get("job_id")
    run_id = str(uuid4())
    scan_id = str(uuid4())
    started = _utcnow()
    meta = {}
    try:
        meta = json.loads(art.get("metadata_json") or "{}")
    except json.JSONDecodeError:
        meta = {}
    pe_run_id = meta.get("pe_extraction_run_id")

    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, notes,
          process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'floss_artifact', 'running', ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            evidence_id,
            started,
            SCHEMA_VERSION,
            f"FLOSS analysis {art['filename']}",
            art.get("process_id"),
            art.get("pid"),
            job_id,
            json.dumps(
                [
                    {
                        "provider": "floss",
                        "target": "extracted_pe",
                        "artifact_id": artifact_id,
                        "reason": "Static / obfuscated string extraction from an extracted PE artifact",
                    }
                ]
            ),
        ),
    )
    if job_id:
        db.execute("UPDATE jobs SET analysis_run_id = ? WHERE id = ?", (run_id, job_id))

    db.execute(
        """
        INSERT INTO floss_scans (
          id, evidence_id, artifact_id, process_id, pid, memory_region_id,
          pe_extraction_run_id, analysis_run_id, job_id, status, floss_version,
          executable_path, string_count, exit_code, output_json_path,
          observed_json, interpretation_json, error_json, started_at, finished_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, 0, NULL, NULL, '{}', '{}', NULL, ?, NULL)
        """,
        (
            scan_id,
            evidence_id,
            artifact_id,
            art.get("process_id"),
            art.get("pid"),
            art.get("memory_region_id"),
            pe_run_id,
            run_id,
            job_id,
            avail.get("floss_version"),
            avail.get("executable_path"),
            started,
        ),
    )
    exec_id = str(uuid4())
    db.execute(
        """
        INSERT INTO plugin_executions (
          id, analysis_run_id, evidence_id, plugin, parameters_json,
          status, started_at, transparency_json
        ) VALUES (?, ?, ?, 'provider.floss', ?, 'running', ?, '{}')
        """,
        (exec_id, run_id, evidence_id, json.dumps({"artifact_id": artifact_id}), started),
    )
    out_dir = paths.analysis / "floss" / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        if cancelled():
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
        progress(f"FLOSS analyzing {art['filename']}")
        result = provider.analyze_pe(stored, cancelled=cancelled)
        json_path = out_dir / "floss.json"
        json_path.write_text(json.dumps(result.get("raw") or {}, indent=2), encoding="utf-8")
        for s in result.get("strings") or []:
            db.execute(
                """
                INSERT INTO floss_strings (
                  id, scan_id, evidence_id, artifact_id, process_id, pid,
                  kind, value, offset, encoding, observed_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid4()),
                    scan_id,
                    evidence_id,
                    artifact_id,
                    art.get("process_id"),
                    art.get("pid"),
                    s.get("kind") or "static",
                    s.get("value"),
                    str(s.get("offset")) if s.get("offset") is not None else None,
                    s.get("encoding"),
                    json.dumps(s.get("observed") or {}),
                    _utcnow(),
                ),
            )
        db.execute(
            """
            UPDATE floss_scans SET status='completed', floss_version=?, executable_path=?,
              string_count=?, exit_code=?, output_json_path=?, observed_json=?,
              interpretation_json=?, finished_at=? WHERE id=?
            """,
            (
                result.get("floss_version"),
                result.get("executable_path"),
                result.get("string_count") or 0,
                result.get("exit_code"),
                str(json_path),
                json.dumps(result.get("observed") or {}),
                json.dumps(result.get("interpretation") or {}),
                _utcnow(),
                scan_id,
            ),
        )
        db.execute(
            """
            UPDATE plugin_executions SET status='completed', finished_at=?, row_count=?,
              transparency_json=? WHERE id=?
            """,
            (
                _utcnow(),
                result.get("string_count") or 0,
                json.dumps(
                    {
                        "tool": "floss",
                        "tool_version": result.get("floss_version"),
                        "artifact_id": artifact_id,
                        "pe_extraction_run_id": pe_run_id,
                    }
                ),
                exec_id,
            ),
        )
        db.execute(
            "UPDATE analysis_runs SET status='completed', finished_at=? WHERE id=?",
            (_utcnow(), run_id),
        )
        db.execute(
            """
            INSERT INTO timeline_events (
              id, evidence_id, event_time, time_precision, classification, event_kind,
              summary, process_id, pid, related_entity_type, related_entity_id,
              source_table, source_plugin, provenance_json, created_at
            ) VALUES (?, ?, NULL, 'analysis_time', 'inferred', 'floss_scan', ?, ?, ?,
              'artifact', ?, 'floss_scans', 'provider.floss', ?, ?)
            """,
            (
                str(uuid4()),
                evidence_id,
                f"FLOSS on {art['filename']}: {result.get('string_count') or 0} string(s)",
                art.get("process_id"),
                art.get("pid"),
                artifact_id,
                json.dumps(
                    {
                        "scan_id": scan_id,
                        "artifact_id": artifact_id,
                        "pe_extraction_run_id": pe_run_id,
                        "extraction_method": art.get("extraction_method"),
                        "string_count": result.get("string_count") or 0,
                    }
                ),
                _utcnow(),
            ),
        )
        return get_floss_scan(db, scan_id)
    except AppError as exc:
        _fail(db, exec_id, run_id, scan_id, exc)
        raise


def _fail(db: Database, exec_id: str, run_id: str, scan_id: str, exc: AppError) -> None:
    now = _utcnow()
    status = "cancelled" if exc.code == "job_cancelled" else "failed"
    payload = json.dumps(exc.to_dict())
    db.execute(
        "UPDATE floss_scans SET status=?, error_json=?, finished_at=? WHERE id=?",
        (status, payload, now, scan_id),
    )
    db.execute(
        "UPDATE plugin_executions SET status=?, finished_at=?, error_json=? WHERE id=?",
        (status, now, payload, exec_id),
    )
    db.execute(
        "UPDATE analysis_runs SET status=?, finished_at=?, error_json=? WHERE id=?",
        (status, now, payload, run_id),
    )


def get_floss_scan(db: Database, scan_id: str) -> dict[str, Any]:
    row = db.fetchone("SELECT * FROM floss_scans WHERE id = ?", (scan_id,))
    if not row:
        raise AppError(code="floss_scan_missing", message="FLOSS scan not found.", entity="floss")
    strings = db.fetchall(
        "SELECT * FROM floss_strings WHERE scan_id = ? ORDER BY kind, value LIMIT 5000",
        (scan_id,),
    )
    return {"scan": _scan_dto(row), "strings": [_str_dto(s) for s in strings]}


def list_floss_scans_for_artifact(db: Database, artifact_id: str) -> dict[str, Any]:
    rows = db.fetchall(
        "SELECT * FROM floss_scans WHERE artifact_id = ? ORDER BY started_at DESC LIMIT 50",
        (artifact_id,),
    )
    items = []
    for r in rows:
        strings = db.fetchall(
            "SELECT * FROM floss_strings WHERE scan_id = ? ORDER BY kind, value LIMIT 5000",
            (r["id"],),
        )
        items.append({"scan": _scan_dto(r), "strings": [_str_dto(s) for s in strings]})
    return {"artifact_id": artifact_id, "total": len(items), "items": items}


def _scan_dto(row: dict[str, Any]) -> dict[str, Any]:
    def _j(key: str, default: Any) -> Any:
        try:
            return json.loads(row.get(key) or json.dumps(default))
        except json.JSONDecodeError:
            return default

    err = None
    if row.get("error_json"):
        try:
            err = json.loads(row["error_json"])
        except json.JSONDecodeError:
            err = {"message": row["error_json"]}
    return {
        "id": row["id"],
        "evidence_id": row["evidence_id"],
        "artifact_id": row["artifact_id"],
        "process_id": row.get("process_id"),
        "pid": row.get("pid"),
        "memory_region_id": row.get("memory_region_id"),
        "pe_extraction_run_id": row.get("pe_extraction_run_id"),
        "analysis_run_id": row.get("analysis_run_id"),
        "job_id": row.get("job_id"),
        "status": row["status"],
        "floss_version": row.get("floss_version"),
        "executable_path": row.get("executable_path"),
        "string_count": row.get("string_count") or 0,
        "exit_code": row.get("exit_code"),
        "output_json_path": row.get("output_json_path"),
        "observed": _j("observed_json", {}),
        "interpretation": _j("interpretation_json", {}),
        "error": err,
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
    }


def _str_dto(row: dict[str, Any]) -> dict[str, Any]:
    try:
        observed = json.loads(row.get("observed_json") or "{}")
    except json.JSONDecodeError:
        observed = {}
    return {
        "id": row["id"],
        "scan_id": row["scan_id"],
        "evidence_id": row.get("evidence_id"),
        "artifact_id": row.get("artifact_id"),
        "process_id": row.get("process_id"),
        "pid": row.get("pid"),
        "kind": row["kind"],
        "value": row["value"],
        "offset": row.get("offset"),
        "encoding": row.get("encoding"),
        "observed": observed,
        "created_at": row.get("created_at"),
    }
