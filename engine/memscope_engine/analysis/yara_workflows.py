"""YARA scan workflows integrated with artifacts, jobs, and provenance."""

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
from memscope_engine.providers.yara_provider import YaraProvider, detect_yara
from memscope_engine.storage import Database

log = logging.getLogger("memscope.analysis")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_or_create_provider(paths: AppPaths, db: Database) -> YaraProvider:
    provider = YaraProvider(default_rules_dir=paths.yara_rules)
    # load settings
    row = db.fetchone("SELECT value_json FROM app_settings WHERE key = 'yara'")
    if row:
        try:
            settings = json.loads(row["value_json"])
            if isinstance(settings, dict):
                # re-apply without re-validating missing paths harshly
                if "timeout_secs" in settings:
                    provider.timeout_secs = float(settings["timeout_secs"])
                extras = settings.get("extra_rule_paths") or []
                valid_extras: list[Path] = []
                for p in extras:
                    pp = Path(str(p))
                    if pp.exists():
                        valid_extras.append(pp.resolve())
                provider.extra_rule_paths = valid_extras
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    return provider


def save_yara_settings(db: Database, provider: YaraProvider) -> dict[str, Any]:
    payload = {
        "timeout_secs": provider.timeout_secs,
        "extra_rule_paths": [str(p) for p in provider.extra_rule_paths],
        "default_rules_dir": str(provider.default_rules_dir)
        if provider.default_rules_dir
        else None,
    }
    db.execute(
        """
        INSERT INTO app_settings(key, value_json, updated_at) VALUES('yara', ?, ?)
        ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
        """,
        (json.dumps(payload), _utcnow()),
    )
    return provider.availability()


def yara_status(paths: AppPaths, db: Database) -> dict[str, Any]:
    provider = get_or_create_provider(paths, db)
    return provider.availability()


def configure_yara(paths: AppPaths, db: Database, settings: dict[str, Any]) -> dict[str, Any]:
    provider = get_or_create_provider(paths, db)
    provider.configure(settings)
    return save_yara_settings(db, provider)


def run_yara_artifact_scan_job(
    db: Database,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: Callable[[str], None],
    *,
    paths: AppPaths,
) -> dict[str, Any]:
    artifact_id = params.get("artifact_id")
    if not artifact_id:
        raise AppError(
            code="artifact_required",
            message="artifact_id is required for YARA scan.",
            entity="yara",
        )

    art = db.fetchone("SELECT * FROM artifacts WHERE id = ?", (artifact_id,))
    if not art:
        raise AppError(code="artifact_missing", message="Artifact not found.", entity="artifact")

    evidence_id = art["evidence_id"]
    job_id = params.get("job_id")

    # Path safety: must live under artifact store
    stored = Path(art["stored_path"])
    try:
        stored = artifact_store.ensure_within_artifacts(paths, stored)
    except AppError:
        raise
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
            code="yara_unavailable",
            message="YARA is not available on this system.",
            details=avail.get("reason"),
            suggestion=avail.get("suggestion"),
            entity="yara",
        )

    run_id = str(uuid4())
    scan_id = str(uuid4())
    started = _utcnow()
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, notes,
          process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'yara_artifact_scan', 'running', ?, 5, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            evidence_id,
            started,
            f"YARA scan artifact {art['filename']}",
            art.get("process_id"),
            art.get("pid"),
            job_id,
            json.dumps(
                [
                    {
                        "provider": "yara",
                        "target": "artifact",
                        "artifact_id": artifact_id,
                        "reason": "Scan extracted artifact bytes with configured YARA rules",
                    }
                ]
            ),
        ),
    )
    if job_id:
        db.execute("UPDATE jobs SET analysis_run_id = ? WHERE id = ?", (run_id, job_id))

    db.execute(
        """
        INSERT INTO yara_scans (
          id, evidence_id, artifact_id, process_id, pid, memory_region_id,
          analysis_run_id, job_id, status, match_count, yara_version, ruleset_json,
          error_json, started_at, finished_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', 0, ?, '{}', NULL, ?, NULL)
        """,
        (
            scan_id,
            evidence_id,
            artifact_id,
            art.get("process_id"),
            art.get("pid"),
            art.get("memory_region_id"),
            run_id,
            job_id,
            avail.get("yara_version"),
            started,
        ),
    )

    exec_id = str(uuid4())
    db.execute(
        """
        INSERT INTO plugin_executions (
          id, analysis_run_id, evidence_id, plugin, parameters_json,
          status, started_at, transparency_json
        ) VALUES (?, ?, ?, 'provider.yara', ?, 'running', ?, '{}')
        """,
        (
            exec_id,
            run_id,
            evidence_id,
            json.dumps({"artifact_id": artifact_id, "target": str(stored)}),
            started,
        ),
    )

    try:
        if cancelled():
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
        progress("Compiling YARA rules")
        progress(f"Scanning artifact {art['filename']}")
        result = provider.scan_file(stored, cancelled=cancelled)

        # replace prior matches for this artifact from completed scans optional —
        # keep history of scans; matches linked to scan_id
        for m in result["matches"]:
            db.execute(
                """
                INSERT INTO yara_matches (
                  id, scan_id, evidence_id, artifact_id, process_id, pid, memory_region_id,
                  rule_name, namespace, rule_source, tags_json, meta_json, strings_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid4()),
                    scan_id,
                    evidence_id,
                    artifact_id,
                    art.get("process_id"),
                    art.get("pid"),
                    art.get("memory_region_id"),
                    m["rule_name"],
                    m.get("namespace"),
                    m.get("rule_source"),
                    json.dumps(m.get("tags") or []),
                    json.dumps(m.get("meta") or {}),
                    json.dumps(m.get("strings") or []),
                    _utcnow(),
                ),
            )

        db.execute(
            """
            UPDATE yara_scans SET status='completed', match_count=?, yara_version=?,
              ruleset_json=?, finished_at=? WHERE id=?
            """,
            (
                result["match_count"],
                result.get("yara_version"),
                json.dumps(result.get("ruleset") or {}),
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
                result["match_count"],
                json.dumps(
                    {
                        "tool": "yara",
                        "tool_version": result.get("yara_version"),
                        "provider": "yara-python",
                        "target": "artifact",
                        "artifact_id": artifact_id,
                        "match_count": result["match_count"],
                    }
                ),
                exec_id,
            ),
        )
        db.execute(
            "UPDATE analysis_runs SET status='completed', finished_at=? WHERE id=?",
            (_utcnow(), run_id),
        )

        # timeline: inferred analysis event (scan time), not OS time
        db.execute(
            """
            INSERT INTO timeline_events (
              id, evidence_id, event_time, time_precision, classification, event_kind,
              summary, process_id, pid, related_entity_type, related_entity_id,
              source_table, source_plugin, provenance_json, created_at
            ) VALUES (?, ?, ?, 'analysis_time', 'inferred', 'yara_scan', ?, ?, ?, 'artifact', ?,
              'yara_scans', 'provider.yara', ?, ?)
            """,
            (
                str(uuid4()),
                evidence_id,
                _utcnow(),
                f"YARA scan of {art['filename']}: {result['match_count']} match(es)",
                art.get("process_id"),
                art.get("pid"),
                artifact_id,
                json.dumps(
                    {
                        "scan_id": scan_id,
                        "match_count": result["match_count"],
                        "yara_version": result.get("yara_version"),
                    }
                ),
                _utcnow(),
            ),
        )

        log.info(
            "yara scan completed",
            extra={"channel": "analysis", "evidence_id": evidence_id},
        )
        return get_yara_scan(db, scan_id)
    except AppError as exc:
        db.execute(
            """
            UPDATE yara_scans SET status=?, error_json=?, finished_at=? WHERE id=?
            """,
            (
                "cancelled" if exc.code == "job_cancelled" else "failed",
                json.dumps(exc.to_dict()),
                _utcnow(),
                scan_id,
            ),
        )
        db.execute(
            """
            UPDATE plugin_executions SET status=?, finished_at=?, error_json=? WHERE id=?
            """,
            (
                "cancelled" if exc.code == "job_cancelled" else "failed",
                _utcnow(),
                json.dumps(exc.to_dict()),
                exec_id,
            ),
        )
        db.execute(
            "UPDATE analysis_runs SET status=?, finished_at=?, error_json=? WHERE id=?",
            (
                "cancelled" if exc.code == "job_cancelled" else "failed",
                _utcnow(),
                json.dumps(exc.to_dict()),
                run_id,
            ),
        )
        raise


def get_yara_scan(db: Database, scan_id: str) -> dict[str, Any]:
    row = db.fetchone("SELECT * FROM yara_scans WHERE id = ?", (scan_id,))
    if not row:
        raise AppError(code="yara_scan_missing", message="YARA scan not found.", entity="yara")
    matches = db.fetchall(
        "SELECT * FROM yara_matches WHERE scan_id = ? ORDER BY rule_name",
        (scan_id,),
    )
    return {
        "scan": _scan_dto(row),
        "matches": [_match_dto(m) for m in matches],
    }


def list_yara_scans_for_artifact(db: Database, artifact_id: str) -> dict[str, Any]:
    rows = db.fetchall(
        """
        SELECT * FROM yara_scans WHERE artifact_id = ?
        ORDER BY started_at DESC LIMIT 50
        """,
        (artifact_id,),
    )
    items = []
    for r in rows:
        matches = db.fetchall(
            "SELECT * FROM yara_matches WHERE scan_id = ? ORDER BY rule_name",
            (r["id"],),
        )
        items.append({"scan": _scan_dto(r), "matches": [_match_dto(m) for m in matches]})
    return {"artifact_id": artifact_id, "total": len(items), "items": items}


def list_yara_matches_for_evidence(db: Database, evidence_id: str) -> dict[str, Any]:
    rows = db.fetchall(
        """
        SELECT * FROM yara_matches WHERE evidence_id = ?
        ORDER BY created_at DESC LIMIT 5000
        """,
        (evidence_id,),
    )
    return {
        "evidence_id": evidence_id,
        "total": len(rows),
        "items": [_match_dto(m) for m in rows],
    }


def _scan_dto(row: dict[str, Any]) -> dict[str, Any]:
    try:
        ruleset = json.loads(row.get("ruleset_json") or "{}")
    except json.JSONDecodeError:
        ruleset = {}
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
        "analysis_run_id": row.get("analysis_run_id"),
        "job_id": row.get("job_id"),
        "status": row["status"],
        "match_count": row.get("match_count") or 0,
        "yara_version": row.get("yara_version"),
        "ruleset": ruleset,
        "error": err,
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
    }


def _match_dto(row: dict[str, Any]) -> dict[str, Any]:
    def _j(key: str, default: Any):
        try:
            return json.loads(row.get(key) or json.dumps(default))
        except json.JSONDecodeError:
            return default

    return {
        "id": row["id"],
        "scan_id": row["scan_id"],
        "evidence_id": row["evidence_id"],
        "artifact_id": row["artifact_id"],
        "process_id": row.get("process_id"),
        "pid": row.get("pid"),
        "memory_region_id": row.get("memory_region_id"),
        "rule_name": row["rule_name"],
        "namespace": row.get("namespace"),
        "rule_source": row.get("rule_source"),
        "tags": _j("tags_json", []),
        "meta": _j("meta_json", {}),
        "strings": _j("strings_json", []),
        "created_at": row.get("created_at"),
    }
