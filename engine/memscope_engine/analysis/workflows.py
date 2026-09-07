"""Evidence import and process analysis workflows."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from memscope_engine.analysis.coverage import coverage_for_evidence
from memscope_engine.errors import AppError
from memscope_engine.memory_image import require_memory_image
from memscope_engine.storage import Database
from memscope_engine.volatility.normalize import normalize_pslist, normalize_windows_info
from memscope_engine.volatility.session import VolatilitySession

log = logging.getLogger("memscope.analysis")

CHUNK = 1024 * 1024

# Child tables first so foreign keys stay satisfied. Jobs and evidence stay.
_EVIDENCE_ANALYSIS_TABLES = (
    "yara_matches",
    "capa_capabilities",
    "floss_strings",
    "pe_sieve_outputs",
    "mal_unpack_outputs",
    "bulk_extractor_features",
    "bulk_extractor_outputs",
    "pe_extraction_items",
    "network_artifacts",
    "pcap_flow_results",
    "yara_scans",
    "capa_scans",
    "floss_scans",
    "pe_sieve_scans",
    "mal_unpack_scans",
    "bulk_extractor_scans",
    "pe_extraction_runs",
    "network_artifact_runs",
    "pcap_reconstructions",
    "plugin_results",
    "analysis_cache",
    "exports",
    "timeline_events",
    "findings",
    "iocs",
    "artifacts",
    "handle_entries",
    "memory_regions",
    "network_connections",
    "modules",
    "processes",
    "plugin_executions",
    "analysis_runs",
)


def _clear_evidence_analysis(db: Database, evidence_id: str) -> None:
    """Drop derived analysis for this evidence. Import is a new investigation."""
    with db.transaction() as conn:
        for table in _EVIDENCE_ANALYSIS_TABLES:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?",
                (table,),
            ).fetchone()
            if not exists:
                continue
            cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
            if not any(str(col["name"]) == "evidence_id" for col in cols):
                continue
            conn.execute(f"DELETE FROM {table} WHERE evidence_id = ?", (evidence_id,))


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(
    path: Path,
    *,
    cancelled: Callable[[], bool] | None = None,
    progress: Callable[..., None] | None = None,
    size: int | None = None,
) -> str:
    """Stream SHA-256 in 1 MiB chunks. Never loads the whole file into memory."""
    total = size if size is not None else path.stat().st_size
    h = hashlib.sha256()
    done = 0
    last_report = -1
    with path.open("rb") as f:
        while True:
            if cancelled and cancelled():
                raise AppError(
                    code="job_cancelled",
                    message="Import was cancelled.",
                    entity="evidence",
                )
            chunk = f.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
            done += len(chunk)
            if progress and total > 0:
                pct = min(100.0, (done / total) * 100.0)
                bucket = int(pct)
                if bucket != last_report and (bucket % 2 == 0 or done == total):
                    last_report = bucket
                    progress(
                        f"Hashing memory image ({bucket}%)",
                        {
                            "phase": "hash",
                            "percent": round(pct, 1),
                            "bytes_done": done,
                            "bytes_total": total,
                        },
                    )
    return h.hexdigest()


def import_evidence(
    db: Database,
    path_str: str,
    *,
    cancelled: Callable[[], bool] | None = None,
    progress: Callable[..., None] | None = None,
) -> dict[str, Any]:
    path = Path(path_str).expanduser()
    try:
        path = path.resolve()
    except OSError as exc:
        raise AppError(
            code="invalid_path",
            message="Could not resolve the memory image path.",
            details=str(exc),
            suggestion="Choose an accessible file path.",
            entity="evidence",
        ) from exc

    if not path.is_file():
        raise AppError(
            code="evidence_not_found",
            message="Memory image file was not found.",
            details=str(path),
            suggestion="Select an existing memory dump file.",
            entity="evidence",
        )

    size = path.stat().st_size
    if size <= 0:
        raise AppError(
            code="evidence_empty",
            message="Memory image file is empty.",
            details=str(path),
            entity="evidence",
        )

    if cancelled and cancelled():
        raise AppError(code="job_cancelled", message="Import was cancelled.", entity="evidence")

    if progress:
        progress(
            "Validating memory image",
            {"phase": "validate", "percent": 0, "bytes_total": size},
        )

    try:
        require_memory_image(path)
    except AppError:
        raise
    except OSError as exc:
        raise AppError(
            code="invalid_path",
            message="Could not read the memory image file.",
            details=str(exc),
            suggestion="Choose an accessible memory dump file.",
            entity="evidence",
        ) from exc

    if cancelled and cancelled():
        raise AppError(code="job_cancelled", message="Import was cancelled.", entity="evidence")

    log.info("hashing evidence", extra={"channel": "analysis"})
    digest = sha256_file(path, cancelled=cancelled, progress=progress, size=size)

    if cancelled and cancelled():
        raise AppError(code="job_cancelled", message="Import was cancelled.", entity="evidence")

    if progress:
        progress(
            "Registering evidence",
            {"phase": "register", "percent": 100, "bytes_total": size},
        )

    existing = db.fetchone("SELECT * FROM evidence WHERE sha256 = ?", (digest,))
    if existing:
        evidence_id = str(existing["id"])
        _clear_evidence_analysis(db, evidence_id)
        now = _utcnow()
        db.execute(
            """
            UPDATE evidence SET
              path = ?, filename = ?, size_bytes = ?,
              detected_os = NULL, architecture = NULL, volatility_compatible = NULL,
              symbol_status = 'unknown', symbol_detail = NULL,
              import_status = 'imported', import_timestamp = ?, metadata_json = '{}'
            WHERE id = ?
            """,
            (str(path), path.name, size, now, evidence_id),
        )
        row = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
        assert row
        log.info(
            "evidence reimported",
            extra={"channel": "analysis", "evidence_id": evidence_id},
        )
        return _evidence_dto(row)

    evidence_id = str(uuid4())
    now = _utcnow()
    db.execute(
        """
        INSERT INTO evidence (
          id, path, filename, size_bytes, sha256,
          detected_os, architecture, volatility_compatible,
          symbol_status, symbol_detail, import_status, import_timestamp, metadata_json
        ) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, 'unknown', NULL, 'imported', ?, '{}')
        """,
        (evidence_id, str(path), path.name, size, digest, now),
    )
    db._conn.commit()
    row = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    assert row
    log.info("evidence imported", extra={"channel": "analysis", "evidence_id": evidence_id})
    return _evidence_dto(row)


def run_evidence_import_job(
    db: Database,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: Callable[..., None],
) -> dict[str, Any]:
    path = params.get("path")
    if not path:
        raise AppError(
            code="invalid_params",
            message="path is required to import a memory image.",
            entity="evidence",
        )
    progress("Importing memory image…", {"phase": "start", "percent": 0})
    evidence = import_evidence(db, str(path), cancelled=cancelled, progress=progress)
    job_id = params.get("job_id")
    if job_id and evidence.get("id"):
        db.execute(
            "UPDATE jobs SET evidence_id = ? WHERE id = ?",
            (evidence["id"], job_id),
        )
    progress(
        "Import complete",
        {"phase": "done", "percent": 100, "evidence_id": evidence["id"]},
    )
    return {"evidence": evidence}


def analyze_evidence_basic(db: Database, evidence_id: str) -> dict[str, Any]:
    """Run windows.info + windows.pslist; persist normalized processes."""
    evidence = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    if not evidence:
        raise AppError(
            code="evidence_missing",
            message="Evidence record not found.",
            entity="evidence",
            data={"evidence_id": evidence_id},
        )

    path = Path(evidence["path"])
    run_id = str(uuid4())
    started = _utcnow()
    vol_version = None

    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at,
          error_json, volatility_version, schema_version, notes
        ) VALUES (?, ?, 'basic_triage', 'running', ?, NULL, NULL, NULL, 1, 'windows.info + windows.pslist')
        """,
        (run_id, evidence_id, started),
    )
    db._conn.commit()

    try:
        session = VolatilitySession(path)
        vol_version = session.volatility_version

        # --- windows.info ---
        from volatility3.plugins.windows.info import Info

        info_exec_id = str(uuid4())
        info_started = _utcnow()
        db.execute(
            """
            INSERT INTO plugin_executions (
              id, analysis_run_id, evidence_id, plugin, parameters_json,
              status, started_at, finished_at, error_json, row_count, transparency_json
            ) VALUES (?, ?, ?, ?, '{}', 'running', ?, NULL, NULL, NULL, '{}')
            """,
            (info_exec_id, run_id, evidence_id, "windows.info", info_started),
        )
        db._conn.commit()

        info_result = session.run_plugin(Info)
        db.execute(
            """
            UPDATE plugin_executions SET status = 'completed', finished_at = ?,
              row_count = ?, transparency_json = ? WHERE id = ?
            """,
            (
                _utcnow(),
                len(info_result.rows),
                json.dumps(info_result.transparency),
                info_exec_id,
            ),
        )

        info_norm = normalize_windows_info(info_result.columns, info_result.rows)
        db.execute(
            """
            UPDATE evidence SET
              detected_os = ?, architecture = ?, volatility_compatible = 1,
              symbol_status = ?, symbol_detail = ?, metadata_json = ?,
              import_status = 'analyzed'
            WHERE id = ?
            """,
            (
                info_norm.get("detected_os"),
                info_norm.get("architecture"),
                info_norm.get("symbol_status") or "unknown",
                info_norm.get("symbol_detail"),
                json.dumps(info_norm.get("info") or {}),
                evidence_id,
            ),
        )
        db._conn.commit()

        # --- windows.pslist ---
        from volatility3.plugins.windows.pslist import PsList

        ps_exec_id = str(uuid4())
        ps_started = _utcnow()
        db.execute(
            """
            INSERT INTO plugin_executions (
              id, analysis_run_id, evidence_id, plugin, parameters_json,
              status, started_at, finished_at, error_json, row_count, transparency_json
            ) VALUES (?, ?, ?, ?, '{}', 'running', ?, NULL, NULL, NULL, '{}')
            """,
            (ps_exec_id, run_id, evidence_id, "windows.pslist", ps_started),
        )
        db._conn.commit()

        ps_result = session.run_plugin(PsList)
        processes = normalize_pslist(
            ps_result.columns,
            ps_result.rows,
            evidence_id=evidence_id,
            analysis_run_id=run_id,
            source_plugin=ps_result.plugin,
        )

        # Replace prior process rows for this evidence (latest triage wins for explorer)
        db.execute("DELETE FROM processes WHERE evidence_id = ?", (evidence_id,))
        for p in processes:
            db.execute(
                """
                INSERT INTO processes (
                  id, evidence_id, analysis_run_id, pid, ppid, name, username,
                  image_path, command_line, create_time, exit_time, offset_hex,
                  threads, handles, session_id, wow64, source_plugin
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    p["id"],
                    p["evidence_id"],
                    p["analysis_run_id"],
                    p["pid"],
                    p["ppid"],
                    p["name"],
                    p["username"],
                    p["image_path"],
                    p["command_line"],
                    p["create_time"],
                    p["exit_time"],
                    p["offset_hex"],
                    p["threads"],
                    p["handles"],
                    p["session_id"],
                    1 if p["wow64"] else (0 if p["wow64"] is False else None),
                    p["source_plugin"],
                ),
            )

        db.execute(
            """
            UPDATE plugin_executions SET status = 'completed', finished_at = ?,
              row_count = ?, transparency_json = ? WHERE id = ?
            """,
            (
                _utcnow(),
                len(processes),
                json.dumps(ps_result.transparency),
                ps_exec_id,
            ),
        )
        db.execute(
            """
            UPDATE analysis_runs SET status = 'completed', finished_at = ?,
              volatility_version = ? WHERE id = ?
            """,
            (_utcnow(), vol_version, run_id),
        )
        db._conn.commit()

        evidence = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
        assert evidence
        return {
            "analysis_run_id": run_id,
            "evidence": _evidence_dto(evidence),
            "process_count": len(processes),
            "plugin_executions": [
                {
                    "plugin": "windows.info",
                    "status": "completed",
                    "row_count": len(info_result.rows),
                    "transparency": info_result.transparency,
                },
                {
                    "plugin": "windows.pslist",
                    "status": "completed",
                    "row_count": len(processes),
                    "transparency": ps_result.transparency,
                },
            ],
        }
    except AppError as exc:
        db.execute(
            """
            UPDATE analysis_runs SET status = 'failed', finished_at = ?,
              error_json = ?, volatility_version = ? WHERE id = ?
            """,
            (_utcnow(), json.dumps(exc.to_dict()), vol_version, run_id),
        )
        db.execute(
            """
            UPDATE evidence SET volatility_compatible = 0,
              symbol_status = COALESCE(symbol_status, 'error'),
              import_status = 'analysis_failed'
            WHERE id = ?
            """,
            (evidence_id,),
        )
        db._conn.commit()
        raise
    except Exception as exc:  # noqa: BLE001
        err = AppError(
            code="analysis_failed",
            message="Basic triage analysis failed.",
            details=f"{type(exc).__name__}: {exc}",
            suggestion="Check that the file is a valid memory image and symbols can be resolved.",
            entity="analysis",
        )
        db.execute(
            """
            UPDATE analysis_runs SET status = 'failed', finished_at = ?,
              error_json = ?, volatility_version = ? WHERE id = ?
            """,
            (_utcnow(), json.dumps(err.to_dict()), vol_version, run_id),
        )
        db._conn.commit()
        raise err from exc


def list_evidence(db: Database) -> list[dict[str, Any]]:
    rows = db.fetchall("SELECT * FROM evidence ORDER BY import_timestamp DESC")
    return [_evidence_dto(r) for r in rows]


def get_evidence(db: Database, evidence_id: str) -> dict[str, Any]:
    row = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    if not row:
        raise AppError(
            code="evidence_missing",
            message="Evidence record not found.",
            entity="evidence",
            data={"evidence_id": evidence_id},
        )
    return _evidence_dto(row)


def list_processes(
    db: Database,
    evidence_id: str,
    *,
    search: str | None = None,
    limit: int = 5000,
    offset: int = 0,
) -> dict[str, Any]:
    get_evidence(db, evidence_id)
    params: list[Any] = [evidence_id]
    where = "evidence_id = ?"
    if search:
        where += " AND (name LIKE ? OR CAST(pid AS TEXT) LIKE ? OR CAST(ppid AS TEXT) LIKE ?)"
        q = f"%{search}%"
        params.extend([q, q, q])
    total_row = db.fetchone(
        f"SELECT COUNT(*) AS c FROM processes WHERE {where}", tuple(params)
    )
    total = int(total_row["c"]) if total_row else 0
    params.extend([limit, offset])
    rows = db.fetchall(
        f"""
        SELECT * FROM processes
        WHERE {where}
        ORDER BY pid ASC
        LIMIT ? OFFSET ?
        """,
        tuple(params),
    )
    return {
        "evidence_id": evidence_id,
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [_process_dto(r) for r in rows],
    }


def overview(db: Database, evidence_id: str) -> dict[str, Any]:
    evidence = get_evidence(db, evidence_id)

    def _count(table: str) -> int:
        row = db.fetchone(
            f"SELECT COUNT(*) AS c FROM {table} WHERE evidence_id = ?",
            (evidence_id,),
        )
        return int(row["c"]) if row else 0

    runs = db.fetchall(
        """
        SELECT id, kind, status, started_at, finished_at, volatility_version, notes, pid
        FROM analysis_runs WHERE evidence_id = ? ORDER BY started_at DESC LIMIT 10
        """,
        (evidence_id,),
    )
    return {
        "evidence": evidence,
        "process_count": _count("processes"),
        "network_count": _count("network_connections"),
        "module_count": _count("modules"),
        "finding_count": _count("findings"),
        "ioc_count": _count("iocs") if _table_exists(db, "iocs") else 0,
        "recent_runs": runs,
        "coverage": coverage_for_evidence(db, evidence_id),
    }


def _table_exists(db: Database, name: str) -> bool:
    row = db.fetchone(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
        (name,),
    )
    return row is not None


def _evidence_dto(row: dict[str, Any]) -> dict[str, Any]:
    meta = row.get("metadata_json") or "{}"
    try:
        metadata = json.loads(meta) if isinstance(meta, str) else meta
    except json.JSONDecodeError:
        metadata = {}
    return {
        "id": row["id"],
        "path": row["path"],
        "filename": row["filename"],
        "size_bytes": row["size_bytes"],
        "sha256": row["sha256"],
        "detected_os": row.get("detected_os"),
        "architecture": row.get("architecture"),
        "volatility_compatible": bool(row["volatility_compatible"])
        if row.get("volatility_compatible") is not None
        else None,
        "symbol_status": row.get("symbol_status"),
        "symbol_detail": row.get("symbol_detail"),
        "import_status": row.get("import_status"),
        "import_timestamp": row.get("import_timestamp"),
        "metadata": metadata,
    }


def _process_dto(row: dict[str, Any]) -> dict[str, Any]:
    wow = row.get("wow64")
    return {
        "id": row["id"],
        "evidence_id": row["evidence_id"],
        "analysis_run_id": row["analysis_run_id"],
        "pid": row["pid"],
        "ppid": row.get("ppid"),
        "name": row.get("name"),
        "username": row.get("username"),
        "image_path": row.get("image_path"),
        "command_line": row.get("command_line"),
        "create_time": row.get("create_time"),
        "exit_time": row.get("exit_time"),
        "offset_hex": row.get("offset_hex"),
        "threads": row.get("threads"),
        "handles": row.get("handles"),
        "session_id": row.get("session_id"),
        "wow64": bool(wow) if wow is not None else None,
        "source_plugin": row.get("source_plugin"),
    }
