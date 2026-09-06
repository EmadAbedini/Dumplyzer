"""Export job workflows: collect, write, persist, never overwrite evidence."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from memscope_engine.analysis import workflows as evidence_workflows
from memscope_engine.errors import AppError
from memscope_engine.export.collect import collect_investigation, normalize_sections
from memscope_engine.export.constants import (
    FORMATS,
    REPORT_SCHEMA_VERSION,
    SCOPES,
)
from memscope_engine.export.csv_export import (
    dataset_rows,
    datasets_for_sections,
    write_csv_file,
)
from memscope_engine.export.html_report import write_html_file
from memscope_engine.export.json_export import write_json_exports, write_json_file
from memscope_engine.export.safe_paths import (
    allocate_export_dir,
    parse_optional_basename,
    reject_user_destination,
    sanitize_filename,
)
from memscope_engine.paths import AppPaths
from memscope_engine.storage import Database

log = logging.getLogger("memscope.analysis")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def available_options() -> dict[str, Any]:
    from memscope_engine.export.constants import CSV_DATASETS, REPORT_SECTIONS

    return {
        "formats": list(FORMATS),
        "scopes": list(SCOPES),
        "sections": list(REPORT_SECTIONS),
        "csv_datasets": list(CSV_DATASETS),
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "pdf": False,
        "destination": "application data / exports",
    }


def _dto(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "evidence_id": row["evidence_id"],
        "job_id": row.get("job_id"),
        "format": row["format"],
        "scope": row["scope"],
        "sections": json.loads(row["sections_json"] or "[]"),
        "status": row["status"],
        "output_dir": row.get("output_dir"),
        "primary_path": row.get("primary_path"),
        "files": json.loads(row["files_json"] or "[]"),
        "size_bytes": row.get("size_bytes"),
        "report_schema_version": row.get("report_schema_version"),
        "error": json.loads(row["error_json"]) if row.get("error_json") else None,
        "created_at": row.get("created_at"),
        "finished_at": row.get("finished_at"),
    }


def get_export(db: Database, export_id: str) -> dict[str, Any]:
    row = db.fetchone("SELECT * FROM exports WHERE id = ?", (export_id,))
    if not row:
        raise AppError(code="export_missing", message="Export not found.", entity="export")
    return _dto(row)


def list_exports(db: Database, evidence_id: str, *, limit: int = 50) -> dict[str, Any]:
    rows = db.fetchall(
        "SELECT * FROM exports WHERE evidence_id = ? ORDER BY created_at DESC LIMIT ?",
        (evidence_id, limit),
    )
    return {"evidence_id": evidence_id, "total": len(rows), "items": [_dto(r) for r in rows]}


def _validate_format_scope(fmt: str, scope: str) -> tuple[str, str]:
    fmt_n = str(fmt or "").strip().lower()
    scope_n = str(scope or "complete").strip().lower()
    if fmt_n not in FORMATS:
        raise AppError(
            code="export_format_unsupported",
            message="Unsupported export format.",
            details=fmt_n,
            suggestion="Use json, csv, or html.",
            entity="export",
        )
    if scope_n not in SCOPES:
        raise AppError(
            code="export_scope_invalid",
            message="Scope must be complete or selected.",
            details=scope_n,
            entity="export",
        )
    return fmt_n, scope_n


def generate_export(
    db: Database,
    paths: AppPaths,
    *,
    evidence_id: str,
    fmt: str,
    scope: str = "complete",
    sections: list[str] | None = None,
    filename_hint: str | None = None,
    destination: str | None = None,
    job_id: str | None = None,
    cancelled: Callable[[], bool] | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    reject_user_destination(destination)
    fmt_n, scope_n = _validate_format_scope(fmt, scope)
    hint = parse_optional_basename(filename_hint)
    section_list = normalize_sections(scope_n, sections)

    if fmt_n == "csv":
        ds = datasets_for_sections(section_list, scope=scope_n)
        if not ds:
            raise AppError(
                code="export_csv_empty",
                message="CSV export requires at least one tabular section.",
                suggestion="Choose processes, network, modules, memory, findings, IOCs, timeline, or artifacts.",
                entity="export",
            )

    evidence = evidence_workflows.get_evidence(db, evidence_id)
    export_id = str(uuid4())
    now = _utcnow()
    db.execute(
        """
        INSERT INTO exports (
          id, evidence_id, job_id, format, scope, sections_json, status,
          output_dir, primary_path, files_json, size_bytes, report_schema_version,
          error_json, created_at, finished_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'running', NULL, NULL, '[]', NULL, ?, NULL, ?, NULL)
        """,
        (
            export_id,
            evidence_id,
            job_id,
            fmt_n,
            scope_n,
            json.dumps(section_list),
            REPORT_SCHEMA_VERSION,
            now,
        ),
    )

    try:
        if progress:
            progress("Collecting investigation data")
        if cancelled and cancelled():
            raise AppError(code="export_cancelled", message="Export cancelled.", entity="export")

        doc = collect_investigation(
            db,
            evidence_id,
            fmt=fmt_n,
            sections=section_list,
            cancelled=cancelled,
            progress=progress,
        )
        out_dir = allocate_export_dir(
            paths,
            evidence_filename=str(evidence.get("filename") or "evidence"),
            export_id=export_id,
            basename_hint=hint,
            evidence_path=evidence.get("path"),
        )
        files: list[dict[str, Any]] = []
        primary: Path | None = None

        if progress:
            progress(f"Writing {fmt_n} export")
        if cancelled and cancelled():
            raise AppError(code="export_cancelled", message="Export cancelled.", entity="export")

        if fmt_n == "json":
            files = write_json_exports(out_dir, doc, section_list, scope=scope_n)
            primary = out_dir / files[0]["name"]
        elif fmt_n == "html":
            primary = out_dir / "report.html"
            size = write_html_file(primary, doc)
            files = [{"name": primary.name, "kind": "html_report", "size_bytes": size}]
        elif fmt_n == "csv":
            datasets = datasets_for_sections(section_list, scope=scope_n)
            for ds in datasets:
                path = out_dir / f"{sanitize_filename(ds)}.csv"
                size = write_csv_file(path, ds, dataset_rows(doc, ds))
                files.append({"name": path.name, "kind": ds, "size_bytes": size})
                if primary is None:
                    primary = path

        manifest = {
            "format": fmt_n,
            "scope": scope_n,
            "sections": section_list,
            "report_schema_version": REPORT_SCHEMA_VERSION,
            "export_id": export_id,
            "evidence_id": evidence_id,
            "generated_at": doc.get("generated_at"),
            "files": files,
            "truncated": doc.get("truncated"),
        }
        man_path = out_dir / "manifest.json"
        write_json_file(man_path, manifest)
        files.append({"name": man_path.name, "kind": "manifest", "size_bytes": man_path.stat().st_size})

        total_size = sum(int(f.get("size_bytes") or 0) for f in files)
        finished = _utcnow()
        db.execute(
            """
            UPDATE exports SET status='completed', output_dir=?, primary_path=?, files_json=?,
              size_bytes=?, finished_at=? WHERE id=?
            """,
            (
                str(out_dir),
                str(primary) if primary else str(out_dir),
                json.dumps(files),
                total_size,
                finished,
                export_id,
            ),
        )
        log.info("export completed", extra={"channel": "analysis", "export_id": export_id})
        return get_export(db, export_id)
    except AppError as exc:
        db.execute(
            """
            UPDATE exports SET status=?, error_json=?, finished_at=? WHERE id=?
            """,
            (
                "cancelled" if exc.code == "export_cancelled" else "failed",
                json.dumps(exc.to_dict()),
                _utcnow(),
                export_id,
            ),
        )
        raise
    except Exception as exc:  # noqa: BLE001
        db.execute(
            """
            UPDATE exports SET status='failed', error_json=?, finished_at=? WHERE id=?
            """,
            (json.dumps({"message": str(exc)}), _utcnow(), export_id),
        )
        raise


def run_export_job(
    db: Database,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: Callable[[str], None],
    *,
    paths: AppPaths,
) -> dict[str, Any]:
    evidence_id = params.get("evidence_id")
    if not evidence_id:
        raise AppError(code="invalid_params", message="evidence_id is required", entity="export")
    result = generate_export(
        db,
        paths,
        evidence_id=str(evidence_id),
        fmt=str(params.get("format") or "html"),
        scope=str(params.get("scope") or "complete"),
        sections=params.get("sections"),
        filename_hint=params.get("filename_hint"),
        destination=params.get("destination") or params.get("output_path"),
        job_id=params.get("job_id"),
        cancelled=cancelled,
        progress=progress,
    )
    return result
