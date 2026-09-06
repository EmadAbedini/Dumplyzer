"""PE-sieve workflows: jobs, provenance, and artifact ingest."""

from __future__ import annotations

import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from memscope_engine.artifacts import store as artifact_store
from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths
from memscope_engine.providers.pe_sieve import (
    TARGET_ARTIFACT,
    PeSieveProvider,
    compute_ui_state,
    describe_target,
)
from memscope_engine.storage import Database

log = logging.getLogger("memscope.analysis")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_or_create_provider(paths: AppPaths, db: Database) -> PeSieveProvider:
    provider = PeSieveProvider(
        tools_dir=paths.tools,
        tmp_dir=paths.tmp,
        artifacts_dir=paths.artifacts,
    )
    row = db.fetchone("SELECT value_json FROM app_settings WHERE key = 'pe_sieve'")
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


def save_pe_sieve_settings(db: Database, provider: PeSieveProvider) -> dict[str, Any]:
    payload = {
        "timeout_secs": provider.timeout_secs,
        "executable_path": str(provider.executable_path) if provider.executable_path else None,
        "tools_dir": str(provider.tools_dir) if provider.tools_dir else None,
    }
    db.execute(
        """
        INSERT INTO app_settings(key, value_json, updated_at) VALUES('pe_sieve', ?, ?)
        ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
        """,
        (json.dumps(payload), _utcnow()),
    )
    return provider.availability()


def pe_sieve_status(paths: AppPaths, db: Database) -> dict[str, Any]:
    provider = get_or_create_provider(paths, db)
    avail = provider.availability()
    avail["ui_state"] = compute_ui_state(
        available=bool(avail.get("available")),
        target_kind=TARGET_ARTIFACT,
    )
    return avail


def configure_pe_sieve(paths: AppPaths, db: Database, settings: dict[str, Any]) -> dict[str, Any]:
    provider = get_or_create_provider(paths, db)
    provider.configure(settings)
    return save_pe_sieve_settings(db, provider)


def run_pe_sieve_artifact_scan_job(
    db: Database,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: Callable[[str], None],
    *,
    paths: AppPaths,
) -> dict[str, Any]:
    """Artifact investigation entry: record unsupported_target, do not invoke PE-sieve."""
    artifact_id = params.get("artifact_id")
    if not artifact_id:
        raise AppError(
            code="artifact_required",
            message="artifact_id is required for a PE-sieve artifact workflow.",
            entity="pe_sieve",
        )
    art = db.fetchone("SELECT * FROM artifacts WHERE id = ?", (artifact_id,))
    if not art:
        raise AppError(code="artifact_missing", message="Artifact not found.", entity="artifact")

    evidence_id = art["evidence_id"]
    job_id = params.get("job_id")

    stored = Path(art["stored_path"])
    stored = artifact_store.ensure_within_artifacts(paths, stored)
    if not stored.is_file():
        raise AppError(
            code="artifact_file_missing",
            message="Artifact file is missing from the controlled store.",
            details=str(stored),
            entity="artifact",
        )

    provider = get_or_create_provider(paths, db)
    avail = provider.availability()
    target = describe_target(TARGET_ARTIFACT)

    run_id = str(uuid4())
    scan_id = str(uuid4())
    started = _utcnow()
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, notes,
          process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'pe_sieve_artifact_scan', 'running', ?, 6, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            evidence_id,
            started,
            f"PE-sieve workflow for artifact {art['filename']}",
            art.get("process_id"),
            art.get("pid"),
            job_id,
            json.dumps(
                [
                    {
                        "provider": "pe_sieve",
                        "target": TARGET_ARTIFACT,
                        "artifact_id": artifact_id,
                        "reason": "PE-sieve cannot scan extracted artifacts; record unsupported target.",
                    }
                ]
            ),
        ),
    )
    if job_id:
        db.execute("UPDATE jobs SET analysis_run_id = ? WHERE id = ?", (run_id, job_id))

    exec_id = str(uuid4())
    db.execute(
        """
        INSERT INTO plugin_executions (
          id, analysis_run_id, evidence_id, plugin, parameters_json,
          status, started_at, transparency_json
        ) VALUES (?, ?, ?, 'provider.pe_sieve', ?, 'running', ?, '{}')
        """,
        (
            exec_id,
            run_id,
            evidence_id,
            json.dumps(
                {
                    "artifact_id": artifact_id,
                    "target": str(stored),
                    "target_kind": TARGET_ARTIFACT,
                    "invoked_pe_sieve": False,
                }
            ),
            started,
        ),
    )

    if cancelled():
        _fail_scan_records(
            db,
            scan_id=None,
            exec_id=exec_id,
            run_id=run_id,
            status="cancelled",
            error=AppError(code="job_cancelled", message="Job was cancelled.", entity="job"),
        )
        raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")

    progress("Checking PE-sieve availability and target support")

    if not avail.get("available"):
        ui_state = "unavailable"
        error = AppError(
            code="pe_sieve_unavailable",
            message="PE-sieve is not available on this system.",
            details=avail.get("reason"),
            suggestion=avail.get("suggestion"),
            entity="pe_sieve",
        )
        db.execute(
            """
            INSERT INTO pe_sieve_scans (
              id, evidence_id, artifact_id, process_id, pid, memory_region_id,
              analysis_run_id, job_id, status, ui_state, target_kind, live_pid,
              pe_sieve_version, executable_path, output_dir, exit_code, pesieve_result,
              observed_json, interpretation_json, error_json, started_at, finished_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unavailable', ?, ?, NULL, ?, ?, NULL, NULL, NULL,
              '{}', ?, ?, ?, ?)
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
                ui_state,
                TARGET_ARTIFACT,
                avail.get("pe_sieve_version"),
                avail.get("executable_path"),
                json.dumps(
                    {
                        "source": "memscope",
                        "ui_state": ui_state,
                        "notes": "PE-sieve EXE not present; no scan was performed.",
                    }
                ),
                json.dumps(error.to_dict()),
                started,
                _utcnow(),
            ),
        )
        _fail_scan_records(
            db, scan_id=None, exec_id=exec_id, run_id=run_id, status="failed", error=error
        )
        raise error

    # Available but artifact is not a valid PE-sieve target — do not invoke the EXE.
    ui_state = "unsupported_target"
    interpretation = {
        "source": "memscope",
        "ui_state": ui_state,
        "has_indicators": False,
        "summary": "PE-sieve was not invoked: extracted artifacts are not valid targets.",
        "notes": target["reason"],
        "invoked_pe_sieve": False,
    }
    observed = {
        "source": "pe-sieve",
        "invoked": False,
        "target_kind": TARGET_ARTIFACT,
        "artifact_id": artifact_id,
        "artifact_sha256": art.get("sha256"),
        "verified_release": avail.get("verified_release"),
    }
    db.execute(
        """
        INSERT INTO pe_sieve_scans (
          id, evidence_id, artifact_id, process_id, pid, memory_region_id,
          analysis_run_id, job_id, status, ui_state, target_kind, live_pid,
          pe_sieve_version, executable_path, output_dir, exit_code, pesieve_result,
          observed_json, interpretation_json, error_json, started_at, finished_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unsupported_target', ?, ?, NULL, ?, ?, NULL, NULL, NULL,
          ?, ?, NULL, ?, ?)
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
            ui_state,
            TARGET_ARTIFACT,
            avail.get("pe_sieve_version"),
            avail.get("executable_path"),
            json.dumps(observed),
            json.dumps(interpretation),
            started,
            _utcnow(),
        ),
    )
    db.execute(
        """
        UPDATE plugin_executions SET status='completed', finished_at=?, row_count=0,
          transparency_json=? WHERE id=?
        """,
        (
            _utcnow(),
            json.dumps(
                {
                    "tool": "pe-sieve",
                    "tool_version": avail.get("pe_sieve_version"),
                    "provider": "pe_sieve",
                    "target": TARGET_ARTIFACT,
                    "artifact_id": artifact_id,
                    "invoked_pe_sieve": False,
                    "ui_state": ui_state,
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
        ) VALUES (?, ?, ?, 'analysis_time', 'inferred', 'pe_sieve_scan', ?, ?, ?, 'artifact', ?,
          'pe_sieve_scans', 'provider.pe_sieve', ?, ?)
        """,
        (
            str(uuid4()),
            evidence_id,
            _utcnow(),
            f"PE-sieve skipped for {art['filename']}: unsupported target (live process required)",
            art.get("process_id"),
            art.get("pid"),
            artifact_id,
            json.dumps(
                {
                    "scan_id": scan_id,
                    "ui_state": ui_state,
                    "pe_sieve_version": avail.get("pe_sieve_version"),
                    "invoked_pe_sieve": False,
                }
            ),
            _utcnow(),
        ),
    )
    log.info(
        "pe-sieve artifact workflow: unsupported target",
        extra={"channel": "analysis", "evidence_id": evidence_id},
    )
    return get_pe_sieve_scan(db, scan_id)


def persist_pe_sieve_result(
    db: Database,
    paths: AppPaths,
    *,
    evidence_id: str,
    result: dict[str, Any],
    artifact_id: str | None = None,
    process_id: str | None = None,
    pid: int | None = None,
    memory_region_id: str | None = None,
    analysis_run_id: str | None = None,
    job_id: str | None = None,
    scan_id: str | None = None,
) -> dict[str, Any]:
    """Ingest PE-sieve output files as artifacts. Never execute them."""
    scan_id = scan_id or str(uuid4())
    now = _utcnow()
    observed = result.get("observed") or {}
    interpretation = result.get("interpretation") or {}
    status = result.get("status") or "completed"
    ui_state = result.get("ui_state") or compute_ui_state(
        available=True,
        scan_status=status,
        pesieve_result=result.get("pesieve_result"),
        modified_total=(observed.get("scan_report") or {}).get("modified", {}).get("total")
        if isinstance(observed.get("scan_report"), dict)
        else None,
        target_kind=result.get("target_kind"),
    )
    existing = db.fetchone("SELECT id FROM pe_sieve_scans WHERE id = ?", (scan_id,))
    if existing:
        db.execute(
            """
            UPDATE pe_sieve_scans SET status=?, ui_state=?, live_pid=?, pe_sieve_version=?,
              executable_path=?, output_dir=?, exit_code=?, pesieve_result=?,
              observed_json=?, interpretation_json=?, finished_at=?
            WHERE id=?
            """,
            (
                status,
                ui_state,
                result.get("live_pid"),
                result.get("pe_sieve_version"),
                result.get("executable_path"),
                result.get("output_dir"),
                result.get("exit_code"),
                result.get("pesieve_result"),
                json.dumps(observed),
                json.dumps(interpretation),
                now,
                scan_id,
            ),
        )
    else:
        db.execute(
            """
            INSERT INTO pe_sieve_scans (
              id, evidence_id, artifact_id, process_id, pid, memory_region_id,
              analysis_run_id, job_id, status, ui_state, target_kind, live_pid,
              pe_sieve_version, executable_path, output_dir, exit_code, pesieve_result,
              observed_json, interpretation_json, error_json, started_at, finished_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
            """,
            (
                scan_id,
                evidence_id,
                artifact_id,
                process_id,
                pid,
                memory_region_id,
                analysis_run_id,
                job_id,
                status,
                ui_state,
                result.get("target_kind") or "live_process",
                result.get("live_pid"),
                result.get("pe_sieve_version"),
                result.get("executable_path"),
                result.get("output_dir"),
                result.get("exit_code"),
                result.get("pesieve_result"),
                json.dumps(observed),
                json.dumps(interpretation),
                now,
                now,
            ),
        )

    output_dir = Path(result["output_dir"]) if result.get("output_dir") else None
    to_copy: list[tuple[str, Path, dict[str, Any]]] = []
    if output_dir and output_dir.is_dir():
        for role, key in (
            ("scan_report", "scan_report_path"),
            ("dump_report", "dump_report_path"),
            ("error_report", "error_report_path"),
        ):
            raw = result.get(key)
            if raw:
                p = Path(str(raw))
                if p.is_file() and _safe_under_output(p, output_dir):
                    to_copy.append((role, p, {"role": role}))
        for bundle in result.get("dump_files") or []:
            entry = bundle.get("entry") or {}
            for role, path in bundle.get("files") or []:
                if path.is_file() and _safe_under_output(path, output_dir):
                    to_copy.append(
                        (
                            str(role),
                            path,
                            {
                                "role": role,
                                "module": entry.get("module"),
                                "dump_mode": entry.get("dump_mode"),
                                "is_shellcode": entry.get("is_shellcode"),
                                "dump_file": entry.get("dump_file"),
                            },
                        )
                    )

    parent = None
    if artifact_id:
        parent = db.fetchone("SELECT * FROM artifacts WHERE id = ?", (artifact_id,))

    seen: set[str] = set()
    for role, src, meta in to_copy:
        key = str(src.resolve()).lower()
        if key in seen:
            continue
        seen.add(key)
        _ingest_output_file(
            db,
            paths,
            evidence_id=evidence_id,
            scan_id=scan_id,
            src=src,
            role=role,
            meta=meta,
            parent=parent,
            process_id=process_id,
            pid=pid,
            memory_region_id=memory_region_id,
            pe_sieve_version=result.get("pe_sieve_version"),
        )

    return get_pe_sieve_scan(db, scan_id)


def _safe_under_output(path: Path, output_dir: Path) -> bool:
    try:
        path.resolve().relative_to(output_dir.resolve())
        return True
    except ValueError:
        return False


def _ingest_output_file(
    db: Database,
    paths: AppPaths,
    *,
    evidence_id: str,
    scan_id: str,
    src: Path,
    role: str,
    meta: dict[str, Any],
    parent: dict[str, Any] | None,
    process_id: str | None,
    pid: int | None,
    memory_region_id: str | None,
    pe_sieve_version: str | None,
) -> str:
    dest_dir = artifact_store.artifact_dir(paths, evidence_id)
    dest_name = artifact_store.sanitize_component(
        f"pesieve.{scan_id[:8]}.{role}.{src.name}", max_len=120
    )
    dest = dest_dir / dest_name
    if dest.exists():
        dest = dest_dir / artifact_store.sanitize_component(
            f"pesieve.{scan_id[:8]}.{uuid4().hex[:8]}.{src.name}", max_len=120
        )
    # Never overwrite the source artifact; copy into a new controlled path.
    shutil.copy2(src, dest)
    dest = artifact_store.ensure_within_artifacts(paths, dest)
    digest = artifact_store.sha256_file(dest)
    ftype = artifact_store.sniff_file_type(dest)
    if dest.suffix.lower() == ".json":
        ftype = "json"
    art_id = str(uuid4())
    if parent:
        notes = f"PE-sieve {role} output; never executed. Parent artifact {parent['id']}"
    else:
        notes = "PE-sieve output; never executed."
    metadata = {
        "pe_sieve_scan_id": scan_id,
        "pe_sieve_role": role,
        "source_dump_path": src.name,
        "pe_sieve_version": pe_sieve_version,
        **{k: v for k, v in meta.items() if k != "observed"},
    }
    db.execute(
        """
        INSERT INTO artifacts (
          id, evidence_id, process_id, pid, memory_region_id, filename, stored_path,
          sha256, size_bytes, file_type, extraction_method, source_plugin, tool_name,
          tool_version, source_address, start_vpn, end_vpn, extracted_at, notes, metadata_json,
          parent_artifact_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            art_id,
            evidence_id,
            process_id or (parent.get("process_id") if parent else None),
            pid if pid is not None else (parent.get("pid") if parent else None),
            memory_region_id or (parent.get("memory_region_id") if parent else None),
            dest.name,
            str(dest),
            digest,
            dest.stat().st_size,
            ftype,
            "pe_sieve_dump",
            "provider.pe_sieve",
            "pe-sieve",
            pe_sieve_version,
            meta.get("module"),
            parent.get("start_vpn") if parent else None,
            parent.get("end_vpn") if parent else None,
            _utcnow(),
            notes,
            json.dumps(metadata),
            parent["id"] if parent else None,
        ),
    )
    db.execute(
        """
        INSERT INTO pe_sieve_outputs (
          id, scan_id, artifact_id, evidence_id, dump_file, dump_mode, module_base,
          is_shellcode, role, observed_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid4()),
            scan_id,
            art_id,
            evidence_id,
            src.name,
            meta.get("dump_mode"),
            meta.get("module"),
            1 if meta.get("is_shellcode") in (1, True, "1") else 0,
            role,
            json.dumps(meta),
            _utcnow(),
        ),
    )
    return art_id


def _fail_scan_records(
    db: Database,
    *,
    scan_id: str | None,
    exec_id: str,
    run_id: str,
    status: str,
    error: AppError,
) -> None:
    now = _utcnow()
    payload = json.dumps(error.to_dict())
    if scan_id:
        db.execute(
            "UPDATE pe_sieve_scans SET status=?, error_json=?, finished_at=? WHERE id=?",
            (status if status != "failed" else "failed", payload, now, scan_id),
        )
    db.execute(
        "UPDATE plugin_executions SET status=?, finished_at=?, error_json=? WHERE id=?",
        (status, now, payload, exec_id),
    )
    db.execute(
        "UPDATE analysis_runs SET status=?, finished_at=?, error_json=? WHERE id=?",
        (status, now, payload, run_id),
    )


def get_pe_sieve_scan(db: Database, scan_id: str) -> dict[str, Any]:
    row = db.fetchone("SELECT * FROM pe_sieve_scans WHERE id = ?", (scan_id,))
    if not row:
        raise AppError(code="pe_sieve_scan_missing", message="PE-sieve scan not found.", entity="pe_sieve")
    outputs = db.fetchall(
        """
        SELECT o.*, a.sha256, a.filename, a.stored_path, a.size_bytes, a.file_type
        FROM pe_sieve_outputs o
        JOIN artifacts a ON a.id = o.artifact_id
        WHERE o.scan_id = ?
        ORDER BY o.created_at
        """,
        (scan_id,),
    )
    return {"scan": _scan_dto(row), "outputs": [_output_dto(o) for o in outputs]}


def list_pe_sieve_scans_for_artifact(db: Database, artifact_id: str) -> dict[str, Any]:
    rows = db.fetchall(
        """
        SELECT * FROM pe_sieve_scans WHERE artifact_id = ?
        ORDER BY started_at DESC LIMIT 50
        """,
        (artifact_id,),
    )
    items = []
    for r in rows:
        outputs = db.fetchall(
            """
            SELECT o.*, a.sha256, a.filename, a.stored_path, a.size_bytes, a.file_type
            FROM pe_sieve_outputs o
            JOIN artifacts a ON a.id = o.artifact_id
            WHERE o.scan_id = ?
            ORDER BY o.created_at
            """,
            (r["id"],),
        )
        items.append({"scan": _scan_dto(r), "outputs": [_output_dto(o) for o in outputs]})
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
    observed = _j("observed_json", {})
    interpretation = _j("interpretation_json", {})
    return {
        "id": row["id"],
        "evidence_id": row["evidence_id"],
        "artifact_id": row.get("artifact_id"),
        "process_id": row.get("process_id"),
        "pid": row.get("pid"),
        "memory_region_id": row.get("memory_region_id"),
        "analysis_run_id": row.get("analysis_run_id"),
        "job_id": row.get("job_id"),
        "status": row["status"],
        "ui_state": row.get("ui_state"),
        "target_kind": row.get("target_kind"),
        "live_pid": row.get("live_pid"),
        "pe_sieve_version": row.get("pe_sieve_version"),
        "executable_path": row.get("executable_path"),
        "output_dir": row.get("output_dir"),
        "exit_code": row.get("exit_code"),
        "pesieve_result": row.get("pesieve_result"),
        "observed": observed,
        "interpretation": interpretation,
        "error": err,
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
    }


def _output_dto(row: dict[str, Any]) -> dict[str, Any]:
    try:
        observed = json.loads(row.get("observed_json") or "{}")
    except json.JSONDecodeError:
        observed = {}
    return {
        "id": row["id"],
        "scan_id": row["scan_id"],
        "artifact_id": row["artifact_id"],
        "evidence_id": row.get("evidence_id"),
        "dump_file": row.get("dump_file"),
        "dump_mode": row.get("dump_mode"),
        "module_base": row.get("module_base"),
        "is_shellcode": bool(row.get("is_shellcode")),
        "role": row["role"],
        "sha256": row.get("sha256"),
        "filename": row.get("filename"),
        "stored_path": row.get("stored_path"),
        "size_bytes": row.get("size_bytes"),
        "file_type": row.get("file_type"),
        "observed": observed,
        "created_at": row.get("created_at"),
    }
