"""PE Extraction workflow: jobs, artifacts, provenance, timeline."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths
from memscope_engine.providers.pe_extraction import PeExtractionProvider
from memscope_engine.providers.process_run import assert_evidence_unchanged, evidence_fingerprint
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION
from memscope_engine.volatility.pe_dump import extract_pe_images

log = logging.getLogger("memscope.analysis")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit_progress(
    progress: Callable[..., None],
    msg: str,
    extra: dict[str, Any] | None = None,
) -> None:
    if extra is None:
        progress(msg)
        return
    try:
        progress(msg, extra)
    except TypeError:
        progress(msg)


class _PeJobProgress:
    """Map pedump stage messages onto a determinate percent for the Jobs UI."""

    def __init__(self, progress: Callable[..., None]) -> None:
        self._progress = progress
        self._percent = 2.0
        self._phase = "pe_extract"
        self._module_pids = 0
        self._vad_pids = 0

    def emit(self, msg: str) -> None:
        lower = (msg or "").lower()
        if "constructing volatility process list" in lower:
            self._percent, self._phase = 6.0, "session"
        elif "extracting process executable" in lower:
            self._percent, self._phase = 12.0, "process_images"
        elif "extracting loaded modules for pid" in lower:
            self._module_pids += 1
            self._percent = min(68.0, 18.0 + self._module_pids * 1.15)
            self._phase = "pe_modules"
        elif "scanning vads" in lower:
            self._vad_pids += 1
            self._percent = min(88.0, 70.0 + self._vad_pids * 0.7)
            self._phase = "pe_vad"
        elif "cached pe" in lower:
            self._percent, self._phase = 91.0, "pe_cache"
        elif "extracting pe images" in lower:
            self._percent, self._phase = 4.0, "pe_extract"
        else:
            self._percent = min(95.0, self._percent + 0.25)
        _emit_progress(
            self._progress,
            msg,
            {"phase": self._phase, "percent": round(self._percent, 1)},
        )

    def done(self, extracted_count: int) -> None:
        _emit_progress(
            self._progress,
            f"PE reconstruction complete ({extracted_count} file"
            f"{'' if extracted_count == 1 else 's'})",
            {"phase": "done", "percent": 100},
        )


def _item_field(item: Any, name: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def pe_extraction_status(_paths: AppPaths, _db: Database) -> dict[str, Any]:
    return PeExtractionProvider().availability()


def configure_pe_extraction(paths: AppPaths, db: Database, settings: dict[str, Any]) -> dict[str, Any]:
    return PeExtractionProvider().configure(settings)


def run_pe_extraction_job(
    db: Database,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: Callable[[str], None],
    *,
    paths: AppPaths,
    extract_fn: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    evidence_id = params.get("evidence_id")
    if not evidence_id:
        raise AppError(
            code="evidence_required",
            message="evidence_id is required for PE extraction.",
            entity="pe_extraction",
        )
    evidence = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    if not evidence:
        raise AppError(code="evidence_missing", message="Evidence not found.", entity="evidence")

    image = Path(evidence["path"])
    if not image.is_file():
        raise AppError(
            code="evidence_not_found",
            message="Memory image file was not found.",
            details=str(image),
            entity="evidence",
        )

    avail = PeExtractionProvider().availability()
    if not avail.get("available") and extract_fn is None:
        raise AppError(
            code="pe_extraction_unavailable",
            message="PE Extraction is not available.",
            details=avail.get("reason"),
            suggestion=avail.get("suggestion"),
            entity="pe_extraction",
        )

    job_id = params.get("job_id")
    pid_filter = params.get("pid")
    run_id = str(uuid4())
    extraction_id = str(uuid4())
    started = _utcnow()
    out_dir = paths.analysis / "pe_extraction" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    strategy = [
        {
            "provider": "pe_extraction",
            "target": "memory_image",
            "reason": (
                "Reconstruct PE images (process EXE, loaded DLL, mapped PE, "
                "unlinked/manual-mapped MZ, cached PE) from the imported dump. "
                "Does not execute extracts or label them as malware."
            ),
            "methods": avail.get("methods"),
            "pid": pid_filter,
        }
    ]
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, notes,
          process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'pe_extraction', 'running', ?, ?, ?, NULL, ?, ?, ?)
        """,
        (
            run_id,
            evidence_id,
            started,
            SCHEMA_VERSION,
            "PE extraction from memory dump",
            int(pid_filter) if pid_filter is not None else None,
            job_id,
            json.dumps(strategy),
        ),
    )
    if job_id:
        db.execute("UPDATE jobs SET analysis_run_id = ? WHERE id = ?", (run_id, job_id))

    db.execute(
        """
        INSERT INTO pe_extraction_runs (
          id, evidence_id, analysis_run_id, job_id, status, volatility_version,
          extracted_count, exe_count, dll_count, skipped_count, candidate_count,
          output_dir, methods_json, observed_json, error_json, started_at, finished_at
        ) VALUES (?, ?, ?, ?, 'running', ?, 0, 0, 0, 0, 0, ?, '[]', '{}', NULL, ?, NULL)
        """,
        (
            extraction_id,
            evidence_id,
            run_id,
            job_id,
            avail.get("volatility_version"),
            str(out_dir),
            started,
        ),
    )

    exec_id = str(uuid4())
    db.execute(
        """
        INSERT INTO plugin_executions (
          id, analysis_run_id, evidence_id, plugin, parameters_json,
          status, started_at, transparency_json
        ) VALUES (?, ?, ?, 'provider.pe_extraction', ?, 'running', ?, '{}')
        """,
        (
            exec_id,
            run_id,
            evidence_id,
            json.dumps({"evidence_id": evidence_id, "pid": pid_filter, "output_dir": str(out_dir)}),
            started,
        ),
    )

    before = evidence_fingerprint(image)
    try:
        if cancelled():
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
        tracker = _PeJobProgress(progress)
        tracker.emit("Extracting PE images from the memory dump")
        impl = extract_fn or extract_pe_images
        include_dumpfiles = bool(params.get("include_dumpfiles"))
        result = impl(
            image,
            out_dir,
            pid_filter=int(pid_filter) if pid_filter is not None else None,
            cancelled=cancelled,
            progress=tracker.emit,
            include_dumpfiles=include_dumpfiles,
        )
        assert_evidence_unchanged(image, before, entity="pe_extraction")

        items = result.get("items") or []
        process_lookup = _process_lookup(db, evidence_id)
        stored: list[dict[str, Any]] = []
        for item in items:
            if cancelled():
                raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
            art = _persist_item(
                db,
                paths,
                evidence_id=evidence_id,
                run_id=run_id,
                extraction_id=extraction_id,
                item=item,
                process_lookup=process_lookup,
                volatility_version=result.get("volatility_version") or avail.get("volatility_version"),
            )
            stored.append(art)

        observed = {
            "extracted_count": len(stored),
            "exe_count": result.get("exe_count", sum(1 for a in stored if (a.get("metadata") or {}).get("pe_kind") == "exe")),
            "dll_count": result.get("dll_count", sum(1 for a in stored if (a.get("metadata") or {}).get("pe_kind") == "dll")),
            "skipped_count": result.get("skipped_count", 0),
            "skipped": (result.get("skipped") or [])[:200],
            "errors": result.get("errors") or [],
            "methods_used": result.get("methods_used") or [],
            "include_dumpfiles": bool(result.get("include_dumpfiles", include_dumpfiles)),
            "dumpfiles_used": bool(result.get("dumpfiles_used")),
            "output_dir": str(out_dir),
            "interpretation": {
                "kind": "extracted_pe_artifact",
                "summary": (
                    f"Extracted {len(stored)} PE artifact(s) from the memory dump. "
                    "These are reconstructed EXE/DLL images, not malware verdicts."
                ),
            },
        }
        db.execute(
            """
            UPDATE pe_extraction_runs SET status='completed', volatility_version=?,
              extracted_count=?, exe_count=?, dll_count=?, skipped_count=?,
              candidate_count=?, methods_json=?, observed_json=?, finished_at=?
            WHERE id=?
            """,
            (
                result.get("volatility_version") or avail.get("volatility_version"),
                len(stored),
                observed["exe_count"],
                observed["dll_count"],
                observed["skipped_count"],
                len(stored) + observed["skipped_count"],
                json.dumps(observed["methods_used"]),
                json.dumps(observed),
                _utcnow(),
                extraction_id,
            ),
        )
        db.execute(
            """
            UPDATE plugin_executions SET status='completed', finished_at=?, row_count=?,
              transparency_json=? WHERE id=?
            """,
            (
                _utcnow(),
                len(stored),
                json.dumps(
                    {
                        "tool": "volatility3",
                        "plugin": "provider.pe_extraction",
                        "methods": observed["methods_used"],
                        "extracted_count": len(stored),
                    }
                ),
                exec_id,
            ),
        )
        db.execute(
            "UPDATE analysis_runs SET status='completed', finished_at=?, volatility_version=? WHERE id=?",
            (_utcnow(), result.get("volatility_version"), run_id),
        )
        db.execute(
            """
            INSERT INTO timeline_events (
              id, evidence_id, event_time, time_precision, classification, event_kind,
              summary, process_id, pid, related_entity_type, related_entity_id,
              source_table, source_plugin, provenance_json, created_at
            ) VALUES (?, ?, NULL, 'analysis_time', 'inferred', 'pe_extraction', ?, NULL, ?,
              'pe_extraction_run', ?, 'pe_extraction_runs', 'provider.pe_extraction', ?, ?)
            """,
            (
                str(uuid4()),
                evidence_id,
                f"PE extraction: {len(stored)} extracted PE artifact(s)",
                pid_filter,
                extraction_id,
                json.dumps(
                    {
                        "extraction_id": extraction_id,
                        "analysis_run_id": run_id,
                        "extracted_count": len(stored),
                        "output_dir": str(out_dir),
                    }
                ),
                _utcnow(),
            ),
        )
        log.info("pe extraction completed", extra={"channel": "analysis", "evidence_id": evidence_id})
        tracker.done(len(stored))
        return get_pe_extraction_run(db, extraction_id)
    except AppError as exc:
        _fail(db, exec_id, run_id, extraction_id, exc)
        raise
    except Exception as exc:  # noqa: BLE001
        err = AppError(
            code="pe_extraction_failed",
            message="PE extraction failed.",
            details=f"{type(exc).__name__}: {exc}",
            entity="pe_extraction",
        )
        _fail(db, exec_id, run_id, extraction_id, err)
        raise err from exc


def _fail(db: Database, exec_id: str, run_id: str, extraction_id: str, exc: AppError) -> None:
    now = _utcnow()
    status = "cancelled" if exc.code == "job_cancelled" else "failed"
    payload = json.dumps(exc.to_dict())
    db.execute(
        "UPDATE plugin_executions SET status=?, finished_at=?, error_json=? WHERE id=?",
        (status, now, payload, exec_id),
    )
    db.execute(
        "UPDATE analysis_runs SET status=?, finished_at=?, error_json=? WHERE id=?",
        (status, now, payload, run_id),
    )
    db.execute(
        "UPDATE pe_extraction_runs SET status=?, error_json=?, finished_at=? WHERE id=?",
        (status, payload, now, extraction_id),
    )


def _process_lookup(db: Database, evidence_id: str) -> dict[int, dict[str, Any]]:
    rows = db.fetchall(
        """
        SELECT id, pid, name, image_path FROM processes
        WHERE evidence_id = ?
        ORDER BY analysis_run_id DESC
        """,
        (evidence_id,),
    )
    out: dict[int, dict[str, Any]] = {}
    for r in rows:
        pid = r.get("pid")
        if pid is not None and int(pid) not in out:
            out[int(pid)] = r
    return out


def _persist_item(
    db: Database,
    paths: AppPaths,
    *,
    evidence_id: str,
    run_id: str,
    extraction_id: str,
    item: Any,
    process_lookup: dict[int, dict[str, Any]],
    volatility_version: str | None,
) -> dict[str, Any]:
    from memscope_engine.analysis.memory_artifacts import _artifact_dto

    stored = Path(_item_field(item, "path"))
    # Allow analysis/pe_extraction as the canonical store for this workflow.
    stored = stored.resolve()
    analysis_root = (paths.analysis / "pe_extraction").resolve()
    try:
        stored.relative_to(analysis_root)
    except ValueError as exc:
        raise AppError(
            code="pe_extraction_path_denied",
            message="Extracted PE path escaped the PE extraction directory.",
            details=str(stored),
            entity="pe_extraction",
        ) from exc

    pid = _item_field(item, "pid")
    proc = process_lookup.get(int(pid)) if pid is not None else None
    art_id = str(uuid4())
    item_id = str(uuid4())
    meta = dict(_item_field(item, "metadata") or {})
    pe_kind = _item_field(item, "pe_kind")
    start_vpn = _item_field(item, "start_vpn")
    end_vpn = _item_field(item, "end_vpn")
    base_address = _item_field(item, "base_address")
    if start_vpn:
        source_address = start_vpn
    elif base_address is not None:
        try:
            source_address = f"0x{int(base_address):x}"
        except (TypeError, ValueError):
            source_address = str(base_address)
    else:
        source_address = None
    meta.update(
        {
            "pe_kind": pe_kind,
            "pe_extraction_run_id": extraction_id,
            "analysis_run_id": run_id,
            "kind": _item_field(item, "kind"),
            "original_path": _item_field(item, "original_path"),
            "memory_region": _item_field(item, "memory_region"),
            "source_address": source_address,
            "label": "extracted_pe_artifact",
        }
    )
    db.execute(
        """
        INSERT INTO artifacts (
          id, evidence_id, process_id, pid, memory_region_id, filename, stored_path,
          sha256, size_bytes, file_type, extraction_method, source_plugin, tool_name,
          tool_version, source_address, start_vpn, end_vpn, extracted_at, notes, metadata_json
        ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, 'pe', ?, ?, 'volatility3', ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            art_id,
            evidence_id,
            proc["id"] if proc else None,
            pid,
            stored.name,
            str(stored),
            _item_field(item, "sha256"),
            _item_field(item, "size_bytes"),
            _item_field(item, "extraction_method"),
            _item_field(item, "source_plugin"),
            volatility_version,
            source_address,
            start_vpn,
            end_vpn,
            _utcnow(),
            _item_field(item, "notes")
            or "Extracted PE artifact; not executed; not classified as malware.",
            json.dumps(meta),
        ),
    )
    db.execute(
        """
        INSERT INTO pe_extraction_items (
          id, run_id, artifact_id, evidence_id, process_id, pid, process_name,
          original_path, pe_kind, memory_region, source_address, start_vpn, end_vpn,
          extraction_method, source_plugin, filename, stored_path, sha256, size_bytes,
          duplicate_of, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
        """,
        (
            item_id,
            extraction_id,
            art_id,
            evidence_id,
            proc["id"] if proc else None,
            pid,
            _item_field(item, "process_name") or (proc or {}).get("name"),
            _item_field(item, "original_path"),
            pe_kind,
            _item_field(item, "memory_region"),
            source_address,
            start_vpn,
            end_vpn,
            _item_field(item, "extraction_method"),
            _item_field(item, "source_plugin"),
            stored.name,
            str(stored),
            _item_field(item, "sha256"),
            _item_field(item, "size_bytes"),
            json.dumps(meta),
            _utcnow(),
        ),
    )
    row = db.fetchone("SELECT * FROM artifacts WHERE id = ?", (art_id,))
    assert row
    return _artifact_dto(row)


def get_pe_extraction_run(db: Database, run_id: str) -> dict[str, Any]:
    row = db.fetchone("SELECT * FROM pe_extraction_runs WHERE id = ?", (run_id,))
    if not row:
        raise AppError(
            code="pe_extraction_missing",
            message="PE extraction run not found.",
            entity="pe_extraction",
        )
    items = db.fetchall(
        "SELECT * FROM pe_extraction_items WHERE run_id = ? ORDER BY created_at",
        (run_id,),
    )
    return {"run": _run_dto(row), "items": [_item_dto(i) for i in items]}


def list_pe_extraction_runs(db: Database, evidence_id: str) -> dict[str, Any]:
    rows = db.fetchall(
        """
        SELECT * FROM pe_extraction_runs WHERE evidence_id = ?
        ORDER BY started_at DESC LIMIT 50
        """,
        (evidence_id,),
    )
    items = []
    for r in rows:
        bundle = get_pe_extraction_run(db, r["id"])
        items.append(bundle)
    return {"evidence_id": evidence_id, "total": len(items), "items": items}


def list_extracted_pe_artifacts(db: Database, evidence_id: str) -> dict[str, Any]:
    """Files shown in Carved Data → Extracted Files (PE reconstruction and VAD dumps)."""
    from memscope_engine.analysis.memory_artifacts import list_artifacts

    return list_artifacts(db, evidence_id)


def _run_dto(row: dict[str, Any]) -> dict[str, Any]:
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
        "analysis_run_id": row.get("analysis_run_id"),
        "job_id": row.get("job_id"),
        "status": row["status"],
        "volatility_version": row.get("volatility_version"),
        "extracted_count": row.get("extracted_count") or 0,
        "exe_count": row.get("exe_count") or 0,
        "dll_count": row.get("dll_count") or 0,
        "skipped_count": row.get("skipped_count") or 0,
        "candidate_count": row.get("candidate_count") or 0,
        "output_dir": row.get("output_dir"),
        "methods": _j("methods_json", []),
        "observed": _j("observed_json", {}),
        "error": err,
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
    }


def _item_dto(row: dict[str, Any]) -> dict[str, Any]:
    try:
        metadata = json.loads(row.get("metadata_json") or "{}")
    except json.JSONDecodeError:
        metadata = {}
    return {
        "id": row["id"],
        "run_id": row["run_id"],
        "artifact_id": row.get("artifact_id"),
        "evidence_id": row.get("evidence_id"),
        "process_id": row.get("process_id"),
        "pid": row.get("pid"),
        "process_name": row.get("process_name"),
        "original_path": row.get("original_path"),
        "pe_kind": row.get("pe_kind"),
        "memory_region": row.get("memory_region"),
        "source_address": row.get("source_address"),
        "start_vpn": row.get("start_vpn"),
        "end_vpn": row.get("end_vpn"),
        "extraction_method": row.get("extraction_method"),
        "source_plugin": row.get("source_plugin"),
        "filename": row.get("filename"),
        "stored_path": row.get("stored_path"),
        "sha256": row.get("sha256"),
        "size_bytes": row.get("size_bytes"),
        "metadata": metadata,
        "label": "extracted_pe_artifact",
        "created_at": row.get("created_at"),
    }
