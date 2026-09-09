"""bulk_extractor workflows: jobs, provenance, IOCs, findings, timeline."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from memscope_engine.analysis.progress import AnalysisProgress
from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths
from memscope_engine.providers.bulk_extractor import (
    BulkExtractorProvider,
    bundled_bulk_extractor_roots,
    compute_ui_state,
    list_output_files,
    normalize_bulk_extractor_output,
)
from memscope_engine.providers.bulk_extractor_features import (
    CATEGORY_META,
    kind_for_scanner,
)
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION

log = logging.getLogger("memscope.analysis")

MAX_IOCS = 8_000
MAX_FINDINGS = 1_500
MAX_FINDINGS_PER_TYPE = 200
MAX_FEATURE_QUERY = 2_000


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_or_create_provider(paths: AppPaths, db: Database) -> BulkExtractorProvider:
    provider = BulkExtractorProvider(
        tools_dir=paths.tools,
        analysis_dir=paths.analysis,
        artifacts_dir=paths.artifacts,
        extra_tool_roots=bundled_bulk_extractor_roots(),
    )
    row = db.fetchone("SELECT value_json FROM app_settings WHERE key = 'bulk_extractor'")
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


def save_bulk_extractor_settings(db: Database, provider: BulkExtractorProvider) -> dict[str, Any]:
    payload = {
        "timeout_secs": provider.timeout_secs,
        "executable_path": str(provider.executable_path) if provider.executable_path else None,
        "tools_dir": str(provider.tools_dir) if provider.tools_dir else None,
    }
    db.execute(
        """
        INSERT INTO app_settings(key, value_json, updated_at) VALUES('bulk_extractor', ?, ?)
        ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
        """,
        (json.dumps(payload), _utcnow()),
    )
    return provider.availability()


def bulk_extractor_status(paths: AppPaths, db: Database) -> dict[str, Any]:
    provider = get_or_create_provider(paths, db)
    avail = provider.availability()
    avail["ui_state"] = compute_ui_state(available=bool(avail.get("available")))
    return avail


def configure_bulk_extractor(paths: AppPaths, db: Database, settings: dict[str, Any]) -> dict[str, Any]:
    provider = get_or_create_provider(paths, db)
    provider.configure(settings)
    return save_bulk_extractor_settings(db, provider)


def _fail_records(
    db: Database,
    *,
    exec_id: str,
    run_id: str,
    status: str,
    error: AppError,
) -> None:
    now = _utcnow()
    payload = json.dumps(error.to_dict())
    db.execute(
        "UPDATE plugin_executions SET status=?, finished_at=?, error_json=? WHERE id=?",
        (status, now, payload, exec_id),
    )
    db.execute(
        "UPDATE analysis_runs SET status=?, finished_at=?, error_json=? WHERE id=?",
        (status, now, payload, run_id),
    )


def run_bulk_extractor_scan_job(
    db: Database,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: Callable[..., None],
    *,
    paths: AppPaths,
) -> dict[str, Any]:
    evidence_id = params.get("evidence_id")
    if not evidence_id:
        raise AppError(
            code="invalid_params",
            message="evidence_id is required to run bulk_extractor.",
            entity="bulk_extractor",
        )
    evidence = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    if not evidence:
        raise AppError(
            code="evidence_not_found",
            message="Evidence was not found.",
            entity="evidence",
        )
    image = Path(str(evidence["path"]))
    job_id = params.get("job_id")
    scan_id = str(uuid4())
    run_id = str(uuid4())
    exec_id = str(uuid4())
    started = _utcnow()
    provider = get_or_create_provider(paths, db)
    avail = provider.availability()
    out_dir = paths.analysis / "bulk_extractor" / scan_id

    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, notes,
          job_id, strategy_json
        ) VALUES (?, ?, 'bulk_extractor_scan', 'running', ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            evidence_id,
            started,
            SCHEMA_VERSION,
            "bulk_extractor scan of the imported memory image",
            job_id,
            json.dumps([{"provider": "bulk_extractor", "target": "memory_image"}]),
        ),
    )
    if job_id:
        db.execute("UPDATE jobs SET analysis_run_id = ? WHERE id = ?", (run_id, job_id))
    db.execute(
        """
        INSERT INTO plugin_executions (
          id, analysis_run_id, evidence_id, plugin, parameters_json, status, started_at, transparency_json
        ) VALUES (?, ?, ?, 'provider.bulk_extractor', ?, 'running', ?, '{}')
        """,
        (
            exec_id,
            run_id,
            evidence_id,
            json.dumps({"output_dir": str(out_dir), "invoked": False}),
            started,
        ),
    )

    if cancelled():
        error = AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
        _insert_scan_stub(
            db,
            scan_id=scan_id,
            evidence_id=evidence_id,
            run_id=run_id,
            job_id=job_id,
            avail=avail,
            output_dir=str(out_dir),
            status="cancelled",
            ui_state="cancelled",
            started=started,
            error=error,
        )
        _fail_records(db, exec_id=exec_id, run_id=run_id, status="cancelled", error=error)
        raise error

    if not avail.get("available"):
        error = AppError(
            code="bulk_extractor_unavailable",
            message="bulk_extractor is not available on this system.",
            details=avail.get("reason"),
            suggestion=avail.get("suggestion"),
            entity="bulk_extractor",
        )
        _insert_scan_stub(
            db,
            scan_id=scan_id,
            evidence_id=evidence_id,
            run_id=run_id,
            job_id=job_id,
            avail=avail,
            output_dir=str(out_dir),
            status="unavailable",
            ui_state="unavailable",
            started=started,
            error=error,
        )
        _fail_records(db, exec_id=exec_id, run_id=run_id, status="failed", error=error)
        raise error

    tracker = AnalysisProgress(progress, ["scan"], cancelled=cancelled)
    try:
        with tracker.running("scan", "Scanning memory image for artifacts"):
            result = provider.scan_image(image, output_dir=out_dir, cancelled=cancelled)
    except AppError as error:
        status = "cancelled" if error.code == "job_cancelled" else "failed"
        ui_state = "cancelled" if status == "cancelled" else "failed"
        _insert_scan_stub(
            db,
            scan_id=scan_id,
            evidence_id=evidence_id,
            run_id=run_id,
            job_id=job_id,
            avail=avail,
            output_dir=str(out_dir),
            status=status,
            ui_state=ui_state,
            started=started,
            error=error,
        )
        _fail_records(db, exec_id=exec_id, run_id=run_id, status=status, error=error)
        raise

    persist_bulk_extractor_result(
        db,
        scan_id=scan_id,
        evidence_id=evidence_id,
        run_id=run_id,
        job_id=job_id,
        exec_id=exec_id,
        started=started,
        result=result,
    )
    progress(
        "bulk_extractor finished",
        {
            "phase": "done",
            "percent": 100,
            "feature_count": result.get("feature_count") or 0,
        },
    )
    return get_bulk_extractor_scan(db, scan_id)


def _insert_scan_stub(
    db: Database,
    *,
    scan_id: str,
    evidence_id: str,
    run_id: str,
    job_id: str | None,
    avail: dict[str, Any],
    output_dir: str,
    status: str,
    ui_state: str,
    started: str,
    error: AppError,
) -> None:
    now = _utcnow()
    db.execute(
        """
        INSERT INTO bulk_extractor_scans (
          id, evidence_id, analysis_run_id, job_id, status, ui_state,
          bulk_extractor_version, executable_path, output_dir, exit_code,
          feature_count, scanner_count, invoked, observed_json, interpretation_json,
          error_json, started_at, finished_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, 0, 0, '{}', ?, ?, ?, ?)
        """,
        (
            scan_id,
            evidence_id,
            run_id,
            job_id,
            status,
            ui_state,
            avail.get("bulk_extractor_version"),
            avail.get("executable_path"),
            output_dir,
            json.dumps(
                {
                    "source": "memscope",
                    "kind": "extracted_artifact",
                    "notes": "bulk_extractor did not complete a scan.",
                    "ui_state": ui_state,
                }
            ),
            json.dumps(error.to_dict()),
            started,
            now,
        ),
    )


def persist_bulk_extractor_result(
    db: Database,
    *,
    scan_id: str,
    evidence_id: str,
    run_id: str,
    job_id: str | None,
    exec_id: str,
    started: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    finished = _utcnow()
    features = result.get("features") or []
    feature_count = int(result.get("feature_count") or len(features))
    scanners = result.get("scanners") or []
    ui_state = compute_ui_state(
        available=True,
        scan_status="completed",
        feature_count=feature_count,
    )
    db.execute(
        """
        INSERT INTO bulk_extractor_scans (
          id, evidence_id, analysis_run_id, job_id, status, ui_state,
          bulk_extractor_version, executable_path, output_dir, exit_code,
          feature_count, scanner_count, invoked, observed_json, interpretation_json,
          error_json, started_at, finished_at
        ) VALUES (?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, NULL, ?, ?)
        """,
        (
            scan_id,
            evidence_id,
            run_id,
            job_id,
            ui_state,
            result.get("bulk_extractor_version"),
            result.get("executable_path"),
            result.get("output_dir"),
            result.get("exit_code"),
            feature_count,
            len(scanners),
            json.dumps(result.get("observed") or {}),
            json.dumps(result.get("interpretation") or {}),
            started,
            finished,
        ),
    )
    _index_output_files(db, scan_id=scan_id, evidence_id=evidence_id, result=result)
    _insert_features(
        db,
        scan_id=scan_id,
        evidence_id=evidence_id,
        features=features,
        created_at=finished,
    )
    _insert_iocs_and_findings(
        db,
        scan_id=scan_id,
        evidence_id=evidence_id,
        run_id=run_id,
        features=features,
        version=result.get("bulk_extractor_version"),
        created_at=finished,
    )
    db.execute(
        """
        INSERT INTO timeline_events (
          id, evidence_id, event_time, time_precision, classification, event_kind,
          summary, related_entity_type, related_entity_id, source_table, source_plugin,
          provenance_json, created_at
        ) VALUES (?, ?, NULL, 'analysis_time', 'inferred', 'bulk_extractor', ?, 'scan', ?,
          'bulk_extractor_scans', 'provider.bulk_extractor', ?, ?)
        """,
        (
            str(uuid4()),
            evidence_id,
            (result.get("interpretation") or {}).get("summary")
            or "bulk_extractor scan completed",
            scan_id,
            json.dumps(
                {
                    "provider": "bulk_extractor",
                    "scan_id": scan_id,
                    "output_dir": result.get("output_dir"),
                    "feature_count": feature_count,
                    "kind": "extracted_artifact",
                }
            ),
            finished,
        ),
    )
    db.execute(
        "UPDATE plugin_executions SET status=?, finished_at=?, row_count=?, result_path=?, parameters_json=? WHERE id=?",
        (
            "completed",
            finished,
            feature_count,
            result.get("output_dir"),
            json.dumps(
                {
                    "output_dir": result.get("output_dir"),
                    "invoked": True,
                    "exit_code": result.get("exit_code"),
                }
            ),
            exec_id,
        ),
    )
    db.execute(
        "UPDATE analysis_runs SET status=?, finished_at=? WHERE id=?",
        ("completed", finished, run_id),
    )
    return get_bulk_extractor_scan(db, scan_id)


def _index_output_files(
    db: Database,
    *,
    scan_id: str,
    evidence_id: str,
    result: dict[str, Any],
) -> None:
    output_dir = Path(str(result.get("output_dir") or ""))
    now = _utcnow()
    files = list_output_files(output_dir) if output_dir.is_dir() else []
    observed_files = {
        f.get("relative_path"): f
        for f in ((result.get("observed") or {}).get("feature_files") or [])
    }
    for path in files:
        rel = path.name
        try:
            rel = str(path.relative_to(output_dir)).replace("\\", "/")
        except ValueError:
            pass
        meta = observed_files.get(rel) or {}
        role = meta.get("role")
        if not role:
            lower = path.name.lower()
            if lower == "report.xml":
                role = "report"
            elif lower.endswith("_histogram.txt"):
                role = "histogram"
            elif lower in {"dumplyzer-stdout.txt", "dumplyzer-stderr.txt"}:
                role = "capture"
            elif lower.endswith((".pcap", ".pcapng")):
                role = "pcap"
            elif lower == "alerts.txt":
                role = "alerts"
            elif path.suffix.lower() == ".txt":
                role = "feature"
            else:
                role = "file"
        if path.name.lower() == "report.xml":
            role = "report"
        db.execute(
            """
            INSERT INTO bulk_extractor_outputs (
              id, scan_id, evidence_id, relative_path, role, scanner, size_bytes, observed_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                scan_id,
                evidence_id,
                rel,
                role,
                meta.get("scanner") or (path.stem if role == "feature" else None),
                path.stat().st_size if path.exists() else 0,
                json.dumps(meta),
                now,
            ),
        )


def _insert_features(
    db: Database,
    *,
    scan_id: str,
    evidence_id: str,
    features: list[dict[str, Any]],
    created_at: str,
) -> None:
    rows: list[tuple[Any, ...]] = []
    for feat in features:
        value = str(feat.get("value") or "")
        if not value:
            continue
        extra = feat.get("extra") if isinstance(feat.get("extra"), dict) else {}
        try:
            count = int(feat.get("count") or 1)
        except (TypeError, ValueError):
            count = 1
        rows.append(
            (
                str(uuid4()),
                scan_id,
                evidence_id,
                str(feat.get("scanner") or "feature"),
                str(feat.get("category") or kind_for_scanner(str(feat.get("scanner") or "")).category),
                str(feat.get("ioc_type") or "feature"),
                str(feat.get("finding_type") or feat.get("ioc_type") or "feature"),
                str(feat.get("offset") or "") or None,
                value[:8000],
                (str(feat.get("context") or "")[:2000] or None),
                max(1, count),
                json.dumps(extra),
                created_at,
            )
        )
    if not rows:
        return
    db.executemany(
        """
        INSERT INTO bulk_extractor_features (
          id, scan_id, evidence_id, scanner, category, ioc_type, finding_type,
          offset, value, context, occurrence_count, extra_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )


def _insert_iocs_and_findings(
    db: Database,
    *,
    scan_id: str,
    evidence_id: str,
    run_id: str,
    features: list[dict[str, Any]],
    version: str | None,
    created_at: str,
) -> None:
    seen_ioc: set[tuple[str, str]] = set()
    ioc_n = 0
    finding_n = 0
    per_type: dict[str, int] = {}
    ioc_per_kind: dict[str, int] = {}
    for feat in features:
        ioc_type = str(feat.get("ioc_type") or "feature")
        value = str(feat.get("value") or "")
        if not value:
            continue
        quota = kind_for_scanner(str(feat.get("scanner") or ioc_type)).ioc_quota
        key = (ioc_type, value.lower())
        if key not in seen_ioc and ioc_n < MAX_IOCS and ioc_per_kind.get(ioc_type, 0) < quota:
            seen_ioc.add(key)
            extra = feat.get("extra") if isinstance(feat.get("extra"), dict) else {}
            count = feat.get("count") or 1
            context = (
                f"bulk_extractor scanner {feat.get('scanner')} "
                f"({feat.get('source_file')}) offset {feat.get('offset')}"
                f" ×{count}"
            )
            if extra.get("note"):
                context = f"{context}; {extra.get('note')}"
            db.execute(
                """
                INSERT INTO iocs (
                  id, evidence_id, process_id, pid, ioc_type, value, context, source, created_at
                ) VALUES (?, ?, NULL, NULL, ?, ?, ?, 'bulk_extractor', ?)
                """,
                (str(uuid4()), evidence_id, ioc_type, value[:4000], context, created_at),
            )
            ioc_n += 1
            ioc_per_kind[ioc_type] = ioc_per_kind.get(ioc_type, 0) + 1
        ftype = str(feat.get("finding_type") or ioc_type)
        if per_type.get(ftype, 0) >= MAX_FINDINGS_PER_TYPE or finding_n >= MAX_FINDINGS:
            continue
        per_type[ftype] = per_type.get(ftype, 0) + 1
        finding_n += 1
        explanation = (
            f"{ftype.replace('_', ' ')} discovered by bulk_extractor "
            f"(scanner {feat.get('scanner')}, file {feat.get('source_file')}). "
            "This is an extracted artifact / IOC candidate, not a confirmed malicious indicator."
        )
        db.execute(
            """
            INSERT INTO findings (
              id, evidence_id, analysis_run_id, process_id, pid, finding_type,
              severity, explanation, field_name, field_value, plugin, confidence, created_at
            ) VALUES (?, ?, ?, NULL, NULL, ?, 'info', ?, ?, ?, 'provider.bulk_extractor', 'extracted', ?)
            """,
            (
                str(uuid4()),
                evidence_id,
                run_id,
                ftype,
                explanation,
                "feature",
                value[:4000],
                created_at,
            ),
        )


def _table_exists(db: Database, name: str) -> bool:
    row = db.fetchone(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
        (name,),
    )
    return bool(row)


def _feature_dto(row: dict[str, Any]) -> dict[str, Any]:
    try:
        extra = json.loads(row.get("extra_json") or "{}")
    except json.JSONDecodeError:
        extra = {}
    return {
        "id": row["id"],
        "scan_id": row.get("scan_id"),
        "evidence_id": row.get("evidence_id"),
        "scanner": row.get("scanner"),
        "category": row.get("category"),
        "ioc_type": row.get("ioc_type"),
        "finding_type": row.get("finding_type"),
        "offset": row.get("offset"),
        "value": row.get("value"),
        "context": row.get("context"),
        "count": row.get("occurrence_count") or 1,
        "extra": extra if isinstance(extra, dict) else {},
        "created_at": row.get("created_at"),
    }


def _categories_from_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        cid = str(row.get("category") or "other")
        meta = CATEGORY_META.get(cid) or {
            "label": cid.replace("_", " "),
            "description": "",
        }
        rec = by_id.setdefault(
            cid,
            {
                "id": cid,
                "label": meta["label"],
                "description": meta["description"],
                "unique_count": 0,
                "row_count": 0,
                "scanners": [],
                "columns": kind_for_scanner(str(row.get("scanner") or cid)).columns,
            },
        )
        rec["unique_count"] += 1
        try:
            rec["row_count"] += int(row.get("occurrence_count") or 1)
        except (TypeError, ValueError):
            rec["row_count"] += 1
        scanner = row.get("scanner")
        if scanner and scanner not in rec["scanners"]:
            rec["scanners"].append(scanner)
    from memscope_engine.providers.bulk_extractor_features import CATEGORY_ORDER

    ordered = [by_id[cid] for cid in CATEGORY_ORDER if cid in by_id]
    extra = [by_id[cid] for cid in by_id if cid not in CATEGORY_ORDER]
    return ordered + extra


def _backfill_features(db: Database, scan: dict[str, Any]) -> None:
    if not _table_exists(db, "bulk_extractor_features"):
        return
    output_dir = Path(str(scan.get("output_dir") or ""))
    if not output_dir.is_dir():
        return
    normalized = normalize_bulk_extractor_output(
        output_dir,
        bulk_extractor_version=scan.get("bulk_extractor_version"),
        exit_code=scan.get("exit_code"),
        stdout="",
        stderr="",
    )
    _insert_features(
        db,
        scan_id=str(scan["id"]),
        evidence_id=str(scan.get("evidence_id") or ""),
        features=normalized.get("features") or [],
        created_at=str(scan.get("finished_at") or scan.get("started_at") or _utcnow()),
    )
    observed = scan.get("observed") if isinstance(scan.get("observed"), dict) else {}
    if not observed:
        try:
            raw = db.fetchone(
                "SELECT observed_json FROM bulk_extractor_scans WHERE id = ?",
                (scan["id"],),
            )
            if raw and raw.get("observed_json"):
                observed = json.loads(raw["observed_json"])
        except json.JSONDecodeError:
            observed = {}
    if isinstance(observed, dict):
        observed["categories"] = normalized.get("categories") or observed.get("categories")
        observed["feature_count"] = normalized.get("feature_count") or observed.get("feature_count")
        db.execute(
            "UPDATE bulk_extractor_scans SET observed_json = ?, feature_count = ? WHERE id = ?",
            (
                json.dumps(observed),
                int(normalized.get("feature_count") or 0),
                scan["id"],
            ),
        )


def list_bulk_extractor_features(
    db: Database,
    scan_id: str,
    *,
    category: str | None = None,
    scanner: str | None = None,
    q: str | None = None,
    hide_weak: bool = False,
    limit: int = 500,
    offset: int = 0,
) -> dict[str, Any]:
    bundle = get_bulk_extractor_scan(db, scan_id)
    scan = bundle["scan"]
    if not _table_exists(db, "bulk_extractor_features"):
        return {
            "scan_id": scan_id,
            "categories": (scan.get("observed") or {}).get("categories") or [],
            "items": [],
            "total": 0,
            "limit": limit,
            "offset": offset,
        }
    existing = db.fetchone(
        "SELECT COUNT(*) AS c FROM bulk_extractor_features WHERE scan_id = ?",
        (scan_id,),
    )
    if int((existing or {}).get("c") or 0) == 0 and scan.get("status") == "completed":
        _backfill_features(db, scan)
        bundle = get_bulk_extractor_scan(db, scan_id)
        scan = bundle["scan"]

    where = ["scan_id = ?"]
    params: list[Any] = [scan_id]
    if category:
        where.append("category = ?")
        params.append(category)
    if scanner:
        where.append("scanner = ?")
        params.append(scanner)
    if q and q.strip():
        where.append("(value LIKE ? OR IFNULL(context, '') LIKE ?)")
        like = f"%{q.strip()}%"
        params.extend([like, like])
    if hide_weak:
        where.append("IFNULL(json_extract(extra_json, '$.weak'), 0) = 0")
    clause = " AND ".join(where)
    rows = db.fetchall(
        f"""
        SELECT * FROM bulk_extractor_features
        WHERE {clause}
        ORDER BY occurrence_count DESC, value
        LIMIT ? OFFSET ?
        """,
        (*params, min(max(1, int(limit)), MAX_FEATURE_QUERY), max(0, int(offset))),
    )
    total_row = db.fetchone(
        f"SELECT COUNT(*) AS c FROM bulk_extractor_features WHERE {clause}",
        tuple(params),
    )
    items = [_feature_dto(r) for r in rows]
    cat_rows = db.fetchall(
        """
        SELECT category, scanner, occurrence_count
        FROM bulk_extractor_features WHERE scan_id = ?
        """,
        (scan_id,),
    )
    observed_cats = (scan.get("observed") or {}).get("categories") if isinstance(scan.get("observed"), dict) else None
    categories = observed_cats if isinstance(observed_cats, list) and observed_cats else _categories_from_rows(
        [
            {
                "category": r["category"],
                "scanner": r["scanner"],
                "occurrence_count": r["occurrence_count"],
            }
            for r in cat_rows
        ]
    )
    return {
        "scan_id": scan_id,
        "evidence_id": scan.get("evidence_id"),
        "categories": categories,
        "category": category,
        "scanner": scanner,
        "items": items,
        "total": int((total_row or {}).get("c") or 0),
        "shown": len(items),
        "limit": min(max(1, int(limit)), MAX_FEATURE_QUERY),
        "offset": max(0, int(offset)),
        "hide_weak": hide_weak,
        "note": (
            "Extracted strings / IOC candidates from bulk_extractor. "
            "Not confirmed malicious indicators."
        ),
    }


def get_bulk_extractor_scan(db: Database, scan_id: str) -> dict[str, Any]:
    row = db.fetchone("SELECT * FROM bulk_extractor_scans WHERE id = ?", (scan_id,))
    if not row:
        raise AppError(
            code="bulk_extractor_scan_missing",
            message="bulk_extractor scan not found.",
            entity="bulk_extractor",
        )
    outputs = db.fetchall(
        "SELECT * FROM bulk_extractor_outputs WHERE scan_id = ? ORDER BY created_at",
        (scan_id,),
    )
    return {"scan": _scan_dto(row), "outputs": [_output_dto(o) for o in outputs]}


def list_bulk_extractor_scans(db: Database, evidence_id: str) -> dict[str, Any]:
    rows = db.fetchall(
        """
        SELECT * FROM bulk_extractor_scans WHERE evidence_id = ?
        ORDER BY started_at DESC LIMIT 50
        """,
        (evidence_id,),
    )
    items = []
    for r in rows:
        outputs = db.fetchall(
            "SELECT * FROM bulk_extractor_outputs WHERE scan_id = ? ORDER BY created_at",
            (r["id"],),
        )
        items.append({"scan": _scan_dto(r), "outputs": [_output_dto(o) for o in outputs]})
    return {"evidence_id": evidence_id, "total": len(items), "items": items}


def _scan_dto(row: dict[str, Any]) -> dict[str, Any]:
    def _j(key: str, default: Any) -> Any:
        raw = row.get(key)
        if not raw:
            return default
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return default

    err = None
    if row.get("error_json"):
        try:
            err = json.loads(row["error_json"])
        except json.JSONDecodeError:
            err = {"message": row["error_json"]}
    observed = _j("observed_json", {})
    feature_files = observed.get("feature_files") if isinstance(observed, dict) else []
    feature_counts: dict[str, int] = {}
    unique_counts: dict[str, int] = {}
    if isinstance(feature_files, list):
        for item in feature_files:
            if not isinstance(item, dict):
                continue
            scanner = item.get("scanner")
            if scanner:
                try:
                    feature_counts[str(scanner)] = int(item.get("row_count") or 0)
                except (TypeError, ValueError):
                    feature_counts[str(scanner)] = 0
                try:
                    unique_counts[str(scanner)] = int(
                        item.get("unique_count") or item.get("row_count") or 0
                    )
                except (TypeError, ValueError):
                    unique_counts[str(scanner)] = 0
    categories = observed.get("categories") if isinstance(observed, dict) else []
    return {
        "id": row["id"],
        "evidence_id": row["evidence_id"],
        "analysis_run_id": row.get("analysis_run_id"),
        "job_id": row.get("job_id"),
        "status": row["status"],
        "ui_state": row.get("ui_state"),
        "bulk_extractor_version": row.get("bulk_extractor_version"),
        "executable_path": row.get("executable_path"),
        "output_dir": row.get("output_dir"),
        "exit_code": row.get("exit_code"),
        "feature_count": row.get("feature_count") or 0,
        "feature_file_count": (observed.get("feature_file_count") if isinstance(observed, dict) else 0)
        or 0,
        "feature_counts": feature_counts,
        "unique_counts": unique_counts,
        "categories": categories if isinstance(categories, list) else [],
        "scanner_count": row.get("scanner_count") or 0,
        "invoked": bool(row.get("invoked")),
        "observed": observed,
        "interpretation": _j("interpretation_json", {}),
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
        "evidence_id": row.get("evidence_id"),
        "relative_path": row.get("relative_path"),
        "role": row.get("role"),
        "scanner": row.get("scanner"),
        "size_bytes": row.get("size_bytes"),
        "observed": observed,
        "created_at": row.get("created_at"),
    }
