"""Assemble a versioned investigation document from normalized MemScope data."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from memscope_engine import __version__ as MEMSCOPE_VERSION
from memscope_engine.analysis import (
    mal_unpack_workflows,
    memory_artifacts,
    pe_sieve_workflows,
    process_analysis,
    search_iocs,
    workflows,
    yara_workflows,
)
from memscope_engine.errors import AppError
from memscope_engine.export.constants import (
    ADVANCED_EXECUTION_LIMIT,
    CSV_MAX_ROWS,
    HTML_MAX_ROWS,
    JSON_MAX_ROWS,
    REPORT_FORMAT,
    REPORT_SCHEMA_VERSION,
    REPORT_SECTIONS,
)
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION

ProgressFn = Callable[[str], None]
CancelFn = Callable[[], bool]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _table_exists(db: Database, name: str) -> bool:
    row = db.fetchone(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
        (name,),
    )
    return row is not None


def _count(db: Database, table: str, evidence_id: str) -> int:
    if not _table_exists(db, table):
        return 0
    row = db.fetchone(
        f"SELECT COUNT(*) AS c FROM {table} WHERE evidence_id = ?",
        (evidence_id,),
    )
    return int(row["c"]) if row else 0


def _limit_for(fmt: str) -> int:
    if fmt == "html":
        return HTML_MAX_ROWS
    if fmt == "csv":
        return CSV_MAX_ROWS
    return JSON_MAX_ROWS


def _cap(items: list[Any], total: int, limit: int) -> dict[str, Any]:
    shown = items[:limit]
    truncated = total > len(shown) or len(items) > limit
    return {
        "total": total,
        "shown": len(shown),
        "truncated": truncated,
        "items": shown,
    }


def _parse_json(raw: Any, default: Any) -> Any:
    if raw is None or raw == "":
        return default
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return default


def normalize_sections(scope: str, sections: list[str] | None) -> list[str]:
    if scope == "complete" or not sections:
        return list(REPORT_SECTIONS)
    out: list[str] = []
    unknown: list[str] = []
    for s in sections:
        name = str(s).strip()
        if name not in REPORT_SECTIONS:
            unknown.append(name)
            continue
        if name not in out:
            out.append(name)
    if unknown:
        raise AppError(
            code="export_section_unknown",
            message="Unknown report section requested.",
            details=", ".join(unknown),
            entity="export",
        )
    if not out:
        raise AppError(
            code="export_section_empty",
            message="Select at least one report section.",
            entity="export",
        )
    # Metadata is always included so provenance and evidence identity remain.
    if "metadata" not in out:
        out.insert(0, "metadata")
    return out


def _volatility_version(db: Database, evidence_id: str) -> str | None:
    row = db.fetchone(
        """
        SELECT volatility_version FROM analysis_runs
        WHERE evidence_id = ? AND volatility_version IS NOT NULL
          AND TRIM(volatility_version) != ''
        ORDER BY started_at DESC LIMIT 1
        """,
        (evidence_id,),
    )
    if row and row.get("volatility_version"):
        return str(row["volatility_version"])
    try:
        from memscope_engine.volatility.discovery import volatility_version

        return volatility_version()
    except Exception:  # noqa: BLE001
        return None


def _parent_map(processes: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    by_pid: dict[int, dict[str, Any]] = {}
    for p in processes:
        pid = p.get("pid")
        if isinstance(pid, int):
            by_pid.setdefault(pid, p)
    return by_pid


def _attach_process_tree(processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_pid = _parent_map(processes)
    children: dict[int, list[int]] = {}
    for p in processes:
        pid = p.get("pid")
        ppid = p.get("ppid")
        if isinstance(pid, int) and isinstance(ppid, int):
            children.setdefault(ppid, []).append(pid)
    out = []
    for p in processes:
        row = dict(p)
        pid = p.get("pid")
        ppid = p.get("ppid")
        parent = by_pid.get(ppid) if isinstance(ppid, int) else None
        row["parent"] = (
            {"pid": parent["pid"], "name": parent.get("name"), "process_id": parent.get("id")}
            if parent
            else ({"pid": ppid, "name": None, "process_id": None} if ppid is not None else None)
        )
        row["child_pids"] = children.get(pid, []) if isinstance(pid, int) else []
        out.append(row)
    return out


def _findings_by_pid(findings: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    grouped: dict[int, list[dict[str, Any]]] = {}
    for f in findings:
        pid = f.get("pid")
        if isinstance(pid, int):
            grouped.setdefault(pid, []).append(f)
    return grouped


def _compact_finding(f: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f.get("id"),
        "title": f.get("finding_type"),
        "severity": f.get("severity"),
        "explanation": f.get("explanation"),
        "plugin": f.get("plugin"),
        "pid": f.get("pid"),
        "process_id": f.get("process_id"),
        "field_name": f.get("field_name"),
        "field_value": f.get("field_value"),
        "confidence": f.get("confidence"),
        "created_at": f.get("created_at"),
        "evidence_id": f.get("evidence_id"),
    }


def _collect_advanced(db: Database, evidence_id: str) -> dict[str, Any]:
    if not _table_exists(db, "plugin_executions"):
        return _cap([], 0, ADVANCED_EXECUTION_LIMIT)
    rows = db.fetchall(
        """
        SELECT pe.*, ar.kind AS run_kind, ar.status AS run_status,
               ar.volatility_version AS run_volatility_version
        FROM plugin_executions pe
        JOIN analysis_runs ar ON ar.id = pe.analysis_run_id
        WHERE pe.evidence_id = ? AND ar.kind = 'plugin_advanced'
        ORDER BY pe.started_at DESC
        LIMIT ?
        """,
        (evidence_id, ADVANCED_EXECUTION_LIMIT + 1),
    )
    total = _count(db, "plugin_executions", evidence_id)
    # Count only advanced runs when possible
    adv = db.fetchone(
        """
        SELECT COUNT(*) AS c FROM plugin_executions pe
        JOIN analysis_runs ar ON ar.id = pe.analysis_run_id
        WHERE pe.evidence_id = ? AND ar.kind = 'plugin_advanced'
        """,
        (evidence_id,),
    )
    if adv:
        total = int(adv["c"])
    items = []
    for row in rows[:ADVANCED_EXECUTION_LIMIT]:
        result_row = None
        if _table_exists(db, "plugin_results"):
            result_row = db.fetchone(
                """
                SELECT row_count, columns_json, from_cache, plugin_id
                FROM plugin_results
                WHERE plugin_execution_id = ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (row["id"],),
            )
        columns = _parse_json(result_row["columns_json"] if result_row else "[]", [])
        err = _parse_json(row.get("error_json"), None)
        items.append(
            {
                "id": row["id"],
                "analysis_run_id": row["analysis_run_id"],
                "plugin": row.get("plugin_id") or row.get("plugin"),
                "parameters": _parse_json(row.get("parameters_json"), {}),
                "status": row["status"],
                "cache_hit": bool(row.get("cache_hit")),
                "row_count": (result_row or {}).get("row_count")
                if result_row
                else row.get("row_count"),
                "started_at": row.get("started_at"),
                "finished_at": row.get("finished_at"),
                "error": err,
                "volatility_version": row.get("run_volatility_version"),
                "result_summary": {
                    "row_count": (result_row or {}).get("row_count")
                    if result_row
                    else row.get("row_count") or 0,
                    "column_count": len(columns) if isinstance(columns, list) else 0,
                    "columns": columns[:40] if isinstance(columns, list) else [],
                    "from_cache": bool(result_row.get("from_cache")) if result_row else bool(row.get("cache_hit")),
                    "raw_output_omitted": True,
                },
            }
        )
    return _cap(items, total, ADVANCED_EXECUTION_LIMIT)


def _collect_malware(db: Database, evidence_id: str, limit: int) -> dict[str, Any]:
    yara_matches = {"total": 0, "shown": 0, "truncated": False, "items": []}
    yara_scans: list[dict[str, Any]] = []
    if _table_exists(db, "yara_matches"):
        listed = yara_workflows.list_yara_matches_for_evidence(db, evidence_id)
        yara_matches = _cap(listed["items"], listed["total"], limit)
    if _table_exists(db, "yara_scans"):
        scan_rows = db.fetchall(
            "SELECT * FROM yara_scans WHERE evidence_id = ? ORDER BY started_at DESC LIMIT ?",
            (evidence_id, min(limit, 500)),
        )
        yara_scans = [yara_workflows._scan_dto(r) for r in scan_rows]

    pe_items: list[dict[str, Any]] = []
    if _table_exists(db, "pe_sieve_scans"):
        rows = db.fetchall(
            "SELECT * FROM pe_sieve_scans WHERE evidence_id = ? ORDER BY started_at DESC LIMIT ?",
            (evidence_id, min(limit, 500)),
        )
        for r in rows:
            pe_items.append(
                {
                    "scan": pe_sieve_workflows._scan_dto(r),
                    "observation_kind": "tool_observed_and_memscope_interpretation",
                }
            )

    mu_items: list[dict[str, Any]] = []
    if _table_exists(db, "mal_unpack_scans"):
        rows = db.fetchall(
            "SELECT * FROM mal_unpack_scans WHERE evidence_id = ? ORDER BY started_at DESC LIMIT ?",
            (evidence_id, min(limit, 500)),
        )
        for r in rows:
            mu_items.append(
                {
                    "scan": mal_unpack_workflows._scan_dto(r),
                    "observation_kind": "tool_observed_and_memscope_interpretation",
                }
            )

    return {
        "yara_matches": yara_matches,
        "yara_scans": {
            "total": len(yara_scans),
            "shown": len(yara_scans),
            "truncated": False,
            "items": yara_scans,
        },
        "pe_sieve": {
            "total": len(pe_items),
            "shown": len(pe_items),
            "truncated": False,
            "items": pe_items,
            "note": "observed is tool output; interpretation is MemScope commentary, not a score.",
        },
        "mal_unpack": {
            "total": len(mu_items),
            "shown": len(mu_items),
            "truncated": False,
            "items": mu_items,
            "note": "observed is tool output; interpretation is MemScope commentary, not a score.",
        },
    }


def collect_investigation(
    db: Database,
    evidence_id: str,
    *,
    fmt: str,
    sections: list[str],
    cancelled: CancelFn | None = None,
    progress: ProgressFn | None = None,
) -> dict[str, Any]:
    evidence = workflows.get_evidence(db, evidence_id)
    limit = _limit_for(fmt)
    vol_ver = _volatility_version(db, evidence_id)

    def _check() -> None:
        if cancelled and cancelled():
            raise AppError(code="export_cancelled", message="Export cancelled.", entity="export")

    def _prog(msg: str) -> None:
        if progress:
            progress(msg)

    generated_at = _utcnow()
    doc: dict[str, Any] = {
        "format": REPORT_FORMAT,
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "analysis_schema_version": SCHEMA_VERSION,
        "memscope_version": MEMSCOPE_VERSION,
        "generated_at": generated_at,
        "sections_included": list(sections),
        "provenance": {
            "chain": [
                "evidence",
                "analysis_run",
                "plugin_execution",
                "entity_or_artifact",
                "finding_or_ioc_or_timeline",
            ],
            "note": (
                "Inferred timeline events are labeled classification=inferred. "
                "They are MemScope reconstructions and are not presented as directly observed evidence."
            ),
        },
    }

    findings_all: list[dict[str, Any]] = []
    if "findings" in sections or "processes" in sections or "network" in sections or "modules" in sections:
        _prog("Collecting findings")
        _check()
        listed = process_analysis.list_findings(db, evidence_id)
        findings_all = listed["items"]

    if "metadata" in sections:
        doc["metadata"] = {
            "memscope_version": MEMSCOPE_VERSION,
            "generated_at": generated_at,
            "evidence_id": evidence["id"],
            "evidence_filename": evidence.get("filename"),
            "evidence_sha256": evidence.get("sha256"),
            "evidence_size_bytes": evidence.get("size_bytes"),
            "evidence_path": evidence.get("path"),
            "detected_os": evidence.get("detected_os"),
            "architecture": evidence.get("architecture"),
            "symbol_status": evidence.get("symbol_status"),
            "symbol_detail": evidence.get("symbol_detail"),
            "import_status": evidence.get("import_status"),
            "import_timestamp": evidence.get("import_timestamp"),
            "volatility_compatible": evidence.get("volatility_compatible"),
            "evidence_metadata": evidence.get("metadata") or {},
            "volatility_version": vol_ver,
            "analysis_schema_version": SCHEMA_VERSION,
            "report_schema_version": REPORT_SCHEMA_VERSION,
        }

    processes_payload = None
    if "processes" in sections or "summary" in sections:
        _prog("Collecting processes")
        _check()
        listed = workflows.list_processes(db, evidence_id, limit=limit, offset=0)
        tree = _attach_process_tree(listed["items"])
        by_pid = _findings_by_pid(findings_all)
        for p in tree:
            pid = p.get("pid")
            rel = by_pid.get(pid, []) if isinstance(pid, int) else []
            p["relevant_findings"] = [_compact_finding(f) for f in rel[:25]]
        processes_payload = _cap(tree, listed["total"], limit)
        if "processes" in sections:
            doc["processes"] = processes_payload

    if "findings" in sections:
        _prog("Collecting findings")
        _check()
        compact = [_compact_finding(f) for f in findings_all]
        total = len(findings_all)
        if _table_exists(db, "findings"):
            total = _count(db, "findings", evidence_id)
        doc["findings"] = _cap(compact, total, limit)

    if "network" in sections:
        _prog("Collecting network")
        _check()
        listed = process_analysis.list_network(db, evidence_id)
        by_pid = _findings_by_pid(findings_all)
        items = []
        for n in listed["items"][:limit]:
            row = dict(n)
            pid = n.get("pid")
            row["relevant_findings"] = [
                _compact_finding(f) for f in (by_pid.get(pid, []) if isinstance(pid, int) else [])[:10]
            ]
            items.append(row)
        doc["network"] = _cap(items, listed["total"], limit)

    if "modules" in sections:
        _prog("Collecting modules")
        _check()
        listed = process_analysis.list_modules(db, evidence_id)
        by_pid = _findings_by_pid(findings_all)
        items = []
        for m in listed["items"][:limit]:
            row = dict(m)
            pid = m.get("pid")
            row["relevant_findings"] = [
                _compact_finding(f) for f in (by_pid.get(pid, []) if isinstance(pid, int) else [])[:10]
            ]
            items.append(row)
        total = listed["total"]
        if _table_exists(db, "modules"):
            total = _count(db, "modules", evidence_id)
        doc["modules"] = _cap(items, total, limit)

    if "memory" in sections:
        _prog("Collecting memory regions")
        _check()
        listed = memory_artifacts.list_memory_regions(db, evidence_id, limit=limit, offset=0)
        items = []
        for r in listed["items"]:
            row = dict(r)
            row["indicators"] = r.get("indicators") or []
            items.append(row)
        doc["memory"] = _cap(items, listed["total"], limit)

    if "timeline" in sections:
        _prog("Collecting timeline")
        _check()
        listed = memory_artifacts.list_timeline(db, evidence_id, limit=limit)
        observed = sum(1 for e in listed["items"] if e.get("classification") == "observed")
        inferred = sum(1 for e in listed["items"] if e.get("classification") == "inferred")
        payload = _cap(listed["items"], listed["total"], limit)
        payload["observed_count"] = observed
        payload["inferred_count"] = inferred
        doc["timeline"] = payload

    if "iocs" in sections:
        _prog("Collecting IOCs")
        _check()
        listed = search_iocs.list_iocs(db, evidence_id)
        payload = _cap(listed["items"], listed["total"], limit)
        by_type: dict[str, int] = {}
        for i in listed["items"]:
            t = str(i.get("ioc_type") or "other")
            by_type[t] = by_type.get(t, 0) + 1
        payload["by_type"] = by_type
        doc["iocs"] = payload

    if "artifacts" in sections:
        _prog("Collecting artifacts")
        _check()
        listed = memory_artifacts.list_artifacts(db, evidence_id)
        items = []
        for a in listed["items"][:limit]:
            row = dict(a)
            row["provenance"] = {
                "evidence_id": a.get("evidence_id"),
                "process_id": a.get("process_id"),
                "pid": a.get("pid"),
                "memory_region_id": a.get("memory_region_id"),
                "parent_artifact_id": a.get("parent_artifact_id"),
                "extraction_method": a.get("extraction_method"),
                "source_plugin": a.get("source_plugin"),
                "tool_name": a.get("tool_name"),
                "tool_version": a.get("tool_version"),
            }
            items.append(row)
        doc["artifacts"] = _cap(items, listed["total"], limit)

    if "malware" in sections:
        _prog("Collecting malware-analysis results")
        _check()
        doc["malware"] = _collect_malware(db, evidence_id, limit)

    if "advanced" in sections:
        _prog("Collecting Advanced Volatility executions")
        _check()
        doc["advanced"] = _collect_advanced(db, evidence_id)

    if "summary" in sections:
        _prog("Building executive summary")
        proc_total = processes_payload["total"] if processes_payload else _count(db, "processes", evidence_id)
        yara_n = _count(db, "yara_matches", evidence_id) if _table_exists(db, "yara_matches") else 0
        pe_n = _count(db, "pe_sieve_scans", evidence_id) if _table_exists(db, "pe_sieve_scans") else 0
        mu_n = _count(db, "mal_unpack_scans", evidence_id) if _table_exists(db, "mal_unpack_scans") else 0
        adv_n = 0
        if _table_exists(db, "plugin_executions"):
            adv = db.fetchone(
                """
                SELECT COUNT(*) AS c FROM plugin_executions pe
                JOIN analysis_runs ar ON ar.id = pe.analysis_run_id
                WHERE pe.evidence_id = ? AND ar.kind = 'plugin_advanced'
                """,
                (evidence_id,),
            )
            adv_n = int(adv["c"]) if adv else 0
        finding_n = _count(db, "findings", evidence_id)
        doc["summary"] = {
            "text": (
                f"Investigation of {evidence.get('filename') or 'unnamed evidence'} "
                f"(SHA-256 {evidence.get('sha256')}). "
                f"{proc_total} process(es), {finding_n} finding(s), "
                f"{_count(db, 'network_connections', evidence_id)} network connection(s), "
                f"{_count(db, 'artifacts', evidence_id)} artifact(s), "
                f"{_count(db, 'iocs', evidence_id) if _table_exists(db, 'iocs') else 0} IOC(s)."
            ),
            "process_count": proc_total,
            "finding_count": finding_n,
            "network_count": _count(db, "network_connections", evidence_id),
            "module_count": _count(db, "modules", evidence_id),
            "memory_region_count": _count(db, "memory_regions", evidence_id)
            if _table_exists(db, "memory_regions")
            else 0,
            "timeline_event_count": _count(db, "timeline_events", evidence_id)
            if _table_exists(db, "timeline_events")
            else 0,
            "artifact_count": _count(db, "artifacts", evidence_id)
            if _table_exists(db, "artifacts")
            else 0,
            "ioc_count": _count(db, "iocs", evidence_id) if _table_exists(db, "iocs") else 0,
            "yara_match_count": yara_n,
            "pe_sieve_scan_count": pe_n,
            "mal_unpack_scan_count": mu_n,
            "advanced_execution_count": adv_n,
            "no_risk_score": True,
        }

    any_trunc = False
    for key in (
        "findings",
        "processes",
        "network",
        "modules",
        "memory",
        "timeline",
        "iocs",
        "artifacts",
        "advanced",
    ):
        block = doc.get(key)
        if isinstance(block, dict) and block.get("truncated"):
            any_trunc = True
    malware = doc.get("malware")
    if isinstance(malware, dict):
        for sub in malware.values():
            if isinstance(sub, dict) and sub.get("truncated"):
                any_trunc = True
    doc["truncated"] = any_trunc
    return doc
