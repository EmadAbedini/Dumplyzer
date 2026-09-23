"""Assemble a versioned investigation document from normalized Dumplyzer data."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from memscope_engine import __version__ as MEMSCOPE_VERSION
from memscope_engine.analysis import (
    bulk_extractor_workflows,
    capa_workflows,
    floss_workflows,
    memory_artifacts,
    network_artifacts,
    pcap_reconstruction,
    pe_extraction_workflows,
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
from memscope_engine.export.shape import coerce_sections, shape_investigation
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
    if fmt in {"csv", "xlsx"}:
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
    requested = coerce_sections(sections)
    if scope == "complete" or not requested:
        return list(REPORT_SECTIONS)
    out: list[str] = []
    unknown: list[str] = []
    for name in requested:
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
    if _table_exists(db, "pe_extraction_runs"):
        rows = db.fetchall(
            "SELECT * FROM pe_extraction_runs WHERE evidence_id = ? ORDER BY started_at DESC LIMIT ?",
            (evidence_id, min(limit, 500)),
        )
        for r in rows:
            pe_items.append(
                {
                    "run": pe_extraction_workflows._run_dto(r),
                    "observation_kind": "extracted_pe_artifact",
                }
            )

    capa_items: list[dict[str, Any]] = []
    if _table_exists(db, "capa_scans"):
        rows = db.fetchall(
            "SELECT * FROM capa_scans WHERE evidence_id = ? ORDER BY started_at DESC LIMIT ?",
            (evidence_id, min(limit, 500)),
        )
        for r in rows:
            capa_items.append(
                {
                    "scan": capa_workflows._scan_dto(r),
                    "observation_kind": "capability",
                }
            )

    floss_items: list[dict[str, Any]] = []
    if _table_exists(db, "floss_scans"):
        rows = db.fetchall(
            "SELECT * FROM floss_scans WHERE evidence_id = ? ORDER BY started_at DESC LIMIT ?",
            (evidence_id, min(limit, 500)),
        )
        for r in rows:
            floss_items.append(
                {
                    "scan": floss_workflows._scan_dto(r),
                    "observation_kind": "extracted_string",
                }
            )

    be_items: list[dict[str, Any]] = []
    if _table_exists(db, "bulk_extractor_scans"):
        rows = db.fetchall(
            "SELECT * FROM bulk_extractor_scans WHERE evidence_id = ? ORDER BY started_at DESC LIMIT ?",
            (evidence_id, min(limit, 500)),
        )
        for r in rows:
            scan = bulk_extractor_workflows._scan_dto(r)
            samples: dict[str, list[dict[str, Any]]] = {}
            if _table_exists(db, "bulk_extractor_features"):
                feat_rows = db.fetchall(
                    """
                    SELECT category, scanner, value, offset, occurrence_count, extra_json
                    FROM bulk_extractor_features
                    WHERE scan_id = ?
                    ORDER BY occurrence_count DESC, value
                    LIMIT 400
                    """,
                    (r["id"],),
                )
                for feat in feat_rows:
                    cid = str(feat.get("category") or "other")
                    bucket = samples.setdefault(cid, [])
                    if len(bucket) >= 25:
                        continue
                    extra = {}
                    try:
                        extra = json.loads(feat.get("extra_json") or "{}")
                    except json.JSONDecodeError:
                        extra = {}
                    bucket.append(
                        {
                            "scanner": feat.get("scanner"),
                            "value": feat.get("value"),
                            "offset": feat.get("offset"),
                            "count": feat.get("occurrence_count") or 1,
                            "extra": extra,
                        }
                    )
            be_items.append(
                {
                    "scan": scan,
                    "observation_kind": "extracted_artifact",
                    "categories": scan.get("categories") or [],
                    "samples": samples,
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
        "pe_extraction": {
            "total": len(pe_items),
            "shown": len(pe_items),
            "truncated": False,
            "items": pe_items,
            "note": (
                "Extracted PE artifacts reconstructed from the memory dump. "
                "Not a malware verdict."
            ),
        },
        "capa": {
            "total": len(capa_items),
            "shown": len(capa_items),
            "truncated": False,
            "items": capa_items,
            "note": "Capability analysis results are static observations, not confirmed malware.",
        },
        "floss": {
            "total": len(floss_items),
            "shown": len(floss_items),
            "truncated": False,
            "items": floss_items,
            "note": "Extracted and deobfuscated strings are not malicious findings.",
        },
        "bulk_extractor": {
            "total": len(be_items),
            "shown": len(be_items),
            "truncated": False,
            "items": be_items,
            "note": (
                "Source: carved memory features. Type: Extracted Artifact / IOC Candidate. "
                "Raw feature files are preserved. Strings are not confirmed malicious indicators."
            ),
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

    names: dict[int, str] = {}
    for row in db.fetchall(
        """
        SELECT pid, name FROM processes
        WHERE evidence_id = ? AND name IS NOT NULL AND TRIM(name) != ''
        """,
        (evidence_id,),
    ):
        try:
            names[int(row["pid"])] = str(row["name"])
        except (TypeError, ValueError):
            continue

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
                "They are Dumplyzer reconstructions and are not presented as directly observed evidence."
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
        if _table_exists(db, "network_artifacts"):
            harvested = network_artifacts.list_network_artifacts(db, evidence_id, limit=limit)
            artifact_items = []
            for a in harvested.get("items") or []:
                artifact_items.append(
                    {
                        "artifact_type": a.get("artifact_type"),
                        "value": a.get("value"),
                        "pid": a.get("pid"),
                        "process_name": a.get("process_name"),
                        "protocol": a.get("protocol"),
                        "local_address": a.get("local_address"),
                        "local_port": a.get("local_port"),
                        "remote_address": a.get("remote_address"),
                        "remote_port": a.get("remote_port"),
                        "source": a.get("source"),
                        "extraction_method": a.get("extraction_method"),
                        "source_plugin": a.get("source_plugin"),
                        "source_address": a.get("source_address") or a.get("offset_hex"),
                        "context": a.get("context"),
                    }
                )
            artifacts_block = _cap(artifact_items, harvested.get("total") or 0, limit)
            artifacts_block["type_counts"] = harvested.get("type_counts") or {}
            doc["network"]["artifacts"] = artifacts_block
            doc["network_artifacts"] = artifacts_block
        if _table_exists(db, "pcap_reconstructions"):
            pcap_list = pcap_reconstruction.list_pcap_reconstructions(db, evidence_id)
            latest = pcap_list.get("latest")
            recon = (latest or {}).get("reconstruction") if latest else None
            if recon:
                doc["network"]["pcap"] = {
                    "reconstruction_status": recon.get("reconstruction_status"),
                    "display_status": recon.get("display_status"),
                    "packet_count": recon.get("packet_count") or 0,
                    "truncated_count": recon.get("truncated_count") or 0,
                    "output_path": recon.get("output_path"),
                    "files": [
                        {k: f.get(k) for k in ("name", "kind", "packet_count", "size_bytes")}
                        for f in (recon.get("files") or [])
                        if isinstance(f, dict)
                    ],
                    "limitations": recon.get("limitations") or [],
                    "pcap_embedded": False,
                    "flows_with_packets": sum(
                        1
                        for flow in (latest.get("flows") or [])
                        if int((flow or {}).get("packet_count") or 0) > 0
                    ),
                    "metadata_only_flows": sum(
                        1
                        for flow in (latest.get("flows") or [])
                        if (flow or {}).get("status") == "metadata_only"
                    ),
                }

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
        pe_n = (
            _count(db, "pe_extraction_runs", evidence_id)
            if _table_exists(db, "pe_extraction_runs")
            else 0
        )
        capa_n = _count(db, "capa_scans", evidence_id) if _table_exists(db, "capa_scans") else 0
        floss_n = _count(db, "floss_scans", evidence_id) if _table_exists(db, "floss_scans") else 0
        be_n = (
            _count(db, "bulk_extractor_scans", evidence_id)
            if _table_exists(db, "bulk_extractor_scans")
            else 0
        )
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
        pcap_status = None
        pcap_path = None
        if _table_exists(db, "pcap_reconstructions"):
            latest = db.fetchone(
                """
                SELECT reconstruction_status, output_path, packet_count
                FROM pcap_reconstructions
                WHERE evidence_id = ? AND status = 'completed'
                ORDER BY started_at DESC LIMIT 1
                """,
                (evidence_id,),
            )
            if latest:
                pcap_status = latest.get("reconstruction_status")
                pcap_path = latest.get("output_path")
        doc["summary"] = {
            "text": (
                f"Investigation of {evidence.get('filename') or 'unnamed evidence'} "
                f"(SHA-256 {evidence.get('sha256')}). "
                f"{proc_total} process(es), {finding_n} finding(s), "
                f"{_count(db, 'network_connections', evidence_id)} network connection(s), "
                f"{_count(db, 'network_artifacts', evidence_id) if _table_exists(db, 'network_artifacts') else 0} network artifact(s), "
                f"{_count(db, 'artifacts', evidence_id)} artifact(s), "
                f"{_count(db, 'iocs', evidence_id) if _table_exists(db, 'iocs') else 0} IOC(s)."
            ),
            "process_count": proc_total,
            "finding_count": finding_n,
            "network_count": _count(db, "network_connections", evidence_id),
            "network_artifact_count": _count(db, "network_artifacts", evidence_id)
            if _table_exists(db, "network_artifacts")
            else 0,
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
            "pe_extraction_run_count": pe_n,
            "capa_scan_count": capa_n,
            "floss_scan_count": floss_n,
            "bulk_extractor_scan_count": be_n,
            "advanced_execution_count": adv_n,
            "pcap_reconstruction_status": pcap_status,
            "pcap_output_path": pcap_path,
            "pcap_embedded": False,
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
    return shape_investigation(doc, names=names)
