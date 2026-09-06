"""Deterministic CSV writers for tabular forensic datasets."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from memscope_engine.export.constants import CSV_DATASETS, SECTION_TO_CSV

CSV_COLUMNS: dict[str, tuple[str, ...]] = {
    "processes": (
        "id",
        "pid",
        "ppid",
        "name",
        "image_path",
        "command_line",
        "username",
        "parent_pid",
        "parent_name",
        "child_pids",
        "source_plugin",
        "analysis_run_id",
        "evidence_id",
    ),
    "network": (
        "id",
        "pid",
        "process_id",
        "protocol",
        "local_address",
        "local_port",
        "remote_address",
        "remote_port",
        "state",
        "owner",
        "source_plugin",
        "evidence_id",
    ),
    "modules": (
        "id",
        "pid",
        "process_id",
        "name",
        "path",
        "base_address",
        "size",
        "load_count",
        "load_time",
        "source_plugin",
        "evidence_id",
    ),
    "vad": (
        "id",
        "pid",
        "process_name",
        "start_vpn",
        "end_vpn",
        "size_bytes",
        "protection",
        "tag",
        "file_path",
        "indicator_codes",
        "source_plugin",
        "analysis_run_id",
        "evidence_id",
    ),
    "findings": (
        "id",
        "title",
        "severity",
        "explanation",
        "plugin",
        "pid",
        "process_id",
        "field_name",
        "field_value",
        "confidence",
        "created_at",
        "evidence_id",
    ),
    "iocs": (
        "id",
        "ioc_type",
        "value",
        "pid",
        "process_id",
        "context",
        "source",
        "created_at",
        "evidence_id",
    ),
    "timeline": (
        "id",
        "event_time",
        "time_precision",
        "classification",
        "event_kind",
        "summary",
        "pid",
        "process_id",
        "related_entity_type",
        "related_entity_id",
        "source_plugin",
        "source_table",
        "evidence_id",
    ),
    "artifacts": (
        "id",
        "filename",
        "sha256",
        "size_bytes",
        "file_type",
        "extraction_method",
        "pid",
        "process_id",
        "memory_region_id",
        "parent_artifact_id",
        "source_plugin",
        "tool_name",
        "tool_version",
        "source_address",
        "extracted_at",
        "evidence_id",
    ),
}


def csv_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return str(value)


def _process_row(item: dict[str, Any]) -> dict[str, Any]:
    parent = item.get("parent") or {}
    return {
        **item,
        "parent_pid": parent.get("pid") if isinstance(parent, dict) else None,
        "parent_name": parent.get("name") if isinstance(parent, dict) else None,
        "child_pids": item.get("child_pids") or [],
    }


def _vad_row(item: dict[str, Any]) -> dict[str, Any]:
    indicators = item.get("indicators") or []
    codes = []
    if isinstance(indicators, list):
        for i in indicators:
            if isinstance(i, dict) and i.get("code"):
                codes.append(i["code"])
            elif isinstance(i, str):
                codes.append(i)
    return {**item, "indicator_codes": codes}


def dataset_rows(doc: dict[str, Any], dataset: str) -> list[dict[str, Any]]:
    if dataset == "processes":
        return [_process_row(i) for i in (doc.get("processes") or {}).get("items") or []]
    if dataset == "network":
        return list((doc.get("network") or {}).get("items") or [])
    if dataset == "modules":
        return list((doc.get("modules") or {}).get("items") or [])
    if dataset == "vad":
        return [_vad_row(i) for i in (doc.get("memory") or {}).get("items") or []]
    if dataset == "findings":
        return list((doc.get("findings") or {}).get("items") or [])
    if dataset == "iocs":
        return list((doc.get("iocs") or {}).get("items") or [])
    if dataset == "timeline":
        return list((doc.get("timeline") or {}).get("items") or [])
    if dataset == "artifacts":
        return list((doc.get("artifacts") or {}).get("items") or [])
    return []


def write_csv_file(path: Path, dataset: str, rows: list[dict[str, Any]]) -> int:
    columns = CSV_COLUMNS[dataset]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        writer.writerow(columns)
        for row in rows:
            writer.writerow([csv_cell(row.get(col)) for col in columns])
    return path.stat().st_size


def datasets_for_sections(sections: list[str], *, scope: str) -> list[str]:
    if scope == "complete":
        return list(CSV_DATASETS)
    out: list[str] = []
    for section in sections:
        ds = SECTION_TO_CSV.get(section)
        if ds and ds not in out:
            out.append(ds)
    return out
