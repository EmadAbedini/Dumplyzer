"""Deterministic CSV writers for tabular forensic datasets."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from memscope_engine.export.constants import CSV_DATASETS, SECTION_TO_CSV

CSV_COLUMNS: dict[str, tuple[str, ...]] = {
    "processes": (
        "pid",
        "ppid",
        "name",
        "image_path",
        "command_line",
        "username",
        "create_time",
        "exit_time",
        "parent_pid",
        "parent_name",
        "child_pids",
        "threads",
        "handles",
        "session_id",
        "wow64",
        "source_plugin",
    ),
    "network": (
        "pid",
        "process_name",
        "protocol",
        "local_address",
        "local_port",
        "remote_address",
        "remote_port",
        "state",
        "owner",
        "source_plugin",
    ),
    "network_artifacts": (
        "artifact_type",
        "value",
        "pid",
        "process_name",
        "protocol",
        "local_address",
        "local_port",
        "remote_address",
        "remote_port",
        "source",
        "extraction_method",
        "source_plugin",
        "source_address",
        "context",
    ),
    "modules": (
        "pid",
        "process_name",
        "name",
        "path",
        "base_address",
        "size",
        "load_time",
        "source_plugin",
    ),
    "vad": (
        "pid",
        "process_name",
        "start_vpn",
        "end_vpn",
        "size_bytes",
        "protection",
        "tag",
        "file_path",
        "private_memory",
        "indicators",
        "source_plugin",
    ),
    "findings": (
        "title",
        "severity",
        "explanation",
        "plugin",
        "pid",
        "process_name",
        "field_name",
        "field_value",
        "confidence",
        "created_at",
    ),
    "iocs": (
        "ioc_type",
        "value",
        "pid",
        "process_name",
        "source",
    ),
    "timeline": (
        "event_time",
        "recorded_at",
        "clock",
        "time_precision",
        "classification",
        "event_kind",
        "summary",
        "pid",
        "process_name",
        "source_plugin",
    ),
    "artifacts": (
        "filename",
        "sha256",
        "size_bytes",
        "file_type",
        "extraction_method",
        "pid",
        "process_name",
        "source_plugin",
        "tool_name",
        "tool_version",
        "source_address",
        "extracted_at",
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


def dataset_rows(doc: dict[str, Any], dataset: str) -> list[dict[str, Any]]:
    if dataset == "processes":
        return list((doc.get("processes") or {}).get("items") or [])
    if dataset == "network":
        return list((doc.get("network") or {}).get("items") or [])
    if dataset == "network_artifacts":
        block = doc.get("network_artifacts") or (doc.get("network") or {}).get("artifacts") or {}
        return list(block.get("items") or [])
    if dataset == "modules":
        return list((doc.get("modules") or {}).get("items") or [])
    if dataset == "vad":
        return list((doc.get("memory") or {}).get("items") or [])
    if dataset == "findings":
        return list((doc.get("findings") or {}).get("items") or [])
    if dataset == "iocs":
        return list((doc.get("iocs") or {}).get("items") or [])
    if dataset == "timeline":
        return list((doc.get("timeline") or {}).get("items") or [])
    if dataset == "artifacts":
        return list((doc.get("artifacts") or {}).get("items") or [])
    return []


def write_csv_file(
    path: Path,
    dataset: str,
    rows: list[dict[str, Any]],
    *,
    meta: dict[str, Any] | None = None,
) -> int:
    from memscope_engine.export.shape import EXPORT_META_KEYS

    columns = CSV_COLUMNS[dataset]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        if meta:
            for key in EXPORT_META_KEYS:
                writer.writerow([key, csv_cell(meta.get(key))])
            writer.writerow([])
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
        if section == "network" and "network_artifacts" not in out:
            out.append("network_artifacts")
    return out
