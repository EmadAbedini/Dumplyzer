"""Shape investigation export payloads for DFIR use: keep analyst fields, drop internal IDs."""

from __future__ import annotations

import json
from typing import Any

from memscope_engine.export.constants import REPORT_SECTIONS

_TIME_KEYS = frozenset(
    {
        "created_at",
        "create_time",
        "exit_time",
        "load_time",
        "event_time",
        "extracted_at",
        "recorded_at",
        "started_at",
        "finished_at",
        "generated_at",
        "import_timestamp",
    }
)

PROCESS_KEYS = (
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
)
NETWORK_KEYS = (
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
)
NETWORK_ARTIFACT_KEYS = (
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
)
MODULE_KEYS = (
    "pid",
    "process_name",
    "name",
    "path",
    "base_address",
    "size",
    "load_time",
    "source_plugin",
)
MEMORY_KEYS = (
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
)
FINDING_KEYS = (
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
)
IOC_KEYS = ("ioc_type", "value", "pid", "process_name", "source")
TIMELINE_KEYS = (
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
)
ARTIFACT_KEYS = (
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
)

EXPORT_META_KEYS = ("evidence_file_name", "created_at", "sha256")


def coerce_sections(sections: Any) -> list[str] | None:
    """Accept a list, JSON array string, or comma-separated names."""
    if sections is None:
        return None
    if isinstance(sections, str):
        text = sections.strip()
        if not text:
            return None
        if text.startswith("["):
            try:
                loaded = json.loads(text)
            except json.JSONDecodeError:
                loaded = None
            if loaded is not None:
                return coerce_sections(loaded)
        return [part.strip() for part in text.split(",") if part.strip()]
    if isinstance(sections, (list, tuple, set)):
        out: list[str] = []
        for item in sections:
            if isinstance(item, str):
                name = item.strip()
                if not name:
                    continue
                if name in REPORT_SECTIONS:
                    out.append(name)
                elif "," in name or name.startswith("["):
                    nested = coerce_sections(name)
                    if nested:
                        out.extend(nested)
                else:
                    out.append(name)
            elif item is not None:
                nested = coerce_sections(item)
                if nested:
                    out.extend(nested)
        return out
    return None


def file_meta(doc: dict[str, Any]) -> dict[str, str]:
    return {
        "evidence_file_name": str(doc.get("evidence_file_name") or ""),
        "created_at": str(doc.get("created_at") or ""),
        "sha256": str(doc.get("sha256") or ""),
    }


def _human_time(value: Any) -> Any:
    from memscope_engine.export.html_report import format_html_time

    if value is None or value == "":
        return value
    if not isinstance(value, str):
        return value
    return format_html_time(value) or value


def _pick(row: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in keys:
        value = row.get(key)
        if key in _TIME_KEYS:
            value = _human_time(value)
        out[key] = value
    return out


def _indicator_codes(item: dict[str, Any]) -> list[str]:
    indicators = item.get("indicators") or item.get("indicator_codes") or []
    codes: list[str] = []
    if isinstance(indicators, list):
        for entry in indicators:
            if isinstance(entry, dict) and entry.get("code"):
                codes.append(str(entry["code"]))
            elif isinstance(entry, str) and entry.strip():
                codes.append(entry.strip())
    return codes


def _with_process_name(row: dict[str, Any], names: dict[int, str]) -> dict[str, Any]:
    out = dict(row)
    if out.get("process_name"):
        return out
    pid = out.get("pid")
    try:
        if pid is not None:
            out["process_name"] = names.get(int(pid))
    except (TypeError, ValueError):
        pass
    return out


def _shape_process(item: dict[str, Any]) -> dict[str, Any]:
    parent = item.get("parent") or {}
    row = dict(item)
    if isinstance(parent, dict):
        row["parent_pid"] = parent.get("pid")
        row["parent_name"] = parent.get("name")
    children = item.get("child_pids") or []
    if isinstance(children, list):
        row["child_pids"] = ", ".join(str(c) for c in children)
    return _pick(row, PROCESS_KEYS)


def _shape_memory(item: dict[str, Any], names: dict[int, str]) -> dict[str, Any]:
    row = _with_process_name(item, names)
    row["indicators"] = ", ".join(_indicator_codes(item))
    return _pick(row, MEMORY_KEYS)


def _shape_items(
    block: dict[str, Any] | None,
    keys: tuple[str, ...],
    names: dict[int, str],
    *,
    transform=None,
) -> dict[str, Any] | None:
    if not isinstance(block, dict):
        return block
    items = []
    for raw in block.get("items") or []:
        if not isinstance(raw, dict):
            continue
        row = transform(raw) if transform else _pick(_with_process_name(raw, names), keys)
        items.append(row)
    return {**block, "items": items, "shown": len(items)}


def _drop_internal_ids(value: Any) -> Any:
    skip = {
        "id",
        "process_id",
        "evidence_id",
        "analysis_run_id",
        "memory_region_id",
        "parent_artifact_id",
        "related_entity_id",
        "plugin_execution_id",
    }
    if isinstance(value, dict):
        return {
            key: _drop_internal_ids(_human_time(val) if key in _TIME_KEYS else val)
            for key, val in value.items()
            if key not in skip
        }
    if isinstance(value, list):
        return [_drop_internal_ids(item) for item in value]
    return value


def shape_investigation(doc: dict[str, Any], *, names: dict[int, str] | None = None) -> dict[str, Any]:
    names = names or {}
    meta = doc.get("metadata") or {}
    created_at = _human_time(doc.get("generated_at") or meta.get("generated_at"))
    evidence_file_name = meta.get("evidence_filename") or ""
    sha256 = meta.get("evidence_sha256") or ""

    slim_meta = {
        "evidence_file_name": evidence_file_name,
        "sha256": sha256,
        "size_bytes": meta.get("evidence_size_bytes"),
        "detected_os": meta.get("detected_os"),
        "architecture": meta.get("architecture"),
        "symbol_status": meta.get("symbol_status"),
        "import_timestamp": _human_time(meta.get("import_timestamp")),
        "volatility_version": meta.get("volatility_version"),
        "path": meta.get("evidence_path"),
    }

    shaped: dict[str, Any] = {
        "format": doc.get("format"),
        "evidence_file_name": evidence_file_name,
        "created_at": created_at,
        "sha256": sha256,
        "report_schema_version": doc.get("report_schema_version"),
        "analysis_schema_version": doc.get("analysis_schema_version"),
        "generated_at": created_at,
        "sections_included": list(doc.get("sections_included") or []),
        "truncated": doc.get("truncated"),
        "note": (
            "Offline Dumplyzer investigation export. "
            "Inferred timeline events are reconstructions, not directly observed evidence. "
            "No malware or risk score is assigned."
        ),
    }
    if doc.get("metadata") is not None:
        shaped["metadata"] = slim_meta
    if doc.get("summary") is not None:
        shaped["summary"] = doc["summary"]
    if doc.get("findings") is not None:
        shaped["findings"] = _shape_items(doc["findings"], FINDING_KEYS, names)
    if doc.get("processes") is not None:
        shaped["processes"] = _shape_items(
            doc["processes"], PROCESS_KEYS, names, transform=_shape_process
        )
    if doc.get("network") is not None:
        shaped["network"] = _shape_items(doc["network"], NETWORK_KEYS, names)
        net = doc["network"] if isinstance(doc["network"], dict) else {}
        if isinstance(shaped.get("network"), dict):
            artifacts = net.get("artifacts")
            if isinstance(artifacts, dict):
                shaped["network"]["artifacts"] = _shape_items(
                    artifacts, NETWORK_ARTIFACT_KEYS, names
                )
            if net.get("pcap") is not None:
                shaped["network"]["pcap"] = _drop_internal_ids(net.get("pcap"))
    if doc.get("network_artifacts") is not None:
        shaped["network_artifacts"] = _shape_items(
            doc["network_artifacts"], NETWORK_ARTIFACT_KEYS, names
        )
    if doc.get("modules") is not None:
        shaped["modules"] = _shape_items(doc["modules"], MODULE_KEYS, names)
    if doc.get("memory") is not None:
        shaped["memory"] = _shape_items(
            doc["memory"], MEMORY_KEYS, names, transform=lambda row: _shape_memory(row, names)
        )
    if doc.get("timeline") is not None:
        shaped["timeline"] = _shape_items(doc["timeline"], TIMELINE_KEYS, names)
    if doc.get("iocs") is not None:
        shaped["iocs"] = _shape_items(doc["iocs"], IOC_KEYS, names)
    if doc.get("artifacts") is not None:
        shaped["artifacts"] = _shape_items(doc["artifacts"], ARTIFACT_KEYS, names)
    if doc.get("malware") is not None:
        shaped["malware"] = _drop_internal_ids(doc["malware"])
    if doc.get("advanced") is not None:
        shaped["advanced"] = _drop_internal_ids(doc["advanced"])
    return shaped
