"""Versioned JSON writers. Stream section files; sort keys for determinism."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TextIO

from memscope_engine.export.constants import REPORT_FORMAT, REPORT_SCHEMA_VERSION

JSON_SECTION_KEYS: tuple[str, ...] = (
    "metadata",
    "summary",
    "findings",
    "processes",
    "network",
    "modules",
    "memory",
    "timeline",
    "iocs",
    "artifacts",
    "malware",
    "advanced",
)


def json_default(obj: Any) -> str:
    return str(obj)


def dump_json(obj: Any, fh: TextIO) -> None:
    json.dump(
        obj,
        fh,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=json_default,
    )
    fh.write("\n")


def write_json_file(path: Path, obj: Any) -> int:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        dump_json(obj, fh)
    return path.stat().st_size


def section_document(doc: dict[str, Any], section: str) -> dict[str, Any]:
    payload = {
        "format": REPORT_FORMAT,
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "analysis_schema_version": doc.get("analysis_schema_version"),
        "memscope_version": doc.get("memscope_version"),
        "generated_at": doc.get("generated_at"),
        "section": section,
        "provenance": doc.get("provenance"),
        "metadata": doc.get("metadata"),
        section: doc.get(section),
    }
    return payload


def write_json_exports(
    output_dir: Path,
    doc: dict[str, Any],
    sections: list[str],
    *,
    scope: str,
) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    if scope == "complete":
        path = output_dir / "investigation.json"
        size = write_json_file(path, doc)
        files.append({"name": path.name, "kind": "complete", "size_bytes": size})
        return files

    for section in sections:
        if section not in JSON_SECTION_KEYS:
            continue
        if section not in doc and section != "metadata":
            continue
        path = output_dir / f"{section}.json"
        size = write_json_file(path, section_document(doc, section))
        files.append({"name": path.name, "kind": section, "size_bytes": size})
    return files
