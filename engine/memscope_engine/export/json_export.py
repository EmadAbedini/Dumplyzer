"""Versioned JSON writers. Stream section files; sort keys for determinism."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TextIO

from memscope_engine.export.constants import REPORT_FORMAT

JSON_SECTION_KEYS: tuple[str, ...] = (
    "metadata",
    "summary",
    "findings",
    "processes",
    "network",
    "network_artifacts",
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


def dump_json(obj: Any, fh: TextIO, *, sort_keys: bool = False) -> None:
    json.dump(
        obj,
        fh,
        ensure_ascii=False,
        indent=2,
        sort_keys=sort_keys,
        default=json_default,
    )
    fh.write("\n")


def write_json_file(path: Path, obj: Any, *, sort_keys: bool = False) -> int:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        dump_json(obj, fh, sort_keys=sort_keys)
    return path.stat().st_size


def section_document(doc: dict[str, Any], section: str) -> dict[str, Any]:
    payload = {
        "format": REPORT_FORMAT,
        "evidence_file_name": doc.get("evidence_file_name"),
        "created_at": doc.get("created_at") or doc.get("generated_at"),
        "sha256": doc.get("sha256"),
        "generated_at": doc.get("generated_at") or doc.get("created_at"),
        "section": section,
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

    written = False
    for section in sections:
        if section not in JSON_SECTION_KEYS:
            continue
        if section == "metadata" and any(s != "metadata" and s in JSON_SECTION_KEYS for s in sections):
            continue
        if section not in doc and section != "metadata":
            continue
        path = output_dir / f"{section}.json"
        size = write_json_file(path, section_document(doc, section))
        files.append({"name": path.name, "kind": section, "size_bytes": size})
        written = True
    if not written and "metadata" in doc:
        path = output_dir / "metadata.json"
        size = write_json_file(path, section_document(doc, "metadata"))
        files.append({"name": path.name, "kind": "metadata", "size_bytes": size})
    return files
