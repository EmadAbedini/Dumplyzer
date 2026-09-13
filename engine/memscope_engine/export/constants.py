"""Versioned report schema and export limits."""

from __future__ import annotations

REPORT_SCHEMA_VERSION = 1
REPORT_FORMAT = "memscope-report-v1"

# SQLite analysis schema is independent; reports record both versions.
HTML_MAX_ROWS = 400
JSON_MAX_ROWS = 20000
CSV_MAX_ROWS = 50000
ADVANCED_EXECUTION_LIMIT = 200

REPORT_SECTIONS: tuple[str, ...] = (
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

CSV_DATASETS: tuple[str, ...] = (
    "processes",
    "network",
    "network_artifacts",
    "modules",
    "vad",
    "findings",
    "iocs",
    "timeline",
    "artifacts",
)

# Report section id → CSV dataset name (tabular sections only).
SECTION_TO_CSV: dict[str, str] = {
    "processes": "processes",
    "network": "network",
    "modules": "modules",
    "memory": "vad",
    "findings": "findings",
    "iocs": "iocs",
    "timeline": "timeline",
    "artifacts": "artifacts",
}

FORMATS: tuple[str, ...] = ("json", "xlsx", "html")
SCOPES: tuple[str, ...] = ("complete", "selected")
