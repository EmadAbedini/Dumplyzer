"""Plausibility checks for OS timestamps recovered from memory.

Volatility dlllist LoadTime is a FILETIME that is often uninitialized
garbage. Those values survive conversion and show up as dates centuries
in the future (or decades before the process existed). Process CreateTime
and windows.info SystemTime are the reliable anchors for a dump.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from memscope_engine.storage import Database

OS_TIME_MIN = datetime(1990, 1, 1, tzinfo=timezone.utc)
OS_TIME_MAX = datetime(2100, 1, 1, tzinfo=timezone.utc)
AFTER_DUMP_SLACK = timedelta(hours=1)
BEFORE_CREATE_SLACK = timedelta(seconds=60)
GLOBAL_BEFORE_SLACK = timedelta(days=7)


def parse_observed_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    text = str(value).strip()
    if not text or text.lower() in {"n/a", "-", "none", "null"}:
        return None
    if text.endswith(" UTC"):
        text = text[:-4].strip() + "+00:00"
    if text.endswith("Z") and len(text) > 1 and text[-2].isdigit():
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def is_sane_os_year(dt: datetime) -> bool:
    return OS_TIME_MIN <= dt < OS_TIME_MAX


@dataclass(frozen=True)
class OsTimeBounds:
    lower: datetime | None = None
    upper: datetime | None = None
    create_by_pid: dict[int, datetime] = field(default_factory=dict)


def evidence_os_time_bounds(db: Database, evidence_id: str) -> OsTimeBounds:
    anchors: list[datetime] = []
    create_by_pid: dict[int, datetime] = {}

    ev = db.fetchone("SELECT metadata_json FROM evidence WHERE id = ?", (evidence_id,))
    if ev:
        try:
            meta = json.loads(ev.get("metadata_json") or "{}")
        except json.JSONDecodeError:
            meta = {}
        if isinstance(meta, dict):
            raw = meta.get("raw") if isinstance(meta.get("raw"), dict) else {}
            system = parse_observed_datetime(
                meta.get("system_time") or (raw or {}).get("SystemTime")
            )
            if system and is_sane_os_year(system):
                anchors.append(system)

    for row in db.fetchall(
        "SELECT pid, create_time FROM processes WHERE evidence_id = ?",
        (evidence_id,),
    ):
        created = parse_observed_datetime(row.get("create_time"))
        if created is None or not is_sane_os_year(created):
            continue
        anchors.append(created)
        pid = row.get("pid")
        try:
            create_by_pid[int(pid)] = created
        except (TypeError, ValueError):
            pass

    if not anchors:
        return OsTimeBounds(create_by_pid=create_by_pid)
    return OsTimeBounds(
        lower=min(anchors) - GLOBAL_BEFORE_SLACK,
        upper=max(anchors) + AFTER_DUMP_SLACK,
        create_by_pid=create_by_pid,
    )


def is_plausible_module_load(
    value: Any,
    pid: int | None,
    bounds: OsTimeBounds | None = None,
) -> bool:
    """True when a dlllist LoadTime could belong to this dump."""
    dt = parse_observed_datetime(value)
    if dt is None or not is_sane_os_year(dt):
        return False
    if bounds is None:
        return True
    if bounds.upper is not None and dt > bounds.upper:
        return False
    created = None
    if pid is not None:
        try:
            created = bounds.create_by_pid.get(int(pid))
        except (TypeError, ValueError):
            created = None
    if created is not None and dt < created - BEFORE_CREATE_SLACK:
        return False
    if created is None and bounds.lower is not None and dt < bounds.lower:
        return False
    return True


ANALYSIS_EVENT_KINDS = frozenset(
    {
        "network_artifacts",
        "bulk_extractor",
        "yara_scan",
        "capa_scan",
        "floss_scan",
        "pcap_reconstruction",
        "pe_extraction",
        "finding",
        "artifact_extraction",
    }
)


def is_analysis_clock_event(event: dict[str, Any]) -> bool:
    """True when the timestamp is when Dumplyzer ran, not when the OS did."""
    precision = str(event.get("time_precision") or "").strip().lower()
    if precision == "analysis_time":
        return True
    kind = str(event.get("event_kind") or "").strip().lower()
    return kind in ANALYSIS_EVENT_KINDS


def keep_timeline_event(event: dict[str, Any], bounds: OsTimeBounds | None) -> bool:
    if event.get("event_kind") != "module_load":
        return True
    return is_plausible_module_load(event.get("event_time"), event.get("pid"), bounds)
