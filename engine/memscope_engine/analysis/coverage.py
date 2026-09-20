"""Derive per-capability analysis coverage from persisted runs (no schema change).

States are based on whether a capability actually executed, not on result counts:
executed + count > 0 → analyzed
executed + count == 0 → analyzed_zero
never executed → not_analyzed
a recorded failed step → failed

Command lines are not collected by Quick Triage (windows.pslist). Zero stored
command lines therefore stay not_analyzed rather than analyzed_zero.
"""

from __future__ import annotations

import json
from typing import Any

from memscope_engine.analysis.profiles import EVIDENCE_IDS, PROCESS_IDS
from memscope_engine.storage import Database

# Standalone analysis_runs.kind values that mean a capability executed.
# Plugin Explorer (`plugin_advanced`) is intentionally omitted so dlllist/netscan
# there cannot mark evidence-wide Modules/Network as analyzed.
# Page-level iocs.extract / timeline.build do not write analysis_runs; coverage
# for those capabilities comes from analysis_profile steps (or a later profile run).
KIND_CAPABILITIES: dict[str, tuple[str, ...]] = {
    "basic_triage": ("processes",),
    "process_recommended": ("recommended", "process_deep_dive"),
    "vad_scan": ("memory_vad",),
    "vad_extract": ("artifacts",),
    "network_artifact_extraction": ("network_artifacts",),
    "yara_artifact_scan": ("signatures",),
    "yara_memory_scan": ("signatures",),
    "yara_extracted_scan": ("signatures",),
}

# Capabilities a running standalone job is actively filling. Used for live
# spinners only — Analyze process must not un-mark evidence-wide Modules /
# Network that Complete Analysis already executed.
KIND_LIVE_CAPABILITIES: dict[str, tuple[str, ...]] = {
    **KIND_CAPABILITIES,
    "process_recommended": (
        "command_lines",
        "modules",
        "network",
        "handles",
        "memory_vad",
        "findings",
        "recommended",
        "process_deep_dive",
    ),
}

ALL_CAPABILITY_IDS: tuple[str, ...] = tuple(EVIDENCE_IDS) + tuple(PROCESS_IDS)


def _item(
    cid: str, state: str, count: int | None, updating: bool = False
) -> dict[str, Any]:
    return {"id": cid, "state": state, "count": count, "updating": updating}


def _parse_strategy(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    if isinstance(raw, list):
        return {}
    try:
        data = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _table_exists(db: Database, name: str) -> bool:
    row = db.fetchone(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
        (name,),
    )
    return row is not None


def _count(db: Database, sql: str, params: tuple[Any, ...]) -> int:
    row = db.fetchone(sql, params)
    return int(row["c"]) if row else 0


def _counts(db: Database, evidence_id: str) -> dict[str, int]:
    out = {
        "processes": _count(
            db, "SELECT COUNT(*) AS c FROM processes WHERE evidence_id = ?", (evidence_id,)
        ),
        "command_lines": _count(
            db,
            """
            SELECT COUNT(*) AS c FROM processes
            WHERE evidence_id = ? AND command_line IS NOT NULL AND TRIM(command_line) != ''
            """,
            (evidence_id,),
        ),
        "modules": _count(
            db, "SELECT COUNT(*) AS c FROM modules WHERE evidence_id = ?", (evidence_id,)
        ),
        "network": _count(
            db,
            "SELECT COUNT(*) AS c FROM network_connections WHERE evidence_id = ?",
            (evidence_id,),
        ),
        "handles": _count(
            db, "SELECT COUNT(*) AS c FROM handle_entries WHERE evidence_id = ?", (evidence_id,)
        )
        if _table_exists(db, "handle_entries")
        else 0,
        "findings": _count(
            db, "SELECT COUNT(*) AS c FROM findings WHERE evidence_id = ?", (evidence_id,)
        ),
        "iocs": _count(db, "SELECT COUNT(*) AS c FROM iocs WHERE evidence_id = ?", (evidence_id,))
        if _table_exists(db, "iocs")
        else 0,
        "timeline": _count(
            db, "SELECT COUNT(*) AS c FROM timeline_events WHERE evidence_id = ?", (evidence_id,)
        )
        if _table_exists(db, "timeline_events")
        else 0,
        "network_artifacts": _count(
            db, "SELECT COUNT(*) AS c FROM network_artifacts WHERE evidence_id = ?", (evidence_id,)
        )
        if _table_exists(db, "network_artifacts")
        else 0,
        "memory_vad": _count(
            db, "SELECT COUNT(*) AS c FROM memory_regions WHERE evidence_id = ?", (evidence_id,)
        )
        if _table_exists(db, "memory_regions")
        else 0,
        "artifacts": _count(
            db, "SELECT COUNT(*) AS c FROM artifacts WHERE evidence_id = ?", (evidence_id,)
        )
        if _table_exists(db, "artifacts")
        else 0,
        "signatures": _count(
            db,
            "SELECT COALESCE(SUM(match_count), 0) AS c FROM yara_scans WHERE evidence_id = ?",
            (evidence_id,),
        )
        if _table_exists(db, "yara_scans")
        else 0,
        "recommended": 0,
        "process_deep_dive": 0,
    }
    return out


def _capability_ids(raw: Any) -> set[str]:
    out: set[str] = set()
    if not isinstance(raw, list):
        return out
    for item in raw:
        if isinstance(item, str) and item.strip():
            out.add(item.strip())
    return out


def _incomplete_from_run(row: dict[str, Any]) -> set[str]:
    """Capabilities this run selected but has not finished."""
    kind = str(row.get("kind") or "")
    status = str(row.get("status") or "")
    if kind == "analysis_profile":
        strategy = _parse_strategy(row.get("strategy_json"))
        resetting = _capability_ids(
            strategy.get("evidence_capabilities") or strategy.get("capabilities")
        )
        done: set[str] = set()
        for step in strategy.get("steps") or []:
            if not isinstance(step, dict):
                continue
            cid = str(step.get("id") or "").strip()
            if not cid:
                continue
            if step.get("status") == "completed":
                done.add(cid)
            elif status != "cancelled" and step.get("status") == "failed":
                done.add(cid)
        return resetting - done
    mapped = KIND_CAPABILITIES.get(kind)
    return set(mapped) if mapped else set()


def _pending_from_run(row: dict[str, Any]) -> set[str]:
    """Capabilities that should show a live spinner for this run."""
    kind = str(row.get("kind") or "")
    if kind == "analysis_profile":
        return _incomplete_from_run(row)
    mapped = KIND_LIVE_CAPABILITIES.get(kind) or KIND_CAPABILITIES.get(kind)
    return set(mapped) if mapped else set()


def _coverage_active_run(rows: list[Any]) -> tuple[Any | None, bool]:
    """Prefer a running analysis profile over nested plugin runs.

    Complete Analysis inserts a parent `analysis_profile` row, then nested
    `basic_triage` (and similar) rows. Using the newest row alone made
    Findings / Timeline / IOCs look skipped while the parent was still running.
    """
    running = [row for row in rows if str(row.get("status") or "") in ("running", "queued")]
    if running:
        profiles = [row for row in running if str(row.get("kind") or "") == "analysis_profile"]
        return (profiles[-1] if profiles else running[-1]), True
    if rows and str(rows[-1].get("status") or "") == "cancelled":
        return rows[-1], False
    return None, False


def collect_executed(
    db: Database, evidence_id: str
) -> tuple[set[str], set[str], set[str], set[str]]:
    """Return (executed ids, failed ids, pending ids, sourced ids).

    Sourced ids were filled by a completed process-scoped job (Analyze process)
    and may have rows without being evidence-wide executed.
    """
    executed: set[str] = set()
    failed: set[str] = set()
    sourced: set[str] = set()
    rows = db.fetchall(
        """
        SELECT kind, status, strategy_json
        FROM analysis_runs
        WHERE evidence_id = ?
        ORDER BY started_at ASC, rowid ASC
        """,
        (evidence_id,),
    )
    for row in rows:
        kind = str(row.get("kind") or "")
        status = str(row.get("status") or "")
        if kind == "analysis_profile":
            strategy = _parse_strategy(row.get("strategy_json"))
            for step in strategy.get("steps") or []:
                if not isinstance(step, dict):
                    continue
                cid = str(step.get("id") or "").strip()
                if not cid:
                    continue
                if step.get("status") == "completed":
                    executed.add(cid)
                elif step.get("status") == "failed" and status != "cancelled":
                    failed.add(cid)
            continue
        mapped = KIND_CAPABILITIES.get(kind)
        if not mapped:
            continue
        if status == "completed":
            executed.update(mapped)
            live = KIND_LIVE_CAPABILITIES.get(kind)
            if live:
                sourced.update(live)
        elif status == "failed":
            failed.update(mapped)
    pending: set[str] = set()
    active, is_live = _coverage_active_run(list(rows))
    if active is not None:
        incomplete = _incomplete_from_run(active)
        if is_live:
            pending = _pending_from_run(active)
        executed -= incomplete
        failed -= incomplete
    failed -= executed
    return executed, failed, pending, sourced


def _analysis_in_progress(db: Database, evidence_id: str) -> bool:
    row = db.fetchone(
        """
        SELECT 1 AS ok FROM analysis_runs
        WHERE evidence_id = ? AND status IN ('running', 'queued')
        LIMIT 1
        """,
        (evidence_id,),
    )
    return bool(row)


def coverage_for_evidence(db: Database, evidence_id: str) -> dict[str, Any]:
    executed, failed, pending, sourced = collect_executed(db, evidence_id)
    in_progress = _analysis_in_progress(db, evidence_id)
    counts = _counts(db, evidence_id)
    items: dict[str, dict[str, Any]] = {}
    for cid in ALL_CAPABILITY_IDS:
        count = counts.get(cid)
        updating = cid in pending
        if cid == "command_lines":
            # Quick Triage / pslist never collect command lines. Show a count
            # only when command-line text is actually stored.
            n = int(count or 0)
            if updating:
                items[cid] = _item(cid, "not_analyzed", n, True)
            elif n > 0 and (cid in executed or cid in sourced or in_progress):
                items[cid] = _item(
                    cid,
                    "analyzed" if cid in executed else "not_analyzed",
                    n,
                )
            elif cid in failed:
                items[cid] = _item(cid, "failed", None)
            else:
                items[cid] = _item(cid, "not_analyzed", None)
            continue
        if cid in executed:
            n = int(count or 0)
            if cid in ("recommended", "process_deep_dive"):
                state = "analyzed"
                n = None
            elif n > 0:
                state = "analyzed"
            else:
                state = "analyzed_zero"
            items[cid] = _item(cid, state, n)
        elif cid in failed:
            items[cid] = _item(cid, "failed", None)
        else:
            n = int(count or 0)
            show_count = updating or (n > 0 and (cid in sourced or in_progress))
            items[cid] = _item(
                cid,
                "not_analyzed",
                n if show_count else None,
                updating,
            )
    sig_count = int(counts.get("signatures") or 0)
    sig_updating = "signatures" in pending
    if sig_count > 0:
        items["signatures"] = _item("signatures", "not_analyzed", sig_count, sig_updating)
    else:
        items["signatures"] = _item("signatures", "not_analyzed", None, sig_updating)
    executed = {cid for cid, item in items.items() if item["state"] in ("analyzed", "analyzed_zero")}
    failed = {cid for cid, item in items.items() if item["state"] == "failed"}
    return {
        "items": items,
        "executed": sorted(executed),
        "failed": sorted(failed),
    }
