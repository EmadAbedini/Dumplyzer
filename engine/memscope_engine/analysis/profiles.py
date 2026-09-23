"""Logical analysis profiles mapped to supported Dumplyzer workflows.

The UI selects capabilities/profiles. This module maps them onto existing
Volatility 3 API jobs and image-wide plugins. It does not construct vol.py
command lines.
"""

from __future__ import annotations

import json
import logging
import time
import traceback
from typing import Any, Callable
from uuid import uuid4

from memscope_engine.analysis import memory_artifacts, process_analysis, search_iocs
from memscope_engine.analysis import network_artifacts as network_artifact_wf
from memscope_engine.analysis.progress import AnalysisProgress, emit_live, persist_live
from memscope_engine.errors import AppError
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION
from memscope_engine.volatility.normalize import (
    findings_from_cmdline,
    normalize_cmdline,
    normalize_dlllist,
    normalize_handles,
    normalize_netscan,
)
from memscope_engine.volatility.session import VolatilitySession

log = logging.getLogger("memscope.analysis")

# Evidence-scoped capabilities can run after import without a selected PID.
# Process-scoped capabilities require a process (existing recommended / VAD jobs).

CAPABILITIES: list[dict[str, Any]] = [
    {
        "id": "processes",
        "label": "Processes",
        "scope": "evidence",
        "description": "windows.info + windows.pslist (basic triage).",
    },
    {
        "id": "command_lines",
        "label": "Command Lines",
        "scope": "evidence",
        "description": "windows.cmdline for processes in the image.",
    },
    {
        "id": "modules",
        "label": "Modules / DLLs",
        "scope": "evidence",
        "description": "windows.dlllist for loaded modules.",
    },
    {
        "id": "network",
        "label": "Network Connections",
        "scope": "evidence",
        "description": "windows.netscan (image-wide).",
    },
    {
        "id": "network_artifacts",
        "label": "Network Artifact Extraction",
        "scope": "evidence",
        "description": "Recover network indicators from connections, extracted features, and stored process text.",
    },
    {
        "id": "handles",
        "label": "Handles",
        "scope": "evidence",
        "description": "windows.handles for open handles.",
    },
    {
        "id": "findings",
        "label": "Findings / Heuristics",
        "scope": "evidence",
        "description": "Heuristic findings from command lines already stored.",
    },
    {
        "id": "iocs",
        "label": "IOC Extraction",
        "scope": "evidence",
        "description": "Extract IOCs from stored process/module/network text.",
    },
    {
        "id": "timeline",
        "label": "Timeline",
        "scope": "evidence",
        "description": "Build the investigation timeline from stored records.",
    },
    {
        "id": "recommended",
        "label": "Recommended Analysis",
        "scope": "process",
        "description": "Per-process cmdline, dlllist, netscan, handles, and VAD.",
    },
    {
        "id": "memory_vad",
        "label": "Memory / VAD",
        "scope": "process",
        "description": "windows.vadinfo for a selected process PID.",
    },
    {
        "id": "process_deep_dive",
        "label": "Process Deep Dive",
        "scope": "process",
        "description": "Same pipeline as recommended analysis for one process.",
    },
    {
        "id": "artifacts",
        "label": "Carved Data",
        "scope": "process",
        "description": "Extract a VAD region after a targeted memory scan.",
    },
    {
        "id": "pe_extraction",
        "label": "Extracted files",
        "scope": "artifacts",
        "description": (
            "Reconstruct EXE/DLL images from the imported dump. Run from Carved Data; "
            "not part of Complete Analysis."
        ),
    },
    {
        "id": "bulk_extractor",
        "label": "Carved artifacts",
        "scope": "artifacts",
        "description": (
            "Carve emails, keys, URLs, and other strings from the dump. Run from "
            "Carved Data; not part of Complete Analysis."
        ),
    },
]

EVIDENCE_IDS = tuple(c["id"] for c in CAPABILITIES if c["scope"] == "evidence")
PROCESS_IDS = tuple(c["id"] for c in CAPABILITIES if c["scope"] == "process")

FULL_CAPABILITIES: tuple[str, ...] = (
    "processes",
    "command_lines",
    "modules",
    "network",
    "handles",
    "findings",
    "iocs",
    "network_artifacts",
    "timeline",
)

RECOMMENDED_CAPABILITIES: tuple[str, ...] = ("processes",)

FULL_ANALYSIS_BLURB = (
    "Full Analysis runs the complete supported Dumplyzer analysis workflow for "
    "this evidence and stores the resulting findings, IOCs, processes, network "
    "data, modules, memory information and timeline according to the currently "
    "supported pipeline. It does not run per-process VAD extraction or optional "
    "Signature Detection / CAPA / FLOSS tools. Extracted files (PE reconstruction) "
    "and carved artifacts are also omitted: those jobs walk the entire dump, write "
    "reconstructed binaries and carved files to disk, and routinely take far longer "
    "than Volatility plugins. Endpoint protection often quarantines reconstructed "
    "PE images because they look like real executables, which can delete output "
    "mid-run. Run them from Carved Data if you need them."
)


def list_profiles() -> dict[str, Any]:
    return {
        "profiles": [
            {
                "id": "full",
                "label": "Full Analysis",
                "capabilities": list(FULL_CAPABILITIES),
                "description": FULL_ANALYSIS_BLURB,
            },
            {
                "id": "recommended",
                "label": "Recommended",
                "capabilities": list(RECOMMENDED_CAPABILITIES),
                "description": (
                    "First-look triage: OS/symbol status and process list "
                    "(windows.info + windows.pslist)."
                ),
            },
            {
                "id": "custom",
                "label": "Custom",
                "capabilities": [],
                "description": "Run only the capabilities you select.",
            },
        ],
        "capabilities": list(CAPABILITIES),
        "full_analysis": FULL_ANALYSIS_BLURB,
        "select_all_evidence": list(EVIDENCE_IDS),
        "select_all_with_process": [c["id"] for c in CAPABILITIES],
    }


def resolve_selection(
    profile: str,
    selected: list[str] | None = None,
) -> dict[str, Any]:
    name = (profile or "custom").strip().lower()
    if name not in ("full", "recommended", "custom"):
        raise AppError(
            code="invalid_profile",
            message="Unknown analysis profile.",
            details=name,
            suggestion="Use full, recommended, or custom.",
            entity="analysis",
        )
    known = {c["id"] for c in CAPABILITIES}
    if name == "full":
        caps = list(FULL_CAPABILITIES)
    elif name == "recommended":
        caps = list(RECOMMENDED_CAPABILITIES)
    else:
        caps = []
        for item in selected or []:
            cid = str(item).strip()
            if cid in known and cid not in caps:
                caps.append(cid)
        if not caps:
            raise AppError(
                code="empty_selection",
                message="Select at least one analysis capability.",
                entity="analysis",
            )
    evidence_caps = [c for c in caps if c in EVIDENCE_IDS]
    process_caps = [c for c in caps if c in PROCESS_IDS]
    return {
        "profile": name,
        "capabilities": caps,
        "evidence_capabilities": evidence_caps,
        "process_capabilities": process_caps,
    }


def _utcnow() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _cancelled(check: Callable[[], bool]) -> None:
    if check():
        raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")


def _is_cancel(exc: AppError, cancelled: Callable[[], bool] | None = None) -> bool:
    if exc.code == "job_cancelled":
        return True
    if cancelled is None:
        return False
    try:
        return bool(cancelled())
    except Exception:
        return False


def _finish_plugin_error(
    db: Database,
    pe: str,
    exc: AppError,
    step_id: str,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    if _is_cancel(exc, cancelled):
        process_analysis._record_plugin_done(
            db, pe, status="cancelled", error=exc.to_dict()
        )
        raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job") from exc
    process_analysis._record_plugin_done(
        db, pe, status="failed", error=exc.to_dict()
    )
    return {"id": step_id, "status": "failed", "error": exc.message}


def _planned_steps(
    evidence_caps: list[str],
    process_caps: list[str],
    *,
    has_processes: bool,
    has_process_target: bool,
) -> list[str]:
    planned: list[str] = []
    plugin_caps = [c for c in evidence_caps if c in ("command_lines", "modules", "network", "handles")]
    follow_on = bool(
        plugin_caps
        or any(c in evidence_caps for c in ("findings", "iocs", "network_artifacts", "timeline"))
    )
    if "processes" in evidence_caps or (follow_on and not has_processes):
        planned.append("processes")
    if plugin_caps:
        planned.append("session")
        planned.extend(plugin_caps)
    for cap in ("findings", "iocs", "network_artifacts", "timeline"):
        if cap in evidence_caps:
            planned.append(cap)
    for cap in process_caps:
        if cap in ("recommended", "process_deep_dive") and has_process_target:
            if "recommended" not in planned:
                planned.append("recommended")
        elif cap == "memory_vad" and has_process_target:
            planned.append("vad")
    return planned


def _pid_map(db: Database, evidence_id: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for row in db.fetchall(
        "SELECT id, pid FROM processes WHERE evidence_id = ?",
        (evidence_id,),
    ):
        out[int(row["pid"])] = row["id"]
    return out


_CAPABILITY_RESET_SQL: dict[str, tuple[str, str]] = {
    "findings": ("findings", "DELETE FROM findings WHERE evidence_id = ?"),
    "iocs": ("iocs", "DELETE FROM iocs WHERE evidence_id = ?"),
    "network_artifacts": (
        "network_artifacts",
        "DELETE FROM network_artifacts WHERE evidence_id = ?",
    ),
    "timeline": ("timeline_events", "DELETE FROM timeline_events WHERE evidence_id = ?"),
    "handles": ("handle_entries", "DELETE FROM handle_entries WHERE evidence_id = ?"),
    "memory_vad": ("memory_regions", "DELETE FROM memory_regions WHERE evidence_id = ?"),
    "artifacts": ("artifacts", "DELETE FROM artifacts WHERE evidence_id = ?"),
    "network": ("network_connections", "DELETE FROM network_connections WHERE evidence_id = ?"),
    "modules": ("modules", "DELETE FROM modules WHERE evidence_id = ?"),
    "command_lines": ("processes", "UPDATE processes SET command_line = NULL WHERE evidence_id = ?"),
    "processes": ("processes", "DELETE FROM processes WHERE evidence_id = ?"),
}


def _reset_capability_results(db: Database, evidence_id: str, capabilities: list[str]) -> None:
    """Clear persisted rows for capabilities this run is about to replace."""
    caps = {str(cid).strip() for cid in capabilities if str(cid).strip()}
    ordered = [
        "findings",
        "iocs",
        "network_artifacts",
        "timeline",
        "handles",
        "memory_vad",
        "artifacts",
        "network",
        "modules",
        "command_lines",
        "processes",
    ]
    with db.transaction() as conn:
        for cid in ordered:
            if cid not in caps:
                continue
            if cid == "command_lines" and "processes" in caps:
                continue
            table, sql = _CAPABILITY_RESET_SQL[cid]
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?",
                (table,),
            ).fetchone()
            if not exists:
                continue
            conn.execute(sql, (evidence_id,))
            if cid == "network_artifacts":
                runs_exist = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name = 'network_artifact_runs'"
                ).fetchone()
                if runs_exist:
                    conn.execute(
                        "DELETE FROM network_artifact_runs WHERE evidence_id = ?",
                        (evidence_id,),
                    )


def _persist_profile_steps(
    db: Database,
    run_id: str,
    strategy: dict[str, Any],
    steps: list[dict[str, Any]],
    skipped: list[dict[str, str]],
    vol_version: str | None,
) -> None:
    payload = json.dumps({**strategy, "steps": steps, "skipped": skipped})
    if vol_version:
        db.execute(
            "UPDATE analysis_runs SET strategy_json = ?, volatility_version = ? WHERE id = ?",
            (payload, vol_version, run_id),
        )
        return
    db.execute(
        "UPDATE analysis_runs SET strategy_json = ? WHERE id = ?",
        (payload, run_id),
    )


def run_analysis_profile_job(
    db: Database,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: Callable[..., None],
) -> dict[str, Any]:
    evidence_id = params.get("evidence_id")
    if not evidence_id:
        raise AppError(
            code="evidence_required",
            message="Select imported evidence before running analysis.",
            entity="evidence",
        )
    evidence = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    if not evidence:
        raise AppError(code="evidence_missing", message="Evidence not found.", entity="evidence")

    resolved = resolve_selection(str(params.get("profile") or "custom"), params.get("capabilities"))
    job_id = params.get("job_id")
    process_id = params.get("process_id")
    pid = params.get("pid")

    strategy = {
        "profile": resolved["profile"],
        "capabilities": resolved["capabilities"],
        "evidence_capabilities": resolved["evidence_capabilities"],
        "process_capabilities": resolved["process_capabilities"],
        "notes": FULL_ANALYSIS_BLURB if resolved["profile"] == "full" else None,
    }

    run_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at, error_json,
          volatility_version, schema_version, notes, process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'analysis_profile', 'running', ?, NULL, NULL, NULL, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            evidence_id,
            _utcnow(),
            SCHEMA_VERSION,
            f"profile={resolved['profile']}",
            process_id,
            int(pid) if pid is not None else None,
            job_id,
            json.dumps(strategy),
        ),
    )
    if job_id:
        db.execute("UPDATE jobs SET analysis_run_id = ? WHERE id = ?", (run_id, job_id))

    steps: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    vol_version = None

    try:
        _cancelled(cancelled)
        reset_caps = [c for c in resolved["evidence_capabilities"] if c != "processes"]
        _reset_capability_results(db, evidence_id, reset_caps)
        emit_live(
            progress,
            db,
            evidence_id,
            "Starting analysis",
            {"phase": "start", "percent": 0},
        )

        def add_step(step: dict[str, Any]) -> None:
            steps.extend([step])
            _persist_profile_steps(db, run_id, strategy, steps, skipped, vol_version)
            emit_live(
                progress,
                db,
                evidence_id,
                f"{step.get('id') or 'step'} complete",
                {"phase": str(step.get("id") or "step")},
            )

        evidence_caps = resolved["evidence_capabilities"]
        procs = db.fetchone(
            "SELECT COUNT(*) AS c FROM processes WHERE evidence_id = ?",
            (evidence_id,),
        )
        has_processes = bool(procs and int(procs["c"] or 0) > 0)
        tracker = AnalysisProgress(
            progress,
            _planned_steps(
                list(evidence_caps),
                list(resolved["process_capabilities"]),
                has_processes=has_processes,
                has_process_target=bool(process_id or pid is not None),
            )
            or ["processes"],
            cancelled=cancelled,
        )

        if "processes" in evidence_caps:
            with tracker.running("processes", "Processes"):
                triage = process_analysis.run_basic_triage_job(
                    db,
                    {"evidence_id": evidence_id, "job_id": None},
                    cancelled,
                    tracker.bind_message("processes"),
                )
            add_step({"id": "processes", "status": "completed", "result": triage})
            vol_version = db.fetchone(
                "SELECT volatility_version FROM analysis_runs WHERE id = ?",
                (triage["analysis_run_id"],),
            )
            vol_version = vol_version["volatility_version"] if vol_version else None
        elif any(
            c in evidence_caps
            for c in (
                "command_lines",
                "modules",
                "network",
                "handles",
                "findings",
                "iocs",
                "network_artifacts",
                "timeline",
            )
        ):
            if not has_processes:
                with tracker.running("processes", "Processes"):
                    triage = process_analysis.run_basic_triage_job(
                        db,
                        {"evidence_id": evidence_id, "job_id": None},
                        cancelled,
                        tracker.bind_message("processes"),
                    )
                add_step({"id": "processes", "status": "completed", "result": triage, "implied": True})

        plugin_caps = [c for c in evidence_caps if c in ("command_lines", "modules", "network", "handles")]
        if plugin_caps:
            _cancelled(cancelled)
            with tracker.running("session", "Opening memory image"):
                session = VolatilitySession(evidence["path"])
            vol_version = session.volatility_version or vol_version
            pid_by = _pid_map(db, evidence_id)
            if "command_lines" in plugin_caps:
                with tracker.running("command_lines", "Command Lines") as vol_cb:
                    add_step(
                        _run_cmdline(
                            db,
                            session,
                            run_id,
                            evidence_id,
                            pid_by,
                            cancelled,
                            progress,
                            progress_callback=vol_cb,
                        )
                    )
            if "modules" in plugin_caps:
                with tracker.running("modules", "Modules / DLLs") as vol_cb:
                    add_step(
                        _run_dlllist(
                            db,
                            session,
                            run_id,
                            evidence_id,
                            pid_by,
                            cancelled,
                            progress,
                            progress_callback=vol_cb,
                        )
                    )
            if "network" in plugin_caps:
                with tracker.running("network", "Network Connections") as vol_cb:
                    add_step(
                        _run_netscan(
                            db,
                            session,
                            run_id,
                            evidence_id,
                            pid_by,
                            cancelled,
                            progress,
                            progress_callback=vol_cb,
                        )
                    )
            if "handles" in plugin_caps:
                with tracker.running("handles", "Handles") as vol_cb:
                    add_step(
                        _run_handles(
                            db,
                            session,
                            run_id,
                            evidence_id,
                            pid_by,
                            cancelled,
                            progress,
                            progress_callback=vol_cb,
                        )
                    )

        if "findings" in evidence_caps:
            _cancelled(cancelled)
            with tracker.running("findings", "Findings & Heuristics"):
                add_step(_run_findings(db, run_id, evidence_id))

        if "iocs" in evidence_caps:
            _cancelled(cancelled)
            with tracker.running("iocs", "IOC Extraction"):
                ioc = search_iocs.extract_iocs(db, evidence_id)
                add_step(
                    {
                        "id": "iocs",
                        "status": "completed",
                        "count": ioc.get("extracted", ioc.get("total")),
                    }
                )

        if "network_artifacts" in evidence_caps:
            _cancelled(cancelled)
            with tracker.running("network_artifacts", "Network Artifact Extraction"):
                harvested = network_artifact_wf.extract_and_store(
                    db,
                    evidence_id,
                    analysis_run_id=run_id,
                    job_id=params.get("job_id"),
                    cancelled=cancelled,
                    progress=tracker.bind_message("network_artifacts"),
                )
                add_step(
                    {
                        "id": "network_artifacts",
                        "status": "completed",
                        "count": harvested.get("artifact_count") or harvested.get("total") or 0,
                    }
                )

        if "timeline" in evidence_caps:
            _cancelled(cancelled)
            with tracker.running("timeline", "Timeline"):
                tl = memory_artifacts.build_timeline(db, evidence_id)
                add_step(
                    {"id": "timeline", "status": "completed", "count": tl.get("count") or tl.get("total")}
                )

        for cap in resolved["process_capabilities"]:
            if cap in ("recommended", "process_deep_dive"):
                if process_id or pid is not None:
                    with tracker.running("recommended", "Process Analysis"):
                        rec = process_analysis.run_process_recommended_job(
                            db,
                            {
                                "evidence_id": evidence_id,
                                "process_id": process_id,
                                "pid": pid,
                                "job_id": None,
                            },
                            cancelled,
                            tracker.bind_message("recommended"),
                        )
                    add_step({"id": cap, "status": "completed", "result": rec})
                else:
                    skipped.append(
                        {
                            "id": cap,
                            "reason": "Requires a selected process after Processes analysis.",
                        }
                    )
            elif cap == "memory_vad":
                if process_id or pid is not None:
                    with tracker.running("vad", "Memory / VAD"):
                        vad = memory_artifacts.run_vad_scan_job(
                            db,
                            {
                                "evidence_id": evidence_id,
                                "process_id": process_id,
                                "pid": pid,
                                "job_id": None,
                            },
                            cancelled,
                            tracker.bind_message("vad"),
                        )
                    add_step({"id": cap, "status": "completed", "result": vad})
                else:
                    skipped.append(
                        {
                            "id": cap,
                            "reason": "VAD scan requires a process PID.",
                        }
                    )
            elif cap == "artifacts":
                skipped.append(
                    {
                        "id": cap,
                        "reason": "Extract artifacts from a VAD region after a targeted memory scan.",
                    }
                )

        db.execute(
            """
            UPDATE analysis_runs SET status = 'completed', finished_at = ?,
              volatility_version = ?, strategy_json = ? WHERE id = ?
            """,
            (
                _utcnow(),
                vol_version,
                json.dumps({**strategy, "steps": steps, "skipped": skipped}),
                run_id,
            ),
        )
        emit_live(
            progress,
            db,
            evidence_id,
            "Analysis complete",
            {"phase": "done", "percent": 100},
        )
        return {
            "analysis_run_id": run_id,
            "profile": resolved["profile"],
            "capabilities": resolved["capabilities"],
            "steps": steps,
            "skipped": skipped,
            "evidence_id": evidence_id,
        }
    except AppError as exc:
        was_cancelled = _is_cancel(exc, cancelled)
        db.execute(
            """
            UPDATE analysis_runs SET status = ?, finished_at = ?, error_json = ?,
              volatility_version = ?, strategy_json = ? WHERE id = ?
            """,
            (
                "cancelled" if was_cancelled else "failed",
                _utcnow(),
                json.dumps(
                    AppError(code="job_cancelled", message="Job was cancelled.", entity="job").to_dict()
                    if was_cancelled
                    else exc.to_dict()
                ),
                vol_version,
                json.dumps({**strategy, "steps": steps, "skipped": skipped}),
                run_id,
            ),
        )
        if was_cancelled and exc.code != "job_cancelled":
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job") from exc
        raise
    except Exception as exc:  # noqa: BLE001
        if cancelled():
            db.execute(
                """
                UPDATE analysis_runs SET status = ?, finished_at = ?, error_json = ?,
                  volatility_version = ?, strategy_json = ? WHERE id = ?
                """,
                (
                    "cancelled",
                    _utcnow(),
                    json.dumps(
                        AppError(code="job_cancelled", message="Job was cancelled.", entity="job").to_dict()
                    ),
                    vol_version,
                    json.dumps({**strategy, "steps": steps, "skipped": skipped}),
                    run_id,
                ),
            )
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job") from exc
        db.execute(
            """
            UPDATE analysis_runs SET status = ?, finished_at = ?, error_json = ?,
              volatility_version = ?, strategy_json = ? WHERE id = ?
            """,
            (
                "failed",
                _utcnow(),
                json.dumps(
                    AppError(
                        code="analysis_profile_failed",
                        message="Analysis failed.",
                        details=f"{type(exc).__name__}: {exc}",
                        suggestion="Inspect engine logs for the full error.",
                        entity="analysis",
                        data={"traceback": traceback.format_exc()},
                    ).to_dict()
                ),
                vol_version,
                json.dumps({**strategy, "steps": steps, "skipped": skipped}),
                run_id,
            ),
        )
        raise


def _run_cmdline(
    db: Database,
    session: VolatilitySession,
    run_id: str,
    evidence_id: str,
    pid_by: dict[int, str],
    cancelled: Callable[[], bool],
    progress: Callable[..., None],
    progress_callback: Callable[[float, str | None], None] | None = None,
) -> dict[str, Any]:
    from volatility3.plugins.windows.cmdline import CmdLine

    _cancelled(cancelled)
    progress("Command lines (windows.cmdline)", {"phase": "command_lines"})
    pe = process_analysis._record_plugin_start(
        db, run_id=run_id, evidence_id=evidence_id, plugin="windows.cmdline", parameters={}
    )
    try:
        res = session.run_plugin(CmdLine, progress_callback=progress_callback, cancelled=cancelled)
        _cancelled(cancelled)
        rows = normalize_cmdline(res.columns, res.rows, pid_filter=None)
        updated = 0
        last = 0.0
        total = len(rows)
        for i, row in enumerate(rows, 1):
            pid = row.get("pid")
            proc_id = pid_by.get(int(pid)) if pid is not None else None
            if proc_id and row.get("command_line") is not None:
                db.execute(
                    "UPDATE processes SET command_line = ? WHERE id = ?",
                    (row["command_line"], proc_id),
                )
                updated += 1
                for f in findings_from_cmdline(
                    evidence_id=evidence_id,
                    analysis_run_id=run_id,
                    process_id=proc_id,
                    pid=int(pid),
                    command_line=row["command_line"],
                ):
                    process_analysis._insert_finding(db, f)
            now = time.monotonic()
            if i == 1 or i == total or now - last >= 0.4:
                last = now
                emit_live(
                    progress,
                    db,
                    evidence_id,
                    "Command lines (windows.cmdline)",
                    {"phase": "command_lines"},
                )
        process_analysis._record_plugin_done(
            db, pe, status="completed", row_count=len(rows), transparency=res.transparency
        )
        return {"id": "command_lines", "status": "completed", "rows": len(rows), "updated": updated}
    except AppError as exc:
        return _finish_plugin_error(db, pe, exc, "command_lines", cancelled)


def _run_dlllist(
    db: Database,
    session: VolatilitySession,
    run_id: str,
    evidence_id: str,
    pid_by: dict[int, str],
    cancelled: Callable[[], bool],
    progress: Callable[..., None],
    progress_callback: Callable[[float, str | None], None] | None = None,
) -> dict[str, Any]:
    from volatility3.plugins.windows.dlllist import DllList

    _cancelled(cancelled)
    progress("Modules / DLLs (windows.dlllist)", {"phase": "modules"})
    pe = process_analysis._record_plugin_start(
        db, run_id=run_id, evidence_id=evidence_id, plugin="windows.dlllist", parameters={}
    )
    try:
        res = session.run_plugin(DllList, progress_callback=progress_callback, cancelled=cancelled)
        _cancelled(cancelled)
        mods = normalize_dlllist(
            res.columns,
            res.rows,
            evidence_id=evidence_id,
            analysis_run_id=run_id,
            process_id=None,
            pid_filter=None,
            source_plugin=res.plugin,
        )
        for m in mods:
            pid = m.get("pid")
            if pid is not None:
                m["process_id"] = pid_by.get(int(pid))
        db.execute("DELETE FROM modules WHERE evidence_id = ?", (evidence_id,))
        emit_live(
            progress,
            db,
            evidence_id,
            "Modules / DLLs (windows.dlllist)",
            {"phase": "modules"},
        )
        persist_live(
            db,
            evidence_id,
            mods,
            lambda m: process_analysis._insert_module(db, m),
            progress=progress,
            message="Modules / DLLs (windows.dlllist)",
            extra={"phase": "modules"},
        )
        process_analysis._record_plugin_done(
            db, pe, status="completed", row_count=len(mods), transparency=res.transparency
        )
        return {"id": "modules", "status": "completed", "rows": len(mods)}
    except AppError as exc:
        return _finish_plugin_error(db, pe, exc, "modules", cancelled)


def _run_netscan(
    db: Database,
    session: VolatilitySession,
    run_id: str,
    evidence_id: str,
    pid_by: dict[int, str],
    cancelled: Callable[[], bool],
    progress: Callable[..., None],
    progress_callback: Callable[[float, str | None], None] | None = None,
) -> dict[str, Any]:
    from volatility3.plugins.windows.netscan import NetScan

    _cancelled(cancelled)
    progress("Network connections (windows.netscan)", {"phase": "network"})
    pe = process_analysis._record_plugin_start(
        db, run_id=run_id, evidence_id=evidence_id, plugin="windows.netscan", parameters={}
    )
    try:
        res = session.run_plugin(NetScan, progress_callback=progress_callback, cancelled=cancelled)
        _cancelled(cancelled)
        conns = normalize_netscan(
            res.columns,
            res.rows,
            evidence_id=evidence_id,
            analysis_run_id=run_id,
            process_id_by_pid=pid_by,
            pid_filter=None,
            source_plugin=res.plugin,
        )
        db.execute("DELETE FROM network_connections WHERE evidence_id = ?", (evidence_id,))
        emit_live(
            progress,
            db,
            evidence_id,
            "Network connections (windows.netscan)",
            {"phase": "network"},
        )
        persist_live(
            db,
            evidence_id,
            conns,
            lambda c: process_analysis._insert_net(db, c),
            progress=progress,
            message="Network connections (windows.netscan)",
            extra={"phase": "network"},
        )
        process_analysis._record_plugin_done(
            db, pe, status="completed", row_count=len(conns), transparency=res.transparency
        )
        return {"id": "network", "status": "completed", "rows": len(conns)}
    except AppError as exc:
        return _finish_plugin_error(db, pe, exc, "network", cancelled)


def _run_handles(
    db: Database,
    session: VolatilitySession,
    run_id: str,
    evidence_id: str,
    pid_by: dict[int, str],
    cancelled: Callable[[], bool],
    progress: Callable[..., None],
    progress_callback: Callable[[float, str | None], None] | None = None,
) -> dict[str, Any]:
    from volatility3.plugins.windows.handles import Handles

    _cancelled(cancelled)
    progress("Handles (windows.handles)", {"phase": "handles"})
    pe = process_analysis._record_plugin_start(
        db, run_id=run_id, evidence_id=evidence_id, plugin="windows.handles", parameters={}
    )
    try:
        res = session.run_plugin(Handles, progress_callback=progress_callback, cancelled=cancelled)
        _cancelled(cancelled)
        rows = normalize_handles(
            res.columns,
            res.rows,
            evidence_id=evidence_id,
            analysis_run_id=run_id,
            process_id=None,
            pid_filter=None,
            source_plugin=res.plugin,
        )
        for h in rows:
            pid = h.get("pid")
            if pid is not None:
                h["process_id"] = pid_by.get(int(pid))
        db.execute("DELETE FROM handle_entries WHERE evidence_id = ?", (evidence_id,))
        emit_live(
            progress,
            db,
            evidence_id,
            "Handles (windows.handles)",
            {"phase": "handles"},
        )
        persist_live(
            db,
            evidence_id,
            rows,
            lambda h: process_analysis._insert_handle(db, h),
            progress=progress,
            message="Handles (windows.handles)",
            extra={"phase": "handles"},
        )
        process_analysis._record_plugin_done(
            db, pe, status="completed", row_count=len(rows), transparency=res.transparency
        )
        return {"id": "handles", "status": "completed", "rows": len(rows)}
    except AppError as exc:
        return _finish_plugin_error(db, pe, exc, "handles", cancelled)


def _run_findings(db: Database, run_id: str, evidence_id: str) -> dict[str, Any]:
    added = 0
    for row in db.fetchall(
        "SELECT id, pid, command_line FROM processes WHERE evidence_id = ?",
        (evidence_id,),
    ):
        if not row.get("command_line"):
            continue
        for f in findings_from_cmdline(
            evidence_id=evidence_id,
            analysis_run_id=run_id,
            process_id=row["id"],
            pid=int(row["pid"]),
            command_line=row["command_line"],
        ):
            existing = db.fetchone(
                """
                SELECT id FROM findings
                WHERE evidence_id = ? AND process_id = ? AND finding_type = ? AND field_value = ?
                """,
                (evidence_id, row["id"], f["finding_type"], f.get("field_value")),
            )
            if existing:
                continue
            process_analysis._insert_finding(db, f)
            added += 1
    return {"id": "findings", "status": "completed", "rows": added}
