"""Process deep-dive and recommended analysis (Volatility 3 APIs)."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from memscope_engine.analysis.progress import emit_live, persist_live
from memscope_engine.errors import AppError
from memscope_engine.storage import Database
from memscope_engine.volatility.normalize import (
    findings_from_cmdline,
    findings_from_vad,
    normalize_cmdline,
    normalize_dlllist,
    normalize_handles,
    normalize_netscan,
    normalize_pslist,
    normalize_vadinfo,
    normalize_windows_info,
)
from memscope_engine.volatility.session import VolatilitySession

log = logging.getLogger("memscope.analysis")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cancelled(check: Callable[[], bool]) -> None:
    if check():
        raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")


def _note_plugin_error(
    db: Database,
    pe: str,
    summary: dict[str, Any],
    plugin: str,
    exc: AppError,
    cancelled: Callable[[], bool] | None = None,
) -> None:
    is_cancel = exc.code == "job_cancelled"
    if not is_cancel and cancelled is not None:
        try:
            is_cancel = bool(cancelled())
        except Exception:
            is_cancel = False
    _record_plugin_done(
        db, pe, status="cancelled" if is_cancel else "failed", error=exc.to_dict()
    )
    summary["plugins"].append(
        {
            "plugin": plugin,
            "status": "cancelled" if is_cancel else "failed",
            "error": exc.message,
        }
    )
    if is_cancel:
        raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job") from exc


def _record_plugin_start(
    db: Database,
    *,
    run_id: str,
    evidence_id: str,
    plugin: str,
    parameters: dict[str, Any],
) -> str:
    exec_id = str(uuid4())
    db.execute(
        """
        INSERT INTO plugin_executions (
          id, analysis_run_id, evidence_id, plugin, parameters_json,
          status, started_at, finished_at, error_json, row_count, transparency_json
        ) VALUES (?, ?, ?, ?, ?, 'running', ?, NULL, NULL, NULL, '{}')
        """,
        (exec_id, run_id, evidence_id, plugin, json.dumps(parameters), _utcnow()),
    )
    return exec_id


def _record_plugin_done(
    db: Database,
    exec_id: str,
    *,
    status: str,
    row_count: int | None = None,
    transparency: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
) -> None:
    db.execute(
        """
        UPDATE plugin_executions SET status = ?, finished_at = ?, row_count = ?,
          transparency_json = ?, error_json = ? WHERE id = ?
        """,
        (
            status,
            _utcnow(),
            row_count,
            json.dumps(transparency or {}),
            json.dumps(error) if error else None,
            exec_id,
        ),
    )


def _emit_progress(
    progress: Callable[..., None],
    msg: str,
    extra: dict[str, Any] | None = None,
) -> None:
    if extra is None:
        progress(msg)
        return
    try:
        progress(msg, extra)
    except TypeError:
        progress(msg)


def run_basic_triage_job(
    db: Database,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: Callable[[str], None],
) -> dict[str, Any]:
    evidence_id = params["evidence_id"]
    job_id = params.get("job_id")
    evidence = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    if not evidence:
        raise AppError(code="evidence_missing", message="Evidence not found.", entity="evidence")

    path = Path(evidence["path"])
    run_id = str(uuid4())
    strategy = [
        {"plugin": "windows.info", "reason": "OS / architecture / symbol status"},
        {"plugin": "windows.pslist", "reason": "Enumerate active processes"},
    ]
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at, error_json,
          volatility_version, schema_version, notes, process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'basic_triage', 'running', ?, NULL, NULL, NULL, 2, ?, NULL, NULL, ?, ?)
        """,
        (run_id, evidence_id, _utcnow(), "windows.info + windows.pslist", job_id, json.dumps(strategy)),
    )
    if job_id:
        db.execute(
            "UPDATE jobs SET analysis_run_id = ? WHERE id = ?",
            (run_id, job_id),
        )

    vol_version = None
    try:
        _cancelled(cancelled)
        _emit_progress(
            progress,
            "Opening memory image (Volatility session)",
            {"phase": "processes", "percent": 5},
        )
        session = VolatilitySession(path)
        vol_version = session.volatility_version

        from volatility3.plugins.windows.info import Info
        from volatility3.plugins.windows.pslist import PsList

        _cancelled(cancelled)
        _emit_progress(progress, "Running windows.info", {"phase": "processes", "percent": 5})
        info_exec = _record_plugin_start(
            db, run_id=run_id, evidence_id=evidence_id, plugin="windows.info", parameters={}
        )
        info_result = session.run_plugin(Info, cancelled=cancelled)
        _record_plugin_done(
            db,
            info_exec,
            status="completed",
            row_count=len(info_result.rows),
            transparency=info_result.transparency,
        )
        info_norm = normalize_windows_info(info_result.columns, info_result.rows)
        db.execute(
            """
            UPDATE evidence SET detected_os = ?, architecture = ?, volatility_compatible = 1,
              symbol_status = ?, symbol_detail = ?, metadata_json = ?, import_status = 'analyzed'
            WHERE id = ?
            """,
            (
                info_norm.get("detected_os"),
                info_norm.get("architecture"),
                info_norm.get("symbol_status") or "unknown",
                info_norm.get("symbol_detail"),
                json.dumps(info_norm.get("info") or {}),
                evidence_id,
            ),
        )

        _cancelled(cancelled)
        _emit_progress(progress, "Running windows.pslist", {"phase": "processes", "percent": 5})
        ps_exec = _record_plugin_start(
            db, run_id=run_id, evidence_id=evidence_id, plugin="windows.pslist", parameters={}
        )
        ps_result = session.run_plugin(PsList, cancelled=cancelled)
        processes = normalize_pslist(
            ps_result.columns,
            ps_result.rows,
            evidence_id=evidence_id,
            analysis_run_id=run_id,
            source_plugin=ps_result.plugin,
        )
        db.execute("DELETE FROM processes WHERE evidence_id = ?", (evidence_id,))
        emit_live(
            progress,
            db,
            evidence_id,
            "Running windows.pslist",
            {"phase": "processes"},
        )
        persist_live(
            db,
            evidence_id,
            processes,
            lambda p: _insert_process(db, p),
            progress=progress,
            message="Running windows.pslist",
            extra={"phase": "processes"},
        )
        _record_plugin_done(
            db,
            ps_exec,
            status="completed",
            row_count=len(processes),
            transparency=ps_result.transparency,
        )

        db.execute(
            """
            UPDATE analysis_runs SET status = 'completed', finished_at = ?, volatility_version = ?
            WHERE id = ?
            """,
            (_utcnow(), vol_version, run_id),
        )
        evidence = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
        return {
            "analysis_run_id": run_id,
            "process_count": len(processes),
            "strategy": strategy,
            "evidence_id": evidence_id,
        }
    except AppError as exc:
        was_cancelled = exc.code == "job_cancelled" or cancelled()
        db.execute(
            """
            UPDATE analysis_runs SET status = ?, finished_at = ?, error_json = ?,
              volatility_version = ? WHERE id = ?
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
                run_id,
            ),
        )
        if not was_cancelled:
            db.execute(
                """
                UPDATE evidence SET volatility_compatible = 0, import_status = 'analysis_failed'
                WHERE id = ?
                """,
                (evidence_id,),
            )
        if was_cancelled and exc.code != "job_cancelled":
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job") from exc
        raise


def run_process_recommended_job(
    db: Database,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: Callable[..., None],
) -> dict[str, Any]:
    evidence_id = params["evidence_id"]
    process_id = params.get("process_id")
    pid = params.get("pid")
    job_id = params.get("job_id")

    if process_id:
        proc = db.fetchone("SELECT * FROM processes WHERE id = ?", (process_id,))
    elif pid is not None:
        proc = db.fetchone(
            """
            SELECT * FROM processes WHERE evidence_id = ? AND pid = ?
            ORDER BY analysis_run_id DESC LIMIT 1
            """,
            (evidence_id, int(pid)),
        )
    else:
        raise AppError(
            code="process_required",
            message="process_id or pid is required for recommended process analysis.",
            entity="process",
        )

    if not proc:
        raise AppError(code="process_missing", message="Process not found.", entity="process")

    process_id = proc["id"]
    pid = int(proc["pid"])
    evidence = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    if not evidence:
        raise AppError(code="evidence_missing", message="Evidence not found.", entity="evidence")

    strategy = [
        {
            "plugin": "windows.cmdline",
            "pid": pid,
            "reason": "Command line for selected process",
        },
        {
            "plugin": "windows.dlllist",
            "pid": pid,
            "reason": "Loaded modules/DLLs for selected process",
        },
        {
            "plugin": "windows.netscan",
            "pid_filter": pid,
            "reason": "Network endpoints; filter results to selected PID (plugin is image-wide)",
        },
        {
            "plugin": "windows.handles",
            "pid": pid,
            "reason": "Open handles for selected process",
        },
        {
            "plugin": "windows.vadinfo",
            "pid": pid,
            "reason": "VAD/memory regions for selected process",
        },
    ]

    run_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, finished_at, error_json,
          volatility_version, schema_version, notes, process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'process_recommended', 'running', ?, NULL, NULL, NULL, 2, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            evidence_id,
            _utcnow(),
            f"Recommended analysis for PID {pid}",
            process_id,
            pid,
            job_id,
            json.dumps(strategy),
        ),
    )
    if job_id:
        db.execute("UPDATE jobs SET analysis_run_id = ? WHERE id = ?", (run_id, job_id))

    path = Path(evidence["path"])
    vol_version = None
    summary: dict[str, Any] = {"plugins": []}

    try:
        _cancelled(cancelled)
        _emit_progress(
            progress,
            f"Opening image for PID {pid}",
            {"phase": "session", "percent": 8},
        )
        session = VolatilitySession(path)
        vol_version = session.volatility_version

        # --- cmdline ---
        from volatility3.plugins.windows.cmdline import CmdLine

        _cancelled(cancelled)
        _emit_progress(
            progress,
            f"windows.cmdline (pid={pid})",
            {"phase": "command_lines", "percent": 20},
        )
        pe = _record_plugin_start(
            db,
            run_id=run_id,
            evidence_id=evidence_id,
            plugin="windows.cmdline",
            parameters={"pid": [pid]},
        )
        try:
            res = session.run_plugin(CmdLine, {"pid": [pid]}, cancelled=cancelled)
            rows = normalize_cmdline(res.columns, res.rows, pid_filter=pid)
            if rows and rows[0].get("command_line") is not None:
                db.execute(
                    "UPDATE processes SET command_line = ? WHERE id = ?",
                    (rows[0]["command_line"], process_id),
                )
                for f in findings_from_cmdline(
                    evidence_id=evidence_id,
                    analysis_run_id=run_id,
                    process_id=process_id,
                    pid=pid,
                    command_line=rows[0]["command_line"],
                ):
                    _insert_finding(db, f)
            _record_plugin_done(
                db, pe, status="completed", row_count=len(rows), transparency=res.transparency
            )
            summary["plugins"].append({"plugin": "windows.cmdline", "status": "completed", "rows": len(rows)})
        except AppError as exc:
            _note_plugin_error(db, pe, summary, "windows.cmdline", exc, cancelled)

        # --- dlllist ---
        from volatility3.plugins.windows.dlllist import DllList

        _cancelled(cancelled)
        _emit_progress(
            progress,
            f"windows.dlllist (pid={pid})",
            {"phase": "modules", "percent": 27},
        )
        pe = _record_plugin_start(
            db,
            run_id=run_id,
            evidence_id=evidence_id,
            plugin="windows.dlllist",
            parameters={"pid": [pid]},
        )
        try:
            res = session.run_plugin(DllList, {"pid": [pid]}, cancelled=cancelled)
            mods = normalize_dlllist(
                res.columns,
                res.rows,
                evidence_id=evidence_id,
                analysis_run_id=run_id,
                process_id=process_id,
                pid_filter=pid,
                source_plugin=res.plugin,
            )
            db.execute(
                "DELETE FROM modules WHERE evidence_id = ? AND pid = ?",
                (evidence_id, pid),
            )
            for m in mods:
                _insert_module(db, m)
            # Prefer image path from first matching module name == process name
            if not proc.get("image_path"):
                for m in mods:
                    if m.get("path") and m.get("name") and proc.get("name"):
                        if str(m["name"]).lower() == str(proc["name"]).lower():
                            db.execute(
                                "UPDATE processes SET image_path = ? WHERE id = ?",
                                (m["path"], process_id),
                            )
                            break
            _record_plugin_done(
                db, pe, status="completed", row_count=len(mods), transparency=res.transparency
            )
            summary["plugins"].append({"plugin": "windows.dlllist", "status": "completed", "rows": len(mods)})
        except AppError as exc:
            _note_plugin_error(db, pe, summary, "windows.dlllist", exc, cancelled)

        # --- netscan (image-wide, filter to pid) ---
        from volatility3.plugins.windows.netscan import NetScan

        _cancelled(cancelled)
        _emit_progress(
            progress,
            "windows.netscan (filter to PID)",
            {"phase": "network", "percent": 37},
        )
        pe = _record_plugin_start(
            db,
            run_id=run_id,
            evidence_id=evidence_id,
            plugin="windows.netscan",
            parameters={"pid_filter": pid},
        )
        try:
            res = session.run_plugin(NetScan, cancelled=cancelled)
            pid_map = {pid: process_id}
            conns = normalize_netscan(
                res.columns,
                res.rows,
                evidence_id=evidence_id,
                analysis_run_id=run_id,
                process_id_by_pid=pid_map,
                pid_filter=pid,
                source_plugin=res.plugin,
            )
            # Replace this PID's connections; keep others from prior runs
            db.execute(
                "DELETE FROM network_connections WHERE evidence_id = ? AND pid = ?",
                (evidence_id, pid),
            )
            for c in conns:
                _insert_net(db, c)
            _record_plugin_done(
                db, pe, status="completed", row_count=len(conns), transparency=res.transparency
            )
            summary["plugins"].append({"plugin": "windows.netscan", "status": "completed", "rows": len(conns)})
        except AppError as exc:
            _note_plugin_error(db, pe, summary, "windows.netscan", exc, cancelled)

        # --- handles ---
        from volatility3.plugins.windows.handles import Handles

        _cancelled(cancelled)
        _emit_progress(
            progress,
            f"windows.handles (pid={pid})",
            {"phase": "handles", "percent": 47},
        )
        pe = _record_plugin_start(
            db,
            run_id=run_id,
            evidence_id=evidence_id,
            plugin="windows.handles",
            parameters={"pid": [pid]},
        )
        try:
            res = session.run_plugin(Handles, {"pid": [pid]}, cancelled=cancelled)
            handles_rows = normalize_handles(
                res.columns,
                res.rows,
                evidence_id=evidence_id,
                analysis_run_id=run_id,
                process_id=process_id,
                pid_filter=pid,
                source_plugin=res.plugin,
            )
            db.execute(
                "DELETE FROM handle_entries WHERE evidence_id = ? AND pid = ?",
                (evidence_id, pid),
            )
            for h in handles_rows:
                _insert_handle(db, h)
            _record_plugin_done(
                db,
                pe,
                status="completed",
                row_count=len(handles_rows),
                transparency=res.transparency,
            )
            summary["plugins"].append(
                {"plugin": "windows.handles", "status": "completed", "rows": len(handles_rows)}
            )
        except AppError as exc:
            _note_plugin_error(db, pe, summary, "windows.handles", exc, cancelled)

        # --- vadinfo ---
        from volatility3.plugins.windows.vadinfo import VadInfo

        _cancelled(cancelled)
        _emit_progress(
            progress,
            f"windows.vadinfo (pid={pid})",
            {"phase": "memory_vad", "percent": 85},
        )
        pe = _record_plugin_start(
            db,
            run_id=run_id,
            evidence_id=evidence_id,
            plugin="windows.vadinfo",
            parameters={"pid": [pid]},
        )
        try:
            res = session.run_plugin(VadInfo, {"pid": [pid]}, cancelled=cancelled)
            regions = normalize_vadinfo(
                res.columns,
                res.rows,
                evidence_id=evidence_id,
                analysis_run_id=run_id,
                process_id=process_id,
                pid_filter=pid,
                source_plugin=res.plugin,
            )
            db.execute(
                "DELETE FROM memory_regions WHERE evidence_id = ? AND pid = ?",
                (evidence_id, pid),
            )
            for r in regions:
                er = r
                try:
                    from memscope_engine.analysis.memory_artifacts import enrich_region

                    er = enrich_region(r)
                    r = dict(r)
                    r["size_bytes"] = er.get("size_bytes")
                    r["indicators_json"] = json.dumps(er.get("indicators") or [])
                except Exception:  # noqa: BLE001
                    r.setdefault("indicators_json", "[]")
                _insert_region(db, r)
                for f in findings_from_vad(
                    evidence_id=evidence_id,
                    analysis_run_id=run_id,
                    process_id=process_id,
                    pid=pid,
                    regions=[er],
                ):
                    _insert_finding(db, f)
            _record_plugin_done(
                db, pe, status="completed", row_count=len(regions), transparency=res.transparency
            )
            summary["plugins"].append(
                {"plugin": "windows.vadinfo", "status": "completed", "rows": len(regions)}
            )
        except AppError as exc:
            _note_plugin_error(db, pe, summary, "windows.vadinfo", exc, cancelled)

        db.execute(
            """
            UPDATE analysis_runs SET status = 'completed', finished_at = ?, volatility_version = ?
            WHERE id = ?
            """,
            (_utcnow(), vol_version, run_id),
        )
        summary["analysis_run_id"] = run_id
        summary["process_id"] = process_id
        summary["pid"] = pid
        summary["strategy"] = strategy
        return summary
    except AppError as exc:
        was_cancelled = exc.code == "job_cancelled" or cancelled()
        db.execute(
            """
            UPDATE analysis_runs SET status = ?, finished_at = ?, error_json = ?,
              volatility_version = ? WHERE id = ?
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
                run_id,
            ),
        )
        if was_cancelled and exc.code != "job_cancelled":
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job") from exc
        raise


def get_process_deep_dive(db: Database, process_id: str) -> dict[str, Any]:
    proc = db.fetchone("SELECT * FROM processes WHERE id = ?", (process_id,))
    if not proc:
        raise AppError(code="process_missing", message="Process not found.", entity="process")

    evidence_id = proc["evidence_id"]
    pid = proc["pid"]

    parent = None
    if proc.get("ppid") is not None:
        parent = db.fetchone(
            """
            SELECT * FROM processes WHERE evidence_id = ? AND pid = ?
            ORDER BY analysis_run_id DESC LIMIT 1
            """,
            (evidence_id, proc["ppid"]),
        )
    children = db.fetchall(
        """
        SELECT * FROM processes WHERE evidence_id = ? AND ppid = ?
        ORDER BY pid ASC
        """,
        (evidence_id, pid),
    )
    modules = db.fetchall(
        "SELECT * FROM modules WHERE evidence_id = ? AND pid = ? ORDER BY name COLLATE NOCASE",
        (evidence_id, pid),
    )
    network = db.fetchall(
        "SELECT * FROM network_connections WHERE evidence_id = ? AND pid = ? ORDER BY protocol, local_port",
        (evidence_id, pid),
    )
    handles = db.fetchall(
        "SELECT * FROM handle_entries WHERE evidence_id = ? AND pid = ? ORDER BY handle_type, name LIMIT 5000",
        (evidence_id, pid),
    )
    regions = db.fetchall(
        "SELECT * FROM memory_regions WHERE evidence_id = ? AND pid = ? ORDER BY start_vpn LIMIT 5000",
        (evidence_id, pid),
    )
    findings = db.fetchall(
        "SELECT * FROM findings WHERE evidence_id = ? AND pid = ? ORDER BY created_at DESC",
        (evidence_id, pid),
    )
    runs = db.fetchall(
        """
        SELECT id, kind, status, started_at, finished_at, notes, strategy_json, job_id
        FROM analysis_runs
        WHERE evidence_id = ? AND (process_id = ? OR pid = ?)
        ORDER BY started_at DESC LIMIT 20
        """,
        (evidence_id, process_id, pid),
    )
    for r in runs:
        try:
            r["strategy"] = json.loads(r.get("strategy_json") or "[]")
        except json.JSONDecodeError:
            r["strategy"] = []

    return {
        "process": _process_dto(proc),
        "parent": _process_dto(parent) if parent else None,
        "children": [_process_dto(c) for c in children],
        "modules": [_module_dto(m) for m in modules],
        "network": [_net_dto(n) for n in network],
        "handles": [_handle_dto(h) for h in handles],
        "memory_regions": [_region_dto_enriched(r) for r in regions],
        "findings": [_finding_dto(f) for f in findings],
        "analysis_runs": runs,
        "counts": {
            "modules": len(modules),
            "network": len(network),
            "handles": len(handles),
            "memory_regions": len(regions),
            "findings": len(findings),
            "children": len(children),
        },
    }


def list_network(db: Database, evidence_id: str) -> dict[str, Any]:
    rows = db.fetchall(
        """
        SELECT * FROM network_connections WHERE evidence_id = ?
        ORDER BY pid, protocol, local_port
        """,
        (evidence_id,),
    )
    names = _process_names_by_pid(db, evidence_id)
    return {
        "evidence_id": evidence_id,
        "total": len(rows),
        "items": [_net_dto(r, names) for r in rows],
    }


def list_modules(db: Database, evidence_id: str, pid: int | None = None) -> dict[str, Any]:
    if pid is not None:
        rows = db.fetchall(
            "SELECT * FROM modules WHERE evidence_id = ? AND pid = ? ORDER BY name COLLATE NOCASE",
            (evidence_id, pid),
        )
    else:
        rows = db.fetchall(
            "SELECT * FROM modules WHERE evidence_id = ? ORDER BY pid, name COLLATE NOCASE LIMIT 20000",
            (evidence_id,),
        )
    names = _process_names_by_pid(db, evidence_id)
    return {
        "evidence_id": evidence_id,
        "total": len(rows),
        "items": [_module_dto(r, names) for r in rows],
    }


def _canonical_finding_severity(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if value in ("", "informational"):
        return "info"
    return value or "info"


def _severity_filter_values(severity: str) -> tuple[str, ...]:
    key = _canonical_finding_severity(severity)
    if key == "info":
        return ("info", "informational", "")
    return (key,)


def _finding_count(
    db: Database, evidence_id: str, severity: str | None = None
) -> int:
    sql = "SELECT COUNT(*) AS n FROM findings WHERE evidence_id = ?"
    args: list[Any] = [evidence_id]
    if severity:
        values = _severity_filter_values(severity)
        sql += " AND LOWER(TRIM(IFNULL(severity, ''))) IN ({})".format(
            ",".join("?" * len(values))
        )
        args.extend(values)
    row = db.fetchone(sql, tuple(args))
    return int((row or {}).get("n") or 0)


def _finding_severity_counts(db: Database, evidence_id: str) -> dict[str, int]:
    rows = db.fetchall(
        """
        SELECT severity, COUNT(*) AS n FROM findings
        WHERE evidence_id = ? GROUP BY severity
        """,
        (evidence_id,),
    )
    out: dict[str, int] = {}
    for row in rows:
        key = _canonical_finding_severity(row.get("severity"))
        out[key] = out.get(key, 0) + int(row["n"] or 0)
    return out


def list_findings(
    db: Database,
    evidence_id: str,
    *,
    severity: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    total = _finding_count(db, evidence_id, severity)
    sql = "SELECT * FROM findings WHERE evidence_id = ?"
    args: list[Any] = [evidence_id]
    if severity:
        values = _severity_filter_values(severity)
        sql += " AND LOWER(TRIM(IFNULL(severity, ''))) IN ({})".format(
            ",".join("?" * len(values))
        )
        args.extend(values)
    sql += """
        ORDER BY CASE LOWER(TRIM(IFNULL(severity, '')))
          WHEN 'critical' THEN 0
          WHEN 'high' THEN 1
          WHEN 'medium' THEN 2
          WHEN 'low' THEN 3
          WHEN 'info' THEN 4
          WHEN 'informational' THEN 4
          ELSE 50
        END, created_at DESC
    """
    start = max(0, int(offset or 0))
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        args.extend([max(0, int(limit)), start])
    rows = db.fetchall(sql, tuple(args))
    return {
        "evidence_id": evidence_id,
        "total": total,
        "items": [_finding_dto(r) for r in rows],
        "severity_counts": _finding_severity_counts(db, evidence_id),
        "offset": start,
        "limit": int(limit) if limit is not None else None,
    }


def _insert_process(db: Database, p: dict[str, Any]) -> None:
    db.execute(
        """
        INSERT INTO processes (
          id, evidence_id, analysis_run_id, pid, ppid, name, username,
          image_path, command_line, create_time, exit_time, offset_hex,
          threads, handles, session_id, wow64, source_plugin
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            p["id"],
            p["evidence_id"],
            p["analysis_run_id"],
            p["pid"],
            p["ppid"],
            p["name"],
            p["username"],
            p["image_path"],
            p["command_line"],
            p["create_time"],
            p["exit_time"],
            p["offset_hex"],
            p["threads"],
            p["handles"],
            p["session_id"],
            1 if p["wow64"] else (0 if p["wow64"] is False else None),
            p["source_plugin"],
        ),
    )


def _insert_module(db: Database, m: dict[str, Any]) -> None:
    db.execute(
        """
        INSERT INTO modules (
          id, evidence_id, analysis_run_id, process_id, pid, name, path,
          base_address, size, load_count, load_time, source_plugin
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            m["id"],
            m["evidence_id"],
            m["analysis_run_id"],
            m["process_id"],
            m["pid"],
            m["name"],
            m["path"],
            m["base_address"],
            m["size"],
            m["load_count"],
            m["load_time"],
            m["source_plugin"],
        ),
    )


def _insert_net(db: Database, c: dict[str, Any]) -> None:
    db.execute(
        """
        INSERT INTO network_connections (
          id, evidence_id, analysis_run_id, process_id, pid, protocol,
          local_address, local_port, remote_address, remote_port, state,
          owner, created, offset_hex, source_plugin
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            c["id"],
            c["evidence_id"],
            c["analysis_run_id"],
            c["process_id"],
            c["pid"],
            c["protocol"],
            c["local_address"],
            c["local_port"],
            c["remote_address"],
            c["remote_port"],
            c["state"],
            c["owner"],
            c["created"],
            c["offset_hex"],
            c["source_plugin"],
        ),
    )


def _insert_handle(db: Database, h: dict[str, Any]) -> None:
    db.execute(
        """
        INSERT INTO handle_entries (
          id, evidence_id, analysis_run_id, process_id, pid, offset_hex,
          handle_value, handle_type, granted_access, name, source_plugin
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            h["id"],
            h["evidence_id"],
            h["analysis_run_id"],
            h["process_id"],
            h["pid"],
            h["offset_hex"],
            h["handle_value"],
            h["handle_type"],
            h["granted_access"],
            h["name"],
            h["source_plugin"],
        ),
    )


def _insert_region(db: Database, r: dict[str, Any]) -> None:
    db.execute(
        """
        INSERT INTO memory_regions (
          id, evidence_id, analysis_run_id, process_id, pid, process_name,
          offset_hex, start_vpn, end_vpn, tag, protection, commit_charge,
          private_memory, parent, file_path, source_plugin, size_bytes, indicators_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            r["id"],
            r["evidence_id"],
            r["analysis_run_id"],
            r["process_id"],
            r["pid"],
            r["process_name"],
            r["offset_hex"],
            r["start_vpn"],
            r["end_vpn"],
            r["tag"],
            r["protection"],
            r["commit_charge"],
            r["private_memory"],
            r["parent"],
            r["file_path"],
            r["source_plugin"],
            r.get("size_bytes"),
            r.get("indicators_json") or "[]",
        ),
    )


def _insert_finding(db: Database, f: dict[str, Any]) -> None:
    db.execute(
        """
        INSERT INTO findings (
          id, evidence_id, analysis_run_id, process_id, pid, finding_type,
          severity, explanation, field_name, field_value, plugin, confidence, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f["id"],
            f["evidence_id"],
            f["analysis_run_id"],
            f["process_id"],
            f["pid"],
            f["finding_type"],
            f["severity"],
            f["explanation"],
            f["field_name"],
            f["field_value"],
            f["plugin"],
            f["confidence"],
            f["created_at"],
        ),
    )


def _process_dto(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not row:
        return None
    wow = row.get("wow64")
    return {
        "id": row["id"],
        "evidence_id": row["evidence_id"],
        "analysis_run_id": row["analysis_run_id"],
        "pid": row["pid"],
        "ppid": row.get("ppid"),
        "name": row.get("name"),
        "username": row.get("username"),
        "image_path": row.get("image_path"),
        "command_line": row.get("command_line"),
        "create_time": row.get("create_time"),
        "exit_time": row.get("exit_time"),
        "offset_hex": row.get("offset_hex"),
        "threads": row.get("threads"),
        "handles": row.get("handles"),
        "session_id": row.get("session_id"),
        "wow64": bool(wow) if wow is not None else None,
        "source_plugin": row.get("source_plugin"),
    }


def _process_names_by_pid(db: Database, evidence_id: str) -> dict[int, str]:
    names: dict[int, str] = {}
    for row in db.fetchall(
        """
        SELECT pid, name FROM processes
        WHERE evidence_id = ? AND name IS NOT NULL AND TRIM(name) != ''
        """,
        (evidence_id,),
    ):
        names[int(row["pid"])] = str(row["name"])
    return names


def _process_name_for_pid(pid: Any, names: dict[int, str] | None) -> str | None:
    if names is None or pid is None:
        return None
    try:
        return names.get(int(pid))
    except (TypeError, ValueError):
        return None


def _module_dto(row: dict[str, Any], names: dict[int, str] | None = None) -> dict[str, Any]:
    return {
        "id": row["id"],
        "evidence_id": row["evidence_id"],
        "process_id": row.get("process_id"),
        "pid": row["pid"],
        "process_name": _process_name_for_pid(row.get("pid"), names),
        "name": row.get("name"),
        "path": row.get("path"),
        "base_address": row.get("base_address"),
        "size": row.get("size"),
        "load_count": row.get("load_count"),
        "load_time": row.get("load_time"),
        "source_plugin": row.get("source_plugin"),
    }


def _net_dto(row: dict[str, Any], names: dict[int, str] | None = None) -> dict[str, Any]:
    return {
        "id": row["id"],
        "evidence_id": row["evidence_id"],
        "process_id": row.get("process_id"),
        "pid": row.get("pid"),
        "process_name": _process_name_for_pid(row.get("pid"), names),
        "protocol": row.get("protocol"),
        "local_address": row.get("local_address"),
        "local_port": row.get("local_port"),
        "remote_address": row.get("remote_address"),
        "remote_port": row.get("remote_port"),
        "state": row.get("state"),
        "owner": row.get("owner"),
        "created": row.get("created"),
        "offset_hex": row.get("offset_hex"),
        "source_plugin": row.get("source_plugin"),
    }


def _handle_dto(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "pid": row["pid"],
        "offset_hex": row.get("offset_hex"),
        "handle_value": row.get("handle_value"),
        "handle_type": row.get("handle_type"),
        "granted_access": row.get("granted_access"),
        "name": row.get("name"),
        "source_plugin": row.get("source_plugin"),
    }


def _region_dto(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "pid": row["pid"],
        "process_name": row.get("process_name"),
        "offset_hex": row.get("offset_hex"),
        "start_vpn": row.get("start_vpn"),
        "end_vpn": row.get("end_vpn"),
        "tag": row.get("tag"),
        "protection": row.get("protection"),
        "commit_charge": row.get("commit_charge"),
        "private_memory": row.get("private_memory"),
        "parent": row.get("parent"),
        "file_path": row.get("file_path"),
        "source_plugin": row.get("source_plugin"),
        "size_bytes": row.get("size_bytes"),
        "process_id": row.get("process_id"),
        "evidence_id": row.get("evidence_id"),
    }


def _region_dto_enriched(row: dict[str, Any]) -> dict[str, Any]:
    from memscope_engine.analysis.memory_artifacts import enrich_region

    return enrich_region(_region_dto(row))


def _finding_dto(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "evidence_id": row["evidence_id"],
        "process_id": row.get("process_id"),
        "pid": row.get("pid"),
        "finding_type": row["finding_type"],
        "severity": row["severity"],
        "explanation": row["explanation"],
        "field_name": row.get("field_name"),
        "field_value": row.get("field_value"),
        "plugin": row.get("plugin"),
        "confidence": row.get("confidence"),
        "created_at": row.get("created_at"),
    }
