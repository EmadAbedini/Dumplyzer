"""Memory/VAD listing, indicators, dump extraction, timeline, artifacts."""

from __future__ import annotations

import io
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from memscope_engine.artifacts import store as artifact_store
from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths
from memscope_engine.storage import Database
from memscope_engine.volatility.normalize import (
    findings_from_vad,
    normalize_vadinfo,
)
from memscope_engine.volatility.session import VolatilitySession

log = logging.getLogger("memscope.analysis")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_hex(value: str | None) -> int | None:
    if value is None:
        return None
    s = str(value).strip().lower()
    try:
        if s.startswith("0x"):
            return int(s, 16)
        return int(s, 16) if any(c in s for c in "abcdef") else int(s)
    except ValueError:
        try:
            return int(s, 0)
        except ValueError:
            return None


def region_indicators(region: dict[str, Any]) -> list[dict[str, str]]:
    """Evidence-based flags — never claim 'malicious' without context."""
    flags: list[dict[str, str]] = []
    prot = (region.get("protection") or "").upper()
    private = region.get("private_memory")
    file_path = region.get("file_path")
    tag = (region.get("tag") or "").lower()

    has_exec = "EXECUTE" in prot or "EXEC" in prot
    has_write = "WRITE" in prot or "WRITECOPY" in prot or "WRITE_COPY" in prot
    # PAGE_EXECUTE_READWRITE and similar
    if has_exec and has_write:
        flags.append(
            {
                "code": "writable_executable",
                "label": "Writable+executable protection",
                "detail": f"Protection string is '{region.get('protection')}'.",
            }
        )
    if private in (1, True) and has_exec and not file_path:
        flags.append(
            {
                "code": "private_executable_unbacked",
                "label": "Private executable, no file backing",
                "detail": "PrivateMemory indicates private pages with execute and no File mapping.",
            }
        )
    if has_exec and not file_path and "vad" in tag:
        flags.append(
            {
                "code": "executable_no_file",
                "label": "Executable region without file mapping",
                "detail": "Executable VAD lacks a File path from vadinfo.",
            }
        )
    size = region.get("size_bytes")
    if size is not None and size > 50 * 1024 * 1024 and has_exec:
        flags.append(
            {
                "code": "large_executable",
                "label": "Large executable region",
                "detail": f"Size is {size} bytes with execute permission.",
            }
        )
    return flags


def enrich_region(region: dict[str, Any]) -> dict[str, Any]:
    start = _parse_hex(region.get("start_vpn"))
    end = _parse_hex(region.get("end_vpn"))
    size = None
    if start is not None and end is not None and end >= start:
        # End VPN is typically inclusive page end in Vol3 get_end semantics —
        # size from plugin is more reliable when available; use end-start if positive.
        size = max(0, end - start)
    region = dict(region)
    if region.get("size_bytes") is None and size is not None:
        region["size_bytes"] = size
    indicators = region_indicators(region)
    region["indicators"] = indicators
    region["indicator_codes"] = [i["code"] for i in indicators]
    return region


def list_memory_regions(
    db: Database,
    evidence_id: str,
    *,
    pid: int | None = None,
    process_id: str | None = None,
    suspicious_only: bool = False,
    limit: int = 10000,
    offset: int = 0,
) -> dict[str, Any]:
    if not db.fetchone("SELECT id FROM evidence WHERE id = ?", (evidence_id,)):
        raise AppError(code="evidence_missing", message="Evidence not found.", entity="evidence")

    clauses = ["evidence_id = ?"]
    params: list[Any] = [evidence_id]
    if pid is not None:
        clauses.append("pid = ?")
        params.append(pid)
    if process_id:
        clauses.append("process_id = ?")
        params.append(process_id)
    where = " AND ".join(clauses)

    rows = db.fetchall(
        f"""
        SELECT * FROM memory_regions
        WHERE {where}
        ORDER BY pid, start_vpn
        LIMIT ? OFFSET ?
        """,
        tuple(params + [limit, offset]),
    )
    items = []
    for r in rows:
        dto = _region_dto(r)
        dto = enrich_region(dto)
        if suspicious_only and not dto["indicators"]:
            continue
        items.append(dto)

    total_row = db.fetchone(
        f"SELECT COUNT(*) AS c FROM memory_regions WHERE {where}",
        tuple(params),
    )
    return {
        "evidence_id": evidence_id,
        "total": int(total_row["c"]) if total_row else 0,
        "returned": len(items),
        "items": items,
        "suspicious_only": suspicious_only,
    }


def get_memory_region(db: Database, region_id: str) -> dict[str, Any]:
    row = db.fetchone("SELECT * FROM memory_regions WHERE id = ?", (region_id,))
    if not row:
        raise AppError(code="region_missing", message="Memory region not found.", entity="memory")
    dto = enrich_region(_region_dto(row))
    arts = db.fetchall(
        "SELECT * FROM artifacts WHERE memory_region_id = ? ORDER BY extracted_at DESC",
        (region_id,),
    )
    dto["artifacts"] = [_artifact_dto(a) for a in arts]
    return dto


def run_vad_scan_job(
    db: Database,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: Callable[[str], None],
) -> dict[str, Any]:
    """Refresh vadinfo for one process (or all if pid omitted — not recommended)."""
    evidence_id = params["evidence_id"]
    pid = params.get("pid")
    process_id = params.get("process_id")
    job_id = params.get("job_id")

    evidence = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    if not evidence:
        raise AppError(code="evidence_missing", message="Evidence not found.", entity="evidence")

    if process_id and not pid:
        proc = db.fetchone("SELECT * FROM processes WHERE id = ?", (process_id,))
        if proc:
            pid = proc["pid"]
            process_id = proc["id"]

    if pid is None:
        raise AppError(
            code="pid_required",
            message="VAD scan requires a process PID (targeted analysis).",
            entity="memory",
        )

    if not process_id:
        proc = db.fetchone(
            "SELECT * FROM processes WHERE evidence_id = ? AND pid = ? ORDER BY analysis_run_id DESC LIMIT 1",
            (evidence_id, int(pid)),
        )
        process_id = proc["id"] if proc else None

    run_id = str(uuid4())
    strategy = [
        {
            "plugin": "windows.vadinfo",
            "pid": int(pid),
            "reason": "Enumerate VAD/memory regions for selected process",
        }
    ]
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, notes,
          process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'vad_scan', 'running', ?, 4, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            evidence_id,
            _utcnow(),
            f"vadinfo PID {pid}",
            process_id,
            int(pid),
            job_id,
            json.dumps(strategy),
        ),
    )
    if job_id:
        db.execute("UPDATE jobs SET analysis_run_id = ? WHERE id = ?", (run_id, job_id))

    if cancelled():
        raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")

    progress(f"windows.vadinfo pid={pid}")
    session = VolatilitySession(Path(evidence["path"]))
    from volatility3.plugins.windows.vadinfo import VadInfo

    exec_id = str(uuid4())
    db.execute(
        """
        INSERT INTO plugin_executions (
          id, analysis_run_id, evidence_id, plugin, parameters_json,
          status, started_at, transparency_json
        ) VALUES (?, ?, ?, 'windows.vadinfo', ?, 'running', ?, '{}')
        """,
        (exec_id, run_id, evidence_id, json.dumps({"pid": [int(pid)]}), _utcnow()),
    )
    try:
        res = session.run_plugin(VadInfo, {"pid": [int(pid)]})
        regions = normalize_vadinfo(
            res.columns,
            res.rows,
            evidence_id=evidence_id,
            analysis_run_id=run_id,
            process_id=process_id,
            pid_filter=int(pid),
            source_plugin=res.plugin,
        )
        db.execute(
            "DELETE FROM memory_regions WHERE evidence_id = ? AND pid = ?",
            (evidence_id, int(pid)),
        )
        for r in regions:
            er = enrich_region(r)
            r["size_bytes"] = er.get("size_bytes")
            r["indicators_json"] = json.dumps(er.get("indicators") or [])
            _insert_region(db, r)
            for f in findings_from_vad(
                evidence_id=evidence_id,
                analysis_run_id=run_id,
                process_id=process_id,
                pid=int(pid),
                regions=[er],
            ):
                _insert_finding(db, f)

        db.execute(
            """
            UPDATE plugin_executions SET status='completed', finished_at=?, row_count=?,
              transparency_json=? WHERE id=?
            """,
            (_utcnow(), len(regions), json.dumps(res.transparency), exec_id),
        )
        db.execute(
            """
            UPDATE analysis_runs SET status='completed', finished_at=?, volatility_version=?
            WHERE id=?
            """,
            (_utcnow(), session.volatility_version, run_id),
        )
        return {
            "analysis_run_id": run_id,
            "pid": int(pid),
            "region_count": len(regions),
            "strategy": strategy,
        }
    except AppError as exc:
        db.execute(
            "UPDATE plugin_executions SET status='failed', finished_at=?, error_json=? WHERE id=?",
            (_utcnow(), json.dumps(exc.to_dict()), exec_id),
        )
        db.execute(
            "UPDATE analysis_runs SET status=?, finished_at=?, error_json=? WHERE id=?",
            (
                "cancelled" if exc.code == "job_cancelled" else "failed",
                _utcnow(),
                json.dumps(exc.to_dict()),
                run_id,
            ),
        )
        raise


def run_vad_extract_job(
    db: Database,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: Callable[[str], None],
    *,
    paths: AppPaths,
) -> dict[str, Any]:
    """Extract one VAD region via Volatility3 VadInfo.vad_dump into artifact store."""
    evidence_id = params["evidence_id"]
    region_id = params.get("memory_region_id")
    if not region_id:
        raise AppError(
            code="region_required",
            message="memory_region_id is required for VAD extraction.",
            entity="artifact",
        )

    region = db.fetchone("SELECT * FROM memory_regions WHERE id = ?", (region_id,))
    if not region or region["evidence_id"] != evidence_id:
        raise AppError(code="region_missing", message="Memory region not found.", entity="memory")

    evidence = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    if not evidence:
        raise AppError(code="evidence_missing", message="Evidence not found.", entity="evidence")

    pid = int(region["pid"])
    start_vpn = region.get("start_vpn")
    end_vpn = region.get("end_vpn")
    start_i = _parse_hex(start_vpn)
    end_i = _parse_hex(end_vpn)
    if start_i is None:
        raise AppError(
            code="invalid_region",
            message="Region start address could not be parsed.",
            details=str(start_vpn),
            entity="memory",
        )

    maxsize = int(params.get("maxsize") or 100 * 1024 * 1024)
    job_id = params.get("job_id")
    run_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, notes,
          process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'vad_extract', 'running', ?, 4, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            evidence_id,
            _utcnow(),
            f"Extract VAD {start_vpn}-{end_vpn} PID {pid}",
            region.get("process_id"),
            pid,
            job_id,
            json.dumps(
                [
                    {
                        "plugin": "windows.vadinfo.vad_dump",
                        "reason": "Extract selected VAD bytes via Volatility API",
                        "start": start_vpn,
                        "end": end_vpn,
                    }
                ]
            ),
        ),
    )
    if job_id:
        db.execute("UPDATE jobs SET analysis_run_id = ? WHERE id = ?", (run_id, job_id))

    if cancelled():
        raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")

    progress("Constructing Volatility session for VAD dump")
    session = VolatilitySession(Path(evidence["path"]))
    from volatility3.framework import exceptions, plugins
    from volatility3.framework.automagic import stacker
    from volatility3.plugins.windows import pslist
    from volatility3.plugins.windows.vadinfo import VadInfo

    # Prepare automagics for pslist/vad access
    automagics = session._automagic.available(session.context)
    automagics = session._automagic.choose_automagic(automagics, pslist.PsList)
    if session.context.config.get("automagic.LayerStacker.stackers", None) is None:
        session.context.config["automagic.LayerStacker.stackers"] = (
            stacker.choose_os_stackers(pslist.PsList)
        )

    out_dir = artifact_store.artifact_dir(paths, evidence_id)
    preferred = artifact_store.build_artifact_filename(
        pid=pid, start_vpn=start_vpn, end_vpn=end_vpn, suffix="dmp"
    )
    open_method = _make_file_handler(out_dir)

    try:
        progress("Locating process and VAD object")
        constructed = plugins.construct_plugin(
            session.context,
            automagics,
            pslist.PsList,
            "plugins",
            lambda *_a, **_k: None,
            open_method,
        )
        try:
            kname = constructed.config["kernel"]
        except Exception as exc:  # noqa: BLE001
            raise AppError(
                code="volatility_unsatisfied",
                message="Could not resolve kernel module for process layer.",
                details=str(exc),
                entity="volatility",
            ) from exc

        proc_obj = None
        for proc in pslist.PsList.list_processes(
            session.context,
            kname,
            filter_func=pslist.PsList.create_pid_filter([pid]),
        ):
            proc_obj = proc
            break
        if proc_obj is None:
            raise AppError(
                code="process_not_in_image",
                message=f"PID {pid} was not found in the memory image for dumping.",
                entity="process",
            )

        vad_obj = None
        for vad in proc_obj.get_vad_root().traverse():
            try:
                vs = int(vad.get_start())
            except Exception:  # noqa: BLE001
                continue
            if vs == start_i:
                vad_obj = vad
                break

        if vad_obj is None:
            raise AppError(
                code="vad_not_found",
                message="Matching VAD object was not found in the process VAD tree.",
                details=f"start={start_vpn} end={end_vpn} pid={pid}",
                suggestion="Re-run VAD scan for this process, then retry extraction.",
                entity="memory",
            )

        if cancelled():
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")

        progress("Dumping VAD bytes (Volatility vad_dump)")
        handle = VadInfo.vad_dump(
            session.context,
            proc_obj,
            vad_obj,
            open_method,
            maxsize=maxsize,
        )
        if handle is None:
            raise AppError(
                code="vad_dump_failed",
                message="Volatility vad_dump returned no file (region may exceed max size or be unreadable).",
                suggestion="Check maxsize limit and region validity.",
                entity="artifact",
            )
        handle.close()
        stored_name = getattr(handle, "committed_path", None)
        if not stored_name:
            candidate = out_dir / handle.preferred_filename
            if not candidate.is_file():
                files = sorted(
                    out_dir.glob("*.dmp"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                if not files:
                    raise AppError(
                        code="vad_dump_missing_file",
                        message="VAD dump completed but output file was not found.",
                        entity="artifact",
                    )
                candidate = files[0]
            stored_path = candidate
        else:
            stored_path = Path(stored_name)

        stored_path = artifact_store.ensure_within_artifacts(paths, stored_path)
        digest = artifact_store.sha256_file(stored_path)
        size_bytes = stored_path.stat().st_size
        ftype = artifact_store.sniff_file_type(stored_path)

        art_id = str(uuid4())
        db.execute(
            """
            INSERT INTO artifacts (
              id, evidence_id, process_id, pid, memory_region_id, filename, stored_path,
              sha256, size_bytes, file_type, extraction_method, source_plugin, tool_name,
              tool_version, source_address, start_vpn, end_vpn, extracted_at, notes, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                art_id,
                evidence_id,
                region.get("process_id"),
                pid,
                region_id,
                stored_path.name,
                str(stored_path),
                digest,
                size_bytes,
                ftype,
                "volatility3.windows.vadinfo.vad_dump",
                "windows.vadinfo",
                "volatility3",
                session.volatility_version,
                start_vpn,
                start_vpn,
                end_vpn,
                _utcnow(),
                "Extracted via VadInfo.vad_dump; not executed.",
                json.dumps({"maxsize": maxsize, "analysis_run_id": run_id}),
            ),
        )

        _insert_timeline(
            db,
            {
                "id": str(uuid4()),
                "evidence_id": evidence_id,
                "event_time": _utcnow(),
                "time_precision": "exact",
                "classification": "observed",
                "event_kind": "artifact_extraction",
                "summary": f"Extracted VAD {start_vpn}-{end_vpn} from PID {pid} → {stored_path.name} SHA256={digest[:16]}…",
                "process_id": region.get("process_id"),
                "pid": pid,
                "related_entity_type": "artifact",
                "related_entity_id": art_id,
                "source_table": "artifacts",
                "source_plugin": "windows.vadinfo",
                "provenance_json": json.dumps(
                    {
                        "memory_region_id": region_id,
                        "method": "vad_dump",
                        "sha256": digest,
                    }
                ),
                "created_at": _utcnow(),
            },
        )

        db.execute(
            "UPDATE analysis_runs SET status='completed', finished_at=?, volatility_version=? WHERE id=?",
            (_utcnow(), session.volatility_version, run_id),
        )
        log.info(
            "artifact extracted",
            extra={"channel": "analysis", "evidence_id": evidence_id},
        )
        row = db.fetchone("SELECT * FROM artifacts WHERE id = ?", (art_id,))
        assert row
        return {"artifact": _artifact_dto(row), "analysis_run_id": run_id}
    except AppError as exc:
        db.execute(
            "UPDATE analysis_runs SET status=?, finished_at=?, error_json=? WHERE id=?",
            (
                "cancelled" if exc.code == "job_cancelled" else "failed",
                _utcnow(),
                json.dumps(exc.to_dict()),
                run_id,
            ),
        )
        raise
    except exceptions.UnsatisfiedException as exc:
        err = AppError(
            code="volatility_unsatisfied",
            message="Volatility requirements unsatisfied during VAD extract.",
            details=str(exc.unsatisfied),
            entity="volatility",
        )
        db.execute(
            "UPDATE analysis_runs SET status='failed', finished_at=?, error_json=? WHERE id=?",
            (_utcnow(), json.dumps(err.to_dict()), run_id),
        )
        raise err from exc
    except Exception as exc:  # noqa: BLE001
        err = AppError(
            code="vad_extract_failed",
            message="VAD extraction failed.",
            details=f"{type(exc).__name__}: {exc}",
            entity="artifact",
        )
        db.execute(
            "UPDATE analysis_runs SET status='failed', finished_at=?, error_json=? WHERE id=?",
            (_utcnow(), json.dumps(err.to_dict()), run_id),
        )
        raise err from exc


def _make_file_handler(output_dir: Path):
    """FileHandler that writes into controlled artifact directory (no shell)."""
    from volatility3.framework.interfaces import plugins as iplugins

    class MemscopeFileHandler(io.BytesIO, iplugins.FileHandlerInterface):
        def __init__(self, filename: str):
            io.BytesIO.__init__(self)
            iplugins.FileHandlerInterface.__init__(self, filename)
            self.committed_path: str | None = None

        def close(self):
            if self.closed:
                return
            self.seek(0)
            safe_name = iplugins.FileHandlerInterface.sanitize_filename(
                self.preferred_filename
            )
            path = output_dir / safe_name
            # uniqueness
            if path.exists():
                stem = path.stem
                suf = path.suffix
                n = 1
                while True:
                    cand = output_dir / f"{stem}-{n}{suf}"
                    if not cand.exists():
                        path = cand
                        break
                    n += 1
            data = self.read()
            with path.open("wb") as f:
                f.write(data)
            self.committed_path = str(path)
            super().close()

    return MemscopeFileHandler


def build_timeline(db: Database, evidence_id: str) -> dict[str, Any]:
    """Rebuild timeline from normalized tables. Does not invent times."""
    if not db.fetchone("SELECT id FROM evidence WHERE id = ?", (evidence_id,)):
        raise AppError(code="evidence_missing", message="Evidence not found.", entity="evidence")

    db.execute("DELETE FROM timeline_events WHERE evidence_id = ?", (evidence_id,))
    events: list[dict[str, Any]] = []
    now = _utcnow()

    for p in db.fetchall(
        "SELECT * FROM processes WHERE evidence_id = ? ORDER BY pid",
        (evidence_id,),
    ):
        t = p.get("create_time")
        events.append(
            {
                "id": str(uuid4()),
                "evidence_id": evidence_id,
                "event_time": t if t else None,
                "time_precision": "observed" if t else "unknown",
                "classification": "observed",
                "event_kind": "process_create",
                "summary": f"Process {p.get('name') or '?'} PID {p['pid']} PPID {p.get('ppid')}",
                "process_id": p["id"],
                "pid": p["pid"],
                "related_entity_type": "process",
                "related_entity_id": p["id"],
                "source_table": "processes",
                "source_plugin": p.get("source_plugin"),
                "provenance_json": json.dumps(
                    {
                        "field": "create_time",
                        "create_time": t,
                        "note": "Timestamp only if provided by pslist CreateTime",
                    }
                ),
                "created_at": now,
            }
        )
        if p.get("ppid") is not None:
            events.append(
                {
                    "id": str(uuid4()),
                    "evidence_id": evidence_id,
                    "event_time": t if t else None,
                    "time_precision": "observed" if t else "unknown",
                    "classification": "observed",
                    "event_kind": "process_relationship",
                    "summary": f"Parent/child: PPID {p.get('ppid')} → PID {p['pid']} ({p.get('name')})",
                    "process_id": p["id"],
                    "pid": p["pid"],
                    "related_entity_type": "process",
                    "related_entity_id": p["id"],
                    "source_table": "processes",
                    "source_plugin": p.get("source_plugin"),
                    "provenance_json": json.dumps({"ppid": p.get("ppid"), "pid": p["pid"]}),
                    "created_at": now,
                }
            )

    for n in db.fetchall(
        "SELECT * FROM network_connections WHERE evidence_id = ?",
        (evidence_id,),
    ):
        t = n.get("created")
        events.append(
            {
                "id": str(uuid4()),
                "evidence_id": evidence_id,
                "event_time": t if t else None,
                "time_precision": "observed" if t else "unknown",
                "classification": "observed",
                "event_kind": "network_activity",
                "summary": (
                    f"{n.get('protocol')} {n.get('local_address')}:{n.get('local_port')} → "
                    f"{n.get('remote_address')}:{n.get('remote_port')} "
                    f"state={n.get('state')} PID={n.get('pid')}"
                ),
                "process_id": n.get("process_id"),
                "pid": n.get("pid"),
                "related_entity_type": "network",
                "related_entity_id": n["id"],
                "source_table": "network_connections",
                "source_plugin": n.get("source_plugin"),
                "provenance_json": json.dumps({"created_field": t}),
                "created_at": now,
            }
        )

    for m in db.fetchall(
        "SELECT * FROM modules WHERE evidence_id = ? AND load_time IS NOT NULL",
        (evidence_id,),
    ):
        t = m.get("load_time")
        events.append(
            {
                "id": str(uuid4()),
                "evidence_id": evidence_id,
                "event_time": t,
                "time_precision": "observed",
                "classification": "observed",
                "event_kind": "module_load",
                "summary": f"Module {m.get('name')} loaded in PID {m['pid']}",
                "process_id": m.get("process_id"),
                "pid": m["pid"],
                "related_entity_type": "module",
                "related_entity_id": m["id"],
                "source_table": "modules",
                "source_plugin": m.get("source_plugin"),
                "provenance_json": json.dumps({"load_time": t, "path": m.get("path")}),
                "created_at": now,
            }
        )

    for f in db.fetchall(
        "SELECT * FROM findings WHERE evidence_id = ?",
        (evidence_id,),
    ):
        # Findings are analytical inference; time is when finding was created, not OS time
        events.append(
            {
                "id": str(uuid4()),
                "evidence_id": evidence_id,
                "event_time": f.get("created_at"),
                "time_precision": "analysis_time",
                "classification": "inferred",
                "event_kind": "finding",
                "summary": f"[{f.get('severity')}] {f.get('finding_type')}: {f.get('explanation')[:200]}",
                "process_id": f.get("process_id"),
                "pid": f.get("pid"),
                "related_entity_type": "finding",
                "related_entity_id": f["id"],
                "source_table": "findings",
                "source_plugin": f.get("plugin"),
                "provenance_json": json.dumps(
                    {
                        "note": "Event time is analysis/heuristic generation time, not observed OS time",
                        "finding_type": f.get("finding_type"),
                    }
                ),
                "created_at": now,
            }
        )

    for a in db.fetchall(
        "SELECT * FROM artifacts WHERE evidence_id = ?",
        (evidence_id,),
    ):
        events.append(
            {
                "id": str(uuid4()),
                "evidence_id": evidence_id,
                "event_time": a.get("extracted_at"),
                "time_precision": "exact",
                "classification": "observed",
                "event_kind": "artifact_extraction",
                "summary": (
                    f"Artifact {a.get('filename')} SHA256={str(a.get('sha256'))[:16]}… "
                    f"via {a.get('extraction_method')}"
                ),
                "process_id": a.get("process_id"),
                "pid": a.get("pid"),
                "related_entity_type": "artifact",
                "related_entity_id": a["id"],
                "source_table": "artifacts",
                "source_plugin": a.get("source_plugin"),
                "provenance_json": json.dumps(
                    {
                        "sha256": a.get("sha256"),
                        "memory_region_id": a.get("memory_region_id"),
                        "stored_path": a.get("stored_path"),
                    }
                ),
                "created_at": now,
            }
        )

    for e in events:
        _insert_timeline(db, e)

    return list_timeline(db, evidence_id)


def list_timeline(
    db: Database,
    evidence_id: str,
    *,
    limit: int = 5000,
) -> dict[str, Any]:
    rows = db.fetchall(
        """
        SELECT * FROM timeline_events
        WHERE evidence_id = ?
        ORDER BY
          CASE WHEN event_time IS NULL THEN 1 ELSE 0 END,
          event_time ASC,
          created_at ASC
        LIMIT ?
        """,
        (evidence_id, limit),
    )
    items = [_timeline_dto(r) for r in rows]
    return {"evidence_id": evidence_id, "total": len(items), "items": items}


def list_artifacts(db: Database, evidence_id: str) -> dict[str, Any]:
    rows = db.fetchall(
        "SELECT * FROM artifacts WHERE evidence_id = ? ORDER BY extracted_at DESC",
        (evidence_id,),
    )
    return {
        "evidence_id": evidence_id,
        "total": len(rows),
        "items": [_artifact_dto(r) for r in rows],
    }


def get_artifact(db: Database, artifact_id: str) -> dict[str, Any]:
    row = db.fetchone("SELECT * FROM artifacts WHERE id = ?", (artifact_id,))
    if not row:
        raise AppError(code="artifact_missing", message="Artifact not found.", entity="artifact")
    dto = _artifact_dto(row)
    chain: list[dict[str, Any]] = [
        {"step": "evidence", "id": row["evidence_id"]},
    ]
    if row.get("process_id"):
        chain.append({"step": "process", "id": row["process_id"], "pid": row.get("pid")})
    if row.get("memory_region_id"):
        chain.append(
            {
                "step": "memory_region",
                "id": row["memory_region_id"],
                "start": row.get("start_vpn"),
                "end": row.get("end_vpn"),
            }
        )
    if row.get("parent_artifact_id"):
        chain.append({"step": "source_artifact", "id": row["parent_artifact_id"]})
    chain.append(
        {
            "step": "artifact",
            "id": row["id"],
            "sha256": row["sha256"],
            "path": row["stored_path"],
            "method": row["extraction_method"],
        }
    )
    meta = dto.get("metadata") or {}
    if isinstance(meta, dict) and meta.get("pe_sieve_scan_id"):
        chain.append(
            {
                "step": "pe_sieve_output",
                "scan_id": meta.get("pe_sieve_scan_id"),
                "role": meta.get("pe_sieve_role"),
                "tool": "pe-sieve",
                "tool_version": row.get("tool_version"),
            }
        )
    if isinstance(meta, dict) and meta.get("mal_unpack_scan_id"):
        chain.append(
            {
                "step": "mal_unpack_output",
                "scan_id": meta.get("mal_unpack_scan_id"),
                "role": meta.get("mal_unpack_role"),
                "tool": "mal_unpack",
                "tool_version": row.get("tool_version"),
            }
        )
    dto["provenance_chain"] = chain
    return dto


def _region_dto(row: dict[str, Any]) -> dict[str, Any]:
    indicators = []
    raw = row.get("indicators_json")
    if raw:
        try:
            indicators = json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError:
            indicators = []
    return {
        "id": row["id"],
        "evidence_id": row["evidence_id"],
        "analysis_run_id": row.get("analysis_run_id"),
        "process_id": row.get("process_id"),
        "pid": row["pid"],
        "process_name": row.get("process_name"),
        "offset_hex": row.get("offset_hex"),
        "start_vpn": row.get("start_vpn"),
        "end_vpn": row.get("end_vpn"),
        "size_bytes": row.get("size_bytes"),
        "tag": row.get("tag"),
        "protection": row.get("protection"),
        "commit_charge": row.get("commit_charge"),
        "private_memory": row.get("private_memory"),
        "parent": row.get("parent"),
        "file_path": row.get("file_path"),
        "source_plugin": row.get("source_plugin"),
        "indicators": indicators,
    }


def _artifact_dto(row: dict[str, Any]) -> dict[str, Any]:
    meta = row.get("metadata_json") or "{}"
    try:
        metadata = json.loads(meta) if isinstance(meta, str) else meta
    except json.JSONDecodeError:
        metadata = {}
    return {
        "id": row["id"],
        "evidence_id": row["evidence_id"],
        "process_id": row.get("process_id"),
        "pid": row.get("pid"),
        "memory_region_id": row.get("memory_region_id"),
        "filename": row["filename"],
        "stored_path": row["stored_path"],
        "sha256": row["sha256"],
        "size_bytes": row["size_bytes"],
        "file_type": row.get("file_type"),
        "extraction_method": row["extraction_method"],
        "source_plugin": row.get("source_plugin"),
        "tool_name": row.get("tool_name"),
        "tool_version": row.get("tool_version"),
        "source_address": row.get("source_address"),
        "start_vpn": row.get("start_vpn"),
        "end_vpn": row.get("end_vpn"),
        "extracted_at": row.get("extracted_at"),
        "notes": row.get("notes"),
        "metadata": metadata,
        "parent_artifact_id": row.get("parent_artifact_id"),
    }


def _timeline_dto(row: dict[str, Any]) -> dict[str, Any]:
    try:
        prov = json.loads(row.get("provenance_json") or "{}")
    except json.JSONDecodeError:
        prov = {}
    return {
        "id": row["id"],
        "evidence_id": row["evidence_id"],
        "event_time": row.get("event_time"),
        "time_precision": row.get("time_precision"),
        "classification": row["classification"],
        "event_kind": row["event_kind"],
        "summary": row["summary"],
        "process_id": row.get("process_id"),
        "pid": row.get("pid"),
        "related_entity_type": row.get("related_entity_type"),
        "related_entity_id": row.get("related_entity_id"),
        "source_table": row.get("source_table"),
        "source_plugin": row.get("source_plugin"),
        "provenance": prov,
        "created_at": row.get("created_at"),
    }


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


def _insert_timeline(db: Database, e: dict[str, Any]) -> None:
    db.execute(
        """
        INSERT INTO timeline_events (
          id, evidence_id, event_time, time_precision, classification, event_kind,
          summary, process_id, pid, related_entity_type, related_entity_id,
          source_table, source_plugin, provenance_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            e["id"],
            e["evidence_id"],
            e.get("event_time"),
            e["time_precision"],
            e["classification"],
            e["event_kind"],
            e["summary"],
            e.get("process_id"),
            e.get("pid"),
            e.get("related_entity_type"),
            e.get("related_entity_id"),
            e.get("source_table"),
            e.get("source_plugin"),
            e.get("provenance_json") or "{}",
            e["created_at"],
        ),
    )
