"""Global search and IOC extraction over normalized SQLite entities."""

from __future__ import annotations

import io
import json
import re
import zipfile
from typing import Any
from uuid import uuid4
from datetime import datetime, timezone

from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths
from memscope_engine.storage import Database

# Conservative patterns — avoid obvious noise where practical
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
_RE_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_RE_DOMAIN = re.compile(
    r"\b(?!(?:\d+\.)+\d+\b)(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|edu|gov|mil|io|co|info|biz|ru|cn|uk|de|fr|local)\b",
    re.IGNORECASE,
)
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_PATH_WIN = re.compile(
    r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"
)
_RE_REG = re.compile(r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s\"']+", re.IGNORECASE)


SEARCH_SCOPES = frozenset(
    {
        "all",
        "process_names",
        "pids",
        "command_lines",
        "usernames",
        "modules",
        "ip_addresses",
        "ports",
        "file_paths",
        "handles",
        "findings",
        "iocs",
    }
)


def global_search(
    db: Database,
    evidence_id: str,
    query: str,
    *,
    limit: int = 200,
    scope: str = "all",
) -> dict[str, Any]:
    q = (query or "").strip()
    if not q:
        raise AppError(
            code="empty_query",
            message="Search query is empty.",
            suggestion="Enter a process name, PID, IP, path, or other indicator.",
            entity="search",
        )
    if not db.fetchone("SELECT id FROM evidence WHERE id = ?", (evidence_id,)):
        raise AppError(code="evidence_missing", message="Evidence not found.", entity="evidence")
    search_scope = (scope or "all").strip().lower() or "all"
    if search_scope not in SEARCH_SCOPES:
        raise AppError(
            code="invalid_search_scope",
            message="Unknown search field.",
            suggestion="Choose All or a supported search field.",
            entity="search",
        )

    like = f"%{q}%"
    q_l = q.lower()
    results: list[dict[str, Any]] = []

    def want(*names: str) -> bool:
        return search_scope == "all" or search_scope in names

    def add(
        *,
        entity: str,
        value: str,
        context: str,
        process_id: str | None = None,
        pid: int | None = None,
        source: str | None = None,
        plugin: str | None = None,
        ref_id: str | None = None,
    ) -> None:
        if len(results) >= limit:
            return
        results.append(
            {
                "entity": entity,
                "value": value,
                "context": context,
                "process_id": process_id,
                "pid": pid,
                "source": source,
                "plugin": plugin,
                "ref_id": ref_id,
            }
        )

    # Processes
    if want("process_names", "pids", "command_lines", "usernames", "file_paths"):
        if search_scope == "process_names":
            proc_sql = "IFNULL(name,'') LIKE ?"
            proc_params: tuple[Any, ...] = (evidence_id, like, limit)
        elif search_scope == "pids":
            proc_sql = "CAST(pid AS TEXT) LIKE ? OR CAST(ppid AS TEXT) LIKE ?"
            proc_params = (evidence_id, like, like, limit)
        elif search_scope == "command_lines":
            proc_sql = "IFNULL(command_line,'') LIKE ?"
            proc_params = (evidence_id, like, limit)
        elif search_scope == "usernames":
            proc_sql = "IFNULL(username,'') LIKE ?"
            proc_params = (evidence_id, like, limit)
        elif search_scope == "file_paths":
            proc_sql = "IFNULL(image_path,'') LIKE ?"
            proc_params = (evidence_id, like, limit)
        else:
            proc_sql = """
              name LIKE ? OR CAST(pid AS TEXT) LIKE ? OR CAST(ppid AS TEXT) LIKE ?
              OR IFNULL(command_line,'') LIKE ? OR IFNULL(image_path,'') LIKE ?
              OR IFNULL(username,'') LIKE ?
            """
            proc_params = (evidence_id, like, like, like, like, like, like, limit)
        for row in db.fetchall(
            f"SELECT * FROM processes WHERE evidence_id = ? AND ({proc_sql}) LIMIT ?",
            proc_params,
        ):
            matched = row.get("name") or str(row.get("pid"))
            if search_scope == "pids":
                pid_s = str(row.get("pid") or "")
                ppid_s = str(row.get("ppid") or "")
                matched = pid_s if q_l in pid_s.lower() else (ppid_s or pid_s)
            elif search_scope == "command_lines":
                matched = str(row.get("command_line") or matched)
            elif search_scope == "usernames":
                matched = str(row.get("username") or matched)
            elif search_scope == "file_paths":
                matched = str(row.get("image_path") or matched)
            elif search_scope == "process_names":
                matched = str(row.get("name") or matched)
            else:
                for col in ("name", "command_line", "image_path", "username"):
                    val = row.get(col)
                    if val and q_l in str(val).lower():
                        matched = str(val)
                        break
            add(
                entity="process",
                value=matched,
                context=f"PID {row['pid']} {row.get('name') or ''}".strip(),
                process_id=row["id"],
                pid=row["pid"],
                source="processes",
                plugin=row.get("source_plugin"),
                ref_id=row["id"],
            )

    # Modules
    if want("modules", "file_paths"):
        if search_scope == "file_paths":
            mod_sql = "IFNULL(path,'') LIKE ?"
            mod_params: tuple[Any, ...] = (evidence_id, like, limit)
        elif search_scope == "modules":
            mod_sql = "IFNULL(name,'') LIKE ? OR IFNULL(path,'') LIKE ?"
            mod_params = (evidence_id, like, like, limit)
        else:
            mod_sql = "IFNULL(name,'') LIKE ? OR IFNULL(path,'') LIKE ? OR CAST(pid AS TEXT) LIKE ?"
            mod_params = (evidence_id, like, like, like, limit)
        for row in db.fetchall(
            f"SELECT * FROM modules WHERE evidence_id = ? AND ({mod_sql}) LIMIT ?",
            mod_params,
        ):
            val = row.get("path") if search_scope == "file_paths" else (row.get("name") or row.get("path") or "")
            add(
                entity="module",
                value=str(val),
                context=f"PID {row['pid']} module",
                process_id=row.get("process_id"),
                pid=row["pid"],
                source="modules",
                plugin=row.get("source_plugin"),
                ref_id=row["id"],
            )

    # Network
    if want("ip_addresses", "ports"):
        if search_scope == "ip_addresses":
            net_sql = "IFNULL(local_address,'') LIKE ? OR IFNULL(remote_address,'') LIKE ?"
            net_params: tuple[Any, ...] = (evidence_id, like, like, limit)
        elif search_scope == "ports":
            net_sql = (
                "CAST(IFNULL(local_port, -1) AS TEXT) LIKE ? "
                "OR CAST(IFNULL(remote_port, -1) AS TEXT) LIKE ?"
            )
            net_params = (evidence_id, like, like, limit)
        else:
            net_sql = """
              IFNULL(local_address,'') LIKE ? OR IFNULL(remote_address,'') LIKE ?
              OR IFNULL(owner,'') LIKE ? OR IFNULL(state,'') LIKE ?
              OR CAST(IFNULL(local_port, -1) AS TEXT) LIKE ?
              OR CAST(IFNULL(remote_port, -1) AS TEXT) LIKE ?
              OR CAST(IFNULL(pid, -1) AS TEXT) LIKE ?
            """
            net_params = (evidence_id, like, like, like, like, like, like, like, limit)
        for row in db.fetchall(
            f"SELECT * FROM network_connections WHERE evidence_id = ? AND ({net_sql}) LIMIT ?",
            net_params,
        ):
            val = f"{row.get('remote_address')}:{row.get('remote_port')}"
            add(
                entity="network",
                value=val,
                context=f"{row.get('protocol')} {row.get('state')} PID {row.get('pid')}",
                process_id=row.get("process_id"),
                pid=row.get("pid"),
                source="network_connections",
                plugin=row.get("source_plugin"),
                ref_id=row["id"],
            )

    # Findings
    if want("findings"):
        for row in db.fetchall(
            """
            SELECT * FROM findings WHERE evidence_id = ? AND (
              finding_type LIKE ? OR explanation LIKE ? OR IFNULL(field_value,'') LIKE ?
            ) LIMIT ?
            """,
            (evidence_id, like, like, like, limit),
        ):
            add(
                entity="finding",
                value=row["finding_type"],
                context=row["explanation"][:300],
                process_id=row.get("process_id"),
                pid=row.get("pid"),
                source="findings",
                plugin=row.get("plugin"),
                ref_id=row["id"],
            )

    # Handles (name)
    if want("handles"):
        for row in db.fetchall(
            """
            SELECT * FROM handle_entries WHERE evidence_id = ? AND IFNULL(name,'') LIKE ?
            LIMIT ?
            """,
            (evidence_id, like, limit),
        ):
            add(
                entity="handle",
                value=str(row.get("name") or ""),
                context=f"{row.get('handle_type')} PID {row['pid']}",
                process_id=row.get("process_id"),
                pid=row["pid"],
                source="handle_entries",
                plugin=row.get("source_plugin"),
                ref_id=row["id"],
            )

    # IOCs table if present
    if want("iocs") and _table_exists(db, "iocs"):
        for row in db.fetchall(
            """
            SELECT * FROM iocs WHERE evidence_id = ? AND (
              value LIKE ? OR ioc_type LIKE ? OR IFNULL(context,'') LIKE ?
            ) LIMIT ?
            """,
            (evidence_id, like, like, like, limit),
        ):
            add(
                entity="ioc",
                value=row["value"],
                context=row.get("context") or row.get("ioc_type") or "",
                process_id=row.get("process_id"),
                pid=row.get("pid"),
                source="iocs",
                plugin=row.get("source"),
                ref_id=row["id"],
            )

    if want("ip_addresses") and _table_exists(db, "network_artifacts"):
        for row in db.fetchall(
            """
            SELECT * FROM network_artifacts WHERE evidence_id = ? AND (
              value LIKE ? OR artifact_type LIKE ? OR IFNULL(context,'') LIKE ?
              OR IFNULL(local_address,'') LIKE ? OR IFNULL(remote_address,'') LIKE ?
            ) LIMIT ?
            """,
            (evidence_id, like, like, like, like, like, limit),
        ):
            add(
                entity="network_artifact",
                value=str(row.get("value") or ""),
                context=row.get("context") or row.get("artifact_type") or "",
                process_id=row.get("process_id"),
                pid=row.get("pid"),
                source=row.get("source"),
                plugin=row.get("source_plugin") or row.get("extraction_method"),
                ref_id=row["id"],
            )

    return {
        "evidence_id": evidence_id,
        "query": q,
        "scope": search_scope,
        "total": len(results),
        "items": results[:limit],
    }


def extract_iocs(db: Database, evidence_id: str) -> dict[str, Any]:
    """Scan normalized text fields and upsert IOC rows. No invented evidence."""
    if not db.fetchone("SELECT id FROM evidence WHERE id = ?", (evidence_id,)):
        raise AppError(code="evidence_missing", message="Evidence not found.", entity="evidence")
    if not _table_exists(db, "iocs"):
        raise AppError(
            code="schema_missing",
            message="IOC table missing; migrate database.",
            entity="ioc",
        )

    found: list[tuple[str, str, str | None, str | None, int | None, str]] = []

    def consider(
        text: str | None,
        *,
        context: str,
        process_id: str | None,
        pid: int | None,
        source: str,
    ) -> None:
        if not text:
            return
        for m in _RE_URL.finditer(text):
            found.append(("url", m.group(0).rstrip(".,);"), context, process_id, pid, source))
        for m in _RE_IPV4.finditer(text):
            ip = m.group(0)
            # skip obvious non-routable noise optionally kept; still forensic
            found.append(("ipv4", ip, context, process_id, pid, source))
        for m in _RE_DOMAIN.finditer(text):
            d = m.group(0)
            if d.lower() in ("microsoft.com", "windows.com", "www.microsoft.com"):
                continue
            found.append(("domain", d, context, process_id, pid, source))
        for m in _RE_PATH_WIN.finditer(text):
            found.append(("path", m.group(0), context, process_id, pid, source))
        for m in _RE_REG.finditer(text):
            found.append(("registry", m.group(0), context, process_id, pid, source))
        for m in _RE_SHA256.finditer(text):
            found.append(("hash_sha256", m.group(0).lower(), context, process_id, pid, source))
        for m in _RE_MD5.finditer(text):
            # skip if part of sha256 already counted — still ok
            found.append(("hash_md5", m.group(0).lower(), context, process_id, pid, source))

    for row in db.fetchall(
        "SELECT id, pid, command_line, image_path, name, username FROM processes WHERE evidence_id = ?",
        (evidence_id,),
    ):
        consider(
            row.get("command_line"),
            context=f"process cmdline PID {row['pid']}",
            process_id=row["id"],
            pid=row["pid"],
            source="processes.command_line",
        )
        consider(
            row.get("image_path"),
            context=f"process image PID {row['pid']}",
            process_id=row["id"],
            pid=row["pid"],
            source="processes.image_path",
        )

    for row in db.fetchall(
        "SELECT id, pid, process_id, path, name FROM modules WHERE evidence_id = ?",
        (evidence_id,),
    ):
        consider(
            row.get("path"),
            context=f"module path PID {row['pid']}",
            process_id=row.get("process_id"),
            pid=row["pid"],
            source="modules.path",
        )

    for row in db.fetchall(
        """
        SELECT id, pid, process_id, local_address, remote_address, owner
        FROM network_connections WHERE evidence_id = ?
        """,
        (evidence_id,),
    ):
        for field in ("local_address", "remote_address"):
            addr = row.get(field)
            if addr and _RE_IPV4.fullmatch(str(addr)):
                found.append(
                    (
                        "ipv4",
                        str(addr),
                        f"network {field} PID {row.get('pid')}",
                        row.get("process_id"),
                        row.get("pid"),
                        "network_connections",
                    )
                )
            elif addr and ":" in str(addr) and not str(addr).replace(":", "").isdigit():
                # possible ipv6
                found.append(
                    (
                        "ipv6",
                        str(addr),
                        f"network {field} PID {row.get('pid')}",
                        row.get("process_id"),
                        row.get("pid"),
                        "network_connections",
                    )
                )

    for row in db.fetchall(
        "SELECT id, pid, process_id, name, handle_type FROM handle_entries WHERE evidence_id = ?",
        (evidence_id,),
    ):
        name = row.get("name")
        if name and str(row.get("handle_type") or "").lower() in ("mutant", "mutex", "key", "file"):
            ioc_type = "mutex" if "mut" in str(row.get("handle_type") or "").lower() else "path"
            if str(row.get("handle_type") or "").lower() == "key":
                ioc_type = "registry"
            found.append(
                (
                    ioc_type,
                    str(name),
                    f"handle {row.get('handle_type')} PID {row['pid']}",
                    row.get("process_id"),
                    row["pid"],
                    "handle_entries",
                )
            )

    # Deduplicate by type+value+pid
    seen: set[tuple[Any, ...]] = set()
    inserted = 0
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "DELETE FROM iocs WHERE evidence_id = ? AND IFNULL(source, '') NOT IN ('bulk_extractor', 'network_artifacts')",
        (evidence_id,),
    )
    for ioc_type, value, context, process_id, pid, source in found:
        key = (ioc_type, value.lower(), pid)
        if key in seen:
            continue
        seen.add(key)
        db.execute(
            """
            INSERT INTO iocs (
              id, evidence_id, process_id, pid, ioc_type, value, context, source, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                evidence_id,
                process_id,
                pid,
                ioc_type,
                value,
                context,
                source,
                now,
            ),
        )
        inserted += 1

    return list_iocs(db, evidence_id) | {"extracted": inserted}


def _ioc_item(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "evidence_id": row["evidence_id"],
        "process_id": row.get("process_id"),
        "pid": row.get("pid"),
        "ioc_type": row["ioc_type"],
        "value": row["value"],
        "context": row.get("context"),
        "source": row.get("source"),
        "created_at": row.get("created_at"),
    }


def _ioc_count(db: Database, evidence_id: str, ioc_type: str | None = None) -> int:
    if ioc_type:
        row = db.fetchone(
            "SELECT COUNT(*) AS n FROM iocs WHERE evidence_id = ? AND ioc_type = ?",
            (evidence_id, ioc_type),
        )
    else:
        row = db.fetchone(
            "SELECT COUNT(*) AS n FROM iocs WHERE evidence_id = ?",
            (evidence_id,),
        )
    return int((row or {}).get("n") or 0)


def list_iocs(
    db: Database,
    evidence_id: str,
    *,
    ioc_type: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    total = _ioc_count(db, evidence_id, ioc_type)
    sql = "SELECT * FROM iocs WHERE evidence_id = ?"
    args: list[Any] = [evidence_id]
    if ioc_type:
        sql += " AND ioc_type = ?"
        args.append(ioc_type)
    sql += " ORDER BY ioc_type, value"
    if limit is not None:
        sql += " LIMIT ?"
        args.append(max(0, int(limit)))
    rows = db.fetchall(sql, tuple(args))
    items = [_ioc_item(r) for r in rows]
    return {"evidence_id": evidence_id, "total": total, "items": items}


_EXPORT_ITEM_KEYS = ("ioc_type", "value", "pid", "source")


def _human_local_time(value: datetime | str | None = None) -> str:
    from memscope_engine.export.html_report import format_html_time

    if value is None:
        value = datetime.now(timezone.utc)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        raw = value.isoformat()
    else:
        raw = str(value)
    return format_html_time(raw) or raw


def _export_ioc_item(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row.get(key) for key in _EXPORT_ITEM_KEYS}


def _export_file_meta(evidence: dict[str, Any], *, created_at: str) -> dict[str, Any]:
    return {
        "evidence_file_name": evidence.get("filename") or "",
        "created_at": created_at,
        "sha256": evidence.get("sha256") or "",
    }


def export_iocs_json(db: Database, evidence_id: str) -> dict[str, Any]:
    data = list_iocs(db, evidence_id)
    return {
        "format": "memscope-iocs-v1",
        "evidence_id": evidence_id,
        "count": data["total"],
        "iocs": data["items"],
    }


def export_iocs_csv(db: Database, evidence_id: str) -> str:
    data = list_iocs(db, evidence_id)
    lines = ["ioc_type,value,pid,source"]
    for i in data["items"]:
        def esc(s: Any) -> str:
            t = "" if s is None else str(s)
            if any(c in t for c in ",\"\n"):
                return '"' + t.replace('"', '""') + '"'
            return t

        lines.append(
            ",".join(
                [
                    esc(i["ioc_type"]),
                    esc(i["value"]),
                    esc(i.get("pid")),
                    esc(i.get("source")),
                ]
            )
        )
    return "\n".join(lines) + "\n"


def _json_bytes(obj: Any) -> bytes:
    buf = io.StringIO()
    json.dump(obj, buf, ensure_ascii=False, indent=2, default=str)
    buf.write("\n")
    return buf.getvalue().encode("utf-8")


def _group_iocs_by_type(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        key = str(item.get("ioc_type") or "unknown")
        groups.setdefault(key, []).append(item)
    return groups


def write_iocs_export(
    db: Database,
    paths: AppPaths,
    evidence_id: str,
    fmt: str,
    *,
    destination: str | None = None,
) -> dict[str, Any]:
    """Write per-type IOC JSON (ZIP) or a single Excel workbook under exports."""
    from memscope_engine.analysis.workflows import get_evidence
    from memscope_engine.export.constants import REPORT_SCHEMA_VERSION
    from memscope_engine.export.safe_paths import (
        allocate_export_dir,
        reject_user_destination,
        sanitize_filename,
    )
    from memscope_engine.export.xlsx_export import write_xlsx_workbook

    reject_user_destination(destination)
    fmt_n = str(fmt or "").strip().lower()
    if fmt_n in {"csv", "excel"}:
        fmt_n = "xlsx"
    if fmt_n not in {"json", "xlsx"}:
        raise AppError(
            code="export_format_unsupported",
            message="Unsupported IOC export format.",
            details=fmt_n,
            suggestion="Use json or xlsx.",
            entity="export",
        )

    evidence = get_evidence(db, evidence_id)
    payload = export_iocs_json(db, evidence_id)
    groups = _group_iocs_by_type(list(payload["iocs"]))
    export_id = str(uuid4())
    now = datetime.now(timezone.utc)
    ioc_created = next(
        (item.get("created_at") for item in payload["iocs"] if item.get("created_at")),
        now.isoformat(),
    )
    created_at = _human_local_time(ioc_created)
    file_meta = _export_file_meta(evidence, created_at=created_at)
    out_dir = allocate_export_dir(
        paths,
        evidence_filename=str(evidence.get("filename") or "evidence"),
        export_id=export_id,
        basename_hint=f"iocs_{fmt_n}",
        evidence_path=evidence.get("path"),
    )

    db.execute(
        """
        INSERT INTO exports (
          id, evidence_id, job_id, format, scope, sections_json, status,
          output_dir, primary_path, files_json, size_bytes, report_schema_version,
          error_json, created_at, finished_at
        ) VALUES (?, ?, NULL, ?, 'selected', ?, 'running', ?, NULL, '[]', NULL, ?, NULL, ?, NULL)
        """,
        (
            export_id,
            evidence_id,
            fmt_n,
            json.dumps(["iocs"]),
            str(out_dir),
            REPORT_SCHEMA_VERSION,
            now.isoformat(),
        ),
    )

    try:
        files: list[dict[str, Any]] = []
        if fmt_n == "json":
            zip_path = out_dir / "iocs-json.zip"
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for type_name, rows in sorted(groups.items()):
                    safe = sanitize_filename(type_name, default="unknown", max_len=40)
                    name = f"{safe}.json"
                    export_rows = [_export_ioc_item(row) for row in rows]
                    body = _json_bytes(
                        {
                            "format": "memscope-iocs-v1",
                            **file_meta,
                            "ioc_type": type_name,
                            "count": len(export_rows),
                            "iocs": export_rows,
                        }
                    )
                    zf.writestr(name, body)
                    files.append(
                        {
                            "name": name,
                            "kind": f"iocs_{type_name}",
                            "size_bytes": len(body),
                        }
                    )
            primary = zip_path
        else:
            sheets = [
                (
                    type_name,
                    _EXPORT_ITEM_KEYS,
                    [_export_ioc_item(row) for row in rows],
                )
                for type_name, rows in sorted(groups.items())
            ]
            if not sheets:
                sheets = [("iocs", _EXPORT_ITEM_KEYS, [])]
            primary = out_dir / "iocs.xlsx"
            size = write_xlsx_workbook(primary, sheets, meta=file_meta)
            files.append(
                {"name": primary.name, "kind": "xlsx_workbook", "size_bytes": size}
            )
        size = primary.stat().st_size
        if fmt_n == "json":
            files.append({"name": primary.name, "kind": "zip", "size_bytes": size})
        finished = datetime.now(timezone.utc).isoformat()
        db.execute(
            """
            UPDATE exports SET status='completed', primary_path=?, files_json=?,
              size_bytes=?, finished_at=? WHERE id=?
            """,
            (str(primary), json.dumps(files), size, finished, export_id),
        )
        return {
            "id": export_id,
            "evidence_id": evidence_id,
            "format": fmt_n,
            "scope": "selected",
            "sections": ["iocs"],
            "status": "completed",
            "output_dir": str(out_dir),
            "primary_path": str(primary),
            "files": files,
            "size_bytes": size,
            "count": payload["count"],
            "type_count": len(groups),
            "created_at": now.isoformat(),
            "finished_at": finished,
        }
    except Exception as exc:  # noqa: BLE001
        db.execute(
            """
            UPDATE exports SET status='failed', error_json=?, finished_at=? WHERE id=?
            """,
            (
                json.dumps({"message": str(exc)}),
                datetime.now(timezone.utc).isoformat(),
                export_id,
            ),
        )
        raise


def _table_exists(db: Database, name: str) -> bool:
    row = db.fetchone(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
        (name,),
    )
    return row is not None
