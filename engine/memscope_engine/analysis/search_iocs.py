"""Global search and IOC extraction over normalized SQLite entities."""

from __future__ import annotations

import json
import re
from typing import Any
from uuid import uuid4
from datetime import datetime, timezone

from memscope_engine.errors import AppError
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


def global_search(
    db: Database,
    evidence_id: str,
    query: str,
    *,
    limit: int = 200,
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

    like = f"%{q}%"
    results: list[dict[str, Any]] = []

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
    for row in db.fetchall(
        """
        SELECT * FROM processes WHERE evidence_id = ? AND (
          name LIKE ? OR CAST(pid AS TEXT) LIKE ? OR CAST(ppid AS TEXT) LIKE ?
          OR IFNULL(command_line,'') LIKE ? OR IFNULL(image_path,'') LIKE ?
          OR IFNULL(username,'') LIKE ?
        ) LIMIT ?
        """,
        (evidence_id, like, like, like, like, like, like, limit),
    ):
        matched = row.get("name") or str(row.get("pid"))
        for field in ("name", "command_line", "image_path", "username"):
            val = row.get(field)
            if val and q.lower() in str(val).lower():
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
    for row in db.fetchall(
        """
        SELECT * FROM modules WHERE evidence_id = ? AND (
          IFNULL(name,'') LIKE ? OR IFNULL(path,'') LIKE ? OR CAST(pid AS TEXT) LIKE ?
        ) LIMIT ?
        """,
        (evidence_id, like, like, like, limit),
    ):
        val = row.get("name") or row.get("path") or ""
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
    for row in db.fetchall(
        """
        SELECT * FROM network_connections WHERE evidence_id = ? AND (
          IFNULL(local_address,'') LIKE ? OR IFNULL(remote_address,'') LIKE ?
          OR IFNULL(owner,'') LIKE ? OR IFNULL(state,'') LIKE ?
          OR CAST(IFNULL(local_port, -1) AS TEXT) LIKE ?
          OR CAST(IFNULL(remote_port, -1) AS TEXT) LIKE ?
          OR CAST(IFNULL(pid, -1) AS TEXT) LIKE ?
        ) LIMIT ?
        """,
        (evidence_id, like, like, like, like, like, like, like, limit),
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
    for row in db.fetchall(
        """
        SELECT * FROM iocs WHERE evidence_id = ? AND (
          value LIKE ? OR ioc_type LIKE ? OR IFNULL(context,'') LIKE ?
        ) LIMIT ?
        """,
        (evidence_id, like, like, like, limit),
    ) if _table_exists(db, "iocs") else []:
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

    return {
        "evidence_id": evidence_id,
        "query": q,
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
    db.execute("DELETE FROM iocs WHERE evidence_id = ?", (evidence_id,))
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


def list_iocs(
    db: Database,
    evidence_id: str,
    *,
    ioc_type: str | None = None,
) -> dict[str, Any]:
    if ioc_type:
        rows = db.fetchall(
            """
            SELECT * FROM iocs WHERE evidence_id = ? AND ioc_type = ?
            ORDER BY ioc_type, value LIMIT 10000
            """,
            (evidence_id, ioc_type),
        )
    else:
        rows = db.fetchall(
            "SELECT * FROM iocs WHERE evidence_id = ? ORDER BY ioc_type, value LIMIT 10000",
            (evidence_id,),
        )
    items = [
        {
            "id": r["id"],
            "evidence_id": r["evidence_id"],
            "process_id": r.get("process_id"),
            "pid": r.get("pid"),
            "ioc_type": r["ioc_type"],
            "value": r["value"],
            "context": r.get("context"),
            "source": r.get("source"),
            "created_at": r.get("created_at"),
        }
        for r in rows
    ]
    return {"evidence_id": evidence_id, "total": len(items), "items": items}


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
    lines = ["ioc_type,value,pid,context,source"]
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
                    esc(i.get("context")),
                    esc(i.get("source")),
                ]
            )
        )
    return "\n".join(lines) + "\n"


def _table_exists(db: Database, name: str) -> bool:
    row = db.fetchone(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
        (name,),
    )
    return row is not None
