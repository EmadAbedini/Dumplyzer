"""Normalize Volatility plugin rows into MemScope entities."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4


def _colmap(columns: list[str]) -> dict[str, int]:
    return {c.lower(): i for i, c in enumerate(columns)}


def _get(row: list[Any], cmap: dict[str, int], *names: str) -> Any:
    for name in names:
        idx = cmap.get(name.lower())
        if idx is not None and idx < len(row):
            return row[idx]
    return None


def normalize_windows_info(
    columns: list[str], rows: list[list[Any]]
) -> dict[str, Any]:
    """Map windows.info Variable/Value pairs to evidence metadata."""
    meta: dict[str, Any] = {"raw": {}}
    cmap = _colmap(columns)
    for row in rows:
        var = _get(row, cmap, "Variable")
        val = _get(row, cmap, "Value")
        if var is None:
            continue
        key = str(var)
        meta["raw"][key] = None if val is None else str(val)
        lk = key.lower()
        if lk in ("nt_major_version", "major/minor", "ntmajorversion"):
            meta.setdefault("nt_major", str(val))
        if "ntproducttype" in lk or key == "NtProductType":
            meta["product_type"] = str(val)
        if key in ("Is64Bit", "Is64bit") or lk == "is64bit":
            meta["is_64bit"] = str(val).lower() in ("true", "1", "yes")
        if key in ("IsPAE",) or lk == "ispae":
            meta["is_pae"] = str(val).lower() in ("true", "1", "yes")
        if "systemtime" in lk or key == "SystemTime":
            meta["system_time"] = str(val)
        if key in ("KdVersionBlock",):
            meta["kd_version_block"] = str(val)
        if "machine type" in lk or key == "MachineType":
            meta["machine_type"] = str(val)
        if key == "Symbols" or "symbol" in lk:
            meta["symbols"] = str(val)

    # Derived OS / arch labels (transparent, not a risk score)
    is64 = meta.get("is_64bit")
    arch = "x64" if is64 is True else ("x86" if is64 is False else None)
    major = meta.get("nt_major") or meta["raw"].get("NtMajorVersion")
    minor = meta["raw"].get("NtMinorVersion")
    detected_os = None
    if major is not None:
        detected_os = f"Windows NT {major}" + (f".{minor}" if minor else "")
    product = meta.get("product_type") or meta["raw"].get("NtProductType")
    if product:
        detected_os = f"{detected_os} ({product})" if detected_os else str(product)

    symbol_status = "unknown"
    symbols = meta.get("symbols") or meta["raw"].get("Symbols")
    if symbols:
        s = str(symbols).lower()
        if "not found" in s or "unavailable" in s or s in ("", "none"):
            symbol_status = "missing"
        else:
            symbol_status = "resolved"

    return {
        "detected_os": detected_os,
        "architecture": arch,
        "symbol_status": symbol_status,
        "symbol_detail": symbols,
        "system_time": meta.get("system_time"),
        "info": meta,
    }


def normalize_pslist(
    columns: list[str],
    rows: list[list[Any]],
    *,
    evidence_id: str,
    analysis_run_id: str,
    source_plugin: str,
) -> list[dict[str, Any]]:
    cmap = _colmap(columns)
    out: list[dict[str, Any]] = []
    for row in rows:
        pid = _get(row, cmap, "PID")
        if pid is None:
            continue
        try:
            pid_i = int(pid)
        except (TypeError, ValueError):
            continue
        ppid = _get(row, cmap, "PPID")
        try:
            ppid_i = int(ppid) if ppid is not None else None
        except (TypeError, ValueError):
            ppid_i = None

        name = _get(row, cmap, "ImageFileName", "Name")
        offset = _get(row, cmap, "Offset(V)", "Offset(P)", "Offset")
        threads = _get(row, cmap, "Threads")
        handles = _get(row, cmap, "Handles")
        session_id = _get(row, cmap, "SessionId")
        wow64 = _get(row, cmap, "Wow64")
        create_time = _get(row, cmap, "CreateTime")
        exit_time = _get(row, cmap, "ExitTime")

        def _int(v: Any) -> int | None:
            try:
                return int(v) if v is not None else None
            except (TypeError, ValueError):
                return None

        def _ts(v: Any) -> str | None:
            if v is None or v == "" or str(v) in ("N/A", "-"):
                return None
            if isinstance(v, datetime):
                return v.isoformat()
            return str(v)

        out.append(
            {
                "id": str(uuid4()),
                "evidence_id": evidence_id,
                "analysis_run_id": analysis_run_id,
                "pid": pid_i,
                "ppid": ppid_i,
                "name": str(name) if name is not None else None,
                "username": None,
                "image_path": None,
                "command_line": None,
                "create_time": _ts(create_time),
                "exit_time": _ts(exit_time),
                "offset_hex": str(offset) if offset is not None else None,
                "threads": _int(threads),
                "handles": _int(handles),
                "session_id": _int(session_id),
                "wow64": bool(wow64) if isinstance(wow64, bool) else (
                    str(wow64).lower() in ("true", "1", "yes") if wow64 is not None else None
                ),
                "source_plugin": source_plugin,
            }
        )
    return out
