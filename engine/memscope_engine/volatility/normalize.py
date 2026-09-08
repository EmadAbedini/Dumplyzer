"""Normalize Volatility plugin rows into Dumplyzer entities."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from memscope_engine.observed_time import is_sane_os_year, parse_observed_datetime


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _colmap(columns: list[str]) -> dict[str, int]:
    return {c.lower(): i for i, c in enumerate(columns)}


def _get(row: list[Any], cmap: dict[str, int], *names: str) -> Any:
    for name in names:
        idx = cmap.get(name.lower())
        if idx is not None and idx < len(row):
            return row[idx]
    return None


def _ts(v: Any) -> str | None:
    if v is None or v == "" or str(v) in ("N/A", "-", "None"):
        return None
    dt = parse_observed_datetime(v)
    if dt is None:
        return str(v)
    if not is_sane_os_year(dt):
        return None
    return dt.isoformat()


def _int(v: Any) -> int | None:
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
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
        pid_i = _int(pid)
        if pid_i is None:
            continue
        ppid_i = _int(_get(row, cmap, "PPID"))
        name = _get(row, cmap, "ImageFileName", "Name")
        offset = _get(row, cmap, "Offset(V)", "Offset(P)", "Offset")
        wow64 = _get(row, cmap, "Wow64")
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
                "create_time": _ts(_get(row, cmap, "CreateTime")),
                "exit_time": _ts(_get(row, cmap, "ExitTime")),
                "offset_hex": str(offset) if offset is not None else None,
                "threads": _int(_get(row, cmap, "Threads")),
                "handles": _int(_get(row, cmap, "Handles")),
                "session_id": _int(_get(row, cmap, "SessionId")),
                "wow64": bool(wow64)
                if isinstance(wow64, bool)
                else (
                    str(wow64).lower() in ("true", "1", "yes")
                    if wow64 is not None
                    else None
                ),
                "source_plugin": source_plugin,
            }
        )
    return out


def normalize_cmdline(
    columns: list[str],
    rows: list[list[Any]],
    *,
    pid_filter: int | None = None,
) -> list[dict[str, Any]]:
    cmap = _colmap(columns)
    out: list[dict[str, Any]] = []
    for row in rows:
        pid = _int(_get(row, cmap, "PID"))
        if pid is None:
            continue
        if pid_filter is not None and pid != pid_filter:
            continue
        args = _get(row, cmap, "Args", "CommandLine", "CmdLine")
        proc = _get(row, cmap, "Process", "ImageFileName", "Name")
        out.append(
            {
                "pid": pid,
                "process": str(proc) if proc is not None else None,
                "command_line": str(args) if args is not None else None,
            }
        )
    return out


def normalize_dlllist(
    columns: list[str],
    rows: list[list[Any]],
    *,
    evidence_id: str,
    analysis_run_id: str,
    process_id: str | None,
    pid_filter: int | None,
    source_plugin: str,
) -> list[dict[str, Any]]:
    cmap = _colmap(columns)
    out: list[dict[str, Any]] = []
    for row in rows:
        pid = _int(_get(row, cmap, "PID"))
        if pid is None:
            continue
        if pid_filter is not None and pid != pid_filter:
            continue
        out.append(
            {
                "id": str(uuid4()),
                "evidence_id": evidence_id,
                "analysis_run_id": analysis_run_id,
                "process_id": process_id,
                "pid": pid,
                "name": _str(_get(row, cmap, "Name")),
                "path": _str(_get(row, cmap, "Path")),
                "base_address": _str(_get(row, cmap, "Base")),
                "size": _str(_get(row, cmap, "Size")),
                "load_count": _int(_get(row, cmap, "LoadCount")),
                "load_time": _ts(_get(row, cmap, "LoadTime")),
                "source_plugin": source_plugin,
            }
        )
    return out


def normalize_netscan(
    columns: list[str],
    rows: list[list[Any]],
    *,
    evidence_id: str,
    analysis_run_id: str,
    process_id_by_pid: dict[int, str],
    pid_filter: int | None,
    source_plugin: str,
) -> list[dict[str, Any]]:
    cmap = _colmap(columns)
    out: list[dict[str, Any]] = []
    for row in rows:
        pid = _int(_get(row, cmap, "PID"))
        if pid_filter is not None and pid != pid_filter:
            continue
        out.append(
            {
                "id": str(uuid4()),
                "evidence_id": evidence_id,
                "analysis_run_id": analysis_run_id,
                "process_id": process_id_by_pid.get(pid) if pid is not None else None,
                "pid": pid,
                "protocol": _str(_get(row, cmap, "Proto", "Protocol")),
                "local_address": _str(_get(row, cmap, "LocalAddr", "LocalAddress")),
                "local_port": _int(_get(row, cmap, "LocalPort")),
                "remote_address": _str(_get(row, cmap, "ForeignAddr", "RemoteAddr", "ForeignAddress")),
                "remote_port": _int(_get(row, cmap, "ForeignPort", "RemotePort")),
                "state": _str(_get(row, cmap, "State")),
                "owner": _str(_get(row, cmap, "Owner")),
                "created": _ts(_get(row, cmap, "Created")),
                "offset_hex": _str(_get(row, cmap, "Offset")),
                "source_plugin": source_plugin,
            }
        )
    return out


def normalize_handles(
    columns: list[str],
    rows: list[list[Any]],
    *,
    evidence_id: str,
    analysis_run_id: str,
    process_id: str | None,
    pid_filter: int | None,
    source_plugin: str,
) -> list[dict[str, Any]]:
    cmap = _colmap(columns)
    out: list[dict[str, Any]] = []
    for row in rows:
        pid = _int(_get(row, cmap, "PID"))
        if pid is None:
            continue
        if pid_filter is not None and pid != pid_filter:
            continue
        out.append(
            {
                "id": str(uuid4()),
                "evidence_id": evidence_id,
                "analysis_run_id": analysis_run_id,
                "process_id": process_id,
                "pid": pid,
                "offset_hex": _str(_get(row, cmap, "Offset")),
                "handle_value": _str(_get(row, cmap, "HandleValue")),
                "handle_type": _str(_get(row, cmap, "Type")),
                "granted_access": _str(_get(row, cmap, "GrantedAccess")),
                "name": _str(_get(row, cmap, "Name")),
                "source_plugin": source_plugin,
            }
        )
    return out


def normalize_vadinfo(
    columns: list[str],
    rows: list[list[Any]],
    *,
    evidence_id: str,
    analysis_run_id: str,
    process_id: str | None,
    pid_filter: int | None,
    source_plugin: str,
) -> list[dict[str, Any]]:
    cmap = _colmap(columns)
    out: list[dict[str, Any]] = []
    for row in rows:
        pid = _int(_get(row, cmap, "PID"))
        if pid is None:
            continue
        if pid_filter is not None and pid != pid_filter:
            continue
        out.append(
            {
                "id": str(uuid4()),
                "evidence_id": evidence_id,
                "analysis_run_id": analysis_run_id,
                "process_id": process_id,
                "pid": pid,
                "process_name": _str(_get(row, cmap, "Process")),
                "offset_hex": _str(_get(row, cmap, "Offset")),
                "start_vpn": _str(_get(row, cmap, "Start VPN", "Start")),
                "end_vpn": _str(_get(row, cmap, "End VPN", "End")),
                "tag": _str(_get(row, cmap, "Tag")),
                "protection": _str(_get(row, cmap, "Protection")),
                "commit_charge": _int(_get(row, cmap, "CommitCharge")),
                "private_memory": _int(_get(row, cmap, "PrivateMemory")),
                "parent": _str(_get(row, cmap, "Parent")),
                "file_path": _str(_get(row, cmap, "File")),
                "source_plugin": source_plugin,
            }
        )
    return out


def _str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v)
    return s if s not in ("", "None", "N/A") else None


def findings_from_cmdline(
    *,
    evidence_id: str,
    analysis_run_id: str,
    process_id: str | None,
    pid: int,
    command_line: str | None,
) -> list[dict[str, Any]]:
    """Transparent heuristics only — never opaque scores."""
    if not command_line:
        return []
    cl = command_line
    cl_l = cl.lower()
    findings: list[dict[str, Any]] = []
    now = _now()

    def add(ftype: str, severity: str, explanation: str) -> None:
        findings.append(
            {
                "id": str(uuid4()),
                "evidence_id": evidence_id,
                "analysis_run_id": analysis_run_id,
                "process_id": process_id,
                "pid": pid,
                "finding_type": ftype,
                "severity": severity,
                "explanation": explanation,
                "field_name": "command_line",
                "field_value": cl[:2000],
                "plugin": "windows.cmdline",
                "confidence": "heuristic",
                "created_at": now,
            }
        )

    if "powershell" in cl_l and (
        "-enc" in cl_l or "-encodedcommand" in cl_l or "frombase64string" in cl_l
    ):
        add(
            "encoded_powershell",
            "high",
            "Command line appears to contain encoded PowerShell (-enc / EncodedCommand / FromBase64String).",
        )
    if "cmd.exe" in cl_l and "/c" in cl_l and (
        "powershell" in cl_l or "mshta" in cl_l or "certutil" in cl_l
    ):
        add(
            "cmd_launch_lolbin",
            "medium",
            "cmd.exe /c appears to launch a commonly abused living-off-the-land binary.",
        )
    if "\\users\\" in cl_l and (
        "\\appdata\\local\\temp\\" in cl_l or "\\appdata\\roaming\\" in cl_l
    ):
        if any(x in cl_l for x in (".exe", ".dll", ".js", ".vbs", ".bat", ".ps1")):
            add(
                "user_temp_execution_path",
                "low",
                "Command line references an executable-like path under a user AppData/Temp location.",
            )
    return findings


def findings_from_vad(
    *,
    evidence_id: str,
    analysis_run_id: str,
    process_id: str | None,
    pid: int,
    regions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    now = _now()
    out: list[dict[str, Any]] = []
    for r in regions:
        prot = (r.get("protection") or "").upper()
        private = r.get("private_memory")
        # Transparent: flag RWX-like protections when string contains EXECUTE and WRITE
        if "EXECUTE" in prot and "WRITE" in prot:
            out.append(
                {
                    "id": str(uuid4()),
                    "evidence_id": evidence_id,
                    "analysis_run_id": analysis_run_id,
                    "process_id": process_id,
                    "pid": pid,
                    "finding_type": "vad_writable_executable",
                    "severity": "medium",
                    "explanation": (
                        f"VAD region {r.get('start_vpn')}–{r.get('end_vpn')} has protection "
                        f"'{r.get('protection')}' (writable+executable)."
                    ),
                    "field_name": "protection",
                    "field_value": r.get("protection"),
                    "plugin": "windows.vadinfo",
                    "confidence": "heuristic",
                    "created_at": now,
                }
            )
        elif private and int(private) == 1 and "EXECUTE" in prot and not r.get("file_path"):
            out.append(
                {
                    "id": str(uuid4()),
                    "evidence_id": evidence_id,
                    "analysis_run_id": analysis_run_id,
                    "process_id": process_id,
                    "pid": pid,
                    "finding_type": "private_executable_vad",
                    "severity": "medium",
                    "explanation": (
                        f"Private executable VAD {r.get('start_vpn')}–{r.get('end_vpn')} "
                        f"with protection '{r.get('protection')}' and no file backing."
                    ),
                    "field_name": "private_memory",
                    "field_value": str(private),
                    "plugin": "windows.vadinfo",
                    "confidence": "heuristic",
                    "created_at": now,
                }
            )
    return out
