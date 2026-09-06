"""Optional PE-sieve provider: user-supplied Windows EXE, live-process interface.

Verified against hasherezade/pe-sieve **v0.4.1.1** (tag, params.h, main.cpp,
pe_sieve_return_codes.h, ResultsDumper, wiki JSON reports).

PE-sieve scans a **live Windows process by PID** (`/pid`). It does not scan
files, extracted PE artifacts, or memory-image process records. MemScope does
not map dump PIDs to live PIDs and never executes artifacts.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from memscope_engine.errors import AppError

log = logging.getLogger("memscope.tool")

# Release whose CLI/JSON/exit codes were verified from upstream source + wiki.
VERIFIED_RELEASE = "0.4.1.1"
VERIFIED_INTERFACE = {
    "release": VERIFIED_RELEASE,
    "required_arg": "/pid",
    "version_arg": "/version",
    "output_arg": "/dir",
    "json_arg": "/json",
    "quiet_arg": "/quiet",
    "scan_report": "scan_report.json",
    "dump_report": "dump_report.json",
    "error_report": "error_report.json",
    "output_subdir_prefix": "process_",
}

# Official EXE names from GitHub release assets (v0.4.1.1).
_EXE_NAMES = ("pe-sieve64.exe", "pe-sieve.exe", "pe-sieve32.exe")
_EXE_NAME_SET = {n.lower() for n in _EXE_NAMES}

# t_pesieve_res from include/pe_sieve_return_codes.h (v0.4.1.1)
PESIEVE_ERROR = -1
PESIEVE_INFO = 0
PESIEVE_NOT_DETECTED = 1
PESIEVE_DETECTED = 2

_VERSION_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+){0,3})")

TARGET_LIVE_PROCESS = "live_process"
TARGET_ARTIFACT = "artifact"
TARGET_MEMORY_REGION = "memory_region"
TARGET_FILE = "file"

# Only live PID is a technically valid PE-sieve target.
PESIEVE_SUPPORTED_TARGET_KINDS = (TARGET_LIVE_PROCESS,)

UNSUPPORTED_ARTIFACT_EXPLANATION = (
    "PE-sieve (v0.4.1.1 interface) scans a live Windows process by /pid. "
    "It does not analyze extracted artifact files or memory-image process "
    "records. A PID from a memory dump is not a live PID on this workstation. "
    "MemScope will not execute artifacts or invoke PE-sieve against dump PIDs."
)

Runner = Callable[..., "ProcessRun"]


@dataclass
class ProcessRun:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    cancelled: bool = False


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return path.resolve() == root.resolve()


def interpret_exit_code(code: int | None) -> str | None:
    """Map PE-sieve EXE return codes (observed, not a MemScope score)."""
    if code is None:
        return None
    # Windows may surface -1 as unsigned 32-bit
    if code in (PESIEVE_ERROR, 0xFFFFFFFF, 4294967295):
        return "error"
    if code == PESIEVE_INFO:
        return "info"
    if code == PESIEVE_NOT_DETECTED:
        return "not_detected"
    if code == PESIEVE_DETECTED:
        return "detected"
    return "unknown"


def compute_ui_state(
    *,
    available: bool,
    scan_status: str | None = None,
    pesieve_result: str | None = None,
    modified_total: int | None = None,
    target_kind: str | None = None,
) -> str:
    """Explicit UI states — never a generic threat score."""
    if scan_status == "queued":
        return "queued"
    if scan_status == "running":
        return "running"
    if scan_status == "cancelled":
        return "cancelled"
    if scan_status == "failed":
        return "failed"
    if scan_status == "unsupported_target":
        return "unsupported_target"
    if scan_status == "unavailable":
        return "unavailable"
    if scan_status == "completed":
        if pesieve_result == "detected" or (modified_total or 0) > 0:
            return "completed_indicators"
        return "completed_no_findings"
    if not available:
        return "unavailable"
    if target_kind and target_kind != TARGET_LIVE_PROCESS:
        return "unsupported_target"
    return "unsupported_target"


def parse_version_output(text: str) -> str | None:
    """Parse `/version` or banner text for a dotted version string."""
    if not text:
        return None
    # Prefer an explicit "Version:" line (banner / help).
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("version"):
            m = _VERSION_RE.search(stripped)
            if m:
                return m.group(1)
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


def discover_executable(roots: list[Path]) -> Path | None:
    for root in roots:
        if not root:
            continue
        try:
            resolved_root = root.expanduser().resolve()
        except OSError:
            continue
        candidates: list[Path] = []
        for name in _EXE_NAMES:
            candidates.append(resolved_root / name)
            candidates.append(resolved_root / "pe-sieve" / name)
        for cand in candidates:
            try:
                if cand.is_file() and cand.name.lower() in _EXE_NAME_SET:
                    return cand.resolve()
            except OSError:
                continue
    return None


def validate_executable_path(
    path: Path,
    allowed_roots: list[Path],
    *,
    deny_roots: list[Path] | None = None,
) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise AppError(
            code="pe_sieve_exe_missing",
            message="PE-sieve executable was not found.",
            details=str(resolved),
            suggestion="Copy pe-sieve64.exe from the official v0.4.1.1 release into the MemScope tools directory.",
            entity="pe_sieve",
        )
    if resolved.suffix.lower() != ".exe":
        raise AppError(
            code="pe_sieve_exe_invalid",
            message="PE-sieve executable must be a Windows .exe file.",
            details=str(resolved),
            entity="pe_sieve",
        )
    if resolved.name.lower() not in _EXE_NAME_SET:
        raise AppError(
            code="pe_sieve_exe_invalid",
            message="Executable name is not a known PE-sieve binary.",
            details=resolved.name,
            suggestion="Use pe-sieve64.exe, pe-sieve.exe, or pe-sieve32.exe from the official release.",
            entity="pe_sieve",
        )
    for deny in deny_roots or []:
        if _is_under(resolved, deny):
            raise AppError(
                code="pe_sieve_exe_denied",
                message="Refusing to execute a path inside the artifact store.",
                details=str(resolved),
                entity="pe_sieve",
            )
    roots = [r.expanduser().resolve() for r in allowed_roots if r is not None]
    if not any(_is_under(resolved, root) for root in roots):
        raise AppError(
            code="pe_sieve_exe_path_denied",
            message="PE-sieve executable is outside configured allowed tool directories.",
            details=str(resolved),
            suggestion="Place the official PE-sieve EXE under the MemScope tools directory.",
            entity="pe_sieve",
        )
    try:
        with resolved.open("rb") as f:
            magic = f.read(2)
    except OSError as exc:
        raise AppError(
            code="pe_sieve_exe_invalid",
            message="Could not read PE-sieve executable.",
            details=str(exc),
            entity="pe_sieve",
        ) from exc
    if magic != b"MZ":
        raise AppError(
            code="pe_sieve_exe_invalid",
            message="PE-sieve executable does not look like a Windows PE file.",
            details=str(resolved),
            entity="pe_sieve",
        )
    return resolved


def validate_output_dir(path: Path, allowed_roots: list[Path]) -> Path:
    resolved = path.expanduser().resolve()
    if not any(_is_under(resolved, root.expanduser().resolve()) for root in allowed_roots):
        raise AppError(
            code="pe_sieve_output_denied",
            message="PE-sieve output directory is outside controlled temp roots.",
            details=str(resolved),
            entity="pe_sieve",
        )
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def validate_live_pid(pid: Any) -> int:
    try:
        if isinstance(pid, str) and pid.strip().lower().startswith("0x"):
            value = int(pid.strip(), 16)
        else:
            value = int(pid)
    except (TypeError, ValueError) as exc:
        raise AppError(
            code="pe_sieve_invalid_pid",
            message="PE-sieve live PID must be a positive integer (decimal or 0x hex).",
            details=str(pid),
            entity="pe_sieve",
        ) from exc
    if value < 1 or value > 0xFFFFFFFF:
        raise AppError(
            code="pe_sieve_invalid_pid",
            message="PE-sieve live PID is out of range.",
            details=str(value),
            entity="pe_sieve",
        )
    return value


def describe_target(kind: str | None) -> dict[str, Any]:
    k = (kind or "").strip() or TARGET_ARTIFACT
    supported = k == TARGET_LIVE_PROCESS
    return {
        "kind": k,
        "supported": supported,
        "reason": None if supported else UNSUPPORTED_ARTIFACT_EXPLANATION,
        "pe_sieve_requires": "/pid <live Windows process id>",
        "verified_release": VERIFIED_RELEASE,
    }


def build_version_argv(exe: Path) -> list[str]:
    return [str(exe), "/version"]


def build_scan_argv(exe: Path, pid: int, output_dir: Path) -> list[str]:
    """Construct PE-sieve argv from the verified v0.4.1.1 interface.

    No shell interpolation. No user-supplied extra arguments.
    `/minidmp` is intentionally omitted (full live-process minidump).
    """
    return [
        str(exe),
        "/pid",
        str(int(pid)),
        "/dir",
        str(output_dir),
        "/json",
        "/quiet",
    ]


def default_subprocess_runner(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout_secs: float = 30.0,
    cancelled: Callable[[], bool] | None = None,
) -> ProcessRun:
    """Run argv as an argument array (never shell). Cooperative cancel + timeout."""
    if not argv:
        raise AppError(
            code="pe_sieve_invalid_argv",
            message="Refusing to execute an empty argument list.",
            entity="pe_sieve",
        )
    creationflags = 0
    if sys.platform == "win32":
        creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))

    log.info(
        "pe-sieve exec",
        extra={"channel": "tool", "argv0": Path(argv[0]).name, "argc": len(argv)},
    )
    try:
        proc = subprocess.Popen(
            argv,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            creationflags=creationflags,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        raise AppError(
            code="pe_sieve_exec_failed",
            message="Failed to start PE-sieve.",
            details=f"{type(exc).__name__}: {exc}",
            entity="pe_sieve",
        ) from exc

    deadline = time.monotonic() + max(1.0, float(timeout_secs))
    stdout_s = ""
    stderr_s = ""

    def _kill() -> None:
        try:
            proc.terminate()
        except OSError:
            return
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass

    while True:
        if cancelled and cancelled():
            _kill()
            try:
                out, err = proc.communicate(timeout=2)
            except (subprocess.TimeoutExpired, OSError, ValueError):
                out, err = "", ""
            return ProcessRun(
                returncode=proc.returncode if proc.returncode is not None else -1,
                stdout=_sanitize_capture(out),
                stderr=_sanitize_capture(err),
                cancelled=True,
            )
        if time.monotonic() >= deadline:
            _kill()
            try:
                out, err = proc.communicate(timeout=2)
            except (subprocess.TimeoutExpired, OSError, ValueError):
                out, err = "", ""
            return ProcessRun(
                returncode=proc.returncode if proc.returncode is not None else -1,
                stdout=_sanitize_capture(out),
                stderr=_sanitize_capture(err),
                timed_out=True,
            )
        rc = proc.poll()
        if rc is not None:
            try:
                out, err = proc.communicate(timeout=5)
            except (subprocess.TimeoutExpired, OSError, ValueError):
                out, err = "", ""
            return ProcessRun(
                returncode=int(rc),
                stdout=_sanitize_capture(out),
                stderr=_sanitize_capture(err),
            )
        time.sleep(0.1)


def _sanitize_capture(data: str | None, limit: int = 64_000) -> str:
    """Keep captured tool output bounded; do not log full contents here."""
    if not data:
        return ""
    if len(data) <= limit:
        return data
    return data[:limit] + "\n…[truncated]"


def _load_json_file(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise AppError(
            code="pe_sieve_output_invalid",
            message="Could not read PE-sieve JSON report.",
            details=str(path),
            entity="pe_sieve",
        ) from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise AppError(
            code="pe_sieve_output_invalid",
            message="PE-sieve JSON report is malformed.",
            details=f"{path.name}: {exc}",
            entity="pe_sieve",
        ) from exc


def find_report_file(output_dir: Path, name: str) -> Path | None:
    """Locate scan_report.json / dump_report.json under /dir or process_<pid>/."""
    root = output_dir.resolve()
    direct = root / name
    if direct.is_file():
        return direct
    try:
        children = list(root.iterdir())
    except OSError:
        return None
    for child in children:
        if not child.is_dir():
            continue
        if not child.name.startswith(VERIFIED_INTERFACE["output_subdir_prefix"]):
            continue
        cand = child / name
        if cand.is_file() and _is_under(cand, root):
            return cand
    return None


def _unwrap_report_blob(blob: Any, inner_key: str) -> dict[str, Any] | None:
    """Accept either a bare report object or the /json stdout wrapper."""
    if not isinstance(blob, dict):
        return None
    if inner_key in blob and isinstance(blob[inner_key], dict):
        return blob[inner_key]
    # Bare scan_report has pid + scanned; dump_report has pid + dumped/dumps
    if inner_key == "scan_report" and ("pid" in blob or "scanned" in blob or "scans" in blob):
        return blob
    if inner_key == "dump_report" and ("dumps" in blob or "dumped" in blob or "output_dir" in blob):
        return blob
    if inner_key == "error_report" and ("pid" in blob or "error" in blob or "message" in blob):
        return blob
    return None


def collect_dump_files(
    output_dir: Path,
    dump_report: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Resolve dump_report dump_file paths; require they stay under output_dir."""
    root = output_dir.resolve()
    items: list[dict[str, Any]] = []
    if not dump_report:
        return items
    dumps = dump_report.get("dumps") or []
    if not isinstance(dumps, list):
        return items
    search_dirs = [root]
    try:
        for child in root.iterdir():
            if child.is_dir() and child.name.startswith("process_"):
                search_dirs.append(child)
    except OSError:
        pass

    for entry in dumps:
        if not isinstance(entry, dict):
            continue
        names = []
        for key in (
            "dump_file",
            "tags_file",
            "iat_hooks_file",
            "imports_file",
            "imp_not_recovered_file",
            "patterns_tag_file",
        ):
            val = entry.get(key)
            if isinstance(val, str) and val.strip():
                names.append((key, val.strip()))
        resolved_files: list[tuple[str, Path]] = []
        for role, raw in names:
            p = Path(raw)
            candidates = [p] if p.is_absolute() else [d / p.name for d in search_dirs] + [root / raw]
            found = None
            for cand in candidates:
                try:
                    rp = cand.resolve()
                except OSError:
                    continue
                if rp.is_file() and _is_under(rp, root):
                    found = rp
                    break
            if found is not None:
                resolved_files.append((role, found))
        items.append({"entry": entry, "files": resolved_files})
    return items


def normalize_pe_sieve_output(
    *,
    scan_report: dict[str, Any] | None,
    dump_report: dict[str, Any] | None,
    error_report: dict[str, Any] | None,
    exit_code: int | None,
    pe_sieve_version: str | None,
    executable_path: str | None,
    output_dir: str | None,
    live_pid: int | None,
    argv: list[str],
) -> dict[str, Any]:
    """Split observed PE-sieve fields from MemScope interpretation.

    Does not invent a malware/threat score.
    """
    pesieve_result = interpret_exit_code(exit_code)
    scanned = {}
    modified = {}
    if isinstance(scan_report, dict):
        scanned = scan_report.get("scanned") or {}
        if isinstance(scanned, dict):
            modified = scanned.get("modified") or {}
        else:
            scanned = {}
            modified = {}
    if not isinstance(modified, dict):
        modified = {}

    def _int(v: Any) -> int | None:
        if v is None:
            return None
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    modified_total = _int(modified.get("total"))
    scanned_total = _int(scanned.get("total")) if isinstance(scanned, dict) else None
    observed_scans: list[dict[str, Any]] = []
    if isinstance(scan_report, dict):
        raw_scans = scan_report.get("scans") or []
        if isinstance(raw_scans, list):
            for item in raw_scans:
                if not isinstance(item, dict):
                    continue
                for scan_type, payload in item.items():
                    if not isinstance(payload, dict):
                        continue
                    observed_scans.append(
                        {
                            "scan_type": str(scan_type),
                            "module": payload.get("module"),
                            "module_file": payload.get("module_file"),
                            "mapped_file": payload.get("mapped_file"),
                            "status": payload.get("status"),
                            "observed": payload,
                        }
                    )

    dumped_summary = {}
    dump_entries: list[dict[str, Any]] = []
    if isinstance(dump_report, dict):
        dumped_summary = dump_report.get("dumped") or {}
        if not isinstance(dumped_summary, dict):
            dumped_summary = {}
        for d in dump_report.get("dumps") or []:
            if isinstance(d, dict):
                dump_entries.append(
                    {
                        "module": d.get("module"),
                        "module_size": d.get("module_size"),
                        "dump_file": d.get("dump_file"),
                        "dump_mode": d.get("dump_mode"),
                        "is_shellcode": d.get("is_shellcode"),
                        "status": d.get("status"),
                        "tags_file": d.get("tags_file"),
                        "iat_hooks_file": d.get("iat_hooks_file"),
                        "imports_file": d.get("imports_file"),
                        "imp_rec_result": d.get("imp_rec_result"),
                        "observed": d,
                    }
                )

    observed = {
        "source": "pe-sieve",
        "verified_release": VERIFIED_RELEASE,
        "exit_code": exit_code,
        "pesieve_result": pesieve_result,
        "pe_sieve_version": pe_sieve_version,
        "executable_path": executable_path,
        "live_pid": live_pid if live_pid is not None else (
            scan_report.get("pid") if isinstance(scan_report, dict) else None
        ),
        "scan_report": {
            "pid": scan_report.get("pid") if isinstance(scan_report, dict) else None,
            "is_64_bit": scan_report.get("is_64_bit") if isinstance(scan_report, dict) else None,
            "is_managed": scan_report.get("is_managed") if isinstance(scan_report, dict) else None,
            "main_image_path": scan_report.get("main_image_path")
            if isinstance(scan_report, dict)
            else None,
            "used_reflection": scan_report.get("used_reflection")
            if isinstance(scan_report, dict)
            else None,
            "scanned_total": scanned_total,
            "scanned_skipped": _int(scanned.get("skipped")) if isinstance(scanned, dict) else None,
            "scanned_errors": _int(scanned.get("errors")) if isinstance(scanned, dict) else None,
            "modified": {
                "total": modified_total,
                "patched": _int(modified.get("patched")),
                "iat_hooked": _int(modified.get("iat_hooked")),
                "replaced": _int(modified.get("replaced")),
                "hdr_modified": _int(modified.get("hdr_modified")),
                "implanted_pe": _int(modified.get("implanted_pe")),
                "implanted_shc": _int(modified.get("implanted_shc")),
                "unreachable_file": _int(modified.get("unreachable_file")),
                "other": _int(modified.get("other")),
            },
            "module_scans": observed_scans,
        }
        if scan_report
        else None,
        "dump_report": {
            "pid": dump_report.get("pid") if isinstance(dump_report, dict) else None,
            "output_dir": dump_report.get("output_dir") if isinstance(dump_report, dict) else None,
            "dumped": dumped_summary,
            "dumps": dump_entries,
        }
        if dump_report
        else None,
        "error_report": error_report,
        "output_dir": output_dir,
        "argv": [Path(argv[0]).name, *argv[1:]] if argv else [],
    }

    has_indicators = bool(
        pesieve_result == "detected" or (modified_total is not None and modified_total > 0)
    )
    interpretation = {
        "source": "memscope",
        "ui_state": compute_ui_state(
            available=True,
            scan_status="completed",
            pesieve_result=pesieve_result,
            modified_total=modified_total,
            target_kind=TARGET_LIVE_PROCESS,
        ),
        "has_indicators": has_indicators,
        "summary": (
            f"PE-sieve reported {modified_total} modified module(s) "
            f"(pesieve_result={pesieve_result})."
            if modified_total is not None
            else f"PE-sieve finished (pesieve_result={pesieve_result})."
        ),
        "notes": (
            "Counts and flags are copied from PE-sieve JSON (observed). "
            "MemScope does not assign a malware or threat score."
        ),
    }
    return {
        "observed": observed,
        "interpretation": interpretation,
        "modified_total": modified_total,
        "pesieve_result": pesieve_result,
        "has_indicators": has_indicators,
    }


@dataclass
class PeSieveProvider:
    """Optional PE-sieve adapter — safe when the EXE is absent."""

    name: str = "pe_sieve"
    tools_dir: Path | None = None
    tmp_dir: Path | None = None
    artifacts_dir: Path | None = None
    executable_path: Path | None = None
    timeout_secs: float = 120.0
    runner: Runner | None = None

    extra_tool_roots: list[Path] = field(default_factory=list)

    def _runner(self) -> Runner:
        return self.runner or default_subprocess_runner

    def _allowed_exe_roots(self) -> list[Path]:
        roots: list[Path] = []
        if self.tools_dir:
            roots.append(self.tools_dir)
            roots.append(self.tools_dir / "pe-sieve")
        roots.extend(self.extra_tool_roots)
        return roots

    def _deny_exe_roots(self) -> list[Path]:
        roots: list[Path] = []
        if self.artifacts_dir:
            roots.append(self.artifacts_dir)
        return roots

    def _resolved_executable(self) -> Path | None:
        if self.executable_path:
            return validate_executable_path(
                self.executable_path,
                self._allowed_exe_roots(),
                deny_roots=self._deny_exe_roots(),
            )
        found = discover_executable(self._allowed_exe_roots())
        if found is None:
            return None
        return validate_executable_path(
            found,
            self._allowed_exe_roots(),
            deny_roots=self._deny_exe_roots(),
        )

    def detect_version(self, exe: Path | None = None) -> str | None:
        target = exe
        if target is None:
            try:
                target = self._resolved_executable()
            except AppError:
                return None
        if target is None:
            return None
        try:
            run = self._runner()(
                build_version_argv(target),
                cwd=target.parent,
                timeout_secs=min(15.0, self.timeout_secs),
                cancelled=None,
            )
        except AppError:
            return None
        if run.timed_out or run.cancelled:
            return None
        return parse_version_output((run.stdout or "") + "\n" + (run.stderr or ""))

    def availability(self) -> dict[str, Any]:
        tools = str(self.tools_dir) if self.tools_dir else None
        base: dict[str, Any] = {
            "provider": self.name,
            "available": False,
            "reason": None,
            "suggestion": None,
            "pe_sieve_version": None,
            "executable_path": None,
            "tools_dir": tools,
            "timeout_secs": self.timeout_secs,
            "verified_release": VERIFIED_RELEASE,
            "verified_interface": VERIFIED_INTERFACE,
            "supported_target_kinds": list(PESIEVE_SUPPORTED_TARGET_KINDS),
            "memscope_artifact_targets_supported": False,
            "unsupported_target_explanation": UNSUPPORTED_ARTIFACT_EXPLANATION,
            "license": {
                "name": "BSD-2-Clause",
                "copyright": "Copyright (c) 2017-2025, @hasherezade",
                "redistribution": (
                    "BSD-2-Clause permits source and binary redistribution with "
                    "copyright notice. MemScope does not bundle PE-sieve; the "
                    "user supplies the official EXE under the tools allow-list."
                ),
                "bundled_in_memscope": False,
            },
        }
        try:
            exe = self._resolved_executable()
        except AppError as exc:
            base["reason"] = exc.message
            base["suggestion"] = exc.suggestion
            base["details"] = exc.details
            return base
        if exe is None:
            base["reason"] = "PE-sieve executable is not installed in the MemScope tools directory."
            base["suggestion"] = (
                f"Download pe-sieve64.exe from https://github.com/hasherezade/pe-sieve/releases/tag/v{VERIFIED_RELEASE} "
                f"and copy it into {tools or 'the MemScope tools directory'}."
            )
            return base
        version = self.detect_version(exe)
        base.update(
            {
                "available": True,
                "pe_sieve_version": version,
                "executable_path": str(exe),
            }
        )
        return base

    def configure(self, settings: dict[str, Any]) -> dict[str, Any]:
        if "timeout_secs" in settings:
            try:
                t = float(settings["timeout_secs"])
                if t < 1 or t > 3600:
                    raise ValueError("out of range")
                self.timeout_secs = t
            except (TypeError, ValueError) as exc:
                raise AppError(
                    code="pe_sieve_invalid_timeout",
                    message="PE-sieve timeout_secs must be between 1 and 3600.",
                    details=str(exc),
                    entity="pe_sieve",
                ) from exc
        if "executable_path" in settings:
            raw = settings["executable_path"]
            if raw in (None, ""):
                self.executable_path = None
            else:
                self.executable_path = validate_executable_path(
                    Path(str(raw)),
                    self._allowed_exe_roots(),
                    deny_roots=self._deny_exe_roots(),
                )
        # Reject any attempt to pass extra CLI tokens through config.
        if "extra_args" in settings or "argv" in settings or "command" in settings:
            raise AppError(
                code="pe_sieve_invalid_config",
                message="Arbitrary PE-sieve command arguments are not allowed.",
                suggestion="Only executable_path and timeout_secs may be configured.",
                entity="pe_sieve",
            )
        return self.availability()

    def assert_target_supported(self, kind: str | None) -> None:
        info = describe_target(kind)
        if not info["supported"]:
            raise AppError(
                code="pe_sieve_unsupported_target",
                message="PE-sieve cannot analyze this MemScope target.",
                details=info["reason"],
                suggestion="PE-sieve requires a live Windows process (/pid). Extracted artifacts are not valid targets.",
                entity="pe_sieve",
                data={"target": info},
            )

    def scan_live_process(
        self,
        pid: Any,
        *,
        output_dir: Path | None = None,
        timeout_secs: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        """Invoke PE-sieve against a live PID. Never executes a target file."""
        avail = self.availability()
        if not avail.get("available"):
            raise AppError(
                code="pe_sieve_unavailable",
                message="PE-sieve is not available on this system.",
                details=avail.get("reason"),
                suggestion=avail.get("suggestion"),
                entity="pe_sieve",
            )
        live_pid = validate_live_pid(pid)
        exe = self._resolved_executable()
        if exe is None:
            raise AppError(
                code="pe_sieve_unavailable",
                message="PE-sieve executable is not available.",
                entity="pe_sieve",
            )
        if self.tmp_dir is None and output_dir is None:
            raise AppError(
                code="pe_sieve_no_output_root",
                message="No controlled temporary directory is configured for PE-sieve output.",
                entity="pe_sieve",
            )
        tmp_root = (output_dir or (self.tmp_dir / "pe_sieve")).expanduser()
        allowed_tmp = [self.tmp_dir] if self.tmp_dir else [tmp_root]
        out = validate_output_dir(tmp_root, allowed_tmp)
        argv = build_scan_argv(exe, live_pid, out)
        if Path(argv[0]).resolve() != exe.resolve():
            raise AppError(
                code="pe_sieve_exe_denied",
                message="Refusing to execute a program that is not the configured PE-sieve EXE.",
                entity="pe_sieve",
            )
        timeout = float(timeout_secs if timeout_secs is not None else self.timeout_secs)
        if cancelled and cancelled():
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")

        run = self._runner()(
            argv,
            cwd=out,
            timeout_secs=timeout,
            cancelled=cancelled,
        )
        if run.cancelled:
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
        if run.timed_out:
            raise AppError(
                code="pe_sieve_timeout",
                message="PE-sieve timed out.",
                suggestion="Increase timeout_secs or scan a smaller process.",
                entity="pe_sieve",
            )

        scan_path = find_report_file(out, "scan_report.json")
        dump_path = find_report_file(out, "dump_report.json")
        err_path = find_report_file(out, "error_report.json")

        scan_report = _load_json_file(scan_path) if scan_path else None
        dump_report = _load_json_file(dump_path) if dump_path else None
        error_report = _load_json_file(err_path) if err_path else None

        stdout_blob = None
        if run.stdout:
            try:
                stdout_blob = json.loads(run.stdout)
            except json.JSONDecodeError:
                stdout_blob = None
        if isinstance(stdout_blob, dict):
            if scan_report is None:
                scan_report = _unwrap_report_blob(stdout_blob, "scan_report")
            if dump_report is None:
                dump_report = _unwrap_report_blob(stdout_blob, "dump_report")

        if isinstance(scan_report, dict):
            scan_report = _unwrap_report_blob(scan_report, "scan_report") or scan_report
        if isinstance(dump_report, dict):
            dump_report = _unwrap_report_blob(dump_report, "dump_report") or dump_report

        pesieve_result = interpret_exit_code(run.returncode)
        if scan_report is None and dump_report is None and error_report is None:
            raise AppError(
                code="pe_sieve_output_invalid",
                message="PE-sieve produced no parseable scan, dump, or error report.",
                details=f"exit_code={run.returncode} pesieve_result={pesieve_result}",
                suggestion="Confirm the EXE is official PE-sieve v0.4.1.1 and that /dir is writable.",
                entity="pe_sieve",
            )

        normalized = normalize_pe_sieve_output(
            scan_report=scan_report if isinstance(scan_report, dict) else None,
            dump_report=dump_report if isinstance(dump_report, dict) else None,
            error_report=error_report if isinstance(error_report, dict) else None,
            exit_code=run.returncode,
            pe_sieve_version=avail.get("pe_sieve_version"),
            executable_path=str(exe),
            output_dir=str(out),
            live_pid=live_pid,
            argv=argv,
        )
        status = "failed" if pesieve_result in ("error", "info", "unknown") and scan_report is None else "completed"
        if error_report is not None and scan_report is None:
            status = "failed"
        dump_files = collect_dump_files(out, dump_report if isinstance(dump_report, dict) else None)
        return {
            "status": status,
            "ui_state": compute_ui_state(
                available=True,
                scan_status=status,
                pesieve_result=normalized["pesieve_result"],
                modified_total=normalized["modified_total"],
                target_kind=TARGET_LIVE_PROCESS,
            ),
            "target_kind": TARGET_LIVE_PROCESS,
            "live_pid": live_pid,
            "pe_sieve_version": avail.get("pe_sieve_version"),
            "executable_path": str(exe),
            "output_dir": str(out),
            "exit_code": run.returncode,
            "pesieve_result": normalized["pesieve_result"],
            "observed": normalized["observed"],
            "interpretation": normalized["interpretation"],
            "scan_report_path": str(scan_path) if scan_path else None,
            "dump_report_path": str(dump_path) if dump_path else None,
            "error_report_path": str(err_path) if err_path else None,
            "dump_files": dump_files,
            "scanned_at": _utcnow(),
        }
