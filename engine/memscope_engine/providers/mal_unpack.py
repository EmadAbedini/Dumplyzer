"""Optional mal_unpack provider: user-supplied Windows EXE.

Verified against hasherezade/mal_unpack **1.0** / ``MALUNP_VERSION_STR "1.0.0.1"``
(mal_unpack_ver.h, params.h, main.cpp, unpack_scanner.h, path_util.cpp).

mal_unpack is a **dynamic unpacker**. Required CLI:

    mal_unpack.exe /exe <path_to_the_malware> /timeout <ms>

It **creates a process from /exe** (main.cpp: ``make_new_process(params.exe_path, ...)``).
Upstream caution: deploy only on a VM.

MemScope never invokes that path against forensic artifacts. The provider records
the real interface, validates configuration, and parses PE-sieve-style dumps
for tests; production artifact jobs do not execute samples.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from memscope_engine.errors import AppError
from memscope_engine.providers.pe_sieve import (
    ProcessRun,
    collect_dump_files,
    default_subprocess_runner,
    find_report_file,
    interpret_exit_code,
    normalize_pe_sieve_output,
    parse_version_output,
)

log = logging.getLogger("memscope.tool")

VERIFIED_RELEASE = "1.0"
VERIFIED_VERSION_STR = "1.0.0.1"
VERIFIED_REPO = "https://github.com/hasherezade/mal_unpack"
VERIFIED_INTERFACE = {
    "release_tag": VERIFIED_RELEASE,
    "version_str": VERIFIED_VERSION_STR,
    "required_args": ["/exe", "/timeout"],
    "exe_arg": "/exe",
    "timeout_arg": "/timeout",
    "timeout_unit": "milliseconds",
    "output_arg": "/dir",
    "version_arg": "/version",
    "output_layout": "{dir}/{exe_basename}.out/scan_{unix_timestamp}/",
    "log_file": "unpack.log",
    "scan_report": "scan_report.json",
    "dump_report": "dump_report.json",
    "error_report": "error_report.json",
    "executes_sample": True,
}

# CMake target is mal_unpack.exe; zip assets are mal_unpack64.zip / mal_unpack32.zip.
_EXE_NAMES = ("mal_unpack.exe", "mal_unpack64.exe", "mal_unpack32.exe")
_EXE_NAME_SET = {n.lower() for n in _EXE_NAMES}

_VERSION_LINE_RE = re.compile(r"MalUnpack:\s*v\.?\s*(\d+\.\d+(?:\.\d+){0,3})", re.I)

TARGET_EXECUTABLE_FILE = "executable_file"
TARGET_ARTIFACT = "artifact"
TARGET_LIVE_PROCESS = "live_process"
TARGET_MEMORY_REGION = "memory_region"
TARGET_MEMORY_DUMP = "memory_dump"

# Native tool target is a PE file that will be executed. MemScope cannot do that safely.
MEMSCOPE_SAFE_TARGET_KINDS: tuple[str, ...] = ()
NATIVE_TARGET_KINDS = (TARGET_EXECUTABLE_FILE,)

UNSUPPORTED_EXPLANATION = (
    "mal_unpack 1.0 (hasherezade/mal_unpack) is a dynamic unpacker: it runs "
    "the file given as /exe, waits, dumps implants with PE-sieve, then kills "
    "the process. MemScope treats memory-derived artifacts as untrusted and "
    "will not execute them. Live processes, memory dumps, and VAD regions are "
    "also not mal_unpack targets. No MemScope investigation target is safe to unpack."
)

Runner = Callable[..., ProcessRun]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return path.resolve() == root.resolve()


def parse_mal_unpack_version(text: str) -> str | None:
    if not text:
        return None
    m = _VERSION_LINE_RE.search(text)
    if m:
        return m.group(1)
    return parse_version_output(text)


def compute_ui_state(
    *,
    available: bool,
    scan_status: str | None = None,
    unpack_result: str | None = None,
    output_count: int | None = None,
    target_kind: str | None = None,
) -> str:
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
        if (output_count or 0) > 0 or unpack_result == "detected":
            return "completed_output_generated"
        return "completed_no_output"
    if not available:
        return "unavailable"
    return "unsupported_target"


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
            candidates.append(resolved_root / "mal_unpack" / name)
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
            code="mal_unpack_exe_missing",
            message="mal_unpack executable was not found.",
            details=str(resolved),
            suggestion="Copy mal_unpack.exe from the official 1.0 release into the MemScope tools directory.",
            entity="mal_unpack",
        )
    if resolved.suffix.lower() != ".exe":
        raise AppError(
            code="mal_unpack_exe_invalid",
            message="mal_unpack executable must be a Windows .exe file.",
            details=str(resolved),
            entity="mal_unpack",
        )
    if resolved.name.lower() not in _EXE_NAME_SET:
        raise AppError(
            code="mal_unpack_exe_invalid",
            message="Executable name is not a known mal_unpack binary.",
            details=resolved.name,
            suggestion="Use mal_unpack.exe from the official hasherezade/mal_unpack 1.0 release.",
            entity="mal_unpack",
        )
    for deny in deny_roots or []:
        if _is_under(resolved, deny):
            raise AppError(
                code="mal_unpack_exe_denied",
                message="Refusing to execute a path inside the artifact store.",
                details=str(resolved),
                entity="mal_unpack",
            )
    roots = [r.expanduser().resolve() for r in allowed_roots if r is not None]
    if not any(_is_under(resolved, root) for root in roots):
        raise AppError(
            code="mal_unpack_exe_path_denied",
            message="mal_unpack executable is outside configured allowed tool directories.",
            details=str(resolved),
            suggestion="Place the official mal_unpack EXE under the MemScope tools directory.",
            entity="mal_unpack",
        )
    try:
        with resolved.open("rb") as f:
            magic = f.read(2)
    except OSError as exc:
        raise AppError(
            code="mal_unpack_exe_invalid",
            message="Could not read mal_unpack executable.",
            details=str(exc),
            entity="mal_unpack",
        ) from exc
    if magic != b"MZ":
        raise AppError(
            code="mal_unpack_exe_invalid",
            message="mal_unpack executable does not look like a Windows PE file.",
            details=str(resolved),
            entity="mal_unpack",
        )
    return resolved


def validate_output_dir(path: Path, allowed_roots: list[Path]) -> Path:
    resolved = path.expanduser().resolve()
    if not any(_is_under(resolved, root.expanduser().resolve()) for root in allowed_roots):
        raise AppError(
            code="mal_unpack_output_denied",
            message="mal_unpack output directory is outside controlled temp roots.",
            details=str(resolved),
            entity="mal_unpack",
        )
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def validate_timeout_ms(value: Any) -> int:
    try:
        ms = int(value)
    except (TypeError, ValueError) as exc:
        raise AppError(
            code="mal_unpack_invalid_timeout",
            message="mal_unpack /timeout must be an integer number of milliseconds.",
            details=str(value),
            entity="mal_unpack",
        ) from exc
    if ms < 1 or ms > 3_600_000:
        raise AppError(
            code="mal_unpack_invalid_timeout",
            message="mal_unpack timeout_ms must be between 1 and 3600000.",
            details=str(ms),
            entity="mal_unpack",
        )
    return ms


def describe_target(kind: str | None) -> dict[str, Any]:
    k = (kind or "").strip() or TARGET_ARTIFACT
    native = k == TARGET_EXECUTABLE_FILE
    memscope_safe = False
    reasons = {
        TARGET_ARTIFACT: (
            "mal_unpack would pass this artifact as /exe and execute it. "
            "MemScope never executes forensic artifacts."
        ),
        TARGET_EXECUTABLE_FILE: (
            "Native mal_unpack target is a PE file that is started as a process. "
            "MemScope will not execute untrusted files."
        ),
        TARGET_LIVE_PROCESS: (
            "mal_unpack does not attach to an existing PID; it starts /exe as a new process."
        ),
        TARGET_MEMORY_REGION: "mal_unpack does not unpack VAD/memory-region dumps.",
        TARGET_MEMORY_DUMP: "mal_unpack does not operate on memory images.",
    }
    return {
        "kind": k,
        "native_tool_target": native,
        "supported": False,
        "memscope_safe": memscope_safe,
        "reason": reasons.get(k, UNSUPPORTED_EXPLANATION),
        "mal_unpack_requires": "/exe <path> (file is executed) and /timeout <ms>",
        "verified_release": VERIFIED_RELEASE,
        "executes_sample": True,
    }


def build_version_argv(exe: Path) -> list[str]:
    return [str(exe), "/version"]


def build_unpack_argv(exe: Path, sample: Path, timeout_ms: int, output_dir: Path) -> list[str]:
    """Construct mal_unpack argv from the verified 1.0 interface.

    /exe and /timeout are required. /dir is the verified output root.
    /cmd is never passed (would become the sample's command line).
    No user-supplied extra arguments.
    """
    if Path(exe).resolve() == Path(sample).resolve():
        raise AppError(
            code="mal_unpack_exe_denied",
            message="The analyzed file must not be the mal_unpack executable.",
            entity="mal_unpack",
        )
    return [
        str(exe),
        "/exe",
        str(sample),
        "/timeout",
        str(int(timeout_ms)),
        "/dir",
        str(output_dir),
    ]


def _load_json_file(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise AppError(
            code="mal_unpack_output_invalid",
            message="Could not read mal_unpack/PE-sieve JSON report.",
            details=str(path),
            entity="mal_unpack",
        ) from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise AppError(
            code="mal_unpack_output_invalid",
            message="mal_unpack JSON report is malformed.",
            details=f"{path.name}: {exc}",
            entity="mal_unpack",
        ) from exc


def find_scan_roots(output_dir: Path) -> list[Path]:
    """Locate ``*.out/scan_<timestamp>`` trees produced by main.cpp."""
    root = output_dir.resolve()
    found: list[Path] = []
    try:
        children = list(root.iterdir())
    except OSError:
        return found
    for child in children:
        if not child.is_dir() or not _is_under(child, root):
            continue
        if child.name.endswith(".out"):
            for scan in child.iterdir() if child.is_dir() else []:
                if scan.is_dir() and scan.name.startswith("scan_") and _is_under(scan, root):
                    found.append(scan)
        if child.name.startswith("scan_"):
            found.append(child)
    return found


def normalize_mal_unpack_output(
    *,
    scan_report: dict[str, Any] | None,
    dump_report: dict[str, Any] | None,
    error_report: dict[str, Any] | None,
    exit_code: int | None,
    mal_unpack_version: str | None,
    executable_path: str | None,
    output_dir: str | None,
    sample_name: str | None,
    argv: list[str],
    unpack_log: str | None,
) -> dict[str, Any]:
    pesieve_norm = normalize_pe_sieve_output(
        scan_report=scan_report,
        dump_report=dump_report,
        error_report=error_report,
        exit_code=exit_code,
        pe_sieve_version=None,
        executable_path=executable_path,
        output_dir=output_dir,
        live_pid=None,
        argv=argv,
    )
    dump_count = 0
    dump_rep = pesieve_norm["observed"].get("dump_report") or {}
    if isinstance(dump_rep, dict):
        dumps = dump_rep.get("dumps") or []
        if isinstance(dumps, list):
            dump_count = len(dumps)
    unpack_result = pesieve_norm["pesieve_result"]
    observed = {
        "source": "mal_unpack",
        "verified_release": VERIFIED_RELEASE,
        "verified_version_str": VERIFIED_VERSION_STR,
        "executes_sample": True,
        "sample_name": sample_name,
        "exit_code": exit_code,
        "unpack_result": unpack_result,
        "mal_unpack_version": mal_unpack_version,
        "executable_path": executable_path,
        "output_dir": output_dir,
        "unpack_log_excerpt": (unpack_log or "")[:4000] if unpack_log else None,
        "pe_sieve_dump": pesieve_norm["observed"],
        "argv": [Path(argv[0]).name, *argv[1:]] if argv else [],
    }
    interpretation = {
        "source": "memscope",
        "ui_state": compute_ui_state(
            available=True,
            scan_status="completed",
            unpack_result=unpack_result,
            output_count=dump_count,
        ),
        "output_count": dump_count,
        "summary": (
            f"mal_unpack finished (unpack_result={unpack_result}, dumps={dump_count})."
        ),
        "notes": (
            "Observed fields come from mal_unpack's PE-sieve dump reports. "
            "MemScope does not assign a malware score. Production workflows "
            "do not execute samples; this result is only produced when invocation "
            "was explicitly confirmed in a test harness."
        ),
    }
    return {
        "observed": observed,
        "interpretation": interpretation,
        "unpack_result": unpack_result,
        "output_count": dump_count,
    }


@dataclass
class MalUnpackProvider:
    """Optional mal_unpack adapter — safe when the EXE is absent; never auto-runs samples."""

    name: str = "mal_unpack"
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
            roots.append(self.tools_dir / "mal_unpack")
        roots.extend(self.extra_tool_roots)
        return roots

    def _deny_exe_roots(self) -> list[Path]:
        roots: list[Path] = []
        if self.artifacts_dir:
            roots.append(self.artifacts_dir)
        return roots

    def timeout_ms(self) -> int:
        return validate_timeout_ms(int(self.timeout_secs * 1000))

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
        return parse_mal_unpack_version((run.stdout or "") + "\n" + (run.stderr or ""))

    def availability(self) -> dict[str, Any]:
        tools = str(self.tools_dir) if self.tools_dir else None
        base: dict[str, Any] = {
            "provider": self.name,
            "available": False,
            "reason": None,
            "suggestion": None,
            "mal_unpack_version": None,
            "executable_path": None,
            "tools_dir": tools,
            "timeout_secs": self.timeout_secs,
            "timeout_ms": int(self.timeout_secs * 1000),
            "verified_release": VERIFIED_RELEASE,
            "verified_version_str": VERIFIED_VERSION_STR,
            "verified_repo": VERIFIED_REPO,
            "verified_interface": VERIFIED_INTERFACE,
            "native_target_kinds": list(NATIVE_TARGET_KINDS),
            "supported_target_kinds": list(MEMSCOPE_SAFE_TARGET_KINDS),
            "memscope_artifact_targets_supported": False,
            "executes_sample": True,
            "unsupported_target_explanation": UNSUPPORTED_EXPLANATION,
            "license": {
                "name": "BSD-2-Clause",
                "copyright": "Copyright (c) 2018-2025, hasherezade",
                "redistribution": (
                    "BSD-2-Clause permits source and binary redistribution with "
                    "copyright notice. MemScope does not bundle mal_unpack; the "
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
            base["reason"] = "mal_unpack executable is not installed in the MemScope tools directory."
            base["suggestion"] = (
                f"Download mal_unpack64.zip from {VERIFIED_REPO}/releases/tag/{VERIFIED_RELEASE} "
                f"and copy mal_unpack.exe into {tools or 'the MemScope tools directory'}."
            )
            return base
        version = self.detect_version(exe)
        base.update(
            {
                "available": True,
                "mal_unpack_version": version,
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
                    code="mal_unpack_invalid_timeout",
                    message="mal_unpack timeout_secs must be between 1 and 3600.",
                    details=str(exc),
                    entity="mal_unpack",
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
        if "extra_args" in settings or "argv" in settings or "command" in settings or "cmd" in settings:
            raise AppError(
                code="mal_unpack_invalid_config",
                message="Arbitrary mal_unpack command arguments are not allowed.",
                suggestion="Only executable_path and timeout_secs may be configured. /cmd is never passed.",
                entity="mal_unpack",
            )
        return self.availability()

    def assert_target_supported(self, kind: str | None) -> None:
        info = describe_target(kind)
        raise AppError(
            code="mal_unpack_unsupported_target",
            message="mal_unpack cannot be used on this MemScope target.",
            details=info["reason"],
            suggestion="MemScope will not execute artifacts. Use a dedicated VM unpacker outside this investigation.",
            entity="mal_unpack",
            data={"target": info},
        )

    def run_unpack(
        self,
        sample: Path,
        *,
        output_dir: Path | None = None,
        timeout_secs: float | None = None,
        cancelled: Callable[[], bool] | None = None,
        confirm_sample_execution: bool = False,
    ) -> dict[str, Any]:
        """Invoke mal_unpack. Requires an explicit confirm flag.

        Production workflows must not set confirm_sample_execution. Tests may
        set it together with a mock runner so the sample is never actually started.
        """
        if not confirm_sample_execution:
            raise AppError(
                code="mal_unpack_execution_forbidden",
                message="Refusing to run mal_unpack: it executes the file given as /exe.",
                details=UNSUPPORTED_EXPLANATION,
                suggestion="MemScope does not deploy samples. Unpack packed malware on an isolated VM only.",
                entity="mal_unpack",
            )
        avail = self.availability()
        if not avail.get("available"):
            raise AppError(
                code="mal_unpack_unavailable",
                message="mal_unpack is not available on this system.",
                details=avail.get("reason"),
                suggestion=avail.get("suggestion"),
                entity="mal_unpack",
            )
        exe = self._resolved_executable()
        if exe is None:
            raise AppError(
                code="mal_unpack_unavailable",
                message="mal_unpack executable is not available.",
                entity="mal_unpack",
            )
        sample_path = sample.expanduser().resolve()
        if not sample_path.is_file():
            raise AppError(
                code="mal_unpack_sample_missing",
                message="mal_unpack sample path does not exist.",
                details=str(sample_path),
                entity="mal_unpack",
            )
        if sample_path.resolve() == exe.resolve():
            raise AppError(
                code="mal_unpack_exe_denied",
                message="The analyzed file must not be the mal_unpack executable.",
                entity="mal_unpack",
            )
        if self.artifacts_dir and _is_under(sample_path, self.artifacts_dir):
            raise AppError(
                code="mal_unpack_execution_forbidden",
                message="Refusing to pass an artifact-store path as mal_unpack /exe.",
                details=str(sample_path),
                entity="mal_unpack",
            )
        if self.tmp_dir is None and output_dir is None:
            raise AppError(
                code="mal_unpack_no_output_root",
                message="No controlled temporary directory is configured for mal_unpack output.",
                entity="mal_unpack",
            )
        tmp_root = (output_dir or (self.tmp_dir / "mal_unpack")).expanduser()
        allowed_tmp = [self.tmp_dir] if self.tmp_dir else [tmp_root]
        out = validate_output_dir(tmp_root, allowed_tmp)
        timeout = float(timeout_secs if timeout_secs is not None else self.timeout_secs)
        timeout_ms = validate_timeout_ms(int(timeout * 1000))
        argv = build_unpack_argv(exe, sample_path, timeout_ms, out)
        if Path(argv[0]).resolve() != exe.resolve():
            raise AppError(
                code="mal_unpack_exe_denied",
                message="Refusing to execute a program that is not the configured mal_unpack EXE.",
                entity="mal_unpack",
            )
        if "/cmd" in argv:
            raise AppError(
                code="mal_unpack_invalid_argv",
                message="Refusing argv that would pass a command line to the sample.",
                entity="mal_unpack",
            )
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
                code="mal_unpack_timeout",
                message="mal_unpack timed out.",
                suggestion="Increase timeout_secs. Note: /timeout is milliseconds in the native CLI.",
                entity="mal_unpack",
            )

        scan_roots = find_scan_roots(out)
        search_roots = scan_roots or [out]
        scan_path = dump_path = err_path = None
        for root in search_roots:
            scan_path = scan_path or find_report_file(root, "scan_report.json")
            dump_path = dump_path or find_report_file(root, "dump_report.json")
            err_path = err_path or find_report_file(root, "error_report.json")
        if scan_path is None:
            scan_path = find_report_file(out, "scan_report.json")
        if dump_path is None:
            dump_path = find_report_file(out, "dump_report.json")

        scan_report = _load_json_file(scan_path) if scan_path else None
        dump_report = _load_json_file(dump_path) if dump_path else None
        error_report = _load_json_file(err_path) if err_path else None
        if isinstance(scan_report, dict) and "scan_report" in scan_report:
            inner = scan_report.get("scan_report")
            if isinstance(inner, dict):
                scan_report = inner
        if isinstance(dump_report, dict) and "dump_report" in dump_report:
            inner = dump_report.get("dump_report")
            if isinstance(inner, dict):
                dump_report = inner

        unpack_result = interpret_exit_code(run.returncode)
        if scan_report is None and dump_report is None and error_report is None:
            raise AppError(
                code="mal_unpack_output_invalid",
                message="mal_unpack produced no parseable scan, dump, or error report.",
                details=f"exit_code={run.returncode} unpack_result={unpack_result}",
                entity="mal_unpack",
            )

        log_text = None
        log_file = out / "unpack.log"
        if log_file.is_file():
            try:
                log_text = log_file.read_text(encoding="utf-8", errors="replace")[:8000]
            except OSError:
                log_text = None

        normalized = normalize_mal_unpack_output(
            scan_report=scan_report if isinstance(scan_report, dict) else None,
            dump_report=dump_report if isinstance(dump_report, dict) else None,
            error_report=error_report if isinstance(error_report, dict) else None,
            exit_code=run.returncode,
            mal_unpack_version=avail.get("mal_unpack_version"),
            executable_path=str(exe),
            output_dir=str(out),
            sample_name=sample_path.name,
            argv=argv,
            unpack_log=log_text,
        )
        status = "failed" if unpack_result in ("error", "info", "unknown") and scan_report is None else "completed"
        if error_report is not None and scan_report is None:
            status = "failed"
        dump_files: list[dict[str, Any]] = []
        for root in search_roots:
            dump_files.extend(
                collect_dump_files(root, dump_report if isinstance(dump_report, dict) else None)
            )
        return {
            "status": status,
            "ui_state": compute_ui_state(
                available=True,
                scan_status=status,
                unpack_result=normalized["unpack_result"],
                output_count=normalized["output_count"],
            ),
            "target_kind": TARGET_EXECUTABLE_FILE,
            "mal_unpack_version": avail.get("mal_unpack_version"),
            "executable_path": str(exe),
            "output_dir": str(out),
            "exit_code": run.returncode,
            "unpack_result": normalized["unpack_result"],
            "observed": normalized["observed"],
            "interpretation": normalized["interpretation"],
            "scan_report_path": str(scan_path) if scan_path else None,
            "dump_report_path": str(dump_path) if dump_path else None,
            "error_report_path": str(err_path) if err_path else None,
            "dump_files": dump_files,
            "scanned_at": _utcnow(),
            "invoked": True,
        }
