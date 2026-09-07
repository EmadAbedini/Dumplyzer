"""Shared subprocess helper for optional analysis EXEs (never shell)."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from memscope_engine.errors import AppError

log = logging.getLogger("memscope.tool")


@dataclass
class ProcessRun:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    cancelled: bool = False
    tree_terminated: bool = False


def path_is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return path.resolve() == root.resolve()


def sanitize_capture(data: str | None, limit: int = 64_000) -> str:
    """Keep captured tool output bounded; do not log full contents here."""
    if not data:
        return ""
    if len(data) <= limit:
        return data
    return data[:limit] + "\n…[truncated]"


def tool_display_name(entity: str) -> str:
    return {"capa": "CAPA", "floss": "FLOSS", "bulk_extractor": "bulk_extractor"}.get(entity, entity)


def captured_run_output(run: ProcessRun) -> str | None:
    parts: list[str] = []
    if run.stdout:
        parts.append("stdout:\n" + run.stdout)
    if run.stderr:
        parts.append("stderr:\n" + run.stderr)
    return "\n".join(parts) if parts else None


def timeout_app_error(
    entity: str,
    timeout_secs: float,
    run: ProcessRun,
    *,
    code: str,
    suggestion: str,
) -> AppError:
    label = tool_display_name(entity)
    return AppError(
        code=code,
        message=f"{label} timed out after {int(timeout_secs)} seconds; process tree terminated.",
        details=captured_run_output(run),
        suggestion=suggestion,
        entity=entity,
        data={
            "timeout_secs": int(timeout_secs),
            "process_tree_terminated": bool(run.tree_terminated),
            "exit_code": run.returncode,
        },
    )


def bundled_tool_roots(subdir: str | None = None) -> list[Path]:
    """Install-tree / env roots that hold shipped optional tool EXEs."""
    found: list[Path] = []
    seen: set[str] = set()

    def _add(path: Path) -> None:
        try:
            resolved = path.expanduser().resolve()
        except OSError:
            return
        if not resolved.is_dir():
            return
        key = str(resolved).lower()
        if key in seen:
            return
        seen.add(key)
        found.append(resolved)

    raw = os.environ.get("DUMPLYZER_BUNDLE_TOOLS")
    if raw and raw.strip():
        p = Path(raw.strip())
        _add(p)
        if subdir:
            _add(p / subdir)
            if p.name.lower() == subdir.lower() and p.parent:
                _add(p.parent)
    try:
        runtime = Path(sys.executable).resolve().parent
        _add(runtime.parent / "tools")
        _add(runtime.parent / "resources" / "tools")
        if subdir:
            _add(runtime.parent / "tools" / subdir)
            _add(runtime.parent / "resources" / "tools" / subdir)
    except OSError:
        pass
    return found


def unique_path(directory: Path, filename: str) -> Path:
    """Return a collision-free path under directory."""
    directory.mkdir(parents=True, exist_ok=True)
    dest = directory / filename
    if not dest.exists():
        return dest
    stem = dest.stem
    suffix = dest.suffix
    n = 1
    while True:
        cand = directory / f"{stem}-{n}{suffix}"
        if not cand.exists():
            return cand
        n += 1


def evidence_fingerprint(path: Path) -> dict[str, Any]:
    st = path.stat()
    return {"size_bytes": st.st_size, "mtime_ns": st.st_mtime_ns, "path": str(path)}


def assert_evidence_unchanged(path: Path, before: dict[str, Any], *, entity: str = "evidence") -> None:
    after = evidence_fingerprint(path)
    if after["size_bytes"] != before.get("size_bytes") or after["mtime_ns"] != before.get("mtime_ns"):
        raise AppError(
            code="evidence_mutated",
            message="The memory image changed while analysis was running.",
            details=str({"before": before, "after": after}),
            entity=entity,
        )


_CREATE_NO_WINDOW = 0x08000000
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9


def _windows_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            return bool(ok) and int(code.value) == STILL_ACTIVE
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:  # noqa: BLE001
        return False


def _windows_taskkill_tree(pid: int) -> None:
    """Kill pid and descendants only (taskkill /T). Never broadcasts."""
    if pid <= 0:
        return
    flags = _CREATE_NO_WINDOW
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(int(pid))],
            capture_output=True,
            timeout=15,
            check=False,
            creationflags=flags,
        )
    except (OSError, subprocess.TimeoutExpired):
        return


class _WindowsJob:
    """Job object so PyInstaller child processes die with the tool EXE."""

    def __init__(self) -> None:
        self.handle = 0
        if sys.platform != "win32":
            return
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32
            self.handle = int(kernel32.CreateJobObjectW(None, None) or 0)
            if not self.handle:
                return

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_uint64),
                    ("WriteOperationCount", ctypes.c_uint64),
                    ("OtherOperationCount", ctypes.c_uint64),
                    ("ReadTransferCount", ctypes.c_uint64),
                    ("WriteTransferCount", ctypes.c_uint64),
                    ("OtherTransferCount", ctypes.c_uint64),
                ]

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            kernel32.SetInformationJobObject(
                self.handle,
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
        except Exception:  # noqa: BLE001
            self.close()

    def assign(self, pid: int) -> bool:
        if not self.handle or pid <= 0 or sys.platform != "win32":
            return False
        try:
            import ctypes

            PROCESS_SET_QUOTA = 0x0100
            PROCESS_TERMINATE = 0x0001
            PROCESS_SYNCHRONIZE = 0x00100000
            access = PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE
            proc = ctypes.windll.kernel32.OpenProcess(access, False, int(pid))
            if not proc:
                return False
            try:
                ok = bool(ctypes.windll.kernel32.AssignProcessToJobObject(self.handle, proc))
            finally:
                ctypes.windll.kernel32.CloseHandle(proc)
            return ok
        except Exception:  # noqa: BLE001
            return False

    def terminate(self) -> None:
        if not self.handle or sys.platform != "win32":
            return
        try:
            import ctypes

            ctypes.windll.kernel32.TerminateJobObject(self.handle, 1)
        except Exception:  # noqa: BLE001
            return

    def close(self) -> None:
        if not self.handle or sys.platform != "win32":
            self.handle = 0
            return
        try:
            import ctypes

            ctypes.windll.kernel32.CloseHandle(self.handle)
        except Exception:  # noqa: BLE001
            pass
        self.handle = 0


def _drain_pipe(stream: Any, chunks: list[str], limit: int) -> None:
    total = 0
    try:
        while True:
            piece = stream.read(4096) if stream else ""
            if not piece:
                break
            if total < limit:
                take = piece[: limit - total]
                chunks.append(take)
                total += len(take)
    except (OSError, ValueError):
        return


def _terminate_process_tree(proc: subprocess.Popen[str], job: _WindowsJob | None) -> bool:
    """Terminate the tool process and its Windows children. Returns True if a tree kill ran."""
    pid = int(proc.pid or 0)
    if job is not None:
        job.terminate()
    if sys.platform == "win32" and pid:
        _windows_taskkill_tree(pid)
    try:
        proc.terminate()
    except OSError:
        pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=3)
        except (subprocess.TimeoutExpired, OSError):
            pass
        if sys.platform == "win32" and pid:
            _windows_taskkill_tree(pid)
    if sys.platform == "win32" and pid:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and _windows_pid_alive(pid):
            _windows_taskkill_tree(pid)
            time.sleep(0.2)
        return not _windows_pid_alive(pid)
    return proc.poll() is not None


def default_subprocess_runner(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout_secs: float = 30.0,
    cancelled: Callable[[], bool] | None = None,
    entity: str = "tool",
    exec_failed_code: str = "tool_exec_failed",
    invalid_argv_code: str = "tool_invalid_argv",
    log_label: str = "tool exec",
) -> ProcessRun:
    """Run argv as an argument array (never shell). Cooperative cancel + timeout.

    On Windows the child is assigned to a job object so PyInstaller helper
    processes are terminated with the tool. stdout/stderr are drained so a
    large JSON report cannot deadlock the pipe.
    """
    if not argv:
        raise AppError(
            code=invalid_argv_code,
            message="Refusing to execute an empty argument list.",
            entity=entity,
        )
    creationflags = 0
    if sys.platform == "win32":
        creationflags = _CREATE_NO_WINDOW | _CREATE_NEW_PROCESS_GROUP

    log.info(
        log_label,
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
            code=exec_failed_code,
            message=f"{tool_display_name(entity)} failed to start.",
            details=f"{type(exc).__name__}: {exc}",
            entity=entity,
        ) from exc

    job = _WindowsJob() if sys.platform == "win32" else None
    if job is not None:
        job.assign(int(proc.pid or 0))

    out_chunks: list[str] = []
    err_chunks: list[str] = []
    readers = [
        threading.Thread(target=_drain_pipe, args=(proc.stdout, out_chunks, 64_000), daemon=True),
        threading.Thread(target=_drain_pipe, args=(proc.stderr, err_chunks, 64_000), daemon=True),
    ]
    for thread in readers:
        thread.start()

    deadline = time.monotonic() + max(1.0, float(timeout_secs))
    timed_out = False
    was_cancelled = False
    tree_terminated = False
    try:
        while True:
            if cancelled and cancelled():
                was_cancelled = True
                tree_terminated = _terminate_process_tree(proc, job)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                tree_terminated = _terminate_process_tree(proc, job)
                break
            rc = proc.poll()
            if rc is not None:
                break
            time.sleep(0.1)
        for thread in readers:
            thread.join(timeout=2)
        try:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
        except OSError:
            pass
        rc = proc.poll()
        return ProcessRun(
            returncode=int(rc) if rc is not None else -1,
            stdout=sanitize_capture("".join(out_chunks)),
            stderr=sanitize_capture("".join(err_chunks)),
            timed_out=timed_out,
            cancelled=was_cancelled,
            tree_terminated=tree_terminated,
        )
    finally:
        if job is not None:
            job.close()
