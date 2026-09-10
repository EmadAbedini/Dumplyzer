"""Optional FLOSS provider: bundled Mandiant standalone Windows EXE.

FLOSS (https://github.com/mandiant/flare-floss) extracts static and
deobfuscated strings from PE files. Apache-2.0. Dumplyzer ships the official
v3.1.1 Windows standalone zip and invokes ``floss.exe`` as a separate process
against extracted PE artifacts only.

Strings are not treated as malicious findings. Dumplyzer never downloads
FLOSS at runtime.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from memscope_engine.errors import AppError
from memscope_engine.providers.process_run import (
    ProcessRun,
    bundled_tool_roots,
    captured_run_output,
    default_subprocess_runner,
    path_is_under,
    timeout_app_error,
)

log = logging.getLogger("memscope.tool")

VERIFIED_RELEASE = "3.1.1"
VERIFIED_REPO = "https://github.com/mandiant/flare-floss"
VERIFIED_INTERFACE = {
    "release": VERIFIED_RELEASE,
    "version_arg": "--version",
    "json_arg": "-j",
    "quiet_arg": "-q",
    "windows_asset": "floss-v3.1.1-windows.zip",
}

_EXE_NAMES = ("floss.exe",)
_EXE_NAME_SET = {n.lower() for n in _EXE_NAMES}
_VERSION_RE = re.compile(r"floss\s+v?(\d+\.\d+(?:\.\d+){0,3})", re.IGNORECASE)

MAX_STRINGS = 5_000
STRING_KINDS = ("static_strings", "stack_strings", "tight_strings", "decoded_strings")

Runner = Callable[..., ProcessRun]


def parse_version_output(text: str) -> str | None:
    if not text:
        return None
    m = _VERSION_RE.search(text)
    if m:
        return m.group(1)
    m = re.search(r"v?(\d+\.\d+(?:\.\d+){0,3})", text)
    return m.group(1) if m else None


def bundled_floss_roots() -> list[Path]:
    return bundled_tool_roots("floss")


def discover_executable(roots: list[Path]) -> Path | None:
    for root in roots:
        if not root:
            continue
        try:
            resolved_root = root.expanduser().resolve()
        except OSError:
            continue
        for name in _EXE_NAMES:
            for cand in (resolved_root / name, resolved_root / "floss" / name):
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
            code="floss_exe_missing",
            message="FLOSS executable was not found.",
            details=str(resolved),
            suggestion="Reinstall Dumplyzer so floss.exe is present under application resources.",
            entity="floss",
        )
    if resolved.suffix.lower() != ".exe" or resolved.name.lower() not in _EXE_NAME_SET:
        raise AppError(
            code="floss_exe_invalid",
            message="Executable name is not a known FLOSS binary.",
            details=resolved.name,
            suggestion="Use floss.exe from the official Mandiant FLOSS Windows release.",
            entity="floss",
        )
    for deny in deny_roots or []:
        if path_is_under(resolved, deny):
            raise AppError(
                code="floss_exe_denied",
                message="Refusing to treat an investigation artifact as the FLOSS executable.",
                entity="floss",
            )
    if not any(path_is_under(resolved, root) for root in allowed_roots if root):
        raise AppError(
            code="floss_exe_path_denied",
            message="FLOSS executable is outside configured allowed tool directories.",
            suggestion="Place floss.exe under application resources/tools/floss or the Dumplyzer tools directory.",
            entity="floss",
        )
    try:
        head = resolved.read_bytes()[:2]
    except OSError as exc:
        raise AppError(
            code="floss_exe_invalid",
            message="Could not read FLOSS executable.",
            details=str(exc),
            entity="floss",
        ) from exc
    if head != b"MZ":
        raise AppError(
            code="floss_exe_invalid",
            message="FLOSS executable does not look like a Windows PE file.",
            entity="floss",
        )
    return resolved


def build_version_argv(exe: Path) -> list[str]:
    return [str(exe), "--version"]


def build_scan_argv(exe: Path, sample: Path) -> list[str]:
    """Official standalone FLOSS v3 interface. No user-supplied extra argv."""
    return [str(exe), "-q", "-j", str(sample)]


def is_pe_sample(path: Path) -> bool:
    try:
        return path.read_bytes()[:2] == b"MZ"
    except OSError:
        return False


def _string_value(item: Any) -> tuple[str | None, dict[str, Any]]:
    if isinstance(item, str):
        return item, {}
    if isinstance(item, dict):
        value = item.get("string") or item.get("value") or item.get("decoded_string")
        extra = {k: v for k, v in item.items() if k not in {"string", "value", "decoded_string"}}
        return (str(value) if value is not None else None), extra
    return None, {}


def normalize_floss_json(doc: dict[str, Any]) -> dict[str, Any]:
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    strings_root = doc.get("strings") if isinstance(doc.get("strings"), dict) else {}
    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for kind in STRING_KINDS:
        items = strings_root.get(kind) or []
        if not isinstance(items, list):
            continue
        counts[kind] = 0
        for item in items:
            value, extra = _string_value(item)
            if not value:
                continue
            rows.append(
                {
                    "kind": kind.replace("_strings", ""),
                    "value": value[:4000],
                    "offset": extra.get("offset") or extra.get("va") or extra.get("address"),
                    "encoding": extra.get("encoding"),
                    "observed": extra,
                }
            )
            counts[kind] += 1
            if len(rows) >= MAX_STRINGS:
                break
        if len(rows) >= MAX_STRINGS:
            break
    version = meta.get("version") or doc.get("version")
    interpretation = {
        "kind": "extracted_string",
        "source": "floss",
        "summary": (
            f"FLOSS extracted {len(rows)} string(s) "
            f"(static/stack/tight/decoded). Strings are not malware findings."
        ),
        "notes": (
            "Decoded and stack strings are statically recovered. Dumplyzer does "
            "not treat string presence as a malicious indicator."
        ),
    }
    return {
        "floss_version": version,
        "string_count": len(rows),
        "strings": rows,
        "counts": counts,
        "observed": {
            "metadata": {"version": version},
            "string_count": len(rows),
            "counts": counts,
        },
        "interpretation": interpretation,
    }


@dataclass
class FlossProvider:
    name: str = "floss"
    tools_dir: Path | None = None
    analysis_dir: Path | None = None
    artifacts_dir: Path | None = None
    executable_path: Path | None = None
    timeout_secs: float = 900.0
    runner: Runner | None = None
    extra_tool_roots: list[Path] = field(default_factory=list)

    def _runner(self) -> Runner:
        return self.runner or default_subprocess_runner

    def _allowed_exe_roots(self) -> list[Path]:
        roots: list[Path] = []
        roots.extend(self.extra_tool_roots)
        if self.tools_dir:
            roots.append(self.tools_dir)
            roots.append(self.tools_dir / "floss")
        return roots

    def _deny_exe_roots(self) -> list[Path]:
        roots: list[Path] = []
        if self.artifacts_dir:
            roots.append(self.artifacts_dir)
        if self.analysis_dir:
            roots.append(self.analysis_dir)
        return roots

    def _source_for(self, exe: Path) -> str:
        for root in self.extra_tool_roots:
            if root and path_is_under(exe, root):
                return "bundled"
        return "user-supplied"

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
                entity="floss",
                exec_failed_code="floss_exec_failed",
                log_label="floss version",
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
            "floss_version": None,
            "executable_path": None,
            "tools_dir": tools,
            "timeout_secs": self.timeout_secs,
            "verified_release": VERIFIED_RELEASE,
            "verified_repo": VERIFIED_REPO,
            "verified_interface": VERIFIED_INTERFACE,
            "supported_target_kinds": ["extracted_pe"],
            "target": "extracted_pe",
            "source": None,
            "license": {
                "name": "Apache-2.0",
                "redistribution": "Apache-2.0. Official standalone Windows binary may be redistributed.",
                "bundled_in_memscope": True,
            },
        }
        try:
            exe = self._resolved_executable()
        except AppError as exc:
            base["reason"] = exc.message
            base["suggestion"] = exc.suggestion
            return base
        if exe is None:
            base["reason"] = "The bundled FLOSS executable is missing from application resources."
            base["suggestion"] = (
                "Reinstall Dumplyzer so floss.exe is present under resources/tools/floss. "
                f"An official override may also be placed in {tools or 'the Dumplyzer tools directory'}."
            )
            return base
        version = self.detect_version(exe)
        base.update(
            {
                "available": True,
                "floss_version": version,
                "executable_path": str(exe),
                "source": self._source_for(exe),
            }
        )
        return base

    def configure(self, settings: dict[str, Any]) -> dict[str, Any]:
        if "timeout_secs" in settings:
            try:
                t = float(settings["timeout_secs"])
                if t < 1 or t > 7200:
                    raise ValueError("out of range")
                self.timeout_secs = t
            except (TypeError, ValueError) as exc:
                raise AppError(
                    code="floss_invalid_timeout",
                    message="FLOSS timeout_secs must be between 1 and 7200.",
                    details=str(exc),
                    entity="floss",
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
        if "extra_args" in settings or "argv" in settings or "command" in settings:
            raise AppError(
                code="floss_invalid_config",
                message="Arbitrary FLOSS command arguments are not allowed.",
                entity="floss",
            )
        return self.availability()

    def analyze_pe(
        self,
        sample: Path,
        *,
        timeout_secs: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        avail = self.availability()
        if not avail.get("available"):
            raise AppError(
                code="floss_unavailable",
                message="FLOSS is not available on this system.",
                details=avail.get("reason"),
                suggestion=avail.get("suggestion"),
                entity="floss",
            )
        exe = self._resolved_executable()
        if exe is None:
            raise AppError(code="floss_unavailable", message="FLOSS executable is not available.", entity="floss")
        sample = Path(sample).expanduser().resolve()
        if not sample.is_file():
            raise AppError(
                code="floss_sample_missing",
                message="FLOSS sample file was not found.",
                details=str(sample),
                entity="floss",
            )
        if not is_pe_sample(sample):
            raise AppError(
                code="floss_unsupported_target",
                message="FLOSS analyzes extracted PE artifacts, not this file.",
                suggestion="Run PE Extraction first, then analyze an extracted EXE or DLL.",
                entity="floss",
            )
        argv = build_scan_argv(exe, sample)
        timeout = float(timeout_secs if timeout_secs is not None else self.timeout_secs)
        run = self._runner()(
            argv,
            cwd=exe.parent,
            timeout_secs=timeout,
            cancelled=cancelled,
            entity="floss",
            exec_failed_code="floss_exec_failed",
            log_label="floss exec",
        )
        if run.cancelled:
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
        if run.timed_out:
            raise timeout_app_error(
                "floss",
                timeout,
                run,
                code="floss_timeout",
                suggestion="Increase timeout_secs or choose a smaller PE.",
            )
        text = (run.stdout or "").strip()
        if not text:
            text = (run.stderr or "").strip()
        doc: dict[str, Any] | None = None
        parse_error: str | None = None
        try:
            parsed = json.loads(text) if text else None
        except json.JSONDecodeError as exc:
            parsed = None
            parse_error = f"{type(exc).__name__}: {exc}"
        if isinstance(parsed, dict):
            doc = parsed
        elif parsed is not None:
            parse_error = "FLOSS JSON root must be an object."
        elif parse_error is None:
            parse_error = "FLOSS did not return valid JSON."
        if doc is not None:
            normalized = normalize_floss_json(doc)
            return {
                "available": True,
                "invoked": True,
                "exit_code": run.returncode,
                "stdout": run.stdout,
                "stderr": run.stderr,
                "executable_path": str(exe),
                "floss_version": avail.get("floss_version") or normalized.get("floss_version"),
                "raw": doc,
                **normalized,
            }
        if run.returncode != 0:
            raise AppError(
                code="floss_exec_failed",
                message="FLOSS returned a non-zero exit code.",
                details=captured_run_output(run),
                entity="floss",
                data={"exit_code": run.returncode, "process_tree_terminated": bool(run.tree_terminated)},
            )
        raise AppError(
            code="floss_output_invalid",
            message="FLOSS did not return valid JSON.",
            details=parse_error,
            entity="floss",
        )
