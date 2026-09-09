"""bulk_extractor provider: bundled official Windows EXE, optional user override.

bulk_extractor (https://github.com/simsong/bulk_extractor) scans a disk image
or memory dump and writes feature files (email, URL, IP, …) without parsing a
file system. Dumplyzer ships the official v2.2.0 ``bulk_extractor64.exe``
release asset in application resources and invokes it as a separate process.

Windows: native MSVC builds are not supported upstream. The shipped binary is
the GitHub Actions MinGW cross-compile. The workflow checks the PE does not
import MinGW/RE2/Abseil/Expat/zlib/GNU crypto DLLs.

A user-supplied EXE under the Dumplyzer tools directory remains allowed as an
override. Dumplyzer never downloads bulk_extractor at runtime.

The evidence file is read-only. Output is written only under the controlled
analysis directory. Extracted bytes are never executed.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from memscope_engine.errors import AppError
from memscope_engine.providers.bulk_extractor_features import (
    aggregate_feature_file,
    category_summary,
    feature_kind_for_stem,
    is_feature_filename,
    kind_for_scanner,
    parse_feature_line,
)
from memscope_engine.providers.process_run import (
    ProcessRun,
    default_subprocess_runner,
)

log = logging.getLogger("memscope.tool")

VERIFIED_RELEASE = "2.2.0"
VERIFIED_REPO = "https://github.com/simsong/bulk_extractor"
VERIFIED_INTERFACE = {
    "release": VERIFIED_RELEASE,
    "version_arg": "-V",
    "output_arg": "-o",
    "image_arg": "positional",
    "windows_asset": "bulk_extractor64.exe",
}

_EXE_NAMES = ("bulk_extractor64.exe", "bulk_extractor.exe", "bulk_extractor32.exe")
_EXE_NAME_SET = {n.lower() for n in _EXE_NAMES}

_VERSION_RE = re.compile(
    r"bulk_extractor\s+(?:version\s+)?v?(\d+\.\d+(?:\.\d+){0,3})",
    re.IGNORECASE,
)
_VERSION_FALLBACK_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+){0,3})")

MAX_FEATURES_PER_FILE = 5_000
MAX_FEATURES_TOTAL = 40_000
MAX_INDEXED_FILES = 500

Runner = Callable[..., ProcessRun]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return path.resolve() == root.resolve()


def parse_version_output(text: str) -> str | None:
    if not text:
        return None
    m = _VERSION_RE.search(text)
    if m:
        return m.group(1)
    for line in text.splitlines():
        stripped = line.strip()
        if "bulk_extractor" in stripped.lower() or stripped.lower().startswith("version"):
            m = _VERSION_FALLBACK_RE.search(stripped)
            if m:
                return m.group(1)
    return None


def bundled_bulk_extractor_roots() -> list[Path]:
    """Install-tree / env roots that hold the shipped bulk_extractor64.exe."""
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
        _add(p / "bulk_extractor")
    try:
        runtime = Path(sys.executable).resolve().parent
        _add(runtime.parent / "tools" / "bulk_extractor")
        _add(runtime.parent / "resources" / "tools" / "bulk_extractor")
    except OSError:
        pass
    return found


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
            candidates.append(resolved_root / "bulk_extractor" / name)
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
            code="bulk_extractor_exe_missing",
            message="bulk_extractor executable was not found.",
            details=str(resolved),
            suggestion=(
                "Reinstall Dumplyzer so the bundled bulk_extractor64.exe is present, "
                "or place an official EXE under the Dumplyzer tools directory."
            ),
            entity="bulk_extractor",
        )
    if resolved.suffix.lower() != ".exe":
        raise AppError(
            code="bulk_extractor_exe_invalid",
            message="bulk_extractor executable must be a Windows .exe file.",
            details=str(resolved),
            entity="bulk_extractor",
        )
    if resolved.name.lower() not in _EXE_NAME_SET:
        raise AppError(
            code="bulk_extractor_exe_invalid",
            message="Executable name is not a known bulk_extractor binary.",
            details=resolved.name,
            suggestion="Use bulk_extractor64.exe (or bulk_extractor.exe) from the official release.",
            entity="bulk_extractor",
        )
    for deny in deny_roots or []:
        if _is_under(resolved, deny):
            raise AppError(
                code="bulk_extractor_exe_denied",
                message="Refusing to execute a path inside the artifact or analysis store.",
                details=str(resolved),
                entity="bulk_extractor",
            )
    roots = [r.expanduser().resolve() for r in allowed_roots if r is not None]
    if not any(_is_under(resolved, root) for root in roots):
        raise AppError(
            code="bulk_extractor_exe_path_denied",
            message="bulk_extractor executable is outside configured allowed tool directories.",
            details=str(resolved),
            suggestion="Place the official bulk_extractor64.exe under the Dumplyzer tools directory.",
            entity="bulk_extractor",
        )
    try:
        with resolved.open("rb") as f:
            magic = f.read(2)
    except OSError as exc:
        raise AppError(
            code="bulk_extractor_exe_invalid",
            message="Could not read bulk_extractor executable.",
            details=str(exc),
            entity="bulk_extractor",
        ) from exc
    if magic != b"MZ":
        raise AppError(
            code="bulk_extractor_exe_invalid",
            message="bulk_extractor executable does not look like a Windows PE file.",
            details=str(resolved),
            entity="bulk_extractor",
        )
    return resolved


def validate_output_dir(path: Path, allowed_roots: list[Path], *, must_not_exist: bool = True) -> Path:
    resolved = path.expanduser().resolve()
    if not any(_is_under(resolved, root.expanduser().resolve()) for root in allowed_roots):
        raise AppError(
            code="bulk_extractor_output_denied",
            message="bulk_extractor output directory is outside the controlled analysis root.",
            details=str(resolved),
            entity="bulk_extractor",
        )
    if must_not_exist and resolved.exists():
        raise AppError(
            code="bulk_extractor_output_exists",
            message="bulk_extractor output directory must not already exist.",
            details=str(resolved),
            entity="bulk_extractor",
        )
    parent = resolved.parent
    parent.mkdir(parents=True, exist_ok=True)
    if not any(_is_under(parent, root.expanduser().resolve()) for root in allowed_roots):
        raise AppError(
            code="bulk_extractor_output_denied",
            message="bulk_extractor output parent is outside the controlled analysis root.",
            details=str(parent),
            entity="bulk_extractor",
        )
    return resolved


def validate_image_path(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise AppError(
            code="bulk_extractor_image_missing",
            message="Memory image file was not found for bulk_extractor.",
            details=str(resolved),
            entity="bulk_extractor",
        )
    return resolved


def build_version_argv(exe: Path) -> list[str]:
    return [str(exe), "-V"]


def build_scan_argv(exe: Path, image: Path, output_dir: Path) -> list[str]:
    """Construct argv from the verified v2.x interface. No user extra args."""
    return [
        str(exe),
        "-o",
        str(output_dir),
        str(image),
    ]


def compute_ui_state(
    *,
    available: bool,
    scan_status: str | None = None,
    feature_count: int | None = None,
) -> str:
    if scan_status == "queued":
        return "queued"
    if scan_status == "running":
        return "running"
    if scan_status == "cancelled":
        return "cancelled"
    if scan_status == "failed":
        return "failed"
    if scan_status == "unavailable":
        return "unavailable"
    if scan_status == "completed":
        if (feature_count or 0) > 0:
            return "completed_features"
        return "completed_no_features"
    if not available:
        return "unavailable"
    return "idle"


def parse_feature_file(path: Path, *, limit: int = MAX_FEATURES_PER_FILE) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parsed = parse_feature_line(line)
                if parsed is None:
                    continue
                rows.append(parsed)
                if len(rows) >= limit:
                    break
    except OSError:
        return []
    return rows


def parse_histogram_file(path: Path, *, limit: int = 20) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split("\t")
                if len(parts) < 2:
                    continue
                count_s, value = parts[0].strip(), parts[1]
                try:
                    count = int(count_s)
                except ValueError:
                    continue
                items.append({"count": count, "value": value})
                if len(items) >= limit:
                    break
    except OSError:
        return []
    return items


def parse_report_xml(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {"version": None, "scanners": [], "filename": path.name}
    if not path.is_file():
        return info
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError):
        return info
    root = tree.getroot()
    text = ET.tostring(root, encoding="unicode")
    vm = _VERSION_RE.search(text) or _VERSION_FALLBACK_RE.search(text)
    if vm:
        info["version"] = vm.group(1) if vm.lastindex else vm.group(0)
    scanners: list[str] = []
    for el in root.iter():
        tag = el.tag.split("}")[-1].lower()
        if tag in {"scanner", "name"} and el.text:
            name = el.text.strip()
            if name and name not in scanners:
                scanners.append(name)
        name_attr = el.attrib.get("name") or el.attrib.get("scanner")
        if name_attr and name_attr not in scanners:
            scanners.append(name_attr)
    info["scanners"] = scanners
    return info


def list_output_files(output_dir: Path) -> list[Path]:
    if not output_dir.is_dir():
        return []
    found: list[Path] = []
    for p in output_dir.rglob("*"):
        if not p.is_file():
            continue
        found.append(p)
        if len(found) >= MAX_INDEXED_FILES:
            break
    return found


def normalize_bulk_extractor_output(
    output_dir: Path,
    *,
    bulk_extractor_version: str | None,
    exit_code: int | None,
    stdout: str = "",
    stderr: str = "",
) -> dict[str, Any]:
    files = list_output_files(output_dir)
    feature_files: list[dict[str, Any]] = []
    histograms: dict[str, list[dict[str, Any]]] = {}
    other_files: list[dict[str, Any]] = []
    features: list[dict[str, Any]] = []
    category_groups: list[dict[str, Any]] = []
    report = parse_report_xml(output_dir / "report.xml")
    pending_features: list[tuple[int, Path, dict[str, Any], str]] = []

    for path in files:
        rel = str(path.relative_to(output_dir)) if _is_under(path, output_dir) else path.name
        rec = {
            "name": path.name,
            "relative_path": rel.replace("\\", "/"),
            "size_bytes": path.stat().st_size if path.exists() else 0,
        }
        lower = path.name.lower()
        if lower.endswith("_histogram.txt"):
            histograms[path.stem] = parse_histogram_file(path)
            other_files.append({**rec, "role": "histogram"})
            continue
        if lower.endswith(".pcap") or lower.endswith(".pcapng"):
            other_files.append({**rec, "role": "pcap"})
            continue
        if lower == "report.xml":
            other_files.append({**rec, "role": "report"})
            continue
        if lower == "alerts.txt":
            other_files.append({**rec, "role": "alerts"})
            continue
        if lower in {"dumplyzer-stdout.txt", "dumplyzer-stderr.txt"}:
            other_files.append({**rec, "role": "capture"})
            continue
        if is_feature_filename(path.name):
            pending_features.append((kind_for_scanner(path.stem).priority, path, rec, rel.replace("\\", "/")))
            continue
        other_files.append({**rec, "role": "other"})

    pending_features.sort(key=lambda item: (item[0], item[1].name.lower()))
    for _priority, path, rec, rel in pending_features:
        kind = kind_for_scanner(path.stem)
        aggregated = aggregate_feature_file(
            path, scanner=path.stem, unique_limit=kind.unique_limit, noisy=kind.noisy
        )
        if not histograms.get(f"{path.stem}_histogram"):
            hist = [
                {"count": int(item.get("count") or 1), "value": str(item.get("value") or "")}
                for item in (aggregated.get("items") or [])[:20]
            ]
            if hist:
                histograms[f"{path.stem}_histogram"] = hist
        feature_files.append(
            {
                **rec,
                "role": "feature",
                "scanner": path.stem,
                "ioc_type": kind.ioc_type,
                "finding_type": kind.finding_type,
                "category": kind.category,
                "label": kind.label,
                "row_count": aggregated.get("row_count") or 0,
                "unique_count": aggregated.get("unique_kept") or 0,
                "unique_total": aggregated.get("unique_total") or 0,
                "truncated": bool(aggregated.get("truncated")),
            }
        )
        category_groups.append(
            {
                "scanner": path.stem,
                "category": kind.category,
                "columns": kind.columns,
                "unique_kept": aggregated.get("unique_kept") or 0,
                "row_count": aggregated.get("row_count") or 0,
            }
        )
        remaining = MAX_FEATURES_TOTAL - len(features)
        for item in (aggregated.get("items") or [])[: max(0, remaining)]:
            extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
            features.append(
                {
                    "scanner": path.stem,
                    "source_file": rel,
                    "ioc_type": kind.ioc_type,
                    "finding_type": kind.finding_type,
                    "category": kind.category,
                    "label": kind.label,
                    "offset": item.get("offset"),
                    "value": item.get("value"),
                    "context": item.get("context"),
                    "count": int(item.get("count") or 1),
                    "extra": extra,
                }
            )
        if len(features) >= MAX_FEATURES_TOTAL:
            break

    scanners = sorted(
        {f["scanner"] for f in feature_files} | set(report.get("scanners") or [])
    )
    categories = category_summary(category_groups)
    unique_count = len(features)
    row_total = sum(int(f.get("row_count") or 0) for f in feature_files)
    observed = {
        "exit_code": exit_code,
        "bulk_extractor_version": bulk_extractor_version or report.get("version"),
        "output_dir": str(output_dir),
        "file_count": len(files),
        "feature_file_count": len(feature_files),
        "feature_count": unique_count,
        "row_count": row_total,
        "scanners": scanners,
        "feature_files": feature_files,
        "categories": categories,
        "histograms": histograms,
        "other_files": other_files,
        "report": report,
        "stdout_preview": (stdout or "")[:4000],
        "stderr_preview": (stderr or "")[:4000],
    }
    interpretation = {
        "source": "memscope",
        "kind": "extracted_artifact",
        "summary": (
            f"bulk_extractor extracted {unique_count} unique value(s) from "
            f"{len(feature_files)} feature file(s) ({row_total} raw row(s))."
            if features
            else "bulk_extractor finished with no parsed feature rows."
        ),
        "notes": (
            "Values are extracted strings / IOC candidates from bulk_extractor "
            "feature files. Dumplyzer does not treat them as confirmed malicious "
            "indicators and does not assign a threat score."
        ),
        "has_features": bool(features),
    }
    return {
        "observed": observed,
        "interpretation": interpretation,
        "features": features,
        "scanners": scanners,
        "categories": categories,
        "feature_count": unique_count,
    }


def write_capture(output_dir: Path, stdout: str, stderr: str) -> None:
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "dumplyzer-stdout.txt").write_text(stdout or "", encoding="utf-8", errors="replace")
        (output_dir / "dumplyzer-stderr.txt").write_text(stderr or "", encoding="utf-8", errors="replace")
    except OSError:
        log.warning("could not write bulk_extractor capture files", extra={"channel": "tool"})


def evidence_fingerprint(path: Path) -> dict[str, Any]:
    st = path.stat()
    return {"size_bytes": st.st_size, "mtime_ns": st.st_mtime_ns, "path": str(path)}


def assert_evidence_unchanged(path: Path, before: dict[str, Any]) -> None:
    after = evidence_fingerprint(path)
    if after["size_bytes"] != before.get("size_bytes") or after["mtime_ns"] != before.get("mtime_ns"):
        raise AppError(
            code="bulk_extractor_evidence_mutated",
            message="The memory image changed while bulk_extractor was running.",
            details=json.dumps({"before": before, "after": after}),
            entity="bulk_extractor",
        )


@dataclass
class BulkExtractorProvider:
    """Optional bulk_extractor adapter — safe when the EXE is absent."""

    name: str = "bulk_extractor"
    tools_dir: Path | None = None
    analysis_dir: Path | None = None
    artifacts_dir: Path | None = None
    executable_path: Path | None = None
    timeout_secs: float = 7200.0
    runner: Runner | None = None
    extra_tool_roots: list[Path] = field(default_factory=list)

    def _runner(self) -> Runner:
        return self.runner or default_subprocess_runner

    def _allowed_exe_roots(self) -> list[Path]:
        roots: list[Path] = []
        roots.extend(self.extra_tool_roots)
        if self.tools_dir:
            roots.append(self.tools_dir)
            roots.append(self.tools_dir / "bulk_extractor")
        return roots

    def _source_for(self, exe: Path) -> str:
        for root in self.extra_tool_roots:
            if root and _is_under(exe, root):
                return "bundled"
        return "user-supplied"

    def _deny_exe_roots(self) -> list[Path]:
        roots: list[Path] = []
        if self.artifacts_dir:
            roots.append(self.artifacts_dir)
        if self.analysis_dir:
            roots.append(self.analysis_dir)
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
        analysis = str(self.analysis_dir) if self.analysis_dir else None
        base: dict[str, Any] = {
            "provider": self.name,
            "available": False,
            "reason": None,
            "suggestion": None,
            "bulk_extractor_version": None,
            "executable_path": None,
            "tools_dir": tools,
            "analysis_dir": analysis,
            "timeout_secs": self.timeout_secs,
            "verified_release": VERIFIED_RELEASE,
            "verified_repo": VERIFIED_REPO,
            "verified_interface": VERIFIED_INTERFACE,
            "supported_target_kinds": ["memory_image"],
            "source": None,
            "bundled_dir": str(self.extra_tool_roots[0]) if self.extra_tool_roots else None,
            "windows_notes": (
                "Dumplyzer ships the official MinGW-cross-compiled bulk_extractor64.exe "
                f"(v{VERIFIED_RELEASE}). Native MSVC Windows builds are not supported "
                "upstream. A user-supplied EXE under the tools directory can override "
                "the bundled binary. Dumplyzer never downloads it at runtime."
            ),
            "license": {
                "name": "GPL-3.0-or-later",
                "copyright": (
                    "bulk_extractor: GPL-3.0-or-later for post-NPS project-authored code; "
                    "see LICENSE.md. Original NPS material is not U.S. copyright."
                ),
                "redistribution": (
                    "GPL-3.0-or-later. Dumplyzer invokes bulk_extractor as a separate "
                    "process (aggregation) and ships corresponding source beside the EXE."
                ),
                "bundled_in_memscope": True,
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
            base["reason"] = (
                "The bundled bulk_extractor executable is missing from application resources."
            )
            bundle = str(self.extra_tool_roots[0]) if self.extra_tool_roots else "application resources"
            base["suggestion"] = (
                f"Reinstall Dumplyzer so bulk_extractor64.exe is present under {bundle}. "
                f"An official override may also be placed in {tools or 'the Dumplyzer tools directory'}."
            )
            return base
        version = self.detect_version(exe)
        base.update(
            {
                "available": True,
                "bulk_extractor_version": version,
                "executable_path": str(exe),
                "source": self._source_for(exe),
            }
        )
        return base

    def configure(self, settings: dict[str, Any]) -> dict[str, Any]:
        if "timeout_secs" in settings:
            try:
                t = float(settings["timeout_secs"])
                if t < 1 or t > 86400:
                    raise ValueError("out of range")
                self.timeout_secs = t
            except (TypeError, ValueError) as exc:
                raise AppError(
                    code="bulk_extractor_invalid_timeout",
                    message="bulk_extractor timeout_secs must be between 1 and 86400.",
                    details=str(exc),
                    entity="bulk_extractor",
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
                code="bulk_extractor_invalid_config",
                message="Arbitrary bulk_extractor command arguments are not allowed.",
                suggestion="Only executable_path and timeout_secs may be configured.",
                entity="bulk_extractor",
            )
        return self.availability()

    def scan_image(
        self,
        image_path: Path,
        *,
        output_dir: Path,
        timeout_secs: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        avail = self.availability()
        if not avail.get("available"):
            raise AppError(
                code="bulk_extractor_unavailable",
                message="bulk_extractor is not available on this system.",
                details=avail.get("reason"),
                suggestion=avail.get("suggestion"),
                entity="bulk_extractor",
            )
        exe = self._resolved_executable()
        if exe is None:
            raise AppError(
                code="bulk_extractor_unavailable",
                message="bulk_extractor executable is not available.",
                entity="bulk_extractor",
            )
        image = validate_image_path(image_path)
        if self.analysis_dir is None:
            raise AppError(
                code="bulk_extractor_no_output_root",
                message="No controlled analysis directory is configured for bulk_extractor output.",
                entity="bulk_extractor",
            )
        allowed = [self.analysis_dir]
        out = validate_output_dir(output_dir, allowed, must_not_exist=True)
        argv = build_scan_argv(exe, image, out)
        if Path(argv[0]).resolve() != exe.resolve():
            raise AppError(
                code="bulk_extractor_exe_denied",
                message="Refusing to execute a program that is not the configured bulk_extractor EXE.",
                entity="bulk_extractor",
            )
        timeout = float(timeout_secs if timeout_secs is not None else self.timeout_secs)
        before = evidence_fingerprint(image)
        if cancelled and cancelled():
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")

        log.info(
            "bulk_extractor exec",
            extra={"channel": "tool", "argv0": Path(argv[0]).name, "argc": len(argv)},
        )
        run = self._runner()(
            argv,
            cwd=exe.parent,
            timeout_secs=timeout,
            cancelled=cancelled,
        )
        write_capture(out if out.exists() else out, run.stdout, run.stderr)
        assert_evidence_unchanged(image, before)

        if run.cancelled:
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
        if run.timed_out:
            raise AppError(
                code="bulk_extractor_timeout",
                message="bulk_extractor timed out.",
                suggestion="Increase timeout_secs or scan a smaller image.",
                entity="bulk_extractor",
            )

        normalized = normalize_bulk_extractor_output(
            out,
            bulk_extractor_version=avail.get("bulk_extractor_version"),
            exit_code=run.returncode,
            stdout=run.stdout,
            stderr=run.stderr,
        )
        return {
            "available": True,
            "invoked": True,
            "exit_code": run.returncode,
            "stdout": run.stdout,
            "stderr": run.stderr,
            "output_dir": str(out),
            "executable_path": str(exe),
            "bulk_extractor_version": avail.get("bulk_extractor_version"),
            "evidence_fingerprint": before,
            **normalized,
        }
