"""Signature Detection provider using bundled yara-python."""

from __future__ import annotations

import logging
import mmap
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from memscope_engine.errors import AppError

log = logging.getLogger("memscope.tool")

_RULE_SUFFIXES = {".yar", ".yara"}
KIND_MEMORY = "memory"
KIND_ARTIFACT = "artifact"
_RULE_DECL = re.compile(r"(?m)^\s*rule\s+")
_RULE_NAME = re.compile(r"(?m)^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)")
DEFAULT_CHUNK_THRESHOLD = 512 * 1024 * 1024
DEFAULT_CHUNK_BYTES = 32 * 1024 * 1024
DEFAULT_CHUNK_OVERLAP = 1024 * 1024


def detect_yara() -> dict[str, Any]:
    """Detect yara-python without requiring it at import time."""
    try:
        import yara  # type: ignore
    except ImportError:
        return {
            "available": False,
            "reason": "Signature Detection is not available in this runtime.",
            "suggestion": "Use the bundled Dumplyzer analysis runtime.",
            "yara_version": None,
            "binding": None,
        }
    ver = getattr(yara, "__version__", None)
    if ver is None:
        try:
            from importlib.metadata import version

            ver = version("yara-python")
        except Exception:  # noqa: BLE001
            ver = "unknown"
    return {
        "available": True,
        "reason": None,
        "suggestion": None,
        "yara_version": str(ver),
        "binding": "yara-python",
        "module_path": getattr(yara, "__file__", None),
    }


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def discover_rule_files(paths: list[Path]) -> list[Path]:
    """Discover .yar/.yara files under allowed roots. No shell, path-validated."""
    found: list[Path] = []
    for root in paths:
        if not root.exists():
            continue
        if root.is_file():
            if root.suffix.lower() in _RULE_SUFFIXES:
                found.append(root.resolve())
            continue
        if not root.is_dir():
            continue
        for p in sorted(root.rglob("*")):
            if p.is_file() and p.suffix.lower() in _RULE_SUFFIXES:
                found.append(p.resolve())
    seen: set[str] = set()
    out: list[Path] = []
    for p in found:
        key = str(p).lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def validate_rule_path(path: Path, allowed_roots: list[Path]) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise AppError(
            code="yara_rule_path_missing",
            message="Signature Detection rule path does not exist.",
            details=str(resolved),
            entity="yara",
        )
    roots = [r.expanduser().resolve() for r in allowed_roots]
    ok = False
    for root in roots:
        try:
            resolved.relative_to(root)
            ok = True
            break
        except ValueError:
            if resolved == root:
                ok = True
                break
    if not ok:
        raise AppError(
            code="yara_rule_path_denied",
            message="Signature Detection rule path is outside the allowed rules directory.",
            details=str(resolved),
            suggestion="Place rules under the Dumplyzer rules/yara directory.",
            entity="yara",
        )
    return resolved


def list_rule_names(path: Path) -> list[str]:
    """Return declared YARA rule identifiers in file order."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return _RULE_NAME.findall(text)


def count_rule_declarations(path: Path) -> int:
    names = list_rule_names(path)
    if names:
        return len(names)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    return len(_RULE_DECL.findall(text))


def classify_rule_kinds(path: Path, *, bundled_dir: Path | None, custom_dir: Path | None) -> set[str]:
    resolved = path.resolve()
    for folder, kind in (("memory", KIND_MEMORY), ("artifact", KIND_ARTIFACT)):
        if bundled_dir:
            try:
                resolved.relative_to((bundled_dir / folder).resolve())
                return {kind}
            except ValueError:
                pass
        if custom_dir:
            try:
                resolved.relative_to((custom_dir / folder).resolve())
                return {kind}
            except ValueError:
                pass
    return {KIND_MEMORY, KIND_ARTIFACT}


def classify_rule_source(
    path: Path, *, bundled_dir: Path | None, custom_dir: Path | None
) -> str:
    """Return bundled, custom, or extra based on the rule file location."""
    resolved = path.resolve()
    if bundled_dir:
        try:
            resolved.relative_to(bundled_dir.resolve())
            return "bundled"
        except (ValueError, OSError):
            pass
    if custom_dir:
        try:
            resolved.relative_to(custom_dir.resolve())
            return "custom"
        except (ValueError, OSError):
            pass
    return "extra"


def _empty_inventory(*, discovered: int = 0, skipped: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {
        "valid_files": [],
        "skipped": skipped or [],
        "discovered_file_count": discovered,
        "valid_file_count": 0,
        "rule_count": 0,
        "memory_file_count": 0,
        "artifact_file_count": 0,
        "bundled_file_count": 0,
        "custom_file_count": 0,
        "extra_file_count": 0,
        "bundled_rule_count": 0,
        "custom_rule_count": 0,
        "extra_rule_count": 0,
    }


def _chunk_threshold() -> int:
    raw = os.environ.get("DUMPLYZER_YARA_CHUNK_THRESHOLD")
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass
    return DEFAULT_CHUNK_THRESHOLD


def _chunk_bytes() -> int:
    raw = os.environ.get("DUMPLYZER_YARA_CHUNK_BYTES")
    if raw:
        try:
            return max(4096, int(raw))
        except ValueError:
            pass
    return DEFAULT_CHUNK_BYTES


@dataclass
class YaraProvider:
    """Signature Detection provider — bundled yara-python with user rules."""

    name: str = "yara"
    default_rules_dir: Path | None = None
    bundled_dir: Path | None = None
    custom_dir: Path | None = None
    extra_rule_paths: list[Path] = field(default_factory=list)
    timeout_secs: float = 60.0
    memory_timeout_secs: float = 300.0

    def availability(self) -> dict[str, Any]:
        base = detect_yara()
        inventory = self.compile_inventory()
        return {
            **base,
            "provider": self.name,
            "bundled": bool(base.get("available")),
            "rule_file_count": inventory["discovered_file_count"],
            "valid_rule_file_count": inventory["valid_file_count"],
            "skipped_rule_file_count": len(inventory["skipped"]),
            "loaded_rule_count": inventory["rule_count"],
            "memory_rule_file_count": inventory["memory_file_count"],
            "artifact_rule_file_count": inventory["artifact_file_count"],
            "bundled_rule_file_count": inventory["bundled_file_count"],
            "custom_rule_file_count": inventory["custom_file_count"],
            "extra_rule_file_count": inventory["extra_file_count"],
            "bundled_rule_count": inventory["bundled_rule_count"],
            "custom_rule_count": inventory["custom_rule_count"],
            "extra_rule_count": inventory["extra_rule_count"],
            "skipped_rule_files": inventory["skipped"][:20],
            "rule_files": [str(p) for p in inventory["valid_files"][:50]],
            "default_rules_dir": str(self.default_rules_dir) if self.default_rules_dir else None,
            "bundled_dir": str(self.bundled_dir) if self.bundled_dir else None,
            "custom_dir": str(self.custom_dir) if self.custom_dir else None,
            "extra_rule_paths": [str(p) for p in self.extra_rule_paths],
            "timeout_secs": self.timeout_secs,
            "memory_timeout_secs": self.memory_timeout_secs,
            "scan_modes": [KIND_MEMORY, KIND_ARTIFACT],
            "status_summary": _status_summary(inventory),
        }

    def configure(self, settings: dict[str, Any]) -> dict[str, Any]:
        if "timeout_secs" in settings:
            try:
                t = float(settings["timeout_secs"])
                if t < 1 or t > 3600:
                    raise ValueError("out of range")
                self.timeout_secs = t
            except (TypeError, ValueError) as exc:
                raise AppError(
                    code="yara_invalid_timeout",
                    message="Signature Detection timeout_secs must be between 1 and 3600.",
                    details=str(exc),
                    entity="yara",
                ) from exc
        if "memory_timeout_secs" in settings:
            try:
                t = float(settings["memory_timeout_secs"])
                if t < 1 or t > 7200:
                    raise ValueError("out of range")
                self.memory_timeout_secs = t
            except (TypeError, ValueError) as exc:
                raise AppError(
                    code="yara_invalid_timeout",
                    message="Memory scan timeout_secs must be between 1 and 7200.",
                    details=str(exc),
                    entity="yara",
                ) from exc
        if "extra_rule_paths" in settings:
            raw = settings["extra_rule_paths"]
            if not isinstance(raw, list):
                raise AppError(
                    code="yara_invalid_config",
                    message="extra_rule_paths must be a list of paths.",
                    entity="yara",
                )
            allowed = self._allowed_roots()
            new_paths: list[Path] = []
            for item in raw:
                p = Path(str(item))
                if self.default_rules_dir is None:
                    raise AppError(
                        code="yara_no_rules_root",
                        message="No default Signature Detection rules directory configured.",
                        entity="yara",
                    )
                resolved = validate_rule_path(
                    p,
                    [self.default_rules_dir, *self.extra_rule_paths, *allowed],
                )
                new_paths.append(resolved)
            self.extra_rule_paths = new_paths
        return self.availability()

    def _allowed_roots(self) -> list[Path]:
        roots: list[Path] = []
        if self.default_rules_dir:
            roots.append(self.default_rules_dir)
        if self.bundled_dir:
            roots.append(self.bundled_dir)
        if self.custom_dir:
            roots.append(self.custom_dir)
        roots.extend(self.extra_rule_paths)
        return roots

    def list_rule_sources(self, kind: str | None = None) -> list[Path]:
        roots = self._allowed_roots()
        files = discover_rule_files(roots)
        if kind is None:
            return files
        out: list[Path] = []
        for path in files:
            kinds = classify_rule_kinds(
                path, bundled_dir=self.bundled_dir, custom_dir=self.custom_dir
            )
            if kind in kinds:
                out.append(path)
        return out

    def compile_inventory(self, kind: str | None = None) -> dict[str, Any]:
        files = self.list_rule_sources(kind)
        skipped: list[dict[str, str]] = []
        valid: list[Path] = []
        info = detect_yara()
        if not info["available"]:
            return _empty_inventory(discovered=len(files), skipped=skipped)
        import yara  # type: ignore

        allowed = self._allowed_roots()
        for path in files:
            try:
                rf = validate_rule_path(path, allowed)
            except AppError as exc:
                skipped.append({"path": str(path), "error": exc.message})
                continue
            try:
                yara.compile(filepath=str(rf))
            except Exception as exc:  # noqa: BLE001
                skipped.append(
                    {
                        "path": str(rf),
                        "error": str(exc).splitlines()[0] if str(exc) else "syntax error",
                    }
                )
                log.info(
                    "yara rule file skipped",
                    extra={"channel": "tool", "path": str(rf), "error": str(exc)},
                )
                continue
            valid.append(rf)
        memory_n = 0
        artifact_n = 0
        rule_n = 0
        bundled_files = 0
        custom_files = 0
        extra_files = 0
        bundled_rules = 0
        custom_rules = 0
        extra_rules = 0
        for path in valid:
            kinds = classify_rule_kinds(
                path, bundled_dir=self.bundled_dir, custom_dir=self.custom_dir
            )
            decls = count_rule_declarations(path)
            rule_n += decls
            source = classify_rule_source(
                path, bundled_dir=self.bundled_dir, custom_dir=self.custom_dir
            )
            if source == "bundled":
                bundled_files += 1
                bundled_rules += decls
            elif source == "custom":
                custom_files += 1
                custom_rules += decls
            else:
                extra_files += 1
                extra_rules += decls
            if KIND_MEMORY in kinds:
                memory_n += 1
            if KIND_ARTIFACT in kinds:
                artifact_n += 1
        return {
            "valid_files": valid,
            "skipped": skipped,
            "discovered_file_count": len(files),
            "valid_file_count": len(valid),
            "rule_count": rule_n,
            "memory_file_count": memory_n,
            "artifact_file_count": artifact_n,
            "bundled_file_count": bundled_files,
            "custom_file_count": custom_files,
            "extra_file_count": extra_files,
            "bundled_rule_count": bundled_rules,
            "custom_rule_count": custom_rules,
            "extra_rule_count": extra_rules,
        }

    def compile_rules(self, rule_files: list[Path] | None = None, *, kind: str | None = None) -> Any:
        info = detect_yara()
        if not info["available"]:
            raise AppError(
                code="yara_unavailable",
                message="Signature Detection is not available on this system.",
                details=info.get("reason"),
                suggestion=info.get("suggestion"),
                entity="yara",
            )
        import yara  # type: ignore

        if rule_files is None:
            inventory = self.compile_inventory(kind)
            files = inventory["valid_files"]
            skipped = inventory["skipped"]
        else:
            files = rule_files
            skipped = []
        if not files:
            if skipped:
                raise AppError(
                    code="yara_compile_failed",
                    message="Signature Detection rules could not be compiled.",
                    details=_skipped_details(skipped),
                    suggestion="Fix the listed rule file and retry.",
                    entity="yara",
                    data={"skipped": skipped},
                )
            raise AppError(
                code="yara_no_rules",
                message="No Signature Detection rule files found.",
                suggestion=f"Add .yar/.yara files under {self.custom_dir or self.default_rules_dir}",
                entity="yara",
            )
        allowed = self._allowed_roots()
        filemap: dict[str, str] = {}
        for i, f in enumerate(files):
            rf = validate_rule_path(f, allowed)
            key = f"r{i}_{rf.stem}"[:40]
            filemap[key] = str(rf)
        try:
            rules = yara.compile(filepaths=filemap)
        except Exception as exc:  # noqa: BLE001
            raise AppError(
                code="yara_compile_failed",
                message="Signature Detection rule compilation failed.",
                details=str(exc).splitlines()[0] if str(exc) else "compile error",
                suggestion="Fix syntax errors in the rule files and retry.",
                entity="yara",
                data={"rule_files": [str(p) for p in files], "skipped": skipped},
            ) from exc
        return rules, {
            "filemap": filemap,
            "rule_files": [str(p) for p in files],
            "skipped": skipped,
            "yara_version": info["yara_version"],
            "binding": info["binding"],
            "kind": kind,
        }

    def scan_file(
        self,
        target: Path,
        *,
        rule_files: list[Path] | None = None,
        timeout_secs: float | None = None,
        cancelled: Any = None,
        kind: str = KIND_ARTIFACT,
    ) -> dict[str, Any]:
        """Scan a trusted artifact file. Does not execute the target."""
        return self._scan_target(
            target,
            kind=kind,
            rule_files=rule_files,
            timeout_secs=timeout_secs if timeout_secs is not None else self.timeout_secs,
            cancelled=cancelled,
            allow_chunked=False,
        )

    def scan_memory_image(
        self,
        target: Path,
        *,
        rule_files: list[Path] | None = None,
        timeout_secs: float | None = None,
        cancelled: Any = None,
        progress: Any = None,
    ) -> dict[str, Any]:
        """Scan an original memory dump in place. The dump is never modified."""
        timeout = timeout_secs if timeout_secs is not None else self.memory_timeout_secs
        return self._scan_target(
            target,
            kind=KIND_MEMORY,
            rule_files=rule_files,
            timeout_secs=timeout,
            cancelled=cancelled,
            allow_chunked=True,
            progress=progress,
        )

    def _scan_target(
        self,
        target: Path,
        *,
        kind: str,
        rule_files: list[Path] | None,
        timeout_secs: float,
        cancelled: Any,
        allow_chunked: bool,
        progress: Any = None,
    ) -> dict[str, Any]:
        info = detect_yara()
        if not info["available"]:
            raise AppError(
                code="yara_unavailable",
                message="Signature Detection is not available on this system.",
                details=info.get("reason"),
                suggestion=info.get("suggestion"),
                entity="yara",
            )
        target = target.expanduser().resolve()
        if not target.is_file():
            raise AppError(
                code="yara_target_missing",
                message="Scan target file does not exist.",
                details=str(target),
                entity="yara",
            )
        rules, ruleset_meta = self.compile_rules(rule_files, kind=kind)
        size = target.stat().st_size
        chunked = allow_chunked and size >= _chunk_threshold()
        if chunked:
            matches, scan_mode = self._match_chunked(
                rules,
                target,
                timeout_secs=timeout_secs,
                cancelled=cancelled,
                progress=progress,
            )
        else:
            if callable(progress):
                progress(0.12)
            matches = self._match_filepath(
                rules, target, timeout_secs=timeout_secs, cancelled=cancelled
            )
            scan_mode = "filepath"
            if callable(progress):
                progress(1.0)
        normalized = [normalize_match(m, ruleset_meta) for m in matches]
        return {
            "status": "completed",
            "match_count": len(normalized),
            "matches": normalized,
            "yara_version": ruleset_meta["yara_version"],
            "ruleset": {
                "rule_files": ruleset_meta["rule_files"],
                "filemap": ruleset_meta["filemap"],
                "binding": ruleset_meta["binding"],
                "skipped": ruleset_meta.get("skipped") or [],
                "kind": kind,
                "scan_mode": scan_mode,
            },
            "target": str(target),
            "target_kind": kind,
            "scanned_at": _utcnow(),
            "file_size": size,
        }

    def _match_filepath(self, rules: Any, target: Path, *, timeout_secs: float, cancelled: Any) -> list[Any]:
        # libyara maps the file; Python does not load the whole dump as bytes.
        return self._run_native_match(
            lambda: rules.match(filepath=str(target), timeout=int(max(1, timeout_secs))),
            timeout_secs=timeout_secs,
            cancelled=cancelled,
        )

    def _match_chunked(
        self,
        rules: Any,
        target: Path,
        *,
        timeout_secs: float,
        cancelled: Any,
        progress: Any = None,
    ) -> tuple[list[Any], str]:
        """Overlapping windows for large dumps. Does not load the entire file into Python.

        Limitations: rules that depend on filesize, the PE module, or whole-file
        hashes can miss or false-negative when a match spans chunk boundaries
        despite overlap. Offset values are adjusted to dump-absolute offsets.
        """
        chunk = _chunk_bytes()
        overlap = min(DEFAULT_CHUNK_OVERLAP, chunk // 4)
        size = target.stat().st_size
        collected: list[Any] = []
        seen: set[tuple[str, int | None]] = set()
        with target.open("rb") as fh:
            mapping = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                offset = 0
                while offset < size:
                    if cancelled and callable(cancelled) and cancelled():
                        raise AppError(
                            code="job_cancelled", message="Job was cancelled.", entity="job"
                        )
                    end = min(size, offset + chunk)
                    if callable(progress):
                        progress(min(end, size) / max(size, 1))
                    window = mapping[offset:end]
                    raw = self._run_native_match(
                        lambda data=window: rules.match(
                            data=data, timeout=int(max(1, min(timeout_secs, 60)))
                        ),
                        timeout_secs=min(timeout_secs, 60),
                        cancelled=cancelled,
                    )
                    for match in raw:
                        _shift_match_offsets(match, offset)
                        key = (getattr(match, "rule", ""), _first_offset(match))
                        if key in seen:
                            continue
                        seen.add(key)
                        collected.append(match)
                    if end >= size:
                        break
                    offset = end - overlap
            finally:
                mapping.close()
        return collected, "chunked"

    def _run_native_match(
        self,
        fn: Any,
        *,
        timeout_secs: float,
        cancelled: Any,
    ) -> list[Any]:
        result_holder: dict[str, Any] = {"matches": None, "error": None}

        def _run() -> None:
            try:
                result_holder["matches"] = fn()
            except Exception as exc:  # noqa: BLE001
                result_holder["error"] = exc

        thr = threading.Thread(target=_run, name="yara-scan", daemon=True)
        thr.start()
        while thr.is_alive():
            if cancelled and callable(cancelled) and cancelled():
                thr.join(timeout=0.2)
                if thr.is_alive():
                    thr.join(timeout=timeout_secs)
                if thr.is_alive():
                    raise AppError(
                        code="yara_cancel_timeout",
                        message="Signature Detection cancel was requested but the scan did not finish in time.",
                        suggestion="Reduce the rule set or timeout. Cancellation is cooperative around the native matcher.",
                        entity="yara",
                    )
                raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
            thr.join(timeout=0.1)

        if result_holder["error"] is not None:
            exc = result_holder["error"]
            name = type(exc).__name__
            msg = str(exc)
            if "timeout" in msg.lower() or name.lower().endswith("timeouterror"):
                raise AppError(
                    code="yara_timeout",
                    message="Signature Detection scan timed out.",
                    details=msg,
                    suggestion="Increase timeout or reduce rule complexity.",
                    entity="yara",
                ) from exc
            raise AppError(
                code="yara_scan_failed",
                message="Signature Detection scan failed.",
                details=f"{name}: {msg}",
                entity="yara",
            ) from exc
        return result_holder["matches"] or []


def _count_noun(n: int, singular: str, plural: str) -> str:
    return singular if n == 1 else plural


def _status_summary(inventory: dict[str, Any]) -> str:
    skipped_n = len(inventory.get("skipped") or [])
    bundled_n = int(inventory.get("bundled_file_count") or 0)
    custom_n = int(inventory.get("custom_file_count") or 0)
    extra_n = int(inventory.get("extra_file_count") or 0)
    rule_n = int(inventory.get("rule_count") or 0)
    parts = [
        f"{bundled_n} bundled {_count_noun(bundled_n, 'rule file', 'rule files')} loaded",
        f"{custom_n} custom {_count_noun(custom_n, 'rule file', 'rule files')}",
    ]
    if extra_n:
        parts.append(
            f"{extra_n} extra {_count_noun(extra_n, 'rule file', 'rule files')}"
        )
    parts.append(f"{rule_n} {_count_noun(rule_n, 'rule', 'rules')} available")
    if skipped_n:
        parts.append(
            f"{skipped_n} rule file skipped due to syntax error"
            if skipped_n == 1
            else f"{skipped_n} rule files skipped due to syntax error"
        )
    return " · ".join(parts)


def _skipped_details(skipped: list[dict[str, str]]) -> str:
    lines = []
    for item in skipped[:8]:
        name = Path(item.get("path") or "").name
        err = item.get("error") or "syntax error"
        lines.append(f"{name}: {err}")
    return "\n".join(lines)


def _first_offset(match: Any) -> int | None:
    for item in getattr(match, "strings", []) or []:
        if hasattr(item, "instances"):
            for inst in getattr(item, "instances", []) or []:
                off = getattr(inst, "offset", None)
                if off is not None:
                    return int(off)
        elif isinstance(item, (tuple, list)) and item:
            try:
                return int(item[0])
            except (TypeError, ValueError):
                continue
    return None


def _shift_match_offsets(match: Any, delta: int) -> None:
    for item in getattr(match, "strings", []) or []:
        if hasattr(item, "instances"):
            for inst in getattr(item, "instances", []) or []:
                off = getattr(inst, "offset", None)
                if off is not None:
                    try:
                        inst.offset = int(off) + delta
                    except Exception:  # noqa: BLE001
                        pass


def normalize_match(match: Any, ruleset_meta: dict[str, Any]) -> dict[str, Any]:
    """Convert yara Match object to JSON-serializable structure."""
    rule_name = getattr(match, "rule", str(match))
    namespace = getattr(match, "namespace", None)
    tags = list(getattr(match, "tags", []) or [])
    meta = dict(getattr(match, "meta", {}) or {})
    strings_out: list[dict[str, Any]] = []
    for item in getattr(match, "strings", []) or []:
        if hasattr(item, "identifier"):
            ident = item.identifier
            instances = []
            for inst in getattr(item, "instances", []) or []:
                instances.append(
                    {
                        "offset": getattr(inst, "offset", None),
                        "matched_length": getattr(inst, "matched_length", None),
                        "matched_data_hex": _safe_hex(getattr(inst, "matched_data", b"")),
                    }
                )
            strings_out.append({"identifier": ident, "instances": instances})
        elif isinstance(item, (tuple, list)) and len(item) >= 2:
            offset = item[0]
            ident = item[1]
            data = item[2] if len(item) > 2 else b""
            strings_out.append(
                {
                    "identifier": str(ident),
                    "instances": [
                        {
                            "offset": int(offset) if offset is not None else None,
                            "matched_length": len(data) if isinstance(data, (bytes, bytearray)) else None,
                            "matched_data_hex": _safe_hex(data),
                        }
                    ],
                }
            )

    rule_source = None
    ns = namespace
    if ns and isinstance(ruleset_meta.get("filemap"), dict):
        rule_source = ruleset_meta["filemap"].get(ns)

    return {
        "rule_name": str(rule_name),
        "namespace": str(namespace) if namespace is not None else None,
        "rule_source": rule_source,
        "tags": tags,
        "meta": {str(k): _jsonable(v) for k, v in meta.items()},
        "strings": strings_out,
    }


def _safe_hex(data: Any, limit: int = 64) -> str | None:
    if data is None:
        return None
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    if not isinstance(data, (bytes, bytearray)):
        return None
    return bytes(data[:limit]).hex()


def _jsonable(v: Any) -> Any:
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return str(v)
