"""Optional YARA provider using yara-python when installed."""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from memscope_engine.errors import AppError

log = logging.getLogger("memscope.tool")

_RULE_SUFFIXES = {".yar", ".yara"}


def detect_yara() -> dict[str, Any]:
    """Detect yara-python without requiring it at import time."""
    try:
        import yara  # type: ignore
    except ImportError:
        return {
            "available": False,
            "reason": "yara-python is not installed",
            "suggestion": "Install optional dependency: pip install yara-python",
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
    # unique preserve order
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
            message="YARA rule path does not exist.",
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
            message="YARA rule path is outside configured allowed directories.",
            details=str(resolved),
            suggestion="Place rules under the MemScope yara_rules directory or add an allowed path.",
            entity="yara",
        )
    return resolved


@dataclass
class YaraProvider:
    """YARA analysis provider — optional; safe when unavailable."""

    name: str = "yara"
    default_rules_dir: Path | None = None
    extra_rule_paths: list[Path] = field(default_factory=list)
    timeout_secs: float = 60.0

    def availability(self) -> dict[str, Any]:
        base = detect_yara()
        rules = self.list_rule_sources()
        return {
            **base,
            "provider": self.name,
            "rule_file_count": len(rules),
            "rule_files": [str(p) for p in rules[:50]],
            "default_rules_dir": str(self.default_rules_dir) if self.default_rules_dir else None,
            "extra_rule_paths": [str(p) for p in self.extra_rule_paths],
            "timeout_secs": self.timeout_secs,
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
                    message="YARA timeout_secs must be between 1 and 3600.",
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
            # Allow adding paths only if they resolve under existing roots OR
            # are explicitly absolute files the user owns under default + listed.
            # For safety: only accept paths under default_rules_dir unless
            # MEMSCOPE allows them — also allow any path that exists as file/dir
            # if it's under user profile data dir roots we already know.
            new_paths: list[Path] = []
            for item in raw:
                p = Path(str(item))
                # expand allow-list to include parent of default
                if self.default_rules_dir:
                    allowed.append(self.default_rules_dir.resolve())
                # For extra paths, require they exist and are under allowed OR
                # we add the path's parent as user-configured root only if path is file/dir
                # under default_rules_dir. Strict: must be under default_rules_dir.
                if self.default_rules_dir is None:
                    raise AppError(
                        code="yara_no_rules_root",
                        message="No default YARA rules directory configured.",
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
        roots.extend(self.extra_rule_paths)
        return roots

    def list_rule_sources(self) -> list[Path]:
        roots = self._allowed_roots()
        return discover_rule_files(roots)

    def compile_rules(self, rule_files: list[Path] | None = None) -> Any:
        info = detect_yara()
        if not info["available"]:
            raise AppError(
                code="yara_unavailable",
                message="YARA is not available on this system.",
                details=info.get("reason"),
                suggestion=info.get("suggestion"),
                entity="yara",
            )
        import yara  # type: ignore

        files = rule_files if rule_files is not None else self.list_rule_sources()
        if not files:
            raise AppError(
                code="yara_no_rules",
                message="No YARA rule files found.",
                suggestion=f"Add .yar/.yara files under {self.default_rules_dir}",
                entity="yara",
            )
        # Validate all under allowed roots
        allowed = self._allowed_roots()
        filemap: dict[str, str] = {}
        for i, f in enumerate(files):
            rf = validate_rule_path(f, allowed)
            # yara needs unique namespace keys
            key = f"r{i}_{rf.stem}"[:40]
            filemap[key] = str(rf)
        try:
            rules = yara.compile(filepaths=filemap)
        except Exception as exc:  # noqa: BLE001 — yara.Error and variants
            raise AppError(
                code="yara_compile_failed",
                message="YARA rule compilation failed.",
                details=str(exc),
                suggestion="Fix syntax errors in the rule files and retry.",
                entity="yara",
                data={"rule_files": [str(p) for p in files]},
            ) from exc
        return rules, {
            "filemap": filemap,
            "rule_files": [str(p) for p in files],
            "yara_version": info["yara_version"],
            "binding": info["binding"],
        }

    def scan_file(
        self,
        target: Path,
        *,
        rule_files: list[Path] | None = None,
        timeout_secs: float | None = None,
        cancelled: Any = None,
    ) -> dict[str, Any]:
        """Scan a single file path. Target must already be a trusted artifact path."""
        info = detect_yara()
        if not info["available"]:
            raise AppError(
                code="yara_unavailable",
                message="YARA is not available on this system.",
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

        timeout = float(timeout_secs if timeout_secs is not None else self.timeout_secs)
        rules, ruleset_meta = self.compile_rules(rule_files)

        result_holder: dict[str, Any] = {"matches": None, "error": None}

        def _run() -> None:
            try:
                # timeout is supported by yara-python match()
                matches = rules.match(filepath=str(target), timeout=int(max(1, timeout)))
                result_holder["matches"] = matches
            except Exception as exc:  # noqa: BLE001
                result_holder["error"] = exc

        thr = threading.Thread(target=_run, name="yara-scan", daemon=True)
        thr.start()
        # Poll for cancel
        while thr.is_alive():
            if cancelled and callable(cancelled) and cancelled():
                # yara timeout is the hard bound; we cannot forcibly kill native match
                # without process isolation. Mark cancel requested; wait for timeout/end.
                thr.join(timeout=0.2)
                if thr.is_alive():
                    # still running — wait remaining with short joins
                    thr.join(timeout=timeout)
                if thr.is_alive():
                    raise AppError(
                        code="yara_cancel_timeout",
                        message="YARA scan cancel requested but native match did not finish in time.",
                        suggestion="Reduce rule set size or timeout; cancel is cooperative around yara-python.",
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
                    message="YARA scan timed out.",
                    details=msg,
                    suggestion="Increase timeout_secs or reduce rule complexity.",
                    entity="yara",
                ) from exc
            raise AppError(
                code="yara_scan_failed",
                message="YARA scan failed.",
                details=f"{name}: {msg}",
                entity="yara",
            ) from exc

        raw_matches = result_holder["matches"] or []
        normalized = [normalize_match(m, ruleset_meta) for m in raw_matches]
        return {
            "status": "completed",
            "match_count": len(normalized),
            "matches": normalized,
            "yara_version": ruleset_meta["yara_version"],
            "ruleset": {
                "rule_files": ruleset_meta["rule_files"],
                "filemap": ruleset_meta["filemap"],
                "binding": ruleset_meta["binding"],
            },
            "target": str(target),
            "scanned_at": _utcnow(),
        }


def normalize_match(match: Any, ruleset_meta: dict[str, Any]) -> dict[str, Any]:
    """Convert yara Match object to JSON-serializable structure."""
    rule_name = getattr(match, "rule", str(match))
    namespace = getattr(match, "namespace", None)
    tags = list(getattr(match, "tags", []) or [])
    meta = dict(getattr(match, "meta", {}) or {})
    strings_out: list[dict[str, Any]] = []
    for item in getattr(match, "strings", []) or []:
        # yara-python 4.x: StringMatch with .identifier .instances
        # older: tuple (offset, identifier, data)
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
