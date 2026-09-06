"""Safe export destination paths. Never write into source evidence."""

from __future__ import annotations

import re
from pathlib import Path
from uuid import uuid4

from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(value: str, *, default: str = "report", max_len: int = 80) -> str:
    raw = (value or "").strip()
    raw = raw.replace("\\", "_").replace("/", "_")
    if not raw or raw in {".", ".."}:
        return default
    cleaned = _SAFE.sub("_", raw).strip("._") or default
    if cleaned in {".", ".."}:
        return default
    return cleaned[:max_len]


def exports_root(paths: AppPaths) -> Path:
    paths.exports.mkdir(parents=True, exist_ok=True)
    root = paths.exports.resolve()
    try:
        root.relative_to(paths.root.resolve())
    except ValueError as exc:
        raise AppError(
            code="export_path_invalid",
            message="Exports directory escaped the application data root.",
            details=str(root),
            entity="export",
        ) from exc
    return root


def reject_user_destination(value: str | None) -> None:
    """Frontend must not supply filesystem destinations."""
    if value is None or value == "":
        return
    raise AppError(
        code="export_path_rejected",
        message="Export destination paths are not accepted from the client.",
        suggestion="Exports are written under the application data exports directory.",
        entity="export",
    )


def parse_optional_basename(value: str | None) -> str | None:
    """Allow a basename hint only — no separators, no traversal, no absolute paths."""
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()
    candidate = Path(text)
    if candidate.is_absolute() or candidate.drive:
        raise AppError(
            code="export_path_rejected",
            message="Absolute export paths are not allowed.",
            details=text,
            entity="export",
        )
    parts = candidate.parts
    if ".." in parts or any(p in {"/", "\\"} for p in text):
        raise AppError(
            code="export_path_rejected",
            message="Path traversal in export filenames is not allowed.",
            details=text,
            entity="export",
        )
    if "/" in text or "\\" in text or ":" in text:
        raise AppError(
            code="export_path_rejected",
            message="Export filenames must not contain path separators.",
            details=text,
            entity="export",
        )
    return sanitize_filename(text)


def ensure_within_exports(paths: AppPaths, candidate: Path) -> Path:
    resolved = candidate.resolve()
    root = exports_root(paths)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise AppError(
            code="export_path_rejected",
            message="Refusing path outside the exports directory.",
            details=str(resolved),
            entity="export",
        ) from exc
    return resolved


def refuse_evidence_overwrite(dest: Path, evidence_path: str | None) -> None:
    if not evidence_path:
        return
    try:
        ev = Path(evidence_path).resolve()
    except OSError:
        return
    dest_res = dest.resolve()
    if dest_res == ev:
        raise AppError(
            code="export_evidence_protected",
            message="Refusing to overwrite source evidence.",
            details=str(ev),
            entity="export",
        )
    if ev.is_dir():
        try:
            dest_res.relative_to(ev)
        except ValueError:
            return
        raise AppError(
            code="export_evidence_protected",
            message="Refusing to write exports inside the evidence path.",
            details=str(ev),
            entity="export",
        )


def allocate_export_dir(
    paths: AppPaths,
    *,
    evidence_filename: str,
    export_id: str,
    basename_hint: str | None = None,
    evidence_path: str | None = None,
) -> Path:
    root = exports_root(paths)
    stamp = sanitize_filename(evidence_filename, default="evidence", max_len=40)
    short = sanitize_filename(export_id, default="export", max_len=8)
    base = sanitize_filename(basename_hint or f"{stamp}_{short}", default="export", max_len=72)
    dest = ensure_within_exports(paths, root / f"{base}_{short}")
    refuse_evidence_overwrite(dest, evidence_path)
    try:
        dest.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        dest = ensure_within_exports(paths, root / f"{base}_{short}_{uuid4().hex[:6]}")
        refuse_evidence_overwrite(dest, evidence_path)
        dest.mkdir(parents=True, exist_ok=False)
    return dest
