"""Safe on-disk artifact store with deterministic paths and hashing."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_component(value: str, *, max_len: int = 80) -> str:
    cleaned = _SAFE.sub("_", value.strip())
    cleaned = cleaned.strip("._") or "x"
    return cleaned[:max_len]


def artifact_dir(paths: AppPaths, evidence_id: str) -> Path:
    # Keep under controlled app data; evidence_id is UUID-like
    eid = sanitize_component(evidence_id, max_len=64)
    d = paths.artifacts / eid
    d.mkdir(parents=True, exist_ok=True)
    # Prevent path escape
    try:
        d.resolve().relative_to(paths.artifacts.resolve())
    except ValueError as exc:
        raise AppError(
            code="artifact_path_invalid",
            message="Artifact path escaped the controlled store.",
            details=str(d),
            entity="artifact",
        ) from exc
    return d


def build_artifact_filename(
    *,
    pid: int | None,
    start_vpn: str | None,
    end_vpn: str | None,
    suffix: str = "dmp",
) -> str:
    parts = ["pid", str(pid if pid is not None else "unknown")]
    if start_vpn:
        parts.append(sanitize_component(start_vpn.replace("0x", "x")))
    if end_vpn:
        parts.append(sanitize_component(end_vpn.replace("0x", "x")))
    name = ".".join(parts) + f".{sanitize_component(suffix, max_len=16)}"
    return name


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sniff_file_type(path: Path) -> str:
    """Lightweight magic sniff — not full format identification."""
    try:
        with path.open("rb") as f:
            head = f.read(16)
    except OSError:
        return "unknown"
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    if head.startswith(b"%PDF"):
        return "pdf"
    return "raw"


def ensure_within_artifacts(paths: AppPaths, candidate: Path) -> Path:
    resolved = candidate.resolve()
    root = paths.artifacts.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise AppError(
            code="artifact_path_invalid",
            message="Refusing path outside the artifact store.",
            details=str(resolved),
            entity="artifact",
        ) from exc
    return resolved


def ensure_within_controlled_data(paths: AppPaths, candidate: Path) -> Path:
    """Allow artifact store and PE extraction output under analysis/pe_extraction."""
    resolved = candidate.resolve()
    roots = [
        paths.artifacts.resolve(),
        (paths.analysis / "pe_extraction").resolve(),
    ]
    for root in roots:
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            continue
    raise AppError(
        code="artifact_path_invalid",
        message="Refusing path outside controlled artifact / PE extraction directories.",
        details=str(resolved),
        entity="artifact",
    )
