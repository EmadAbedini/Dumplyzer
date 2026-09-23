"""Optional local Volatility Foundation Windows ISF pack.

The official windows.zip is not downloaded automatically. If a user copies it
into the symbols directory, Volatility will index it like any other ISF tree.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from memscope_engine.paths import AppPaths
from memscope_engine.volatility.runtime import active_paths

WINDOWS_ZIP_URL = (
    "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip"
)
WINDOWS_ZIP_SHA256 = "231d69735b9a5482b16bdbf1ec356e0a95574c44079e68dfb02ebddb34d55f3e"
WINDOWS_ZIP_BYTES = 839_727_133
_LINUX_MAC_FORMATS = frozenset({"lime", "elf_core", "macho_core"})
_CHUNK = 1024 * 1024


def windows_zip_path(paths: AppPaths | None = None) -> Path:
    return (paths or active_paths()).symbols / "windows.zip"


def pack_marker_path(dest: Path) -> Path:
    return dest.with_name(dest.name + ".sha256")


def pack_is_ready(paths: AppPaths | None = None) -> bool:
    dest = windows_zip_path(paths)
    marker = pack_marker_path(dest)
    if not dest.is_file() or dest.stat().st_size != WINDOWS_ZIP_BYTES:
        return False
    if marker.is_file() and marker.read_text(encoding="utf-8").strip() == WINDOWS_ZIP_SHA256:
        return True
    if dest.is_file() and dest.stat().st_size == WINDOWS_ZIP_BYTES:
        return _promote_existing(dest)
    return False


def image_may_need_windows_pack(image_path: Path) -> bool:
    """True when a Windows-like dump may need kernel ISF/PDB files."""
    from memscope_engine.memory_image import classify_memory_image

    try:
        classification = classify_memory_image(image_path)
    except OSError:
        return True
    if not classification.is_memory_image:
        return False
    return classification.format_id not in _LINUX_MAC_FORMATS


def _promote_existing(dest: Path) -> bool:
    digest = hashlib.sha256()
    with dest.open("rb") as handle:
        while True:
            chunk = handle.read(_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    if digest.hexdigest() != WINDOWS_ZIP_SHA256:
        return False
    pack_marker_path(dest).write_text(WINDOWS_ZIP_SHA256, encoding="utf-8")
    return True
