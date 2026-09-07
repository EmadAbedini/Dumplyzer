"""Cleanup of Dumplyzer-created temporary working files.

Import stores the original evidence path and hashes in place. It does not copy
the memory image. Python/Volatility TEMP is redirected to AppPaths.tmp
(%LOCALAPPDATA%\\Dumplyzer\\tmp). This module removes those working files and
dumpfiles scratch directories. It never deletes:

* the user's original evidence file
* exported reports
* artifact store contents the analyst extracted
* analysis cache / SQLite / config / logs / rules / tools
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from memscope_engine.paths import AppPaths

_DUMPFILES_TMP = "_dumpfiles_tmp"


def _clear_directory_contents(path: Path) -> int:
    """Delete children of path; keep the directory. Returns files/dirs removed."""
    removed = 0
    if not path.is_dir():
        return 0
    try:
        entries = list(path.iterdir())
    except OSError:
        return 0
    for child in entries:
        try:
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)
            removed += 1
        except OSError:
            continue
    return removed


def _remove_named_dirs(root: Path, name: str) -> int:
    removed = 0
    if not root.is_dir():
        return 0
    try:
        entries = list(root.iterdir())
    except OSError:
        return 0
    for child in entries:
        if not child.is_dir():
            continue
        if child.name == name:
            shutil.rmtree(child, ignore_errors=True)
            removed += 1
            continue
        removed += _remove_named_dirs(child, name)
    return removed


def cleanup_session_temp(paths: AppPaths) -> dict[str, Any]:
    """Remove case-specific temporary files Dumplyzer created.

    Safe to call on engine init (crash leftovers) and on shutdown.
    """
    tmp_removed = 0
    if paths.tmp.exists():
        tmp_removed = _clear_directory_contents(paths.tmp)
    paths.tmp.mkdir(parents=True, exist_ok=True)
    dumpfiles_removed = _remove_named_dirs(paths.analysis, _DUMPFILES_TMP)
    return {
        "tmp_dir": str(paths.tmp),
        "tmp_entries_removed": tmp_removed,
        "dumpfiles_scratch_removed": dumpfiles_removed,
    }
