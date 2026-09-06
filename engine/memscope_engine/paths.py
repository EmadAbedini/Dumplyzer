"""Application data directories (Windows-first, portable).

Mutable forensic data lives under the user data root, never inside the
install/runtime tree. Override with MEMSCOPE_DATA_DIR for tests.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from memscope_engine.version import APP_IDENTIFIER, APP_NAME


LEGACY_BUNDLE_ID = APP_IDENTIFIER

_TOOLS_README = """MemScope optional tools (user-supplied)

Place official binaries here. MemScope never downloads these tools.

PE-sieve (optional)
  Allowed names: pe-sieve64.exe, pe-sieve.exe, pe-sieve32.exe
  Put the file in this folder or in tools\\pe-sieve\\

mal_unpack (optional)
  Allowed names: mal_unpack.exe, mal_unpack64.exe, mal_unpack32.exe
  Put the file in this folder or in tools\\mal_unpack\\
  MemScope will not invoke mal_unpack against investigation artifacts.

YARA rules (optional)
  Put .yar / .yara files in the sibling yara_rules directory, not here.
"""


def default_data_dir() -> Path:
    override = os.environ.get("MEMSCOPE_DATA_DIR")
    if override and override.strip():
        return Path(override).expanduser().resolve()

    local = os.environ.get("LOCALAPPDATA")
    if local:
        return Path(local) / APP_NAME

    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / APP_NAME.lower()

    return Path.home() / f".{APP_NAME.lower()}"


def legacy_data_dirs() -> list[Path]:
    """Previous Tauri identifier-based data locations (not install dirs)."""
    found: list[Path] = []
    roaming = os.environ.get("APPDATA")
    if roaming:
        found.append(Path(roaming) / LEGACY_BUNDLE_ID)
    local = os.environ.get("LOCALAPPDATA")
    if local:
        found.append(Path(local) / LEGACY_BUNDLE_ID)
    return found


def is_canonical_user_data_dir(path: Path) -> bool:
    """True only for %LOCALAPPDATA%\\MemScope, never for test override roots."""
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return False
    try:
        return path.resolve() == (Path(local) / APP_NAME).resolve()
    except OSError:
        return False


def maybe_migrate_legacy_data(dest: Path) -> Path | None:
    """Copy an older identifier-based database into the canonical data dir.

    Never deletes the source. Never overwrites an existing dest database.
    """
    dest = Path(dest).expanduser()
    if (dest / "memscope.db").exists():
        return None
    for src in legacy_data_dirs():
        try:
            if not src.exists():
                continue
            src_res = src.resolve()
            if not (src_res / "memscope.db").is_file():
                continue
            if dest.exists() and src_res == dest.resolve():
                continue
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src_res, dest, dirs_exist_ok=True)
            return src_res
        except OSError:
            continue
    return None


class AppPaths:
    def __init__(self, root: Path | str | None = None) -> None:
        if isinstance(root, str):
            root = Path(root)
        self.root = (root or default_data_dir()).expanduser().resolve()
        self.logs = self.root / "logs"
        self.db_path = self.root / "memscope.db"
        self.artifacts = self.root / "artifacts"
        self.cache = self.root / "cache"
        self.config_path = self.root / "config.json"
        self.tmp = self.root / "tmp"
        self.yara_rules = self.root / "yara_rules"
        self.tools = self.root / "tools"
        self.exports = self.root / "exports"

    def ensure(self) -> "AppPaths":
        if is_canonical_user_data_dir(self.root):
            maybe_migrate_legacy_data(self.root)
        for p in (
            self.root,
            self.logs,
            self.artifacts,
            self.cache,
            self.tmp,
            self.yara_rules,
            self.tools,
            self.exports,
        ):
            p.mkdir(parents=True, exist_ok=True)
        (self.tools / "pe-sieve").mkdir(parents=True, exist_ok=True)
        (self.tools / "mal_unpack").mkdir(parents=True, exist_ok=True)
        (self.cache / "plugin_results").mkdir(parents=True, exist_ok=True)
        readme = self.tools / "README.txt"
        if not readme.exists():
            readme.write_text(_TOOLS_README, encoding="utf-8")
        return self

    def as_dict(self) -> dict[str, str]:
        return {
            "root": str(self.root),
            "logs": str(self.logs),
            "db_path": str(self.db_path),
            "artifacts": str(self.artifacts),
            "cache": str(self.cache),
            "config_path": str(self.config_path),
            "tmp": str(self.tmp),
            "yara_rules": str(self.yara_rules),
            "tools": str(self.tools),
            "exports": str(self.exports),
        }
