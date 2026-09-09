"""Application data directories (Windows-first, portable).

Mutable forensic data lives under the user data root, never inside the
install/runtime tree. Override with DUMPLYZER_DATA_DIR (or the legacy
MEMSCOPE_DATA_DIR alias) for tests.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from memscope_engine.version import (
    APP_IDENTIFIER,
    APP_NAME,
    LEGACY_APP_IDENTIFIER,
    LEGACY_APP_NAME,
)


LEGACY_BUNDLE_ID = LEGACY_APP_IDENTIFIER

_TOOLS_README = """Dumplyzer optional tools (user-supplied overrides)

Place official binaries here only as overrides. Dumplyzer never downloads these tools.

bulk_extractor (bundled by default; optional override)
  Dumplyzer ships bulk_extractor64.exe in application resources.
  To override, put bulk_extractor64.exe / bulk_extractor.exe / bulk_extractor32.exe
  in this folder or in tools\\bulk_extractor\\. Raw output is written under
  analysis\\bulk_extractor\\.

CAPA (bundled by default; optional override)
  Dumplyzer ships capa.exe (Mandiant CAPA, Apache-2.0) in application resources.
  Override: capa.exe in this folder or tools\\capa\\. Analyzes extracted PE artifacts.

FLOSS (bundled by default; optional override)
  Dumplyzer ships floss.exe (Mandiant FLOSS, Apache-2.0) in application resources.
  Override: floss.exe in this folder or tools\\floss\\. Analyzes extracted PE artifacts.

PE Extraction is a Volatility 3 workflow (not an EXE in this folder).
Output is written under analysis\\pe_extraction\\<run-id>\\.

YARA / Signature Detection
  Bundled rules ship with Dumplyzer. User rules: sibling rules\\yara\\custom\\.
  Put .yar / .yara files there (or in custom\\memory / custom\\artifact).
  Dumplyzer never overwrites custom rules on upgrade.
"""


def data_dir_override() -> Path | None:
    for key in ("DUMPLYZER_DATA_DIR", "MEMSCOPE_DATA_DIR"):
        override = os.environ.get(key)
        if override and override.strip():
            return Path(override).expanduser().resolve()
    return None


def default_data_dir() -> Path:
    override = data_dir_override()
    if override is not None:
        return override

    local = os.environ.get("LOCALAPPDATA")
    if local:
        return Path(local) / APP_NAME

    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / APP_NAME.lower()

    return Path.home() / f".{APP_NAME.lower()}"


def legacy_data_dirs() -> list[Path]:
    """Previous product and identifier-based data locations (not install dirs)."""
    found: list[Path] = []
    roaming = os.environ.get("APPDATA")
    if roaming:
        found.append(Path(roaming) / LEGACY_BUNDLE_ID)
    local = os.environ.get("LOCALAPPDATA")
    if local:
        found.append(Path(local) / LEGACY_APP_NAME)
        found.append(Path(local) / LEGACY_BUNDLE_ID)
        found.append(Path(local) / APP_IDENTIFIER)
    return found


def is_canonical_user_data_dir(path: Path) -> bool:
    """True only for %LOCALAPPDATA%\\Dumplyzer, never for test override roots."""
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return False
    try:
        return path.resolve() == (Path(local) / APP_NAME).resolve()
    except OSError:
        return False


def maybe_migrate_legacy_data(dest: Path) -> Path | None:
    """Copy an older MemScope or identifier-based database into the canonical dir.

    Never deletes the source. Never overwrites an existing dest database.
    The SQLite file name remains memscope.db.
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
        self.yara_rules = self.root / "rules" / "yara"
        self.yara_rules_bundled = self.yara_rules / "bundled"
        self.yara_rules_custom = self.yara_rules / "custom"
        self.tools = self.root / "tools"
        self.exports = self.root / "exports"
        self.analysis = self.root / "analysis"

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
            self.yara_rules_bundled,
            self.yara_rules_bundled / "memory",
            self.yara_rules_bundled / "artifact",
            self.yara_rules_custom,
            self.yara_rules_custom / "memory",
            self.yara_rules_custom / "artifact",
            self.tools,
            self.exports,
            self.analysis,
        ):
            p.mkdir(parents=True, exist_ok=True)
        (self.tools / "bulk_extractor").mkdir(parents=True, exist_ok=True)
        (self.tools / "capa").mkdir(parents=True, exist_ok=True)
        (self.tools / "floss").mkdir(parents=True, exist_ok=True)
        (self.analysis / "bulk_extractor").mkdir(parents=True, exist_ok=True)
        (self.analysis / "pe_extraction").mkdir(parents=True, exist_ok=True)
        (self.analysis / "pcap").mkdir(parents=True, exist_ok=True)
        (self.analysis / "capa").mkdir(parents=True, exist_ok=True)
        (self.analysis / "floss").mkdir(parents=True, exist_ok=True)
        (self.cache / "plugin_results").mkdir(parents=True, exist_ok=True)
        self._migrate_legacy_yara_rules()
        sync_bundled_yara_rules(self.yara_rules_bundled)
        custom_readme = self.yara_rules_custom / "README.txt"
        if not custom_readme.exists():
            src = _package_custom_readme()
            if src and src.is_file():
                shutil.copy2(src, custom_readme)
            else:
                custom_readme.write_text(
                    "Place .yar / .yara files here. Dumplyzer never overwrites this folder.\n",
                    encoding="utf-8",
                )
        readme = self.tools / "README.txt"
        if not readme.exists():
            readme.write_text(_TOOLS_README, encoding="utf-8")
        return self

    def _migrate_legacy_yara_rules(self) -> None:
        """Copy a previous flat yara_rules directory into custom/ without overwriting."""
        legacy = self.root / "yara_rules"
        if not legacy.is_dir():
            return
        try:
            if legacy.resolve() == self.yara_rules.resolve():
                return
        except OSError:
            return
        for src in sorted(legacy.rglob("*")):
            if not src.is_file() or src.suffix.lower() not in {".yar", ".yara"}:
                continue
            dest = self.yara_rules_custom / src.name
            if dest.exists():
                continue
            try:
                shutil.copy2(src, dest)
            except OSError:
                continue

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
            "yara_rules_bundled": str(self.yara_rules_bundled),
            "yara_rules_custom": str(self.yara_rules_custom),
            "tools": str(self.tools),
            "exports": str(self.exports),
            "analysis": str(self.analysis),
        }


def _package_bundled_rules_dir() -> Path | None:
    try:
        root = Path(__file__).resolve().parent / "rules" / "yara" / "bundled"
        if root.is_dir():
            return root
    except OSError:
        return None
    return None


def _package_custom_readme() -> Path | None:
    try:
        path = Path(__file__).resolve().parent / "rules" / "yara" / "custom_README.txt"
        if path.is_file():
            return path
    except OSError:
        return None
    return None


def bundled_yara_rule_sources() -> list[Path]:
    """Install-tree and package locations for shipped Signature Detection rules."""
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

    raw = os.environ.get("DUMPLYZER_BUNDLE_RULES")
    if raw and raw.strip():
        p = Path(raw.strip())
        _add(p)
        _add(p / "bundled")
        _add(p / "yara" / "bundled")
    try:
        runtime = Path(sys.executable).resolve().parent
        _add(runtime.parent / "rules" / "yara" / "bundled")
        _add(runtime.parent / "resources" / "rules" / "yara" / "bundled")
    except OSError:
        pass
    pkg = _package_bundled_rules_dir()
    if pkg is not None:
        _add(pkg)
    return found


def sync_bundled_yara_rules(dest: Path) -> None:
    """Refresh Dumplyzer-shipped rules. Never writes into custom/.

    Copies the current curated tree, then removes stale bundled ``.yar`` /
    ``.yara`` files that are no longer shipped so upgrades do not keep
    retired signatures.
    """
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "memory").mkdir(parents=True, exist_ok=True)
    (dest / "artifact").mkdir(parents=True, exist_ok=True)
    sources = bundled_yara_rule_sources()
    if not sources:
        return
    src_root = sources[0]
    try:
        if src_root.resolve() == dest.resolve():
            return
    except OSError:
        pass
    wanted: set[str] = set()
    for src in src_root.rglob("*"):
        if not src.is_file():
            continue
        try:
            rel = src.relative_to(src_root)
        except ValueError:
            continue
        wanted.add(rel.as_posix().lower())
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, target)
        except OSError:
            continue
    for existing in dest.rglob("*"):
        if not existing.is_file():
            continue
        if existing.suffix.lower() not in {".yar", ".yara"}:
            continue
        try:
            rel = existing.relative_to(dest)
        except ValueError:
            continue
        if rel.as_posix().lower() in wanted:
            continue
        try:
            existing.unlink()
        except OSError:
            continue
