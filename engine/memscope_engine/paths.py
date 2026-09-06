"""Application data directories (Windows-first, portable)."""

from __future__ import annotations

import os
from pathlib import Path


APP_NAME = "MemScope"


def default_data_dir() -> Path:
    override = os.environ.get("MEMSCOPE_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()

    local = os.environ.get("LOCALAPPDATA")
    if local:
        return Path(local) / APP_NAME

    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / APP_NAME.lower()

    return Path.home() / f".{APP_NAME.lower()}"


class AppPaths:
    def __init__(self, root: Path | str | None = None) -> None:
        if isinstance(root, str):
            root = Path(root)
        self.root = (root or default_data_dir()).resolve()
        self.logs = self.root / "logs"
        self.db_path = self.root / "memscope.db"
        self.artifacts = self.root / "artifacts"
        self.cache = self.root / "cache"
        self.config_path = self.root / "config.json"
        self.tmp = self.root / "tmp"
        self.yara_rules = self.root / "yara_rules"
        self.tools = self.root / "tools"

    def ensure(self) -> "AppPaths":
        for p in (
            self.root,
            self.logs,
            self.artifacts,
            self.cache,
            self.tmp,
            self.yara_rules,
            self.tools,
        ):
            p.mkdir(parents=True, exist_ok=True)
        (self.tools / "pe-sieve").mkdir(parents=True, exist_ok=True)
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
        }
