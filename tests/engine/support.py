"""Helpers for locating a Python interpreter that can run memscope_engine."""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def engine_python() -> Path:
    env = os.environ.get("DUMPLYZER_ENGINE_PYTHON") or os.environ.get("MEMSCOPE_ENGINE_PYTHON")
    if env:
        candidate = Path(env)
        if candidate.is_file():
            return candidate
    bundled = REPO_ROOT / "app" / "desktop" / "resources" / "runtime" / "python.exe"
    if bundled.is_file():
        return bundled
    venv = REPO_ROOT / "engine" / ".venv" / "Scripts" / "python.exe"
    if venv.is_file():
        return venv
    posix = REPO_ROOT / "engine" / ".venv" / "bin" / "python"
    if posix.is_file():
        return posix
    raise FileNotFoundError("engine Python runtime not found")


def bundled_runtime_python() -> Path | None:
    path = REPO_ROOT / "app" / "desktop" / "resources" / "runtime" / "python.exe"
    return path if path.is_file() else None
