"""Structured logging for application / analysis / tool channels."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        for key in ("channel", "job_id", "evidence_id", "plugin"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(log_dir: Path, level: int = logging.INFO) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    fmt = JsonFormatter()

    file_handler = RotatingFileHandler(
        log_dir / "engine.jsonl",
        maxBytes=5_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)

    # stderr only for bootstrap failures — keep stdout clean for NDJSON RPC
    err = logging.StreamHandler(sys.stderr)
    err.setLevel(logging.WARNING)
    err.setFormatter(fmt)
    root.addHandler(err)

    logging.getLogger("memscope.app").setLevel(level)
    logging.getLogger("memscope.analysis").setLevel(level)
    logging.getLogger("memscope.tool").setLevel(level)


def get_logger(channel: str) -> logging.Logger:
    return logging.getLogger(f"memscope.{channel}")
