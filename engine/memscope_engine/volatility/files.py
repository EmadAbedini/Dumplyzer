"""Controlled FileHandler for Volatility plugins that emit files.

Writes only under a Dumplyzer-controlled directory. Never executes output.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any
from uuid import uuid4

from memscope_engine.artifacts import store as artifact_store


def make_file_handler_class(output_dir: Path, collected: list[dict[str, Any]]):
    """Return a FileHandlerInterface subclass bound to output_dir."""
    from volatility3.framework.interfaces import plugins as iplugins

    output_dir.mkdir(parents=True, exist_ok=True)

    class MemScopeFileHandler(iplugins.FileHandlerInterface):
        def __init__(self, filename: str) -> None:
            super().__init__(filename)
            self._buffer = io.BytesIO()
            self._committed = False
            self.output_path: Path | None = None

        def readable(self) -> bool:
            return False

        def writable(self) -> bool:
            return True

        def write(self, b: bytes) -> int:  # type: ignore[override]
            if isinstance(b, str):
                b = b.encode("utf-8", errors="replace")
            if not isinstance(b, (bytes, bytearray, memoryview)):
                raise TypeError("FileHandler.write expects bytes")
            return self._buffer.write(bytes(b))

        def close(self) -> None:
            if self._committed:
                return
            self._committed = True
            data = self._buffer.getvalue()
            preferred = self.preferred_filename or "plugin.bin"
            safe = iplugins.FileHandlerInterface.sanitize_filename(preferred)
            dest = output_dir / safe
            if dest.exists():
                dest = output_dir / f"{uuid4().hex[:8]}.{safe}"
            dest.write_bytes(data)
            dest = dest.resolve()
            try:
                dest.relative_to(output_dir.resolve())
            except ValueError:
                dest.unlink(missing_ok=True)
                raise
            digest = artifact_store.sha256_file(dest)
            self.output_path = dest
            collected.append(
                {
                    "filename": dest.name,
                    "preferred_filename": preferred,
                    "path": str(dest),
                    "sha256": digest,
                    "size_bytes": dest.stat().st_size,
                }
            )
            self._buffer.close()

    return MemScopeFileHandler
