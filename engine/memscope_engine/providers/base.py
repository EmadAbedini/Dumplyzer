"""Provider protocol for optional external analysis tools."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class AnalysisProvider(Protocol):
    """Extensible adapter surface (YARA now; PE-sieve / mal_unpack later)."""

    name: str

    def availability(self) -> dict[str, Any]:
        """Return availability status without raising when optional deps missing."""
        ...

    def configure(self, settings: dict[str, Any]) -> dict[str, Any]:
        """Apply validated configuration; return effective settings."""
        ...
