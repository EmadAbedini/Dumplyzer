"""Structured application errors for IPC propagation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class AppError(Exception):
    """User-facing error with optional technical detail and next step."""

    code: str
    message: str
    details: str | None = None
    suggestion: str | None = None
    entity: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return self.message

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        return payload


def rpc_error_payload(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, AppError):
        return {
            "code": -32000,
            "message": exc.message,
            "data": {
                "app_code": exc.code,
                "details": exc.details,
                "suggestion": exc.suggestion,
                "entity": exc.entity,
                **exc.data,
            },
        }
    return {
        "code": -32000,
        "message": f"{type(exc).__name__}: {exc}",
        "data": {"app_code": "internal_error", "details": str(exc)},
    }
