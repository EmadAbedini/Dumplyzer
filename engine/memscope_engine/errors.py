"""Structured application errors for IPC propagation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


class JobCancelled(BaseException):
    """Abort in-flight Volatility work.

    Subclass of BaseException (not Exception) so Volatility 3 cannot swallow
    it. ``automagic.run`` and ``DataLayerInterface.scan`` catch Exception and
    otherwise keep running the current plugin for tens of seconds.
    """


def job_cancelled_error() -> AppError:
    return AppError(code="job_cancelled", message="Job was cancelled.", entity="job")


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
        data: dict[str, Any] = {
            "app_code": exc.code,
            "suggestion": exc.suggestion,
            "entity": exc.entity,
        }
        for key, value in exc.data.items():
            if key in {"details", "traceback", "raw", "stack"}:
                continue
            data[key] = value
        return {
            "code": -32000,
            "message": exc.message,
            "data": data,
        }
    return {
        "code": -32000,
        "message": "Something went wrong.",
        "data": {"app_code": "internal_error"},
    }
