"""Generic TreeGrid → JSON table (not CLI text)."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

from memscope_engine.errors import AppError

RESULT_MODEL_VERSION = 1


def _cancel_requested(cancelled: Callable[[], bool] | None, *, seen: list[int], last: list[float]) -> bool:
    if cancelled is None:
        return False
    seen[0] += 1
    now = time.monotonic()
    if seen[0] > 2 and last[0] > 0 and now - last[0] < 0.1:
        return False
    last[0] = now
    try:
        return bool(cancelled())
    except Exception:
        return False


def treegrid_to_table(
    grid: Any,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Convert a Volatility TreeGrid into a versioned tabular structure."""
    columns_meta: list[dict[str, Any]] = []
    for col in getattr(grid, "columns", []) or []:
        name = getattr(col, "name", None)
        ctype = getattr(col, "type", None)
        if name is None and isinstance(col, (tuple, list)) and len(col) >= 2:
            name, ctype = col[0], col[1]
        columns_meta.append(
            {
                "name": str(name) if name is not None else "",
                "type": _type_name(ctype),
            }
        )
    rows: list[dict[str, Any]] = []
    seen = [0]
    last = [0.0]

    def _visitor(node: Any, accumulator: Any) -> Any:
        if _cancel_requested(cancelled, seen=seen, last=last):
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
        values = list(node.values) if getattr(node, "values", None) is not None else []
        depth = 0
        path = getattr(node, "path", None)
        if path is not None:
            try:
                depth = max(0, len(path) - 1)
            except TypeError:
                depth = 0
        cells = [_cell_to_json(v) for v in values]
        named: dict[str, Any] = {}
        for i, col in enumerate(columns_meta):
            named[col["name"]] = cells[i] if i < len(cells) else None
        rows.append(
            {
                "depth": depth,
                "cells": cells,
                "values": named,
            }
        )
        return accumulator

    if hasattr(grid, "populate"):
        grid.populate(_visitor, None)
    if cancelled and cancelled():
        raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
    nested = any(r["depth"] for r in rows)
    return {
        "model_version": RESULT_MODEL_VERSION,
        "columns": columns_meta,
        "rows": rows,
        "row_count": len(rows),
        "nested": nested,
    }


def _type_name(ctype: Any) -> str:
    if ctype is None:
        return "object"
    if ctype is int:
        return "int"
    if ctype is str:
        return "str"
    if ctype is float:
        return "float"
    if ctype is bool:
        return "bool"
    if ctype is bytes:
        return "bytes"
    if ctype is datetime:
        return "datetime"
    name = getattr(ctype, "__name__", None) or str(ctype)
    lname = name.lower()
    if "hex" in lname:
        return "hex"
    if "datetime" in lname:
        return "datetime"
    if "disassembly" in lname:
        return "disassembly"
    return name


def cell_to_json(value: Any) -> Any:
    return _cell_to_json(value)


def _cell_to_json(value: Any) -> Any:
    if value is None:
        return None
    cls_name = type(value).__name__
    if "Absent" in cls_name or cls_name.endswith("NotApplicable"):
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return {"type": "bytes", "hex": value.hex(), "length": len(value)}
    if isinstance(value, datetime) or hasattr(value, "isoformat"):
        try:
            iso = value.isoformat()
            if isinstance(iso, str):
                return iso
        except Exception:  # noqa: BLE001
            pass
    if isinstance(value, (list, tuple)):
        return [_cell_to_json(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _cell_to_json(v) for k, v in value.items()}
    try:
        return str(value)
    except Exception:  # noqa: BLE001
        return repr(value)
