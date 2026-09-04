"""NDJSON JSON-RPC 2.0 server over stdio (smoke + future engine API)."""

from __future__ import annotations

import json
import sys
import traceback
from importlib.metadata import PackageNotFoundError, version
from typing import Any


def _vol_init() -> dict[str, Any]:
    """Import Volatility 3 and return verified initialization metadata."""
    import volatility3
    from volatility3.framework import constants, contexts, automagic, plugins

    try:
        vol_ver = version("volatility3")
    except PackageNotFoundError:
        vol_ver = getattr(constants, "PACKAGE_VERSION", "unknown")

    # Touch core framework surfaces used by real analysis paths.
    _ = contexts.Context
    _ = automagic
    _ = plugins

    return {
        "ok": True,
        "engine_version": "0.1.0-dev",
        "python_version": sys.version.split()[0],
        "volatility3_version": vol_ver,
        "volatility3_path": getattr(volatility3, "__file__", None),
        "framework_package_version": getattr(constants, "PACKAGE_VERSION", None),
    }


HANDLERS = {
    "health": lambda _params: {
        "ok": True,
        "service": "memscope_engine",
        "version": "0.1.0-dev",
    },
    "volatility.init": lambda _params: _vol_init(),
    "smoke.e2e": lambda _params: {
        "ok": True,
        "health": HANDLERS["health"]({}),
        "volatility": _vol_init(),
    },
}


def _write(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _error(req_id: Any, code: int, message: str, data: Any = None) -> None:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    _write({"jsonrpc": "2.0", "id": req_id, "error": err})


def handle_line(line: str) -> None:
    line = line.strip()
    if not line:
        return
    try:
        req = json.loads(line)
    except json.JSONDecodeError as exc:
        _error(None, -32700, "Parse error", str(exc))
        return

    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params") or {}

    if req.get("jsonrpc") != "2.0" or not isinstance(method, str):
        _error(req_id, -32600, "Invalid Request")
        return

    handler = HANDLERS.get(method)
    if handler is None:
        _error(req_id, -32601, f"Method not found: {method}")
        return

    try:
        result = handler(params)
        if req_id is not None:
            _write({"jsonrpc": "2.0", "id": req_id, "result": result})
    except Exception as exc:  # noqa: BLE001 — surface full smoke failures
        _error(
            req_id,
            -32000,
            f"{type(exc).__name__}: {exc}",
            traceback.format_exc(),
        )


def main() -> None:
    # Line-buffered-ish: read requests until EOF.
    for line in sys.stdin:
        handle_line(line)


if __name__ == "__main__":
    main()
