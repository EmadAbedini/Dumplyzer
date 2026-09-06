"""Engine smoke: Volatility 3 init via package entrypoint."""

from __future__ import annotations

import json
import subprocess
import sys

from support import engine_python


def test_smoke_e2e_volatility_init() -> None:
    python = engine_python()
    req = json.dumps(
        {"jsonrpc": "2.0", "id": "t1", "method": "smoke.e2e", "params": {}}
    ) + "\n"
    proc = subprocess.run(
        [str(python), "-m", "memscope_engine"],
        input=req,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    line = next((ln for ln in proc.stdout.splitlines() if ln.strip()), "")
    assert line, f"no stdout; stderr={proc.stderr!r}"
    msg = json.loads(line)
    assert "error" not in msg, msg
    result = msg["result"]
    assert result["ok"] is True
    assert result["volatility"]["ok"] is True
    assert result["volatility"]["volatility3_version"]


if __name__ == "__main__":
    test_smoke_e2e_volatility_init()
    print("engine smoke OK", file=sys.stderr)
