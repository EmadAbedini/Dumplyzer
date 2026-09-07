"""Subprocess lifecycle: timeout must kill the Windows process tree."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from memscope_engine.providers.process_run import (
    _windows_pid_alive,
    default_subprocess_runner,
)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows process-tree kill")
def test_timeout_terminates_child_process_tree(tmp_path: Path) -> None:
    child_pid_file = tmp_path / "child.pid"
    script = tmp_path / "parent.py"
    script.write_text(
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
        f"Path(r'{child_pid_file}').write_text(str(child.pid), encoding='utf-8')\n"
        "time.sleep(120)\n",
        encoding="utf-8",
    )
    run = default_subprocess_runner(
        [sys.executable, str(script)],
        timeout_secs=2.0,
        entity="capa",
    )
    assert run.timed_out is True
    deadline = time.monotonic() + 8
    child_pid = None
    while time.monotonic() < deadline:
        if child_pid_file.is_file():
            text = child_pid_file.read_text(encoding="utf-8").strip()
            if text:
                child_pid = int(text)
                break
        time.sleep(0.1)
    assert child_pid is not None, "child pid file was not written before timeout"
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and _windows_pid_alive(child_pid):
        time.sleep(0.2)
    assert not _windows_pid_alive(child_pid)
    assert run.tree_terminated is True


def test_timeout_preserves_captured_output(tmp_path: Path) -> None:
    script = tmp_path / "noisy.py"
    script.write_text(
        "import sys, time\n"
        "sys.stdout.write('hello-stdout\\n')\n"
        "sys.stdout.flush()\n"
        "sys.stderr.write('hello-stderr\\n')\n"
        "sys.stderr.flush()\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    run = default_subprocess_runner(
        [sys.executable, str(script)],
        timeout_secs=1.5,
        entity="floss",
    )
    assert run.timed_out is True
    assert "hello-stdout" in run.stdout
    assert "hello-stderr" in run.stderr
