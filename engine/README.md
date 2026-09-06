# MemScope Engine (Python 3.12)

Runtime for development:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -U pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Pinned runtime dependencies: `requirements.lock.txt` (Volatility 3 **2.28.0**, pefile **2024.8.26**). Optional YARA: `pip install -e ".[yara]"` — not required and not shipped in the Windows installer.

Run smoke server:

```powershell
.\.venv\Scripts\python.exe -m memscope_engine
```

Send NDJSON on stdin, e.g. `{"jsonrpc":"2.0","id":"1","method":"smoke.e2e","params":{}}`

Release builds bundle official CPython 3.12.10 embeddable + this package via `scripts/windows/prepare-engine-runtime.ps1`. See `docs/windows-release.md`.
