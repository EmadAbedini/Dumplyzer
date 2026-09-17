# Dumplyzer Engine (Python 3.12)

Runtime for development:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -U pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Pinned runtime dependencies: `requirements.lock.txt` (Volatility 3 **2.28.0**, pefile **2024.8.26**, yara-python **4.5.4**). Signature Detection is bundled in the Windows installer; users do not install Python or YARA. PE Extraction is a Volatility 3 workflow in this package. bulk_extractor v2.2.0, CAPA v9.4.0, and FLOSS v3.1.1 are bundled in application resources (`scripts/windows/prepare-*.ps1`) and are never downloaded at runtime.

Run smoke server:

```powershell
.\.venv\Scripts\python.exe -m memscope_engine
```

Send NDJSON on stdin, e.g. `{"jsonrpc":"2.0","id":"1","method":"smoke.e2e","params":{}}`

Release builds bundle official CPython 3.12.10 embeddable + this package via `scripts/windows/prepare-engine-runtime.ps1`. See `docs/windows-release.md`.
