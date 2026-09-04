# MemScope Engine (Python 3.12)

Create venv and install:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -U pip
.\.venv\Scripts\python.exe -m pip install -e .
```

Run smoke server:

```powershell
.\.venv\Scripts\python.exe -m memscope_engine
```

Send NDJSON on stdin, e.g. `{"jsonrpc":"2.0","id":"1","method":"smoke.e2e","params":{}}`
