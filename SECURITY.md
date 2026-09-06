# Security

MemScope is an offline, single-user forensic workstation. Memory images, extracted artifacts, and plugin output are treated as untrusted.

## Process model

- The UI never imports Volatility and never shells out to `vol`.
- The Tauri shell starts the Python engine with an argument array (no shell).
- Packaged builds use the application-local CPython 3.12.10 runtime with `python312._pth` isolation, `PYTHONNOUSERSITE=1`, and `PYTHONPATH` / `PYTHONHOME` removed.
- Engine temp files are directed at `%LOCALAPPDATA%\MemScope\tmp`.

## Paths and data

- Canonical user data: `%LOCALAPPDATA%\MemScope\`.
- Install trees (`%LOCALAPPDATA%\Programs\MemScope` or `%ProgramFiles%\MemScope`) must not hold databases, artifacts, evidence, or optional tool EXEs.
- Export destinations supplied by the UI are rejected. Reports are written only under `exports\`.
- Artifact, cache, and export writers confine paths to their roots (no `..` traversal).
- `app.init` ignores a client `data_dir` when `MEMSCOPE_DATA_DIR` is already set by the desktop shell.

## Optional tools

| Tool | Policy |
|------|--------|
| YARA | Optional Python extra. Not bundled. Rules must live under `yara_rules`. |
| PE-sieve | User-supplied official EXE, allow-listed names, MZ check, tools root only. No download. Artifact workflow does not invoke the EXE. |
| mal_unpack | User-supplied official EXE, allow-listed names. Native `/exe` executes the sample; MemScope does not invoke that path on investigation artifacts. No download. |

## Reports and logs

- HTML reports are static, with `html.escape` on forensic strings, no JavaScript, no CDN.
- Structured engine logs are JSON. stderr is appended to `logs\engine-stderr.log` (NUL bytes stripped).
- Do not log raw memory contents.

## Packaging

- Runtime zip and WiX 3.14.1 zip are pinned by SHA-256 (see `packaging/windows/runtime-manifest.json`).
- Per-user NSIS install does not require administrator rights. The install directory is still user-writable; the engine is spawned by absolute path and does not add that directory to `PATH`.
- DLL search for `python.exe` uses the runtime directory. Packaged engine `PATH` is reduced to `System32`.

## Reporting issues

File security issues against the repository. There is no telemetry, account system, or network service in MemScope.
