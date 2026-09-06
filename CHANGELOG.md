# Changelog

## 0.1.0 — 2026-09-06

First packaged Windows x64 release train (feature freeze on forensic workflows).

### Packaging

- Bundle a pinned CPython **3.12.10** embeddable runtime with Volatility 3 **2.28.0** and `memscope-engine` 0.1.0 so end users do not install Python.
- Produce per-user NSIS (`currentUser`, default `%LOCALAPPDATA%\Programs\MemScope`) and WiX 3.14 MSI installers.
- Keep mutable forensic data under `%LOCALAPPDATA%\MemScope\` (database, cache, artifacts, exports, YARA rules, optional tools, logs).

### Reliability and security

- Resolve the engine from the bundled runtime in packaged builds; keep `engine\.venv` for developers.
- Drain engine stderr to a log file, kill the engine process on application exit, and spawn Python with `CREATE_NO_WINDOW`.
- Ignore client `data_dir` overrides when `MEMSCOPE_DATA_DIR` is set; scrub `PYTHONPATH` / user site for the engine process.
- Copy a previous identifier-based database from `%APPDATA%\com.memscope.workbench\` into the canonical data directory when the new database does not exist.

### Documentation / versioning

- Unify application, Tauri, engine, and installer metadata at **0.1.0**. Report schema remains v1; SQLite schema remains v9.
