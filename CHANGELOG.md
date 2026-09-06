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

### License and release validation

- Add Apache-2.0 `LICENSE` for MemScope application source and `THIRD_PARTY_NOTICES.md` from inspected redistributed metadata (CPython PSF, Volatility 3 VSL, pefile MIT).
- Document Authenticode signing procedure; 0.1.0 NSIS, MSI, and `MemScope.exe` remain **unsigned**.
- Document WebView2 Evergreen as required. `embedBootstrapper` can fetch the runtime when missing; offline WebView2-absent machines are not a supported launch environment.
- Confirm install trees stay separate from `%LOCALAPPDATA%\MemScope\` user data; optional tools are loaded only from the user-data tools allow-list.
- Confirm the bundled runtime omits yara-python / capstone / pycryptodome and does not mark failed plugin imports as available.
- Clean-machine VM checklist remains unexecuted on this host.
