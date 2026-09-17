# Changelog

## Unreleased

- Remove PE-sieve and mal_unpack providers.
- Add dedicated **PE Extraction** from Windows memory dumps (Volatility 3 `windows.pedump` reconstruction, loaded modules, mapped/unlinked PE, optional dumpfiles). Extracted files are labeled extracted PE artifacts, not malware.
- Expand the bundled Signature Detection ruleset to a curated **42** original Dumplyzer YARA rules (memory-forensics oriented; Apache-2.0). Provenance: `engine/memscope_engine/rules/yara/RULES.md`. Settings continues to show the provider's live `bundled_rule_count`.
- Bundle Mandiant **CAPA** v9.4.0 (Apache-2.0) for capability analysis of extracted PE artifacts.
- Bundle Mandiant **FLOSS** v3.1.1 (Apache-2.0) for static/deobfuscated strings from extracted PE artifacts.
- Optional **bulk_extractor** provider: bundled official v2.2.0 `bulk_extractor64.exe` (GPL-3.0-or-later, separate process + corresponding source). Evidence-scoped scan of the imported memory dump; raw feature files under `analysis/bulk_extractor/`. User-supplied EXE remains an override.
- SQLite schema **v12**: YARA scans may target the original memory dump (`artifact_id` nullable, `target_kind`). Older PE-sieve / mal_unpack tables are retained for compatibility.
- Add **Network Artifact Extraction** (evidence-scoped capability + job) that harvests recoverable network indicators from netscan connections, bulk_extractor features, IOCs, FLOSS strings, and process command lines, with provenance. SQLite schema **v13**.
- Add on-demand **PCAP Reconstruction** that carves structurally valid Ethernet/IP records from the imported memory image and writes classic `.pcap` files under `analysis/pcap/`. Connection metadata is never labeled as a PCAP. Original evidence is not modified.

## 0.1.0 — 2026-09-06

First packaged Windows x64 release train (feature freeze on forensic workflows).

Product branding is **Dumplyzer** (formerly MemScope). The Python package remains `memscope-engine` / `memscope_engine`, and the SQLite file remains `memscope.db`.

### Packaging

- Bundle a pinned CPython **3.12.10** embeddable runtime with Volatility 3 **2.28.0** and `memscope-engine` 0.1.0 so end users do not install Python.
- Produce per-user NSIS (`currentUser`, default `%LOCALAPPDATA%\Programs\Dumplyzer`) and WiX 3.14 MSI installers.
- Keep mutable forensic data under `%LOCALAPPDATA%\Dumplyzer\` (database, cache, artifacts, exports, YARA rules, optional tools, logs).
- Copy an older `%LOCALAPPDATA%\MemScope\` or `%APPDATA%\com.memscope.workbench\` database into `%LOCALAPPDATA%\Dumplyzer\` when the new database does not exist. The source is never deleted.

### Reliability and security

- Resolve the engine from the bundled runtime in packaged builds; keep `engine\.venv` for developers.
- Drain engine stderr to a log file, kill the engine process on application exit, and spawn Python with `CREATE_NO_WINDOW`.
- Ignore client `data_dir` overrides when `DUMPLYZER_DATA_DIR` or `MEMSCOPE_DATA_DIR` is set; scrub `PYTHONPATH` / user site for the engine process.
- Copy a previous identifier-based database from `%APPDATA%\com.memscope.workbench\` into the canonical data directory when the new database does not exist.

### Documentation / versioning

- Unify application, Tauri, engine, and installer metadata at **0.1.0**. Report schema remains v1; SQLite schema remains v9.

### License and release validation

- Add Apache-2.0 `LICENSE` for Dumplyzer application source and `THIRD_PARTY_NOTICES.md` from inspected redistributed metadata (CPython PSF, Volatility 3 VSL, pefile MIT).
- Document Authenticode signing procedure; 0.1.0 NSIS, MSI, and `dumplyzer.exe` remain **unsigned**.
- Document WebView2 Evergreen as required. `embedBootstrapper` can fetch the runtime when missing; offline WebView2-absent machines are not a supported launch environment.
- Confirm install trees stay separate from `%LOCALAPPDATA%\Dumplyzer\` user data; optional tools are loaded only from the user-data tools allow-list.
- Confirm the bundled runtime includes yara-python 4.5.4; capstone / pycryptodome remain omitted. Failed plugin imports must not be marked available.
- Clean-machine NSIS install executed on a Windows 11 x64 VM (2026-09-07): **PASS WITH LIMITATIONS** (`docs/clean-machine-validation.md`). MSI and WebView2-absent-offline were not tested.
