# Changelog

## Unreleased

- Sidebar Memory count follows currently displayed Memory rows; an empty PID box (no records) shows a dash instead of the dump-wide VAD total.
- Show **Analysing N%** on the Process Deep Dive Analyze Process button, using the same live job percent as Jobs.
- Rewrite Findings / IOCs / Search notes so they describe stored data rather than a dump-wide scan.
- Shorten PCAP reconstruction limitations and rename the timeline action to **Rebuild From Extracted Records**.
- Keep Process results filling during Complete Analysis instead of waiting until the whole job ends.
- Use Volatility Threading for in-process layer scans (with a ``threading.Pool`` alias so scans do not silently miss hits), pass bulk_extractor ``-j`` as ``min(max(1, CPU-2), 8)``, and poll import/kernel-symbol jobs every 500ms.
- Keep FileLayer's Threading lock cloneable so the next plugin after a successful kernel ISF load does not fail with ``cannot pickle '_thread.lock'``.
- Drop splash TOPMOST and hide it as soon as the workbench HWND is shown, so the brand window does not sit on the main UI for a frame.
- Convert downloaded kernel PDBs in memory so Download & Continue does not fail after Microsoft has already returned a valid PDB.
- Show kernel-symbol download progress on the Download button instead of creating a Jobs row; analysis starts after the file is ready.
- Show **Waiting for PDB** in the sidebar and Overview instead of Failed while the kernel-symbols dialog is open.
- Kernel-symbols dialog: Download & Continue is the primary path. Browse File is secondary. The Microsoft Symbol Server URL is not shown or copied; browsers save that redirect as a `.blob` file.
- Warm the Volatility plugin catalog in the background after engine init so Plugin Explorer does not wait about two seconds on first open.
- Use capability labels in HTML export instead of YARA, CAPA, FLOSS, bulk_extractor, and PE Extraction.
- Download & Continue retrieves the Microsoft PDB through the symbol-server protocol (including Azure Blob redirects), verifies PDB magic, then converts it to Volatility ISF. Azure `.blob` object names are not treated as symbols without that check.
- Closing the kernel-symbols prompt keeps the imported dump and returns to Overview so Run Analysis can be used again.
- NSIS installer still does not pack `windows.zip`; kernel PDBs stay under `%LOCALAPPDATA%\Dumplyzer\symbols` after in-app Download & Continue.
- Ask before installing WebView2, and exit setup if the user declines or cancels the download, so the InstFiles page does not sit frozen.
- Ask before fetching Windows kernel symbols, and download only the PDB/ISF for that dump's build (or import a .pdb / .json / .json.xz / .json.gz the user provides). Do not pull the 800 MB Windows pack automatically.
- Download Windows kernel PDBs over HTTPS with a Microsoft-Symbol-Server User-Agent so a missing ISF GUID is not reported as absent after a 403.
- Quote the WebView2 bootstrapper path and show its installer UI. Silent `/silent /install` looked frozen on machines that do not already have WebView2.
- Reload PCAP Reconstruction when its job finishes, and keep Reconstructing… until that fetch returns, so the panel does not flash 0 records.
- Observe job cancel on a timer instead of on every dump read, and do not refresh Overview while Volatility is running, so Quick Triage and Analyze Process are not stalled by filesystem/RPC contention.
- Stop Dumplyzer and its bundled `python.exe` before NSIS copies runtime files so upgrades are not blocked by a locked `_bz2.pyd`.
- Poll import/job status immediately instead of waiting for the next interval, and list in-flight imports even before they have an evidence id, so Jobs does not sit on Waiting to start for about a second.
- Uninstall removes `%ProgramFiles%\Dumplyzer` with one `rmdir` instead of deleting each bundled Python/Volatility file in the NSIS details list.
- Show bundled Analysis Capabilities immediately instead of Checking…. Settings does not import Volatility plugins or probe tools before the workbench is usable.
- Write a temporary `stop-dumplyzer-runtime.ps1` and invoke it with PowerShell `-File` so NSIS upgrade/uninstall no longer raises `MissingEndCurlyBrace`.
- Keep the WebView2 profile under `%LOCALAPPDATA%\Dumplyzer\webview`. Uninstall **Delete app data** now also removes `%LOCALAPPDATA%\Dumplyzer` (forensic data + UI cache), not only `com.dumplyzer.workbench`.
- Keep the engine job worker alive across repeated `app.init` so an in-flight memory-image import is not silently dropped.
- Point Volatility 3 symbol cache at `%LOCALAPPDATA%\Dumplyzer` and skip malformed Windows CA certificates so packaged installs can resolve kernel PDBs.
- Do not run Volatility/tool health checks on the RPC thread during an in-flight import, and close leftover `queued`/`running` jobs from a previous crash so Import Memory Dump can start.

- Prepare public repository docs: current architecture notes, sanitized validation records, and removal of internal project-state tracking.
- Remove unused frontend Radix UI / CVA packages that the UI no longer imports.
- Remove leftover PE-sieve and mal_unpack provider modules. SQLite tables from schema v6–v7 remain so older databases still open.
- Keep the splash window until the workbench has painted, so a blank white main window is not shown between splash and UI.
- Default the NSIS installer to `%ProgramFiles%\Dumplyzer` (`perMachine`; requires elevation). User data stays in `%LOCALAPPDATA%\Dumplyzer`.
- Ship one NSIS installer only. Embed the small WebView2 Evergreen bootstrapper. If WebView2 is missing, the bootstrapper downloads the runtime during setup.
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
