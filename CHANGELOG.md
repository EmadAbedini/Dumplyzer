# Changelog

All notable changes to Dumplyzer are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] — 2026-10-04

Investigation workbench follow-up to the first public Windows x64 release. Application, Tauri, engine, and installer metadata are **0.1.1**. Report schema remains v1. SQLite schema remains v14. Installer: `Dumplyzer_0.1.1_x64-setup.exe`. NSIS and `dumplyzer.exe` remain **unsigned**.

`Dumplyzer_0.1.1_x64-setup.exe` was install-tested on 2026-10-04 on the same Windows 10/11 x64 hosts as 0.1.0 (Windows 11 Pro 24H2 26100.1742, Windows 10 Pro 22H2 19045.2006, Windows 10 Education 22H2 19045.6456). Notes: [README](README.md#1-windows-installer-recommended), [docs/clean-machine-validation.md](docs/clean-machine-validation.md).

### Added

- CSV export for investigation reports (Export) and IOC lists, alongside HTML, JSON, and Excel.
- Per-scan YARA selection: choose individual rules or whole categories (including a Custom group) before scanning the memory image or extracted PE files.
- Jobs labels Analyze Process (process deep dive) with the target PID on the same line as the job kind.
- Bundled YARA rules expanded from 42 to **56** (33 memory, 23 artifact) for stealers, C2 frameworks, and recon tools. Provenance: `engine/memscope_engine/rules/yara/RULES.md`.
- Pagination on large result views (IOCs, network, modules, carved features, and related lists) so those pages no longer load the full stored set at once.

### Changed

- Domain IOCs use the Public Suffix List (registrable eTLD+1) instead of a TLD-allowlist regex. The old matcher missed suffixes such as `.xyz`, `.app`, and `.co.uk`. A naive `anything.anything` matcher treated filenames like `jquery.js` and path segments as hosts. Hits are scored by source (network/URL vs filesystem path) so file extensions are less likely to become domain IOCs.
- Carved Data antivirus warning: clearer layout, **Antivirus Warning** title, and the resolved data-folder path with Copy Path / Open Folder.
- Signature Detection keeps the latest scan per target and stays locked while another analysis job is running.
- NSIS setup no longer copies over an older Dumplyzer. If a previous version is installed, setup says it must be uninstalled; Next removes that version (user data stays) and then installs this one. Cancel exits without changing the installed copy.

### Fixed

- Job progress percent included queued jobs as 0% in the average, so the displayed total lagged. Queued jobs are omitted until they start.
- Upgrading or uninstalling froze on "Uninstalling" with no moving progress bar while the bundled Python tree was deleted. Setup now removes those files in the background and shows a determinate progress bar until it finishes.
- Uninstall no longer flashes a PowerShell window. Windows Settings can find `uninstall.exe` after an upgrade because that file stays until uninstall finishes.
- Processes could look fully analyzed in the workspace before command-line collection finished. Quick Triage (`windows.pslist`) never stores command lines; that coverage stays not-analyzed until cmdline text is stored.
- IOC export from the IOCs view failed or wrote the wrong file extension for some formats. JSON, Excel, and CSV saves now complete with the correct suffix.
- Custom `.yar` / `.yara` files saved as UTF-16 (typical Windows Notepad encoding) failed to compile. Those files now load; Settings lists files that were skipped.
- Consecutive Analyze Process rows used the same highlight, so adjacent analyzed processes blended into one block. Those rows now alternate.

## [0.1.0] — 2026-09-25

First public Windows x64 release of **Dumplyzer**.

Dumplyzer is a local-first desktop workbench for memory forensics. Analysis runs on the workstation. The original memory image stays at its imported location. There is no cloud analysis, no account system, no telemetry, and no malware verdict.

The product was previously named MemScope. The Python package remains `memscope_engine`, and the SQLite file remains `memscope.db`. Application, Tauri, engine, and installer metadata are **0.1.0**. Report schema is v1. SQLite schema is v14.

### Added

#### Investigation workspace

- Import supported Windows and Linux memory images (crash dump, LiME, ELF core, QEMU/VMware snapshot, raw physical memory). Dumplyzer records path, hash, and metadata; it does not copy the dump into Program Files or the user-data tree.
- **Quick Triage**, **Complete Analysis**, and **Custom Analysis**. Complete Analysis does not auto-run PE reconstruction, signature detection, CAPA, FLOSS, bulk_extractor, or PCAP reconstruction — those stay explicit jobs.
- Processes: list, command lines, loaded modules, open handles, parent/child relationships, and per-process deep dive (including a Family view).
- Network connections extracted from the image, plus harvested network indicators with provenance.
- Findings (paginated, filterable by high / medium / low / info), IOCs, and search over stored analysis. Search, IOCs, and Findings describe what analysis already stored; they do not rescan the dump.
- Investigation timeline built from stored records, with time-range filtering. Rebuild uses extracted records, not a second walk of the image.
- Memory regions (VAD) for a selected process, including extract-to-file.
- Carved Data: reconstructed PE images, extracted memory regions, and carved feature files. After a memory-region extract, Dumplyzer opens Extracted Files. **Scan Extracted PE Files** includes those VAD dumps, not only reconstructed PE.
- Signatures: YARA on the memory dump and/or extracted files, including operator-supplied `.yar` / `.yara` rules. Matches are investigation indicators, not verdicts.
- Plugin Explorer for supported Volatility 3 plugins, with cached results and job history.
- Jobs with live progress when the engine knows it. Process Deep Dive shows the same percent on **Analyze Process**.
- Export HTML, JSON, or Excel under `%LOCALAPPDATA%\Dumplyzer\exports\`. HTML reports are static (no JavaScript, no CDN).

Linux evidence can be imported and explored through Plugin Explorer. Quick Triage and Complete Analysis currently provide the guided Windows Volatility workflow.

#### Bundled analysis

- [Volatility 3](https://github.com/volatilityfoundation/volatility3) **2.28.0** on a pinned CPython **3.12.10** embeddable runtime. End users do not install Python. Integration uses Volatility Python APIs, not `vol.py` stdout.
- **42** original Dumplyzer YARA rules (26 memory, 16 artifact; Apache-2.0). Provenance: `engine/memscope_engine/rules/yara/RULES.md`. Settings reports the provider's live compiled-rule count.
- PE reconstruction from Windows process memory (Volatility `windows.pedump` and related workflows). Files are labeled extracted PE artifacts, not malware, and are never executed.
- Mandiant [CAPA](https://github.com/mandiant/capa) **9.4.0** (Apache-2.0) for capability analysis of extracted PE artifacts — capabilities, not verdicts.
- Mandiant [FLOSS](https://github.com/mandiant/flare-floss) **3.1.1** (Apache-2.0) for static and deobfuscated strings from extracted PE artifacts.
- Official [bulk_extractor](https://github.com/simsong/bulk_extractor) **2.2.0** (`bulk_extractor64.exe`, GPL-3.0-or-later, corresponding source shipped) for emails, URLs, IPs, MAC addresses, HTTP logs, AES key candidates, and similar features.
- On-demand PCAP reconstruction: structurally valid Ethernet/IP records from the imported image, written as classic `.pcap` files under `analysis/pcap/`. Connection metadata is never labeled as a PCAP. A reconstructed capture is not a full original capture.

YARA, CAPA, FLOSS, bulk_extractor, and PE reconstruction ship in the installer. They are not downloaded when a job starts.

#### Windows kernel symbols

Windows analysis needs type information for the NT kernel that was running when the dump was taken — the PDB (or Volatility ISF) for **that OS build**, not a generic pack.

- The NSIS installer does **not** ship Microsoft PDBs or the Volatility `windows.zip` archive.
- The first Quick Triage, Complete Analysis, or Custom Analysis on a Windows image whose symbols are not cached asks before continuing.
- **Download & Continue** (recommended) fetches only that dump's kernel PDB over the Microsoft Symbol Server protocol (HTTPS, including Azure Blob redirects), verifies PDB magic, converts it to a Volatility ISF, and caches it under `%LOCALAPPDATA%\Dumplyzer\symbols`. Later dumps from the same build reuse the cache.
- **Browse File** accepts a matching `.pdb`, `.json`, `.json.xz`, or `.json.gz`. A PDB from a different build will not analyze that dump.
- Download never starts by itself. Closing the prompt keeps the imported dump; **Run Analysis** can be used again when symbols are ready.
- While the dialog is open, Overview and the sidebar show **Waiting for PDB**, not Failed.
- Linux images do not use this path.

#### Packaging and data

- One per-machine NSIS installer: `Dumplyzer_0.1.0_x64-setup.exe`, default `%ProgramFiles%\Dumplyzer` (elevation required). MSI is not an end-user artifact.
- Small Microsoft Edge WebView2 Evergreen bootstrapper. If WebView2 is already installed, setup skips it. If it is missing, setup asks before downloading from Microsoft; declining or cancelling that download exits Dumplyzer setup.
- User data stays under `%LOCALAPPDATA%\Dumplyzer\` (database, logs, cache, artifacts, exports, symbol cache, YARA rules, WebView2 profile). The install tree does not hold evidence or generated analysis.
- First launch copies an older `%LOCALAPPDATA%\MemScope\` or `%APPDATA%\com.memscope.workbench\` database into the Dumplyzer data directory when `memscope.db` does not yet exist. The source is never deleted.
- Uninstall keeps user data unless **Delete app data** is checked. That option removes `%LOCALAPPDATA%\Dumplyzer\` (including the WebView2 profile), not only leftover identifier folders.
- Setup stops Dumplyzer and the bundled `python.exe` before copying runtime files so upgrades are not blocked by a locked interpreter DLL.
- Empty Evidence is a valid first-launch state.

### Security

- Local-first process model: the UI never imports Volatility and never shells out to `vol`. The engine is started with an argument array (no shell). Packaged Python uses `python312._pth` isolation, `PYTHONNOUSERSITE=1`, and a reduced `PATH`.
- Dumplyzer does not open a network listener and does not phone home. The only optional Microsoft downloads are WebView2 during setup if the runtime is missing, and one kernel PDB after in-app consent.
- Client `data_dir` overrides are ignored when `DUMPLYZER_DATA_DIR` or `MEMSCOPE_DATA_DIR` is already set. Engine `PYTHONPATH` / user site are scrubbed for the engine process.
- Memory images and extracted artifacts are treated as untrusted and are not executed.
- Export destinations from the UI are rejected; reports are written only under `exports\`. Artifact, cache, and export writers confine paths to their roots.
- Dumplyzer application source is Apache-2.0. Redistributed components keep their own terms (CPython PSF, Volatility Software License, pefile MIT, bulk_extractor GPLv3, CAPA/FLOSS Apache-2.0). See `LICENSE` and `THIRD_PARTY_NOTICES.md`.

### Known limitations

- 0.1.0 NSIS and `dumplyzer.exe` are **unsigned**. SmartScreen or organization policy may warn on first run.
- The desktop application is Windows 10 22H2+ / Windows 11, **x64 only**. Linux and macOS hosts are not a release target yet.
- Before **Carved Data** jobs, exclude `%LOCALAPPDATA%\Dumplyzer\` from real-time antivirus. Carved Artifacts and Extracted Files write reconstructed EXE/DLL images there. Scanners often quarantine those files (job output vanishes or the scan stops). The same process-aware heuristics can quarantine or delete `Dumplyzer.exe`. That is expected endpoint behavior, not a product defect. Pausing AV globally is not required and is not recommended. See [README](README.md#antivirus-exclusions-carved-data) and [SECURITY.md](SECURITY.md#endpoint-protection-and-extracted-binaries).
- A reconstructed PCAP is a carve of recoverable Ethernet/IP records, not a guaranteed full original capture.
- Clean-machine NSIS install on Windows 11 Pro 10.0.26100 x64 (2026-09-20): **pass with limitations**. WebView2 was already present, so first-time WebView2 setup was not observed. See `docs/clean-machine-validation.md`.

[Unreleased]: https://github.com/EmadAbedini/Dumplyzer/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/EmadAbedini/Dumplyzer/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/EmadAbedini/Dumplyzer/releases/tag/v0.1.0
