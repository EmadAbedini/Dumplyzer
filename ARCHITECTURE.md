# Dumplyzer architecture

Offline Windows x64 desktop workbench for Volatility 3 memory forensics.

React UI → Tauri 2 shell → bundled Python 3.12 engine → Volatility 3 APIs.

Dumplyzer is not a CLI wrapper, not a cloud product, and does not score malware.

## Layout

```
React + TypeScript (app/frontend)
        │  Tauri commands / events
Tauri 2 shell (app/desktop, Rust)
        │  JSON-RPC NDJSON over stdio
Python engine (engine/memscope_engine)
        │  Volatility 3 APIs, optional tool EXEs
Memory image on disk (never copied into the install tree)
```

The UI consumes normalized application data, not `vol.py` stdout.

## Repository

```
app/frontend/     Vite + React + TypeScript UI
app/desktop/      Tauri 2 shell, installer config, bundled resources
engine/           memscope-engine Python package (name kept from the MemScope rename)
tests/engine/     Engine unit and integration tests
packaging/        Windows runtime manifest and NSIS template
scripts/          Release and tool-prep scripts
docs/             Windows release and clean-machine validation
```

The Python import path remains `memscope_engine`. The SQLite file remains `memscope.db`.
Legacy user data under `%LOCALAPPDATA%\MemScope\` is copied into `%LOCALAPPDATA%\Dumplyzer\`
on first launch when the new database does not exist. The source is not deleted.

## Layers

### Frontend (`app/frontend`)

Investigation views, local UI state, and Tauri IPC. No Volatility imports and no `vol` process.

### Desktop (`app/desktop`)

Windowing, file dialogs, engine process lifecycle, and packaging. The engine is spawned with an
argument array (no shell). Packaged builds use `<install>\resources\runtime\python.exe -m memscope_engine`.

### Engine (`engine/memscope_engine`)

Forensic analysis, SQLite persistence, job queue, Volatility 3 adapter, and provider workflows
(PE Extraction, Signature Detection, CAPA, FLOSS, bulk_extractor, network artifacts, PCAP reconstruction).

## IPC

Frontend ↔ Tauri: commands for request/response, events for job progress and engine status.

Tauri ↔ engine: JSON-RPC 2.0 NDJSON on stdin/stdout. stderr is for bootstrap failures only.
Stdio is used instead of a localhost HTTP port so the product stays offline-first and does not
open a network listener.

## Volatility 3

All Volatility-specific code lives under `engine/memscope_engine/volatility/`. Plugins are
constructed through Volatility Python APIs (`construct_plugin` / TreeGrid). Plugin Explorer
discovers the installed registry dynamically. Failed imports are listed and are never marked available.

The memory image is never loaded into SQLite. Evidence rows store path, hash, and metadata.

## Data locations

| Kind | Location |
|------|----------|
| Install | `%ProgramFiles%\Dumplyzer\` |
| User data | `%LOCALAPPDATA%\Dumplyzer\` |
| Database | `%LOCALAPPDATA%\Dumplyzer\memscope.db` |
| Signature rules | `%LOCALAPPDATA%\Dumplyzer\rules\yara\` (`bundled\` refreshed, `custom\` never overwritten) |

Override the data directory with `DUMPLYZER_DATA_DIR` (or the legacy `MEMSCOPE_DATA_DIR` alias)
only for tests or support. Evidence files stay where they were imported.

## SQLite

Current schema version is **14**. Migrations are additive. Opening an older `memscope.db` upgrades
in place and keeps existing evidence rows.

| Version | Contents |
|---------|----------|
| v5 | YARA scans |
| v6–v7 | PE-sieve / mal_unpack tables retained for compatibility; those providers are not shipped |
| v8 | Analysis cache + plugin results |
| v9 | Exports |
| v10 | bulk_extractor scans |
| v11 | PE Extraction, CAPA, FLOSS |
| v12 | YARA memory-dump scans (`artifact_id` nullable, `target_kind`) |
| v13 | Network artifacts + PCAP reconstruction |
| v14 | bulk_extractor feature rows |

Report schema is independent (`memscope-report-v1`).

## Jobs and cache

Jobs move `queued → running → completed | failed | cancelled`. The UI does not block on analysis.
Progress is a real percentage only when known; otherwise it is indeterminate.

Advanced plugin results are cached by evidence SHA-256, Volatility version, plugin id, canonical
parameters, and schema version. Cache hits still create execution rows with `cache_hit`.

## Providers

| Capability | Role | Shipping |
|------------|------|----------|
| Volatility 3 | Memory analysis | Bundled in the engine runtime (2.28.0) |
| PE Extraction | Reconstruct EXE/DLL from the dump | Volatility 3 workflow, not a separate EXE |
| Signature Detection | YARA on the dump and/or extracted PE | Bundled yara-python 4.5.4 + curated rules |
| CAPA | Capabilities on extracted PE | Bundled official Windows EXE v9.4.0 |
| FLOSS | Strings on extracted PE | Bundled official Windows EXE v3.1.1 |
| bulk_extractor | Feature extraction on the dump | Bundled official Windows EXE v2.2.0 (GPLv3, separate process) |

These jobs are explicit. Full Analysis does not auto-run Signature Detection, CAPA, FLOSS,
bulk_extractor, or PE Extraction. Extracted PE files are labeled artifacts, not malware, and
are never executed.

PE-sieve and mal_unpack are not part of Dumplyzer. Older SQLite tables remain so existing
databases still open.

## Security

- Treat memory images, dumps, and extracted artifacts as hostile.
- Argument arrays only; no `shell=True`.
- Path confinement for artifacts, cache, exports, and optional tool EXEs.
- Exports are written only under the user-data `exports\` directory.
- Packaged Python uses `python312._pth` isolation, `PYTHONNOUSERSITE=1`, and a reduced `PATH`.
- HTML reports are static (`html.escape`, no JavaScript, no CDN).

See `SECURITY.md`.

## Packaging

One NSIS installer (`Dumplyzer_0.1.0_x64-setup.exe`), default `%ProgramFiles%\Dumplyzer`,
elevation required. The small WebView2 Evergreen bootstrapper is packed (`embedBootstrapper`).
If WebView2 is missing, that bootstrapper downloads the runtime during setup.

The engine runtime is official CPython 3.12.10 embeddable plus `site-packages`. Not PyInstaller.
Not a first-run venv. Generated `app/desktop/resources/runtime/` is gitignored.

Build procedure: `docs/windows-release.md`.

## Engine RPC

Implemented methods in `engine/memscope_engine/server.py`:

| Area | Methods |
|------|---------|
| Lifecycle | `health`, `app.init`, `app.paths`, `app.shutdown`, `volatility.init`, `smoke.e2e` |
| Evidence | `evidence.import`, `evidence.list`, `evidence.get`, `evidence.analyze_basic` |
| Analysis | `analysis.profiles`, `analysis.run`, `overview.get` |
| Processes | `processes.list`, `process.get`, `process.analyze_recommended` |
| Network | `network.list`, `network.artifacts`, `network.artifact_runs`, `network.extract_artifacts` |
| PCAP | `pcap.reconstructions`, `pcap.get`, `pcap.reconstruct`, `pcap.export_flow` |
| Entities | `modules.list`, `findings.list`, `search.query`, `iocs.*`, `memory.*`, `timeline.*`, `artifacts.*` |
| YARA | `yara.status`, `yara.reload`, `yara.configure`, `yara.scan_*`, `yara.scans_*`, `yara.scan_get`, `yara.matches_for_evidence` |
| PE / CAPA / FLOSS | `pe_extraction.*`, `capa.*`, `floss.*` |
| bulk_extractor | `bulk_extractor.status`, `bulk_extractor.configure`, `bulk_extractor.scan`, `bulk_extractor.scans`, `bulk_extractor.scan_get`, `bulk_extractor.features` |
| Plugins | `plugins.list`, `plugins.get`, `plugins.validate`, `plugins.execute`, `plugins.execution_get`, `plugins.executions` |
| Export | `export.options`, `export.generate`, `export.list`, `export.get`, `export.delete` |
| Jobs | `jobs.submit`, `jobs.get`, `jobs.list`, `jobs.cancel` |

## Tests

| Layer | Location |
|-------|----------|
| Engine | `tests/engine` |
| Desktop | `cargo test` in `app/desktop` |
| Frontend | `npm run build` (`tsc --noEmit` + Vite) in `app/frontend` |

Contributor setup: `CONTRIBUTING.md`.
