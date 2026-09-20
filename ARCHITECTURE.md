# Dumplyzer — Architecture

> Describes the **intended and implemented** architecture. Update when the implementation changes.  
> Last verified: 2026-09-09 — PE Extraction + CAPA + FLOSS (schema v11, report schema v1).

**Product:** Dumplyzer — focused desktop workbench for Volatility 3 memory forensics  
**Platform primary:** Windows x64 (portable design for Linux later)  
**Character:** Professional analyst workstation — not a CLI wrapper, not a SOC dashboard

---

## 1. Overall architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  React + TypeScript UI (Guided Mode + Advanced Mode)            │
│  Tailwind CSS + shadcn/ui                                       │
└────────────────────────────┬────────────────────────────────────┘
                             │ Tauri invoke / events
┌────────────────────────────▼────────────────────────────────────┐
│  Tauri 2 desktop shell (Rust)                                   │
│  - Windowing, file dialogs, path validation                     │
│  - Engine process lifecycle                                     │
│  - IPC bridge (frontend ↔ engine)                               │
│  - App config paths, logging hooks                              │
└────────────────────────────┬────────────────────────────────────┘
                             │ JSON-RPC (NDJSON) over stdio
┌────────────────────────────▼────────────────────────────────────┐
│  Python Analysis Engine (sidecar)                               │
│  - Job manager, cache, SQLite storage                           │
│  - Normalized forensic models                                   │
│  - Volatility 3 API adapter                                     │
│  - Providers: Volatility 3, PE Extraction, YARA, CAPA, FLOSS, bulk_extractor │
└────────────────────────────┬────────────────────────────────────┘
                             │ Volatility 3 frameworks / plugins
                             ▼
                      Memory image (on disk)
```

**Non-negotiable rule:** The UI consumes **normalized application data**, not Volatility CLI text. CLI/human output may be retained only for transparency/debug.

---

## 2. Layer responsibilities

### 2.1 React frontend (`app/frontend`)

- Investigation UX: Import, Overview, Processes, Deep Dive, Network, Modules, Memory/VAD, Findings, IOC Search, Timeline, Artifacts, Jobs, Plugin Explorer, Advanced execution, Export / Report
- Local UI state + server/engine state via Tauri commands and event subscriptions
- Tables, filters, search, virtualization for large result sets
- No Volatility imports; no shelling out to `vol`
- Dark-mode-first, compact forensic workstation layout

### 2.2 Tauri desktop (`app/desktop`)

- Native window and application lifecycle
- Spawn/monitor/restart Python engine sidecar with explicit argv (no shell)
- Bridge: frontend commands → engine JSON-RPC; engine notifications → frontend events
- Safe file pickers; path canonicalization; evidence path allowlisting concepts
- App data directories (config, logs, SQLite, artifact store, cache, **exports**)
- Packaging entrypoint (Windows x64)

### 2.3 Python engine (`engine`)

- All forensic analysis and Volatility interaction
- SQLite persistence of metadata and normalized results
- Job queue (queued / running / completed / failed / cancelled)
- Analysis cache keyed by evidence hash + tool versions + params + schema version
- Findings heuristics, IOC extraction, timeline assembly, artifact provenance, forensic export/reporting
- Provider adapters for optional external tools
- Structured logging (app / analysis / tool)

---

## 3. Repository layout (planned)

```
memscope/
├── app/
│   ├── frontend/          # Vite + React + TS + Tailwind + shadcn
│   └── desktop/           # Tauri 2 (Rust) project
├── engine/
│   ├── memscope_engine/   # Installable Python package
│   │   ├── api/           # JSON-RPC method handlers
│   │   ├── volatility/    # Vol3 adapter (isolated)
│   │   ├── analysis/      # Strategies, recommended analysis
│   │   ├── models/        # Pydantic / dataclasses → normalized entities
│   │   ├── jobs/          # Job manager
│   │   ├── cache/         # Analysis cache
│   │   ├── artifacts/     # Extraction + provenance
│   │   ├── findings/      # Heuristics engine
│   │   ├── ioc/           # IOC extraction
│   │   ├── providers/     # yara, pe_extraction, capa, floss, bulk_extractor adapters
│   │   ├── storage/       # SQLite, migrations
│   │   └── logging/       # Structured logs
│   ├── pyproject.toml
│   └── requirements*.txt
├── tests/
│   ├── engine/
│   ├── frontend/
│   └── integration/
├── docs/
├── scripts/               # dev bootstrap, package helpers
├── .github/workflows/
├── ARCHITECTURE.md
├── PROJECT_STATE.md
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── CHANGELOG.md
└── LICENSE
```

Exact package names may shift slightly during scaffolding; this document must be updated to match reality.

---

## 4. IPC mechanism

### 4.1 Frontend ↔ Tauri

- Tauri **commands** for request/response (import evidence, list processes, start job, cancel job, search, export)
- Tauri **events** for job progress, log lines, engine status
- Typed TypeScript bindings generated or hand-maintained to match command contracts

### 4.2 Tauri ↔ Python engine

- Engine started as child process: `python -m memscope_engine` (packaged: bundled `runtime\python.exe`)
- **Transport:** stdin/stdout, **newline-delimited JSON** (NDJSON)
- **Protocol:** JSON-RPC 2.0 style messages
  - Request: `{ "jsonrpc": "2.0", "id": "...", "method": "...", "params": { } }`
  - Response: `{ "jsonrpc": "2.0", "id": "...", "result": { } }` or `error`
  - Notification (no id): job updates, log append
- stderr reserved for unstructured panic/bootstrap failures; structured logs go via notifications or log files
- **Security:** no `shell=True`; cwd controlled; env scrubbed where needed; timeouts; kill tree on app exit

### 4.3 Why not HTTP localhost?

Avoids opening ports, firewall prompts, and accidental remote exposure. Stdio keeps the product offline-first and simpler to reason about for a single-user desktop tool.

---

## 5. Volatility integration

### 5.1 Principles

- Use **Volatility 3 Python APIs / frameworks / plugins** — not stdout table scraping as the data model
- All Vol3-specific code lives under `engine/memscope_engine/volatility/`
- Adapter produces **normalized entities** (`Process`, `Module`, `NetworkConnection`, etc.)
- Plugin execution metadata retained for transparency (plugin name, params, version, timestamps, status)

### 5.2 Conceptual types

| Type | Role |
|------|------|
| `Evidence` | Imported memory image metadata (path external) |
| `AnalysisRun` | A logical analysis session / batch |
| `PluginExecution` | One plugin run with params + status |
| `NormalizedResult` | Typed rows mapped into entities |
| `Finding` | Transparent heuristic conclusion with evidence links |
| `Artifact` | Extracted file with provenance chain |

### 5.3 Symbol / OS detection

- Import flow: validate path → hash (streaming SHA-256) → probe with Vol3 → record OS/arch/symbol status
- Memory image **never** fully loaded into SQLite
- Symbol failure must surface actionable errors (what failed, why, next step)

### 5.4 Verification gate (Phase 1–2)

Before locking APIs, inspect installed `volatility3` version, plugin list, and framework interfaces on the target Python. **Do not invent plugin names or constructor signatures.**

---

## 6. Normalized data model (logical)

### Evidence

`id`, `path`, `filename`, `size`, `sha256`, `detected_os`, `architecture`, `volatility_compatibility`, `symbol_status`, `import_timestamp`, `metadata_json`

### Process

`id`, `evidence_id`, `pid`, `ppid`, `name`, `username`, `path`, `command_line`, `create_time`, `parent_id`, suspicion flags via Findings, `source_plugin`

### Module

`id`, `evidence_id`, `process_id`, `name`, `path`, `base_address`, `size`, `characteristics`, `source_plugin`

### NetworkConnection

`id`, `evidence_id`, `process_id`, `protocol`, `local_address`, `local_port`, `remote_address`, `remote_port`, `state`, `source_plugin`

### MemoryRegion

`id`, `evidence_id`, `process_id`, `start`, `end`, `size`, `protection`, `type`, `backing`, suspicious via Findings, `source_plugin`

### Handle (Phase 3+)

Linked to process; source plugin metadata

### IOC

`type` ∈ {ipv4, ipv6, domain, url, path, hash, registry, mutex, username, other}, `value`, links to entity/finding/source

### Finding

`type`, `severity`, `explanation` (human-readable **why**), entity links, `evidence_id`, `plugin`, `field`, `timestamp`, optional `confidence` — **no opaque risk scores**

### Artifact

Provenance: evidence → process → region/module → extraction method → sha256 → optional provider results

### TimelineEvent

`timestamp`, `kind`, `summary`, `entity_refs`, `classification` ∈ {`observed`, `inferred`}

---

## 7. Database (SQLite)

- Database: `%LOCALAPPDATA%\Dumplyzer\memscope.db` on Windows, not inside the memory image and not inside the install directory
- Stores: evidence metadata, normalized entities, jobs, cache index, findings, IOCs, artifacts metadata, timeline
- **Does not store** raw memory dump bytes
- Migrations: sequential SQL or lightweight migration runner from day one
- Large result sets: paginated queries; UI virtualization

---

## 8. Job lifecycle

```
queued → running → completed
                 → failed
                 → cancelled
```

- UI never blocks on long analysis
- Progress: real percentage only if known; otherwise **indeterminate** (no fake %)
- Cancellation cooperative where Vol3 allows; process-level cancel as last resort for hung work
- Each job records: timestamps, params, errors, tool versions, logs reference

---

## 9. Analysis cache

Cache key components:

1. Evidence SHA-256  
2. Volatility version  
3. Plugin name + normalized parameters  
4. Dumplyzer analysis/schema version  
5. Provider tool version when applicable  

Invalidation on schema/version change. Never serve stale forensic results after relevant invalidation.

Implemented for Advanced Execution in `memscope_engine.cache` (`analysis_cache` table + JSON result files). Cache hits remain visible as distinct PluginExecution rows with `cache_hit`.

---

## 10. Artifact & provenance architecture

```
Memory Image (Evidence)
  → Process / memory region / module
    → PE Extraction → Extracted PE Artifact (EXE/DLL under analysis/pe_extraction)
      → Signature Detection matches (memory dump and/or extracted artifacts)
      → optional CAPA capabilities
      → optional FLOSS strings
  → optional bulk_extractor feature extraction on the memory image
  → Network Artifact Extraction (harvested indicators with provenance)
  → optional PCAP Reconstruction (carved packet records → analysis/pcap/*.pcap)
```

- Artifact store path under app data; quarantine semantics (never auto-execute)
- Metadata always in SQLite; bytes always files
- Every artifact row stores extraction method, tool/version, source addresses, timestamps

---

## 11. Plugin system & Advanced Mode

- **Guided Mode:** Recommended Analysis strategies select relevant plugins for the task (e.g. process deep dive) — not “run everything”
- **Advanced Mode / Plugin Explorer (implemented):** dynamic discovery from the installed Volatility 3 registry (`framework.import_files` + `framework.list_plugins`). Analysts inspect metadata, configure simple requirements, and run a `plugin_advanced` JobManager job. Results are a generic TreeGrid table plus structured raw JSON — not `vol.py` stdout.
- Frontend never imports Volatility. Plugin ids resolve only through the discovered registry (no `import_module` of user strings, no shell, no arbitrary Python).
- Framework requirements (URI/image location, `ModuleRequirement` kernel, translation layers, symbol tables, version dependencies) are filled from Dumplyzer Evidence + automagic. The UI edits only configurable Boolean/Int/String/Choice/List parameters.
- Dedicated forensic views (Processes, Memory, Network, …) remain the guided path. Plugin Explorer is explicitly labeled generic execution.

---

## 12. Findings engine

Rule-based, explainable heuristics, for example:

- Encoded PowerShell command lines  
- Suspicious parent/child pairs  
- Unusual image paths  
- RWX / private executable regions  
- Suspicious DLL paths  
- Network from unusual processes  

Each finding answers **why** and links to evidence fields. Prefer precision over noisy scoring.

---

## 13. Analysis capabilities (providers)

| Capability | Role | Bundling |
|----------|------|----------|
| Signature Detection | Rule scan of the original memory dump and/or extracted PE artifacts | **Bundled** yara-python 4.5.4 plus a small curated rule set. User rules: `%LOCALAPPDATA%\Dumplyzer\rules\yara\custom\` |
| PE Extraction | Reconstruct EXE/DLL from the memory dump | Bundled Volatility 3 workflow (`windows.pedump` / VAD / dumpfiles) |
| CAPA | Capabilities on extracted PE artifacts | **Bundled** official Windows standalone v9.4.0 (Apache-2.0) |
| FLOSS | Static / deobfuscated strings on extracted PE | **Bundled** official Windows standalone v3.1.1 (Apache-2.0) |
| bulk_extractor | Raw feature / artifact extraction from the memory image | **Bundled** official Windows EXE (GPL-3.0-or-later). Complements Volatility; invoked as a separate process |

Interface: `Provider` protocol with `availability()`, `run(request) -> ProviderResult`. Signature Detection, CAPA, FLOSS, PE Extraction, and bulk_extractor remain explicit jobs; PE extraction does not auto-run the others.

---

## 14. Security boundaries

- Treat memory images, dumps, and artifacts as **hostile**
- Argument arrays only; no string shell interpolation
- Path validation and controlled temp/artifact directories
- Timeouts and cancellation
- Do not execute extracted PE/artifacts
- Sanitize logs (no dumping full memory contents)
- Engine runs as child of the UI process; same user context (desktop app reality) — defense is isolation of tools and careful I/O, not a full sandbox VM (out of scope)

---

## 15. Logging & errors

**Logs (separated):**

- Application (UI/desktop)
- Analysis (engine jobs)
- Tool execution (Vol3/provider invocations metadata)

**Errors:** actionable messages — what failed, why, entity affected, suggested next step, expandable technical detail. No silent swallow.

---

## 16. Packaging (Windows x64)

- Tauri 2 bundler produces one **NSIS** installer. Default install dir is `%ProgramFiles%\Dumplyzer` on the Windows system drive (elevation required). WebView2 Evergreen standalone is packed for offline install.
- Engine: **official CPython 3.12.10 Windows embeddable** + `Lib\site-packages` containing `memscope-engine`, pinned Volatility 3 **2.28.0**, and **yara-python 4.5.4**. Not PyInstaller. Not a first-run venv. Not the developer's global Python.
- Packaged spawn: absolute `runtime\python.exe -m memscope_engine` (argv, no shell, `CREATE_NO_WINDOW`, env scrubbed).
- Developer spawn: source-tree `app/desktop/resources/runtime/python.exe` when present (`tauri dev`); otherwise `engine\.venv\Scripts\python.exe`. Packaged spawn is unchanged.
- User data is `%LOCALAPPDATA%\Dumplyzer\`, never inside the install directory.
- Do not commit dumps, malware, local DBs, secrets, or generated `resources/runtime` / installer output.
- Signature Detection (yara-python 4.5.4) is bundled and is never auto-downloaded. User custom rules under `%LOCALAPPDATA%\Dumplyzer\rules\yara\custom\` survive upgrades.
- bulk_extractor v2.2.0, CAPA v9.4.0, and FLOSS v3.1.1 official Windows binaries are bundled in application resources and invoked as separate programs. They are never downloaded at runtime.

---

## 17. Cross-platform considerations

- Path handling via proper path APIs (not string concat with `\`)
- App data dirs via Tauri path API
- Engine process spawn differences (Windows vs POSIX) isolated in desktop layer
- Linux support is a later port of the same architecture, not a fork

---

## 18. Testing strategy

| Layer | Focus |
|-------|--------|
| Engine unit | Models, normalization, cache keys, findings rules, IOC extractors, jobs |
| Engine integration | Vol3 against fixture images when available |
| Frontend unit | Filters, search, transformers, state helpers |
| IPC contract | Golden JSON request/response fixtures |
| E2E (later) | Import → analyze → deep dive smoke on Windows |

Tests grow with features; no “test only at the end.”

---

## 19. Extension points

1. New normalized entity + migration  
2. New Vol3 plugin mapper in volatility adapter  
3. New finding rule module  
4. New optional `Provider`  
5. New Guided workflow composing existing jobs  

---

## 20. Verified environment (2026-09-06)

| Component | Verified version / path |
|-----------|-------------------------|
| Rust | 1.98.1 `stable-x86_64-pc-windows-msvc` |
| VS Build Tools | 17.14.39 — MSVC 14.44.35207 |
| Engine Python | **3.12.10** via `engine/.venv` for development; **bundled embeddable 3.12.10** for release |
| Volatility 3 | **2.28.0** (`volatility3.framework` import + plugin package walk) |
| Tauri | **2.11.5** — debug `dumplyzer.exe` builds |
| Node / npm | 22.18.0 / 10.9.3 |
| WebView2 | Required at runtime. NSIS packs the Evergreen standalone installer (`offlineInstaller`) so a machine without WebView2 and without network can still install |

### Smoke path implemented

```
Frontend invoke("smoke_e2e") / engine_call(method, params)
  → Tauri persistent EngineState (app/desktop/src/lib.rs)
    → packaged: <install>/runtime/python.exe -m memscope_engine
       developer: app/desktop/resources/runtime/python.exe or engine/.venv/Scripts/python.exe -m memscope_engine
      (argv, no shell)
      → NDJSON JSON-RPC
        → SQLite + Volatility 3 APIs
```

User data root: `%LOCALAPPDATA%\Dumplyzer\` (`MEMSCOPE_DATA_DIR` from the desktop shell).

### IPC methods (implemented)

| Method | Purpose |
|--------|---------|
| `health` | Liveness |
| `app.init` | Data dir, logging, DB migrate, start JobManager |
| `app.paths` | Resolved paths |
| `volatility.init` | Vol3 import check |
| `smoke.e2e` | Combined health + vol init |
| `evidence.import` | Hash + metadata row |
| `evidence.list` / `evidence.get` | Evidence read |
| `evidence.analyze_basic` | Queue `basic_triage` job (async) |
| `processes.list` | Normalized processes |
| `process.get` | Deep dive aggregate from SQLite |
| `process.analyze_recommended` | Queue `process_recommended` job |
| `overview.get` | Investigation summary |
| `network.list` / `modules.list` / `findings.list` | Entity lists |
| `network.artifacts` / `network.extract_artifacts` / `network.artifact_runs` | Network artifact harvest from stored analysis |
| `pcap.reconstructions` / `pcap.reconstruct` / `pcap.get` / `pcap.export_flow` | On-demand packet-record reconstruction to `.pcap` |
| `yara.status` / `yara.configure` | Provider availability + settings |
| `yara.scan_artifact` | Queue artifact YARA job |
| `yara.scans_for_artifact` / `yara.scan_get` / `yara.matches_for_evidence` | Results |
| `pe_extraction.status` | Volatility 3 PE reconstruction availability |
| `pe_extraction.run` | Queue PE Extraction against the imported memory dump |
| `pe_extraction.runs` / `pe_extraction.run_get` / `pe_extraction.artifacts` | Extraction runs, counts, extracted PE artifacts |
| `capa.status` / `capa.configure` | Provider availability + EXE path/timeout |
| `capa.scan_artifact` | Queue CAPA against an extracted PE artifact |
| `capa.scans_for_artifact` / `capa.scan_get` | Capability results |
| `floss.status` / `floss.configure` | Provider availability + EXE path/timeout |
| `floss.scan_artifact` | Queue FLOSS against an extracted PE artifact |
| `floss.scans_for_artifact` / `floss.scan_get` | String results |
| `bulk_extractor.status` / `bulk_extractor.configure` | Provider availability + EXE path/timeout (no extra CLI) |
| `bulk_extractor.scan` | Queue evidence-scoped bulk_extractor job against the imported memory image |
| `bulk_extractor.scans` / `bulk_extractor.scan_get` | Scan records, raw output file index, feature summary |
| `plugins.list` | Dynamic Volatility 3 plugin catalog (+ runnable flag for selected evidence) |
| `plugins.get` | Normalized plugin metadata, requirements, OS constraints |
| `plugins.validate` | Validate plugin id + configurable parameters against Evidence |
| `plugins.execute` | Queue `plugin_advanced` job (Volatility Python APIs, not CLI) |
| `plugins.execution_get` | Paginated generic TreeGrid result + structured raw + execution metadata |
| `plugins.executions` | Recent advanced executions for evidence |
| `export.options` | Formats, sections, CSV datasets, report schema version |
| `export.generate` | Queue `export_report` job (HTML / JSON / CSV) |
| `export.list` / `export.get` | Persisted export records for evidence |

### SQLite schema version

**v13** — `network_artifacts` / `network_artifact_runs`, `pcap_reconstructions` / `pcap_flow_results`. **v12** — YARA memory-dump scans (`artifact_id` nullable, `target_kind`). **v11** — `pe_extraction_runs/items`, `capa_scans/capabilities`, `floss_scans/strings`. Prior: v10 `bulk_extractor_*`; v9 `exports`; v8 analysis_cache + plugin_results; v7 mal_unpack tables retained; v6 PE-sieve tables retained; v5 YARA; v4 artifacts/timeline.

### Optional providers

```
providers/
  base.py               # AnalysisProvider protocol
  yara_provider.py      # yara-python adapter (optional import)
  pe_extraction.py      # Volatility 3 PE reconstruction helpers
  capa.py               # bundled capa.exe adapter
  floss.py              # bundled floss.exe adapter
  bulk_extractor.py     # bundled/user-supplied bulk_extractor*.exe adapter
  process_run.py        # shared subprocess helper
```

**YARA**

- Optional: `pip install yara-python` / `pip install -e ".[yara]"`
- Rules directory: `{app_data}/yara_rules/` (`.yar` / `.yara`)
- Scan target: **artifact file paths** under the artifact store and `analysis/pe_extraction/` only
- Job kind: `yara_artifact_scan`
- Results: rule name, namespace, source file, tags, meta, string identifiers + offsets
- No threat scores; no process live-memory scan unless later explicitly added with a real target
- Security: path allow-list for rules, artifact path confinement, no shell, timeouts, cooperative cancel

**PE Extraction**

- Volatility 3 workflow, not an external EXE. Reconstructs PE images from the imported Windows dump using `IMAGE_DOS_HEADER.reconstruct` via `windows.pedump`, plus VAD MZ scans and optional `windows.dumpfiles` for cached PE.
- Candidates: process EXE, loaded DLLs, mapped PE, unlinked/manual-mapped executable MZ regions, and cached FILE_OBJECT PE files.
- Output: `{app_data}/analysis/pe_extraction/<run-id>/` with collision-resistant filenames. Original evidence is fingerprinted and must not change.
- Artifacts are labeled **extracted PE artifact**, never malware. They are never executed.
- Provenance: dump → process/PID → memory region/VAD → extraction method/plugin → stored file SHA-256.
- Job kind: `pe_extraction`

**CAPA**

- Official Mandiant CAPA **v9.4.0** Windows standalone (`capa.exe`). Apache-2.0. Bundled from the GitHub zip with pinned SHA-256.
- Target: extracted PE artifacts only. CLI: `capa.exe -q -j --color never <pe>`.
- Results are capabilities (injection, network, persistence, …), not malware verdicts. Provenance includes `pe_extraction_run_id` when present.
- Job kind: `capa_artifact`. No runtime download.

**FLOSS**

- Official Mandiant FLOSS **v3.1.1** Windows standalone (`floss.exe`). Apache-2.0. Bundled from the GitHub zip with pinned SHA-256.
- Target: extracted PE artifacts only. CLI: `floss.exe -q -j <pe>`.
- Results are static / stack / tight / decoded strings, not malware findings. Provenance includes `pe_extraction_run_id` when present.
- Job kind: `floss_artifact`. No runtime download.

**bulk_extractor**

- Verified project: **[simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)** release **v2.2.0** (`bulk_extractor64.exe` GitHub Actions MinGW cross-compile). Native MSVC Windows builds are not supported upstream.
- License: **GPL-3.0-or-later** for post-NPS project-authored code (`LICENSE.md` at tag v2.2.0). Original NPS material is not U.S. copyright. Dumplyzer **bundles** the official Windows EXE as a **separate process** (aggregation) and ships corresponding source (`bulk_extractor-2.2.0.tar.gz`) plus license texts under `{install}/resources/tools/bulk_extractor/`.
- Role: complementary **raw feature / artifact extraction** on the imported memory image. It does not replace Volatility, PE Extraction, YARA, CAPA, or FLOSS and is not invoked from Volatility Python.
- CLI used: `-V` for version; scan argv `[exe, "-o", <new output dir>, <image>]`. No extra user arguments. The `-o` directory must not already exist.
- Output layout: `{app_data}/analysis/bulk_extractor/<scan-id>/` — original feature files (`email.txt`, `url.txt`, `ip.txt`, …), histograms, `report.xml`, and captured stdout/stderr. Files are not flattened or discarded.
- Normalization: detect present scanners/feature files dynamically. Map known stems (URL, domain, IPv4/IPv6, email, HTTP, telephone, CCN candidates, …) into IOC candidates and informational findings. Unknown `*.txt` feature files are still indexed.
- Provenance: `source=bulk_extractor`, plugin `provider.bulk_extractor`. Findings use severity `info` / confidence `extracted` and state they are not confirmed malicious indicators.
- Timeline: one analysis-time event (`event_kind=bulk_extractor`) when a scan completes. Feature-file timestamps are not treated as evidence timestamps.
- Security: EXE allow-list (known names, MZ header, tools root **or** bundled resources; artifact/analysis roots denied as the EXE), argv arrays, no runtime download, evidence fingerprint before/after, timeout, cooperative cancel. Extracted bytes are never executed.
- Default resolution: bundled `{install}/resources/tools/bulk_extractor/bulk_extractor64.exe`. User-supplied EXE under `{app_data}/tools/` is an override when configured or when the bundle is missing.
- Job kind: `bulk_extractor_scan`
- UI states: unavailable, idle, queued, running, completed_features, completed_no_features, failed, cancelled
- Full Analysis does **not** run bulk_extractor, PE Extraction, YARA, CAPA, or FLOSS

**Plugin Explorer / Advanced execution**

- Discovery: `volatility3.framework.import_files` + `list_plugins` against Volatility **2.28.0** (191 plugins on this machine: windows 99, linux 60, mac 23, framework 9). Import failures are listed and never marked available.
- Metadata model version 1: id, module path, class, description, requirements, types, defaults, optional/required, version, discovery errors
- Configurable requirements rendered in UI: Boolean, Int, String, Choice, List. Framework types (URI, TranslationLayer, SymbolTable, Module, Version, Plugin, LayerList, Class) are engine-resolved
- Evidence image is always `URIRequirement.location_from_file` via `VolatilitySession`; frontend cannot supply arbitrary paths
- Job kind `plugin_advanced`; AnalysisRun + PluginExecution persisted; TreeGrid stored as versioned JSON under `{app_data}/cache/plugin_results/`
- Cache key: evidence SHA-256 + Volatility version + plugin id + canonical parameters + schema version. Hits still create execution rows with `cache_hit=1`
- Cancellation/timeout are cooperative around `construct_plugin` / `run()` — Volatility does not interrupt mid-plugin
- FileHandler writes plugin-emitted files into the artifact store; never executed
- Navigation: PID column → existing `processes` row only when the PID is already stored
- No malware score; no vol.py / stdout scraping

**Export / reporting**

- Formats: **JSON** (`memscope-report-v1`, report schema **v1**), **CSV** (tabular datasets), **HTML** (primary human-readable forensic report). No PDF.
- Job kind `export_report`; records persist in SQLite `exports` (schema **v9**; analysis schema currently **v11**)
- Output is always under `{app_data}/exports/<sanitized-name>_<id>/`. Client destination paths are rejected. Filenames are sanitized. Source evidence is never overwritten. Path traversal and absolute paths are rejected.
- JSON complete export writes `investigation.json` plus `manifest.json`. Selected JSON writes per-section documents that still include metadata and provenance.
- CSV datasets (deterministic columns): processes, network, modules, vad, findings, iocs, timeline, artifacts. Nulls become empty cells; dict/list values are compact JSON. Complete CSV writes one file per dataset.
- HTML is self-contained (inline CSS, no CDN, no JavaScript). Forensic strings are `html.escape`d. Large tables truncate at 400 rows with a pointer to JSON/CSV. Advanced Volatility executions are summarized (plugin, params, status, cache hit/miss, row counts) — raw TreeGrid output is omitted.
- Provenance chain recorded on the report: Evidence → AnalysisRun → PluginExecution → Entity/Artifact → Finding/IOC/Timeline. Timeline `classification` is `observed` or `inferred`; inferred events are labeled and not presented as directly observed.
- Executive summary is factual counts only. **No malware/risk score.**
- Optional provider results (YARA, CAPA, FLOSS, PE Extraction, bulk_extractor) are included when present. CAPA/FLOSS keep `observed` (tool) vs `interpretation` (Dumplyzer). Extracted PE files are labeled extracted artifacts, not malware. bulk_extractor is labeled Source: bulk_extractor / Type: Extracted Artifact / IOC Candidate. Missing providers yield empty sections.
- Limits: HTML 400 rows/section, JSON 20k, CSV 50k. Collection uses existing list DTOs / SQLite, not a raw table dump.
- Security: no shell, no artifact execution, no network fetches from the report, no secrets added by Dumplyzer. Command lines, paths, usernames, and plugin output are treated as untrusted text.

---

## 21. Open decisions

1. **License:** Apache-2.0 for Dumplyzer application source (`LICENSE`). Redistributed Volatility 3 remains VSL; CPython embeddable is PSF; pefile is MIT. See `THIRD_PARTY_NOTICES.md`.  
2. **Engine shipping for release:** official CPython 3.12.10 embeddable + site-packages (AD-043)  
3. **Python engine runtime:** **3.12.10** (decided)  
4. **PE Extraction / CAPA / FLOSS:** PE Extraction is a Volatility 3 workflow. Official CAPA v9.4.0 and FLOSS v3.1.1 Windows standalones are bundled (Apache-2.0). **bulk_extractor:** official v2.2.0 Windows EXE is bundled (GPL-3.0-or-later, separate process + corresponding source). YARA remains an optional Python extra.  
5. **Code signing:** procedure documented in `docs/windows-release.md`. No certificate is in the repository. 0.1.0 artifacts are unsigned.  
6. **Clean-machine VM sign-off:** Offline NSIS path executed 2026-09-20 (**PASS WITH LIMITATIONS**, `docs/clean-machine-validation.md`). Windows 10 and WebView2-absent first install remain untested.  
7. **WebView2:** Evergreen required. NSIS packs the Evergreen standalone (`offlineInstaller`); no Internet is required at install time.  

Ordinary implementation choices proceed without further permission.

---

## 22. Document maintenance

When code lands:

- Update section headings that describe imaginary vs real modules
- Record actual IPC method names
- Record actual SQLite schema version
- Record actual Volatility version tested
- Keep `PROJECT_STATE.md` in sync with phase progress
