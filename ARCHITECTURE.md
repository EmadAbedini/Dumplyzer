# MemScope — Architecture

> Describes the **intended and implemented** architecture. Update when the implementation changes.  
> Last verified: 2026-09-06 — **0.1.0 release validation / hardening (schema v9, report schema v1)**.

**Product:** MemScope — focused desktop workbench for Volatility 3 memory forensics  
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
│  - Optional providers: YARA, PE-sieve, mal_unpack               │
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
│   │   ├── providers/     # yara, pe_sieve, mal_unpack adapters
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

- Database: `%LOCALAPPDATA%\MemScope\memscope.db` on Windows, not inside the memory image and not inside the install directory
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
4. MemScope analysis/schema version  
5. Provider tool version when applicable  

Invalidation on schema/version change. Never serve stale forensic results after relevant invalidation.

Implemented for Advanced Execution in `memscope_engine.cache` (`analysis_cache` table + JSON result files). Cache hits remain visible as distinct PluginExecution rows with `cache_hit`.

---

## 10. Artifact & provenance architecture

```
Memory Image (Evidence)
  → Process
    → Memory Region / Module
      → Extracted Artifact (bytes on disk under controlled artifact store)
        → SHA-256
        → optional YARA matches
        → optional PE-sieve / mal_unpack results
```

- Artifact store path under app data; quarantine semantics (never auto-execute)
- Metadata always in SQLite; bytes always files
- Every artifact row stores extraction method, tool/version, source addresses, timestamps

---

## 11. Plugin system & Advanced Mode

- **Guided Mode:** Recommended Analysis strategies select relevant plugins for the task (e.g. process deep dive) — not “run everything”
- **Advanced Mode / Plugin Explorer (implemented):** dynamic discovery from the installed Volatility 3 registry (`framework.import_files` + `framework.list_plugins`). Analysts inspect metadata, configure simple requirements, and run a `plugin_advanced` JobManager job. Results are a generic TreeGrid table plus structured raw JSON — not `vol.py` stdout.
- Frontend never imports Volatility. Plugin ids resolve only through the discovered registry (no `import_module` of user strings, no shell, no arbitrary Python).
- Framework requirements (URI/image location, `ModuleRequirement` kernel, translation layers, symbol tables, version dependencies) are filled from MemScope Evidence + automagic. The UI edits only configurable Boolean/Int/String/Choice/List parameters.
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

## 13. Optional providers

| Provider | Role | Bundling |
|----------|------|----------|
| YARA | Rule scan on artifacts/process memory where supported | Optional; user rules; `yara-python` or CLI adapter after verification |
| PE-sieve | Suspicious process PE anomaly detection / dump | **User-supplied** official EXE (BSD-2-Clause; not bundled). Live `/pid` only; artifacts unsupported |
| mal_unpack | Dynamic unpacker (hasherezade/mal_unpack 1.0) | **User-supplied** official EXE (BSD-2-Clause; not bundled). Native `/exe` executes the sample; MemScope never invokes that path |

Interface: `Provider` protocol with `availability()`, `run(request) -> ProviderResult`. Core app runs without any of them.

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

- Tauri 2 bundler produces **NSIS** (per-user, no admin) and **MSI** (WiX 3.14.1).
- Engine: **official CPython 3.12.10 Windows embeddable** + `Lib\site-packages` containing `memscope-engine` and pinned Volatility 3 **2.28.0**. Not PyInstaller. Not a first-run venv. Not the developer's global Python.
- Packaged spawn: absolute `runtime\python.exe -m memscope_engine` (argv, no shell, `CREATE_NO_WINDOW`, env scrubbed).
- Developer spawn: `engine\.venv\Scripts\python.exe` when no bundled runtime is present.
- User data is `%LOCALAPPDATA%\MemScope\`, never inside the install directory.
- Do not commit dumps, malware, local DBs, secrets, or generated `resources/runtime` / installer output.
- Optional YARA / PE-sieve / mal_unpack are not bundled and are never auto-downloaded.

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
| Tauri | **2.11.5** — debug `memscope.exe` builds |
| Node / npm | 22.18.0 / 10.9.3 |
| WebView2 | Present on this developer host (Evergreen **152.0.4191.66**). Required at runtime. Installer uses `embedBootstrapper` (can download if missing). A machine without WebView2 and without network is **not** a supported launch environment |

### Smoke path implemented

```
Frontend invoke("smoke_e2e") / engine_call(method, params)
  → Tauri persistent EngineState (app/desktop/src/lib.rs)
    → packaged: <install>/runtime/python.exe -m memscope_engine
       developer: engine/.venv/Scripts/python.exe -m memscope_engine
      (argv, no shell)
      → NDJSON JSON-RPC
        → SQLite + Volatility 3 APIs
```

User data root: `%LOCALAPPDATA%\MemScope\` (`MEMSCOPE_DATA_DIR` from the desktop shell).

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
| `yara.status` / `yara.configure` | Provider availability + settings |
| `yara.scan_artifact` | Queue artifact YARA job |
| `yara.scans_for_artifact` / `yara.scan_get` / `yara.matches_for_evidence` | Results |
| `pe_sieve.status` / `pe_sieve.configure` | Provider availability + EXE path/timeout |
| `pe_sieve.scan_artifact` | Queue artifact PE-sieve workflow (records unsupported target; does not invoke the EXE) |
| `pe_sieve.scans_for_artifact` / `pe_sieve.scan_get` | Results + generated output artifacts |
| `mal_unpack.status` / `mal_unpack.configure` | Provider availability + EXE path/timeout (no extra CLI) |
| `mal_unpack.unpack_artifact` | Queue artifact mal_unpack workflow (records unsupported target; does not invoke the EXE) |
| `mal_unpack.scans_for_artifact` / `mal_unpack.scan_get` | Results + generated output artifacts |
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

**v9** — `exports` table (format, scope, sections, output paths, report schema version). Prior: v8 analysis_cache + plugin_results; v7 mal_unpack; v6 PE-sieve; v5 YARA; v4 artifacts/timeline.

### Optional providers

```
providers/
  base.py          # AnalysisProvider protocol
  yara_provider.py # yara-python adapter (optional import)
  pe_sieve.py      # user-supplied pe-sieve*.exe adapter (optional)
  mal_unpack.py    # user-supplied mal_unpack*.exe adapter (optional)
```

**YARA**

- Optional: `pip install yara-python` / `pip install -e ".[yara]"`
- Rules directory: `{app_data}/yara_rules/` (`.yar` / `.yara`)
- Scan target: **artifact file paths** under controlled artifact store only
- Job kind: `yara_artifact_scan`
- Results: rule name, namespace, source file, tags, meta, string identifiers + offsets
- No threat scores; no process live-memory scan unless later explicitly added with a real target
- Security: path allow-list for rules, artifact path confinement, no shell, timeouts, cooperative cancel

**PE-sieve**

- Verified interface: **hasherezade/pe-sieve v0.4.1.1** (`pe_sieve_ver_short.h`, `params.h`, `main.cpp`, `pe_sieve_return_codes.h`, `ResultsDumper`, wiki JSON reports)
- License: **BSD-2-Clause** (Copyright (c) 2017-2025, @hasherezade). Redistribution of source and binary is permitted with copyright notice. **MemScope does not bundle the EXE**; the user copies an official release binary into `{app_data}/tools/` (or `tools/pe-sieve/`).
- Required CLI: `/pid <live process id>` — there is **no file/artifact scan mode**
- Optional args used by MemScope when invoking: `/dir <controlled tmp>`, `/json`, `/quiet`; version probe: `/version`
- Default output: `{/dir}/process_<pid>/scan_report.json`, `dump_report.json`, dumped modules, optional `error_report.json`
- Exit codes (observed, not a MemScope score): `-1` error, `0` info/help, `1` not detected, `2` detected
- MemScope artifact workflow: **unsupported target**. Dump PIDs are not live PIDs; artifacts are never executed; the UI does not offer a live `/pid` scan from the artifact panel
- Provider `scan_live_process` exists for the real PE-sieve interface (tests use a mock runner). It is not wired as an evidence/artifact action
- Generated dumps (when a live scan result is persisted) become artifacts with SHA-256, `parent_artifact_id`, tool metadata, and `pe_sieve_outputs` links
- Security: EXE allow-list (known names, MZ header, tools root only; artifact store denied), argv arrays, no extra user CLI, controlled tmp `/dir`, timeout, cooperative cancel, logs sanitized
- Job kind: `pe_sieve_artifact_scan`
- UI states: unavailable, unsupported target, queued, running, completed/no findings, completed/indicators, failed, cancelled
- No malware/threat score

**mal_unpack**

- Verified project: **[hasherezade/mal_unpack](https://github.com/hasherezade/mal_unpack)** release tag **1.0** (`MALUNP_VERSION_STR "1.0.0.1"` in `mal_unpack_ver.h`; CLI in `params.h` / `main.cpp`)
- Related projects not integrated: MalUnpackCompanion (kernel driver), `mal_unpack_py`
- License: **BSD-2-Clause** (Copyright (c) 2018-2025, hasherezade). Redistribution of source and binary is permitted with copyright notice. **MemScope does not bundle the EXE**; the user copies an official 1.0 zip (`mal_unpack64.zip` / `mal_unpack32.zip`) into `{app_data}/tools/` (or `tools/mal_unpack/`). Allow-listed names: `mal_unpack.exe`, `mal_unpack64.exe`, `mal_unpack32.exe`
- Real interface (required): `/exe <path_to_the_malware>` and `/timeout <ms>`. Optional output root: `/dir`. Version: `/version` prints `MalUnpack: v.{version}`
- Native behavior: **creates a live process from `/exe`**, waits, dumps implants via PE-sieve, then kills the process. Upstream: use only on a VM. MemScope **never** passes a forensic artifact as `/exe` and never sets `/cmd`
- Exit codes (same as PE-sieve, observed not scored): `-1` error, `0` info, `1` not detected, `2` detected
- Output layout: `{/dir}/{exe_basename}.out/scan_{unix_timestamp}/` with PE-sieve `process_<pid>/scan_report.json`, `dump_report.json`, optional `error_report.json`; `unpack.log` in CWD
- MemScope-safe targets: **none**. Native kind `executable_file` is unsafe here. Artifacts, live PIDs, VAD regions, and memory dumps are unsupported
- Job `mal_unpack_artifact` records `unsupported_target` or `unavailable`; `run_unpack(..., confirm_sample_execution=False)` is the default and raises `mal_unpack_execution_forbidden`. Tests may confirm only with a mock runner and must refuse artifact-store paths as `/exe`
- If dumps are persisted (test/mock ingest): first-class artifacts with SHA-256, `parent_artifact_id`, `extraction_method=mal_unpack_dump`, `mal_unpack_outputs` links. Output is never executed
- Result model splits `observed` (tool) vs `interpretation` (MemScope). No malware score
- Security: EXE allow-list (known names, MZ header, tools root only; artifact store denied), argv arrays, no extra user CLI, `/cmd` never passed, controlled tmp `/dir`, timeout, cooperative cancel, logs sanitized
- Job kind: `mal_unpack_artifact`
- UI states: unavailable, unsupported target, queued, running, completed/no output, completed/output generated, failed, cancelled
- Unpack action in Artifacts UI is disabled for all investigation targets

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
- Job kind `export_report`; records persist in SQLite `exports` (schema **v9**)
- Output is always under `{app_data}/exports/<sanitized-name>_<id>/`. Client destination paths are rejected. Filenames are sanitized. Source evidence is never overwritten. Path traversal and absolute paths are rejected.
- JSON complete export writes `investigation.json` plus `manifest.json`. Selected JSON writes per-section documents that still include metadata and provenance.
- CSV datasets (deterministic columns): processes, network, modules, vad, findings, iocs, timeline, artifacts. Nulls become empty cells; dict/list values are compact JSON. Complete CSV writes one file per dataset.
- HTML is self-contained (inline CSS, no CDN, no JavaScript). Forensic strings are `html.escape`d. Large tables truncate at 400 rows with a pointer to JSON/CSV. Advanced Volatility executions are summarized (plugin, params, status, cache hit/miss, row counts) — raw TreeGrid output is omitted.
- Provenance chain recorded on the report: Evidence → AnalysisRun → PluginExecution → Entity/Artifact → Finding/IOC/Timeline. Timeline `classification` is `observed` or `inferred`; inferred events are labeled and not presented as directly observed.
- Executive summary is factual counts only. **No malware/risk score.**
- Optional provider results (YARA, PE-sieve, mal_unpack) are included when present; PE-sieve/mal_unpack keep `observed` (tool) vs `interpretation` (MemScope). Missing providers yield empty sections.
- Limits: HTML 400 rows/section, JSON 20k, CSV 50k. Collection uses existing list DTOs / SQLite, not a raw table dump.
- Security: no shell, no artifact execution, no network fetches from the report, no secrets added by MemScope. Command lines, paths, usernames, and plugin output are treated as untrusted text.

---

## 21. Open decisions

1. **License:** Apache-2.0 for MemScope application source (`LICENSE`). Redistributed Volatility 3 remains VSL; CPython embeddable is PSF; pefile is MIT. See `THIRD_PARTY_NOTICES.md`.  
2. **Engine shipping for release:** official CPython 3.12.10 embeddable + site-packages (AD-043)  
3. **Python engine runtime:** **3.12.10** (decided)  
4. **PE-sieve / mal_unpack:** user-supplied official EXEs (not bundled). mal_unpack 1.0 executes `/exe`; MemScope will not invoke it against investigation targets.  
5. **Code signing:** procedure documented in `docs/windows-release.md`. No certificate is in the repository. 0.1.0 artifacts are unsigned.  
6. **Clean-machine VM sign-off:** remaining public-release blocker (`docs/clean-machine-validation.md`).  
7. **WebView2:** Evergreen required. Offline machines that do not already have WebView2 are unsupported with the current bootstrapper packaging.  

Ordinary implementation choices proceed without further permission.

---

## 22. Document maintenance

When code lands:

- Update section headings that describe imaginary vs real modules
- Record actual IPC method names
- Record actual SQLite schema version
- Record actual Volatility version tested
- Keep `PROJECT_STATE.md` in sync with phase progress
