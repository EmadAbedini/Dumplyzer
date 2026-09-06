# MemScope — Architecture

> Describes the **intended and implemented** architecture. Update when the implementation changes.  
> Last verified: 2026-09-06 — **mal_unpack optional provider (schema v7) implemented**.

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

- Investigation UX: Import, Overview, Processes, Deep Dive, Network, Modules, Memory/VAD, Findings, IOC Search, Timeline, Artifacts, Jobs, Plugin Explorer, Advanced execution
- Local UI state + server/engine state via Tauri commands and event subscriptions
- Tables, filters, search, virtualization for large result sets
- No Volatility imports; no shelling out to `vol`
- Dark-mode-first, compact forensic workstation layout

### 2.2 Tauri desktop (`app/desktop`)

- Native window and application lifecycle
- Spawn/monitor/restart Python engine sidecar with explicit argv (no shell)
- Bridge: frontend commands → engine JSON-RPC; engine notifications → frontend events
- Safe file pickers; path canonicalization; evidence path allowlisting concepts
- App data directories (config, logs, SQLite, artifact store, cache)
- Packaging entrypoint (Windows x64)

### 2.3 Python engine (`engine`)

- All forensic analysis and Volatility interaction
- SQLite persistence of metadata and normalized results
- Job queue (queued / running / completed / failed / cancelled)
- Analysis cache keyed by evidence hash + tool versions + params + schema version
- Findings heuristics, IOC extraction, timeline assembly, artifact provenance
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

- Engine started as child process: `python -m memscope_engine.server` (or equivalent entrypoint)
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

- Location: under app data dir (e.g. `%APPDATA%\MemScope\` on Windows), not inside the memory image
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
- **Advanced Mode / Plugin Explorer:** discover plugins, show descriptions/params/availability, execute, view structured + optional raw/transparency payload
- Frontend still only sees MemScope DTOs; Vol3 details appear as transparency metadata

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

- Tauri bundler → installable artifact (MSI and/or NSIS)
- Engine: ship via **bundled embedded Python** or **first-run venv bootstrap** — decision finalized in Phase 1/7 after size and Volatility packaging trials
- Do not commit dumps, malware, local DBs, secrets, or build outputs
- GitHub Actions: lint, typecheck, tests, release artifacts + checksums

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
| Engine Python | **3.12.10** via `engine/.venv` (host may also have 3.13.7) |
| Volatility 3 | **2.28.0** (`volatility3.framework` import + plugin package walk) |
| Tauri | **2.11.5** — debug `memscope.exe` builds |
| Node / npm | 22.18.0 / 10.9.3 |
| WebView2 | Present |

### Smoke path implemented

```
Frontend invoke("smoke_e2e") / engine_call(method, params)
  → Tauri persistent EngineState (app/desktop/src/lib.rs)
    → engine/.venv/Scripts/python.exe -m memscope_engine  (argv, no shell)
      → NDJSON JSON-RPC
        → SQLite + Volatility 3 APIs
```

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

### SQLite schema version

**v7** — `mal_unpack_scans`, `mal_unpack_outputs`; prior v6 PE-sieve tables + `artifacts.parent_artifact_id`; v5 YARA; v4 artifacts/timeline.

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

---

## 21. Open decisions

1. **License:** Apache-2.0 proposed for app code  
2. **Engine shipping for release:** embedded Python vs first-run venv (Phase 7)  
3. **Python engine runtime:** **3.12.x venv** (decided)  
4. **PE-sieve / mal_unpack:** user-supplied official EXEs (BSD-2-Clause; not bundled). mal_unpack 1.0 executes `/exe`; MemScope will not invoke it against investigation targets.  

Ordinary implementation choices proceed without further permission.

---

## 22. Document maintenance

When code lands:

- Update section headings that describe imaginary vs real modules
- Record actual IPC method names
- Record actual SQLite schema version
- Record actual Volatility version tested
- Keep `PROJECT_STATE.md` in sync with phase progress
