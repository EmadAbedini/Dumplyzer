# MemScope — Project State

> Single source of truth for project continuity. Update after every meaningful milestone.

**Last updated:** 2026-09-04  
**Version target:** 0.1.0-dev  
**Current phase:** Phase 2 — Volatility Core (in progress; import + basic triage + process explorer landed)

---

## Current Status

Phase 1 foundation is complete. Phase 2 first forensic workflow is implemented end-to-end in code:

**Import memory → SHA-256 → SQLite evidence → Volatility 3 `windows.info` + `windows.pslist` (API) → normalize processes → Overview + Process Explorer**

Verified without a real dump:

- Import + hashing + DB persistence (RPC + unit tests)
- Junk image analyze returns structured `volatility_unsatisfied` AppError (real Vol3 `construct_plugin` path)
- Workstation shell builds; cargo/frontend/pytest green

Full process listing against a real Windows memory image still needs a sample dump on this machine.

---

## Completed

### Phase 0–1 environment
- [x] Toolchains (Rust 1.98.1 MSVC, VS Build Tools 17.14.39, Python 3.12.10 venv, Vol3 2.28.0)
- [x] Smoke Tauri → engine → Vol3 init

### Phase 1 foundation
- [x] SQLite schema v1 + migrations (`evidence`, `analysis_runs`, `plugin_executions`, `processes`, `jobs`)
- [x] App data paths (`LOCALAPPDATA/MemScope` or `MEMSCOPE_DATA_DIR`)
- [x] Structured JSON logging (`engine.jsonl`, channels app/analysis/tool)
- [x] AppError + RPC error propagation (code, message, details, suggestion)
- [x] Persistent engine process from Tauri + `engine_call` / `get_app_paths`
- [x] Workstation shell: Tailwind v4 + shadcn-style primitives, dark compact layout
- [x] Navigation: Overview, Processes, Network, Modules, Memory, Findings, IOCs, Timeline, Artifacts, Jobs, Plugins, Settings
- [x] Frontend typed contracts + error parsing

### Phase 2 (first slice)
- [x] Evidence import (path validate, size, streaming SHA-256, DB upsert by hash)
- [x] VolatilitySession via official APIs (`URIRequirement.location_from_file`, `automagic`, `plugins.construct_plugin`, TreeGrid.populate)
- [x] `windows.info` → OS/arch/symbol status normalization
- [x] `windows.pslist` → normalized Process rows persisted
- [x] Overview + Process Explorer UI wired to engine
- [x] File open dialog (`tauri-plugin-dialog`)

---

## In Progress

- Phase 2 remainder: network/modules via Vol3, richer process fields (cmdline/dlllist), real dump validation
- Job manager UI (table exists in schema; not fully used yet)

---

## Known Issues

| Issue | Severity | Notes |
|-------|----------|-------|
| No real memory image on machine | Info | Process explorer empty until analyst imports a dump; junk file correctly fails Vol3 |
| MSI/WiX timeout | Low | Deferred; debug exe builds |
| Engine RPC is synchronous under one lock | Medium | Long analysis blocks other calls; acceptable for now |
| Symbol download may need network | Info | Vol3 automagic may fetch symbols; offline symbol path TBD |
| `child` process kill on timeout not fully wired | Low | Field retained for future timeout kill |

---

## Technical Debt

- shadcn components hand-rolled (Button/Input/Badge only)
- No virtualized process table yet
- Jobs table unused by workflows
- Analysis runs not cancellable mid-plugin
- Frontend filter is client-side only

---

## Architecture Decisions

| ID | Decision | Status |
|----|----------|--------|
| AD-003 | Engine Python 3.12 venv | Accepted |
| AD-004 | Volatility 3 2.28.0 | Accepted |
| AD-011 | Persistent engine child + NDJSON multiplex | Accepted |
| AD-012 | Schema v1 SQLite under app data dir | Accepted |
| AD-013 | Basic triage = `windows.info` + `windows.pslist` via APIs | Accepted |
| AD-014 | TreeGrid → JSON rows then normalize (not CLI text) | Accepted |

---

## Dependencies (key)

| Component | Version |
|-----------|---------|
| volatility3 | 2.28.0 |
| tauri | 2.11.5 |
| tauri-plugin-dialog | 2.7.x |
| React | 19.2.x |
| Tailwind | 4.3.x |
| Python engine | 3.12.10 |

---

## Build/Test Status

| Check | Result |
|-------|--------|
| `pytest tests/engine` | **6 passed** |
| `cargo test` | **2 passed** |
| `npm run build` (frontend) | **PASS** |
| `cargo build` (desktop) | **PASS** |
| RPC import + analyze junk dump | **PASS** (import ok; analyze → `volatility_unsatisfied`) |

---

## Current Phase

**Phase 2 — Volatility Core** (import/triage/process explorer done; expand plugins next)

---

## Next Steps

1. Obtain/use a real Windows memory image; verify process list end-to-end
2. Add `windows.cmdline` / `dlllist` / `netscan` normalization + UI pages
3. Job manager for long runs + cancellation
4. Process deep dive view
5. Analysis cache keys
6. Continue Phase 3 analyst UX polish

---

## Important Discoveries

1. Vol3 2.28 plugin construction: set `automagic.LayerStacker.single_location` from `URIRequirement.location_from_file`, `choose_automagic`, `stacker.choose_os_stackers`, then `plugins.construct_plugin`.
2. TreeGrid consumption: `grid.populate(visitor, None)` (not CLI renderer).
3. PsList columns: PID, PPID, ImageFileName, Offset(V/P), Threads, Handles, SessionId, Wow64, CreateTime, ExitTime, File output.
4. Unsatisfied requirements surface as actionable `AppError` with `volatility_unsatisfied`.

---

## Unfinished Work

- Network/modules/memory/findings/IOC/timeline/artifacts features
- Advanced plugin explorer
- YARA/PE-sieve/mal_unpack
- Packaging/release
- LICENSE and full docs set
