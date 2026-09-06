# MemScope — Project State

> Single source of truth for project continuity. Update after every meaningful milestone.

**Last updated:** 2026-09-06  
**Version target:** 0.1.0-dev  
**Current phase:** Phase 6 — Plugin Explorer / Advanced Volatility execution done

---

## Current Status

**Plugin Explorer** is implemented as generic Volatility 3 execution (Python APIs, not `vol.py`).

- Installed Volatility **2.28.0**: **191** discovered plugins (windows 99, linux 60, mac 23, framework 9)
- 6 module import failures are recorded and never shown as available
- Advanced Execution is a real `plugin_advanced` JobManager job bound to imported Evidence
- Results are a generic TreeGrid table + structured raw JSON; cache hits are labeled
- Dedicated views (Processes, Memory, …) remain the guided workflow

Optional providers (YARA, PE-sieve, mal_unpack) are unchanged.

---

## Completed

- Phases 0–4 forensic core  
- Optional YARA / PE-sieve / mal_unpack providers  
- [x] Dynamic Volatility plugin discovery + normalized metadata  
- [x] Requirement classification (configurable vs framework)  
- [x] Advanced execution job + AnalysisRun / PluginExecution  
- [x] Generic TreeGrid result model + cache (schema **v8**)  
- [x] Plugin Explorer UI (search, categories, parameters, job state, results, raw)

---

## In Progress / Next

1. Export/reporting  
2. Release packaging (MSI deferred)

---

## Known Issues / Limitations

| Issue | Notes |
|-------|--------|
| YARA cancel is cooperative | Cannot kill native `yara.match` mid-call; timeout bounds runtime |
| Process not scanned live by YARA | Only extracted artifact files |
| Rule paths restricted | Must live under configured yara_rules roots |
| No threat score | By design |
| PE-sieve cannot scan artifacts | Upstream tool requires `/pid` of a live process |
| Dump PID ≠ live PID | MemScope will not map memory-image PIDs to workstation processes |
| PE-sieve not bundled | User supplies official v0.4.1.1 EXE under tools allow-list |
| mal_unpack executes `/exe` | MemScope will not invoke it against investigation targets |
| Advanced plugin cancel is cooperative | Volatility `run()` is not interruptible mid-plugin; UI does not claim instant stop |
| Dummy/unanalyzed images | Automagic often raises `volatility_unsatisfied` until symbols/OS resolve |
| Plugin Explorer is generic | Does not replace dedicated process/memory views |
| Result preview cap | UI/IPC preview is 500 rows; full table remains in the cache file |
| 6 Vol3 import failures | Discovery records them; those modules are not listed as available |

---

## Volatility on this machine

| Item | Value |
|------|-------|
| Version | **2.28.0** |
| Discovered plugins | **191** |
| Categories | windows 99, linux 60, mac 23, framework 9 |
| Import failures | 6 (not marked available) |

---

## Build/Test Status

| Check | Result |
|-------|--------|
| pytest | **88 passed, 2 skipped** (skips = real PE-sieve and mal_unpack EXEs not installed) |
| cargo test | **Not run** — `cargo` is not installed on this machine |
| frontend build | **PASS** (`tsc --noEmit && vite build`) |
| cargo build | **Not run** — `cargo` is not installed on this machine |

---

## Architecture Decisions

| ID | Decision | Status |
|----|----------|--------|
| AD-023–AD-032 | Prior YARA / PE-sieve / mal_unpack decisions | Accepted |
| AD-033 | Plugin Explorer uses Volatility 3 Python APIs only (`construct_plugin` / TreeGrid), never vol.py stdout | Accepted |
| AD-034 | Plugin ids resolve only via `framework.list_plugins`; no user `import_module` | Accepted |
| AD-035 | Evidence URI/kernel/layers are engine-filled; UI edits only simple configurable requirements | Accepted |
| AD-036 | Schema v8 analysis_cache + plugin_results; large TreeGrids live as JSON files under app cache | Accepted |
| AD-037 | Cache key = evidence SHA-256 + Vol version + plugin id + canonical params + schema version | Accepted |
| AD-038 | PID→process navigation only when a process row already exists for that PID | Accepted |
