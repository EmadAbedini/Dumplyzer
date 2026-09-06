# MemScope — Project State

> Single source of truth for project continuity. Update after every meaningful milestone.

**Last updated:** 2026-09-06  
**Version target:** 0.1.0-dev  
**Current phase:** Phase 7 — Export / reporting done

---

## Current Status

**Export / reporting** is implemented on top of existing MemScope evidence (findings, timeline, IOCs, artifacts, provenance, processes, network, VAD, YARA, PE-sieve, mal_unpack, Advanced Volatility).

- Formats: JSON (`memscope-report-v1`), CSV tabular datasets, self-contained HTML forensic report
- Report schema **v1**; analysis SQLite schema **v9** (`exports` table)
- Job kind `export_report` with queued / running / completed / failed / cancelled
- Files written only under `{app_data}/exports/`; evidence is never overwritten
- HTML truncates large tables; Advanced plugin TreeGrid is summarized, not dumped

Plugin Explorer and optional providers are unchanged.

---

## Completed

- Phases 0–4 forensic core  
- Optional YARA / PE-sieve / mal_unpack providers  
- Plugin Explorer + Advanced Volatility execution (schema v8)  
- [x] JSON / CSV / HTML investigation export  
- [x] Forensic HTML report (metadata, summary, findings, processes, network, modules, VAD, timeline, IOCs, artifacts, malware analysis, Advanced Volatility)  
- [x] Provenance chain + observed vs inferred timeline  
- [x] Export UI (complete vs selected sections, generation states, cancel)  
- [x] Safe output paths, filename sanitization, HTML escaping  

---

## In Progress / Next

1. Release packaging (MSI deferred)

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
| HTML report row cap | 400 rows per large section; remainder is in JSON/CSV |
| JSON/CSV row caps | JSON 20000 / CSV 50000 per section; not a full unbounded dump |
| No PDF export | Intentionally omitted |
| Export destination | Engine-chosen under app data `exports/` only; client paths rejected |
| HTML is static | No JavaScript; open as a file. Command lines/paths are escaped text, not executed |
| No desktop UI browser pass | Export view verified via TypeScript build + engine IPC tests |

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
| pytest | **105 passed, 2 skipped** (skips = real PE-sieve and mal_unpack EXEs not installed) |
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
| AD-039 | Export formats are JSON, CSV, and HTML only; no PDF until a dedicated architecture exists | Accepted |
| AD-040 | Exports write only under `{app_data}/exports/`; client destination paths and traversal are rejected | Accepted |
| AD-041 | Report schema `memscope-report-v1` is independent of SQLite schema version | Accepted |
| AD-042 | HTML reports omit raw Advanced plugin TreeGrid; summaries + structured JSON/CSV hold detail | Accepted |
