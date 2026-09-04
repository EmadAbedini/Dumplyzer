# MemScope — Project State

> Single source of truth for project continuity. Update after every meaningful milestone.

**Last updated:** 2026-09-04  
**Version target:** 0.1.0-dev  
**Current phase:** Phase 3 — Analyst UX (Deep Dive, jobs, search, IOCs landed)

---

## Current Status

Process Deep Dive, Recommended Analysis, Global Search, and IOC extraction are implemented against normalized SQLite data and real Volatility 3 APIs (when jobs run on a real dump).

Workflow:

**Process Explorer → select process → Deep Dive → Analyze process (job)**  
→ `windows.cmdline` / `dlllist` / `netscan` (PID filter) / `handles` / `vadinfo`  
→ normalized modules, network, handles, VAD, transparent findings  
→ Jobs view (queued/running/completed/failed/cancelled)

No synthetic forensic rows are fabricated. Empty states are explicit until a real dump is analyzed.

---

## Completed

### Prior
- Phase 0–1 foundation, Phase 2 import + basic triage + process list

### This milestone
- [x] SQLite schema **v2** (modules, network_connections, handle_entries, memory_regions, findings, job/process fields)
- [x] Thread-safe DB + **JobManager** (background worker, cancel flag)
- [x] Jobs: `basic_triage`, `process_recommended`
- [x] IPC: `jobs.*`, `process.get`, `process.analyze_recommended`, `network.list`, `modules.list`, `findings.list`
- [x] Process Deep Dive UI (tabs: overview, cmdline, family, modules, network, handles, memory, findings)
- [x] Recommended analysis strategy documented on AnalysisRun (`strategy_json`)
- [x] Targeted plugins: cmdline/dlllist/handles/vadinfo with `pid` list; netscan image-wide then PID filter
- [x] Heuristic findings (encoded PowerShell, VAD W+X / private executable) — explainable only
- [x] Jobs UI + polling; basic triage is async (does not freeze UI on submit)
- [x] Network / Modules / Findings investigation views (data-backed empty states)
- [x] Global search over normalized entities
- [x] IOC extraction + list + JSON/CSV export (schema v3 `iocs`)
- [x] Search / IOCs UI

---

## In Progress

- Memory/VAD global explorer
- Timeline
- Artifact extraction / provenance

---

## Known Issues

| Issue | Severity | Notes |
|-------|----------|-------|
| No real memory image on machine | Info | Deep dive / search data empty until real dump + jobs complete |
| netscan is image-wide | Info | By Vol3 API design; we filter to selected PID when persisting |
| Job cancel cooperative only | Medium | Between plugins; cannot abort inside Vol3 plugin mid-run |
| IOC domain regex conservative | Low | May miss uncommon TLDs; avoids some noise |
| Handles capped at 5000 in deep dive query | Low | Pagination later |
| Single worker queue | Low | One analysis at a time in engine process |

---

## Technical Debt

- Username still not populated (needs getsids/other plugin later)
- Artifacts extraction not started
- Engine RPC still one-request-at-a-time on stdio while jobs run in parallel thread (reads OK)

---

## Architecture Decisions

| ID | Decision | Status |
|----|----------|--------|
| AD-015 | Schema v2 for process-related entities | Accepted |
| AD-016 | Background JobManager for triage + process analysis | Accepted |
| AD-017 | process_recommended strategy: cmdline, dlllist, netscan, handles, vadinfo | Accepted |
| AD-018 | Transparent findings only (no risk scores) | Accepted |

---

## Build/Test Status

| Check | Result |
|-------|--------|
| pytest | **12 passed** |
| cargo test | **2 passed** |
| frontend build | **PASS** |
| cargo build | **PASS** |

---

## Next Steps

1. Memory/VAD global explorer (from stored regions + optional job)
2. Lightweight timeline from process create times + findings
3. Artifact dump/provenance for suspicious VADs
4. Username enrichment plugin when selected  

---

## Important Discoveries

1. CmdLine/DllList/Handles/VadInfo accept `ListRequirement pid`.  
2. NetScan has no PID requirement — filter after TreeGrid normalize.  
3. Parallel Rust IPC tests must use unique `MEMSCOPE_DATA_DIR` (shared PID temp dir raced).
