# MemScope — Project State

> Single source of truth for project continuity. Update after every meaningful milestone.

**Last updated:** 2026-09-04  
**Version target:** 0.1.0-dev  
**Current phase:** Phase 4 — Forensic features (Memory/VAD, Timeline, Artifacts)

---

## Current Status

Memory/VAD explorer, forensic timeline, and first-class artifact provenance are implemented on schema **v4**.

- VAD list with indicators (W+X, private executable unbacked, etc.) — **not** malice labels  
- Jobs: `vad_scan`, `vad_extract` (real `VadInfo.vad_dump` API)  
- Timeline rebuild from normalized tables; **observed** vs **inferred**  
- Artifacts: controlled store, SHA-256, PE sniff, provenance chain Evidence→Process→Region→Artifact  

No synthetic forensic evidence. Empty states until a real dump is analyzed.

---

## Completed

- Phase 0–3: foundation, triage, deep dive, jobs, search, IOCs  
- [x] Schema v4: artifacts, timeline_events, region size/indicators  
- [x] Memory explorer UI + scan/extract jobs  
- [x] Timeline build/list UI  
- [x] Artifacts list + provenance detail  
- [x] Safe artifact paths + hashing  
- [x] Tests (16 pytest, 2 cargo)

---

## In Progress

- Optional providers: YARA, PE-sieve, mal_unpack  
- Plugin Explorer / Advanced Volatility mode  
- Export/reporting  
- Windows release engineering (MSI deferred)

---

## Known Issues

| Issue | Severity | Notes |
|-------|----------|-------|
| No real memory image | Info | Extract/scan need a real dump |
| VAD size = end-start | Low | Approximate if end exclusive semantics differ |
| Single job worker | Low | One analysis at a time |
| MSI/WiX | Deferred | |

---

## Build/Test Status

| Check | Result |
|-------|--------|
| pytest | **16 passed** |
| cargo test | **2 passed** |
| frontend build | **PASS** |
| cargo build | **PASS** |

---

## Next Steps

1. YARA provider (optional, user rules)  
2. PE-sieve / mal_unpack adapters (user-supplied binaries)  
3. Plugin Explorer + advanced plugin execution  
4. Reporting/export  
5. Release packaging later  

---

## Architecture Decisions

| ID | Decision | Status |
|----|----------|--------|
| AD-019 | Schema v4 artifacts + timeline | Accepted |
| AD-020 | VAD extract via `VadInfo.vad_dump` + controlled FileHandler | Accepted |
| AD-021 | Timeline classification observed vs inferred | Accepted |
| AD-022 | Never auto-execute artifacts | Accepted |
