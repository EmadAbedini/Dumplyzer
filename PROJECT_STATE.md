# MemScope — Project State

> Single source of truth for project continuity. Update after every meaningful milestone.

**Last updated:** 2026-09-04  
**Version target:** 0.1.0-dev  
**Current phase:** Phase 5 — Optional malware providers (YARA done)

---

## Current Status

**YARA** is integrated as an optional provider:

- Detects `yara-python` (this machine: **4.5.4**)
- Rules under `%LOCALAPPDATA%\MemScope\yara_rules` (or `MEMSCOPE_DATA_DIR/yara_rules`)
- Job `yara_artifact_scan` scans **extracted artifacts only**
- Results in `yara_scans` / `yara_matches` (schema **v5**) with full provenance links
- Artifacts UI: availability, rule count, Scan with YARA, match details
- Distinguishes: unavailable / no matches / failure / matches

Core MemScope works without YARA (`pip install -e ".[yara]"` optional).

---

## Completed

- Phases 0–4 forensic core  
- [x] Provider protocol + YaraProvider  
- [x] Schema v5 YARA tables + app_settings  
- [x] Job + AnalysisRun + PluginExecution linkage  
- [x] Artifact UI YARA panel  
- [x] Tests (availability, compile fail, match/nomatch, path deny, job, unavailable mock)

---

## In Progress / Next

1. PE-sieve provider (user-supplied binary; license check)  
2. mal_unpack provider  
3. Plugin Explorer / Advanced Volatility  
4. Export/reporting  
5. Release packaging (MSI deferred)

---

## Known Issues / Limitations

| Issue | Notes |
|-------|--------|
| YARA cancel is cooperative | Cannot kill native `yara.match` mid-call; timeout bounds runtime |
| Process not scanned live | Only extracted artifact files |
| Rule paths restricted | Must live under configured yara_rules roots |
| No threat score | By design |

---

## YARA on this machine

| Item | Value |
|------|--------|
| Available | **Yes** |
| Package | yara-python **4.5.4** |
| Binding | yara-python |
| CLI `yara` | Not on PATH (not required) |

---

## Build/Test Status

| Check | Result |
|-------|--------|
| pytest | **23 passed** |
| cargo test | **2 passed** |
| frontend build | **PASS** |
| cargo build | **PASS** |

---

## Architecture Decisions

| ID | Decision | Status |
|----|----------|--------|
| AD-023 | YARA optional via yara-python | Accepted |
| AD-024 | Scan targets = artifact files only | Accepted |
| AD-025 | Provider protocol for future PE-sieve/mal_unpack | Accepted |
| AD-026 | Schema v5 yara_scans/matches | Accepted |
