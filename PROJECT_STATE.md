# MemScope — Project State

> Single source of truth for project continuity. Update after every meaningful milestone.

**Last updated:** 2026-09-06  
**Version target:** 0.1.0-dev  
**Current phase:** Phase 5 — Optional malware providers (YARA + PE-sieve done)

---

## Current Status

**PE-sieve** is integrated as an optional, user-supplied provider:

- Verified interface: **hasherezade/pe-sieve v0.4.1.1** (`/pid`, `/dir`, `/json`, `/quiet`, `/version`)
- License: **BSD-2-Clause** — redistribution permitted with copyright notice; **EXE is not bundled**
- Place `pe-sieve64.exe` (or `pe-sieve.exe` / `pe-sieve32.exe`) under `%LOCALAPPDATA%\MemScope\tools\` (or `tools\pe-sieve\`)
- PE-sieve scans **live Windows processes only**. Extracted artifacts and memory-image PIDs are **unsupported targets**
- Job `pe_sieve_artifact_scan` records that limitation (does not invoke the EXE against dump PIDs or files)
- Results in `pe_sieve_scans` / `pe_sieve_outputs` (schema **v6**) with artifact provenance when dumps are ingested
- Artifacts UI: availability, version, EXE path, supported target types, disabled Scan control, explicit UI states
- Distinguishes observed PE-sieve JSON from MemScope interpretation; **no malware score**

**YARA** remains as previously delivered (`yara-python` optional, artifact scans).

Core MemScope works without PE-sieve. This machine: **PE-sieve EXE not installed**.

---

## Completed

- Phases 0–4 forensic core  
- [x] Provider protocol + YaraProvider  
- [x] Schema v5 YARA tables + app_settings  
- [x] Job + AnalysisRun + PluginExecution linkage  
- [x] Artifact UI YARA panel  
- [x] Tests (availability, compile fail, match/nomatch, path deny, job, unavailable mock)
- [x] PeSieveProvider (user-supplied EXE, live-PID interface, artifact workflow = unsupported)
- [x] Schema v6 pe_sieve tables + parent_artifact_id
- [x] Artifact UI PE-sieve panel (unsupported-target explanation; no misleading live scan)

---

## In Progress / Next

1. mal_unpack provider (user-supplied binary; verify license/CLI before implementation)  
2. Plugin Explorer / Advanced Volatility  
3. Export/reporting  
4. Release packaging (MSI deferred)

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
| PE-sieve not bundled | User supplies official v0.4.1.1 (or compatible) EXE under tools allow-list |
| Live `/pid` scan not in artifact UI | Provider implements it; investigation workflow does not invoke it |

---

## YARA on this machine

| Item | Value |
|------|-------|
| Available | **Yes** |
| Package | yara-python **4.5.4** |
| Binding | yara-python |
| CLI `yara` | Not on PATH (not required) |

---

## PE-sieve on this machine

| Item | Value |
|------|-------|
| Available | **No** (EXE not in MemScope tools directory or PATH) |
| Verified release targeted | **v0.4.1.1** |
| License | BSD-2-Clause; not redistributed in this repo |
| Installation | Copy `pe-sieve64.exe` from [GitHub releases](https://github.com/hasherezade/pe-sieve/releases/tag/v0.4.1.1) into `%LOCALAPPDATA%\MemScope\tools\` |

---

## Build/Test Status

| Check | Result |
|-------|--------|
| pytest | **45 passed, 1 skipped** (skip = real PE-sieve EXE not installed) |
| cargo test | **Not run** — `cargo` is not installed on this machine |
| frontend build | **PASS** (`tsc --noEmit && vite build`) |
| cargo build | **Not run** — `cargo` is not installed on this machine |

---

## Architecture Decisions

| ID | Decision | Status |
|----|----------|--------|
| AD-023 | YARA optional via yara-python | Accepted |
| AD-024 | Scan targets = artifact files only | Accepted |
| AD-025 | Provider protocol for future PE-sieve/mal_unpack | Accepted |
| AD-026 | Schema v5 yara_scans/matches | Accepted |
| AD-027 | PE-sieve is user-supplied EXE; not bundled despite BSD-2-Clause permitting redistribution with notice | Accepted |
| AD-028 | PE-sieve artifact/dump targets are unsupported; live `/pid` is the only valid upstream target | Accepted |
| AD-029 | Schema v6 pe_sieve_scans/outputs + parent_artifact_id | Accepted |
