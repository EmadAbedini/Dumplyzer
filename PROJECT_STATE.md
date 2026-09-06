# MemScope — Project State

> Single source of truth for project continuity. Update after every meaningful milestone.

**Last updated:** 2026-09-06  
**Version target:** 0.1.0-dev  
**Current phase:** Phase 5 — Optional malware providers (YARA + PE-sieve + mal_unpack done)

---

## Current Status

**mal_unpack** is integrated as an optional, user-supplied provider:

- Verified project: **hasherezade/mal_unpack** release **1.0** (`MALUNP_VERSION_STR "1.0.0.1"`)
- License: **BSD-2-Clause** — redistribution permitted with copyright notice; **EXE is not bundled**
- Place `mal_unpack.exe` (or `mal_unpack64.exe` / `mal_unpack32.exe`) under `%LOCALAPPDATA%\MemScope\tools\` (or `tools\mal_unpack\`)
- Native CLI: `/exe <file>` + `/timeout <ms>` (optional `/dir`, `/version`). The tool **executes** `/exe`
- MemScope-safe investigation targets: **none**. Artifacts, live processes, VAD regions, and memory dumps are unsupported
- Job `mal_unpack_artifact` records that limitation (does not invoke the EXE)
- Results in `mal_unpack_scans` / `mal_unpack_outputs` (schema **v7**) with artifact provenance when dumps are ingested from mock/test runs
- Artifacts UI: availability, version, EXE path, supported target types (none), disabled Unpack control, explicit UI states
- Distinguishes observed tool output from MemScope interpretation; **no malware score**

**PE-sieve** and **YARA** remain as previously delivered.

Core MemScope works without mal_unpack. This machine: **mal_unpack EXE not installed**.

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
- [x] MalUnpackProvider (user-supplied EXE; real `/exe` interface recorded; production jobs never execute samples)
- [x] Schema v7 mal_unpack_scans / mal_unpack_outputs
- [x] Artifact UI mal_unpack panel (disabled unpack; unavailable / unsupported-target states)

---

## In Progress / Next

1. Plugin Explorer / Advanced Volatility  
2. Export/reporting  
3. Release packaging (MSI deferred)

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
| mal_unpack executes `/exe` | Upstream dynamic unpacker starts the sample; MemScope will not invoke it |
| No MemScope-safe mal_unpack target | Artifacts, dumps, VADs, and live PIDs are all unsupported here |
| mal_unpack not bundled | User supplies official 1.0 EXE under tools allow-list |

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

## mal_unpack on this machine

| Item | Value |
|------|-------|
| Available | **No** (EXE not in MemScope tools directory) |
| Verified project | [hasherezade/mal_unpack](https://github.com/hasherezade/mal_unpack) |
| Verified release | **1.0** (`1.0.0.1`) |
| License | BSD-2-Clause; not redistributed in this repo |
| Installation | Copy `mal_unpack.exe` from [mal_unpack64.zip](https://github.com/hasherezade/mal_unpack/releases/tag/1.0) into `%LOCALAPPDATA%\MemScope\tools\` (or `tools\mal_unpack\`) |
| Redistribution | Permitted with copyright notice; MemScope still does not bundle the binary |

---

## Build/Test Status

| Check | Result |
|-------|--------|
| pytest | **67 passed, 2 skipped** (skips = real PE-sieve and mal_unpack EXEs not installed) |
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
| AD-030 | mal_unpack is user-supplied hasherezade/mal_unpack 1.0 EXE; not bundled | Accepted |
| AD-031 | mal_unpack `/exe` executes the sample; MemScope never invokes it against investigation targets | Accepted |
| AD-032 | Schema v7 mal_unpack_scans/outputs | Accepted |
