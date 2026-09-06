# MemScope — Project State

> Single source of truth for project continuity. Update after every meaningful milestone.

**Last updated:** 2026-09-06  
**Version target:** 0.1.0  
**Current phase:** Release engineering — Windows packaging

---

## Current Status

**Windows release packaging** is implemented on top of the frozen forensic feature set.

- End-user installers: NSIS per-user (`%LOCALAPPDATA%\Programs\MemScope`) and WiX 3.14 MSI
- Engine: official CPython **3.12.10** embeddable + `memscope-engine` **0.1.0** + Volatility 3 **2.28.0** (no global Python)
- User data: `%LOCALAPPDATA%\MemScope\` (db, logs, cache, artifacts, exports, yara_rules, tools)
- YARA / PE-sieve / mal_unpack remain optional and are not bundled or downloaded
- Clean-machine installation on a VM **was not executed** in this milestone

Forensic workflows (Volatility core, process/module/network/VAD, findings/IOC/timeline, artifacts, YARA/PE-sieve/mal_unpack providers, Plugin Explorer, Advanced execution, JobManager, SQLite, cache, JSON/CSV/HTML export) are unchanged aside from version metadata and data-dir hardening.

---

## Completed

- Phases 0–4 forensic core  
- Optional YARA / PE-sieve / mal_unpack providers  
- Plugin Explorer + Advanced Volatility execution (schema v8)  
- JSON / CSV / HTML investigation export (schema v9, report v1)  
- [x] Windows engine runtime packaging (embeddable CPython, not PyInstaller)  
- [x] Pinned lockfiles (Python runtime, Volatility, pefile, frontend npm lock, Cargo.lock)  
- [x] NSIS + MSI installer configuration  
- [x] First-launch directories, canonical data path, legacy db copy, engine process lifecycle  

---

## In Progress / Next

1. Clean-machine validation on a Windows x64 VM without developer toolchains (checklist in `docs/clean-machine-validation.md`)
2. Authenticode signing
3. Linux packaging (out of scope for 0.1.0)

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
| Volatility `full` extras omitted | capstone / pycryptodome / yara-python are not in the shipped runtime; some plugins may import-fail |
| HTML report row cap | 400 rows per large section; remainder is in JSON/CSV |
| JSON/CSV row caps | JSON 20000 / CSV 50000 per section; not a full unbounded dump |
| No PDF export | Intentionally omitted |
| Export destination | Engine-chosen under app data `exports/` only; client paths rejected |
| HTML is static | No JavaScript; open as a file. Command lines/paths are escaped text, not executed |
| No desktop UI browser pass | Export view verified via TypeScript build + engine IPC tests |
| Clean-machine install | Not run; do not claim it passed |
| Code signing | Not configured |
| Per-user install is writable | Windows current-user install directory is user-writable |

---

## Volatility on this machine

| Item | Value |
|------|-------|
| Version | **2.28.0** |
| Discovered plugins | **191** (developer venv; shipped runtime may show additional import failures without `full` extras) |
| Categories | windows 99, linux 60, mac 23, framework 9 |
| Import failures | 6 on the developer venv (not marked available) |

---

## Build/Test Status

| Check | Result |
|-------|--------|
| pytest | **119 passed, 2 skipped** (skips = real PE-sieve and mal_unpack EXEs not installed) |
| cargo test | **6 passed** (engine IPC + launch resolution) |
| frontend build | **PASS** (`tsc --noEmit && vite build`) |
| cargo build | **PASS** (debug); **PASS** (release via `tauri build`) |
| NSIS installer | **PASS** `MemScope_0.1.0_x64-setup.exe` (12.7 MB) |
| MSI installer | **PASS** `MemScope_0.1.0_x64_en-US.msi` (16.3 MB) |
| Clean-machine install | **Not run** |

---

## Architecture Decisions

| ID | Decision | Status |
|----|----------|--------|
| AD-023–AD-042 | Prior forensic / export decisions | Accepted |
| AD-043 | Ship official CPython 3.12.10 Windows embeddable + site-packages, not PyInstaller and not a first-run venv | Accepted |
| AD-044 | NSIS `currentUser` default install dir is `%LOCALAPPDATA%\Programs\MemScope` so it does not collide with user data | Accepted |
| AD-045 | Canonical user data is `%LOCALAPPDATA%\MemScope\` (not Tauri roaming identifier) | Accepted |
| AD-046 | WiX Toolset **3.14.1** for MSI, prefetch with pinned SHA-256 | Accepted |
| AD-047 | Application/engine/installer version is **0.1.0**; report schema and SQLite schema stay independent | Accepted |
