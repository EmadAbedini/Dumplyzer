# MemScope — Project State

> Single source of truth for project continuity. Update after every meaningful milestone.

**Last updated:** 2026-09-06  
**Version target:** 0.1.0  
**Current phase:** Release engineering — final validation / hardening

---

## Current Status

**Windows packaging** is complete. This milestone is **release validation and hardening**, not new forensic features.

- End-user installers: NSIS per-user (`%LOCALAPPDATA%\Programs\MemScope`) and WiX 3.14 MSI
- Engine: official CPython **3.12.10** embeddable + `memscope-engine` **0.1.0** + Volatility 3 **2.28.0** (no global Python)
- User data: `%LOCALAPPDATA%\MemScope\` (db, logs, cache, artifacts, exports, yara_rules, tools)
- Application source license: **Apache-2.0** (`LICENSE`). Redistributed Volatility 3 remains **VSL** (`THIRD_PARTY_NOTICES.md`)
- Installers are **unsigned**. Authenticode procedure is documented; no certificate is configured
- WebView2 Evergreen is required. The installer embeds the bootstrapper; a machine **without WebView2 and without network** is not a supported launch environment
- Clean-machine installation on a VM **was not executed**. Do not claim it passed

Forensic workflows are unchanged.

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
- [x] Apache-2.0 LICENSE for MemScope application source + third-party notices for inspected redistributed metadata
- [x] Authenticode procedure documented (unsigned artifacts remain labeled unsigned)
- [x] WebView2 supported-environment limitation documented
- [x] Optional Volatility extras / plugin availability honesty checks on the bundled runtime
- [x] Install vs mutable-data separation tests

---

## In Progress / Next

1. Clean-machine validation on a Windows x64 VM without developer toolchains (checklist in `docs/clean-machine-validation.md`) — **blocker for public release**
2. Authenticode signing with a real code-signing certificate — **blocker for trusted public installers**
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
| Volatility `full` extras omitted | capstone / pycryptodome / yara-python are not in the shipped runtime; some plugins may import-fail and must not be marked available |
| HTML report row cap | 400 rows per large section; remainder is in JSON/CSV |
| JSON/CSV row caps | JSON 20000 / CSV 50000 per section; not a full unbounded dump |
| No PDF export | Intentionally omitted |
| Export destination | Engine-chosen under app data `exports/` only; client paths rejected |
| HTML is static | No JavaScript; open as a file. Command lines/paths are escaped text, not executed |
| No desktop UI browser pass | Export view verified via TypeScript build + engine IPC tests |
| Clean-machine install | **Not run**; developer host has Python/Node/Rust. Do not claim it passed |
| Code signing | Not configured. 0.1.0 NSIS/MSI/`MemScope.exe` are unsigned |
| WebView2 offline-absent | `embedBootstrapper` can download Evergreen if the runtime is missing; without WebView2 **and** without network, launch is not guaranteed |
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

Recorded on the developer host (Windows 11 Pro 10.0.26200 x64, WebView2 152.0.4191.66 present). Not a clean machine.

| Check | Result |
|-------|--------|
| pytest | **122 passed, 2 skipped** (skips = real PE-sieve and mal_unpack EXEs not installed) |
| cargo test | **6 passed** (engine IPC + launch resolution + data-dir vs install-dir) |
| frontend build | **PASS** (`tsc --noEmit && vite build`) |
| cargo build | **PASS** (debug); **PASS** (release via `tauri build`) |
| NSIS installer | **PASS** unsigned `MemScope_0.1.0_x64-setup.exe` (13.3 MB, SHA-256 `4f216cf1b08f6f9bea0d3755d5c267eda4cfa54beee5595182dd6c398350a94e`) |
| MSI installer | **PASS** unsigned `MemScope_0.1.0_x64_en-US.msi` (17.6 MB, SHA-256 `891b73d430deee1fbfad1a1a2677fdc63e3baa9753cf1a7bbf85186b2520148a`) |
| Authenticode | **NotSigned** (NSIS, MSI, `memscope.exe`) |
| Clean-machine install | **Not run** — no clean Windows x64 VM available (Hyper-V query needs elevation; VirtualBox/QEMU/vmconnect not installed) |

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
| AD-048 | MemScope application source is Apache-2.0; redistributed Volatility 3 remains VSL; notices live in `THIRD_PARTY_NOTICES.md` | Accepted |
| AD-049 | Do not invent a signing certificate. Unsigned 0.1.0 artifacts stay labeled unsigned; Authenticode procedure is documented | Accepted |
| AD-050 | Keep `webviewInstallMode.embedBootstrapper`. Do not pretend offline WebView2-absent machines can launch | Accepted |
