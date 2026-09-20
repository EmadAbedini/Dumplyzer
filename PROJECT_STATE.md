# Dumplyzer — Project State

> Single source of truth for project continuity. Update after every meaningful milestone.

**Last updated:** 2026-09-20  
**Version target:** 0.1.0  
**Current phase:** Release engineering — final validation / hardening

---

## Current Status

**Windows packaging** is complete. Product branding is **Dumplyzer** (formerly MemScope). This milestone is **release validation and hardening**, not new forensic features.

- End-user installer: one NSIS EXE (`Dumplyzer_0.1.0_x64-setup.exe`), default `%ProgramFiles%\Dumplyzer`, with an embedded WebView2 Evergreen standalone (offline) installer
- Executable: `dumplyzer.exe`; installer identity `Dumplyzer_0.1.0_x64-setup.exe`
- Engine: official CPython **3.12.10** embeddable + `memscope-engine` **0.1.0** + Volatility 3 **2.28.0** (no global Python)
- User data: `%LOCALAPPDATA%\Dumplyzer\` (db, logs, cache, artifacts, exports, `rules\yara`, tools)
- Legacy data: first launch copies `%LOCALAPPDATA%\MemScope\` or `%APPDATA%\com.memscope.workbench\` into the canonical directory when the new `memscope.db` does not exist. The source is never deleted.
- Application source license: **Apache-2.0** (`LICENSE`). Redistributed Volatility 3 remains **VSL** (`THIRD_PARTY_NOTICES.md`)
- Installers are **unsigned**. Authenticode procedure is documented; no certificate is configured
- WebView2 Evergreen is required at runtime. The NSIS installer embeds the Evergreen standalone installer so a machine **without WebView2 and without network** can still install
- Clean-machine **offline** NSIS install on a Windows 11 x64 VM **was executed** (2026-09-20): **PASS WITH LIMITATIONS**. See `docs/clean-machine-validation.md`. WebView2 was already present and could not be uninstalled (exit 93). The installer packs the Evergreen standalone payload and did not download anything. Authenticode remains unsigned. Windows 10 was not install-tested.

Forensic workflows are unchanged.

---

## Completed

- Phases 0–4 forensic core
- Optional YARA / CAPA / FLOSS / bulk_extractor providers; dedicated PE Extraction workflow; Signature Detection bundled (yara-python 4.5.4)
- Plugin Explorer + Advanced Volatility execution (schema v8)
- JSON / CSV / HTML investigation export (schema v9, report v1); bulk_extractor scans in schema **v10**; PE Extraction / CAPA / FLOSS in schema **v11**; Signature Detection memory scans / nullable artifact_id in schema **v12**; network artifacts + PCAP reconstruction in schema **v13**
- [x] Windows engine runtime packaging (embeddable CPython, not PyInstaller)
- [x] Pinned lockfiles (Python runtime, Volatility, pefile, frontend npm lock, Cargo.lock)
- [x] NSIS + MSI installer configuration
- [x] First-launch directories, canonical data path, legacy db copy, engine process lifecycle
- [x] Apache-2.0 LICENSE for Dumplyzer application source + third-party notices for inspected redistributed metadata
- [x] Authenticode procedure documented (unsigned artifacts remain labeled unsigned)
- [x] WebView2 supported-environment limitation documented
- [x] Optional Volatility extras / plugin availability honesty checks on the bundled runtime
- [x] Install vs mutable-data separation tests

---

## In Progress / Next

1. Authenticode signing with a real code-signing certificate — **blocker for trusted public installers**
2. Optional follow-up: install on a machine that truly has no WebView2, to watch the packed Evergreen standalone run
3. Windows 10 21H2+ install test (dependency-compatible; not yet executed)
4. Linux packaging (out of scope for 0.1.0)

---

## Known Issues / Limitations

| Issue | Notes |
|-------|--------|
| YARA cancel is cooperative | Cannot kill native `yara.match` mid-call; timeout bounds runtime |
| Large-dump Signature Detection | Files at or above 512 MiB (override `DUMPLYZER_YARA_CHUNK_THRESHOLD`) are scanned in overlapping windows so Python does not load the whole dump. Rules that need `filesize`, the PE module, or whole-file hashes can miss across chunk boundaries. Offsets are adjusted to dump-absolute values. Smaller dumps use libyara filepath/mmap. |
| Process not scanned live | Signature Detection scans the original dump file and extracted artifact files, not a live OS process |
| Rule paths restricted | Must live under configured `rules\yara` roots |
| Custom rules survive upgrades | `%LOCALAPPDATA%\Dumplyzer\rules\yara\custom\` is never overwritten |
| No threat score | By design |
| Extracted PE is not malware | PE Extraction labels reconstructed EXE/DLL files as artifacts |
| CAPA/FLOSS/Signature Detection not auto-run | Analyst must start those jobs; PE extraction does not invoke them |
| bulk_extractor not in Python runtime | Official `bulk_extractor64.exe` is bundled under application resources, not site-packages |
| Advanced plugin cancel is cooperative | Volatility `run()` is not interruptible mid-plugin; UI does not claim instant stop |
| Dummy/unanalyzed images | Automagic often raises `volatility_unsatisfied` until symbols/OS resolve |
| Plugin Explorer is generic | Does not replace dedicated process/memory views |
| Result preview cap | UI/IPC preview is 500 rows; full table remains in the cache file |
| Volatility `full` extras omitted | capstone / pycryptodome are not in the shipped runtime; some plugins may import-fail and must not be marked available. yara-python 4.5.4 is bundled. |
| HTML report row cap | 400 rows per large section; remainder is in JSON/CSV |
| JSON/CSV row caps | JSON 20000 / CSV 50000 per section; not a full unbounded dump |
| No PDF export | Intentionally omitted |
| Export destination | Engine-chosen under app data `exports/` only; client paths rejected |
| HTML is static | No JavaScript; open as a file. Command lines/paths are escaped text, not executed |
| No desktop UI browser pass | Export view verified via TypeScript build + engine IPC tests |
| Clean-machine install | **OFFLINE PASS WITH LIMITATIONS** (2026-09-20 NSIS on Windows 11 Pro 10.0.26100). WebView2 already present; Windows 10 not install-tested |
| Code signing | Not configured. 0.1.0 NSIS/MSI/`Dumplyzer.exe` are unsigned |
| WebView2 offline-absent | NSIS embeds the Evergreen standalone installer (`offlineInstaller`); no Internet is required at install time |
| Program Files install is protected | Default `%ProgramFiles%\Dumplyzer` requires elevation; user data stays in `%LOCALAPPDATA%\Dumplyzer` |

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
| pytest | **164 passed** (yara-python 4.5.4 bundled in venv and engine tests) |
| cargo test | **12 passed** (engine IPC + launch resolution + data-dir vs install-dir + bundled rules dir) |
| frontend build | **PASS** (`tsc --noEmit && vite build`) |
| cargo build | **PASS** (debug); **PASS** (release via `tauri build`) |
| NSIS installer | **PASS** unsigned `Dumplyzer_0.1.0_x64-setup.exe` (312.3 MB, 327,510,849 bytes, SHA-256 `49bd1f759986f92de17a39589aed2dd122d612c379b3313f355de15e31b10f81`) with bundled CPython, Volatility, tools, Dumplyzer icon, and offline WebView2 Evergreen standalone |
| MSI installer | Not an end-user artifact. Build produces NSIS only. |
| Authenticode | **NotSigned** (`Dumplyzer_0.1.0_x64-setup.exe`, `dumplyzer.exe`) |
| Clean-machine install | **OFFLINE PASS WITH LIMITATIONS** — Windows 11 Pro 10.0.26100 x64 VM via SSH; NSIS per-machine `%ProgramFiles%\Dumplyzer`; outbound blocked; bundled CPython 3.12.10; Volatility 2.28.0; 191 plugins. Details in `docs/clean-machine-validation.md` |

---

## Architecture Decisions

| ID | Decision | Status |
|----|----------|--------|
| AD-023–AD-042 | Prior forensic / export decisions | Accepted |
| AD-043 | Ship official CPython 3.12.10 Windows embeddable + site-packages, not PyInstaller and not a first-run venv | Accepted |
| AD-044 | NSIS/MSI default install dir is `%ProgramFiles%\Dumplyzer` on the Windows system drive; user data stays `%LOCALAPPDATA%\Dumplyzer` | Accepted |
| AD-045 | Canonical user data is `%LOCALAPPDATA%\Dumplyzer\` (not Tauri roaming identifier) | Accepted |
| AD-046 | WiX Toolset **3.14.1** for MSI, prefetch with pinned SHA-256 | Accepted |
| AD-047 | Application/engine/installer version is **0.1.0**; report schema and SQLite schema stay independent | Accepted |
| AD-048 | Dumplyzer application source is Apache-2.0; redistributed Volatility 3 remains VSL; notices live in `THIRD_PARTY_NOTICES.md` | Accepted |
| AD-049 | Do not invent a signing certificate. Unsigned 0.1.0 artifacts stay labeled unsigned; Authenticode procedure is documented | Accepted |
| AD-050 | Embed WebView2 Evergreen standalone (`offlineInstaller`) so a machine without WebView2 and without network can install | Accepted |
