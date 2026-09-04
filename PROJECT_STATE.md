# MemScope — Project State

> Single source of truth for project continuity. Update after every meaningful milestone.

**Last updated:** 2026-09-04  
**Version target:** 0.1.0-dev  
**Current phase:** Phase 1 — Foundation (environment verified; minimal shell scaffolded)

---

## Current Status

Development environment is **verified** for Windows x64 MemScope work.

End-to-end smoke path confirmed:

**Tauri desktop layer (Rust) → Python engine (stdio JSON-RPC) → Volatility 3 2.28.0 init**

Minimal application shell exists (`app/frontend`, `app/desktop`, `engine`). Not a product UI yet — smoke/workbench bootstrap only.

---

## Completed

- [x] Phase 0 discovery (`ARCHITECTURE.md`, initial `PROJECT_STATE.md`)
- [x] Local Git identity (`user.name` / `user.email` for this repo only)
- [x] Install Rust via rustup (`stable-x86_64-pc-windows-msvc`)
- [x] Install Visual Studio Build Tools 2022 + VC Tools workload (elevated)
- [x] Install Python 3.12.10 (side-by-side with system 3.13.7)
- [x] Create `engine/.venv` on Python 3.12
- [x] Install Volatility 3 **2.28.0** + pefile; verify framework imports
- [x] Scaffold monorepo: frontend (Vite/React/TS), desktop (Tauri 2), engine package
- [x] NDJSON JSON-RPC smoke server (`health`, `volatility.init`, `smoke.e2e`)
- [x] Engine smoke scripts/tests
- [x] Rust IPC unit test `engine_volatility_init_via_ipc` — **PASS**
- [x] `cargo check` / `cargo build` Tauri app — **PASS** → `app/desktop/target/debug/memscope.exe`
- [x] Frontend production build — **PASS**
- [x] `tauri build --debug` compiles app binary — **PASS** (MSI/WiX download timed out; see Known Issues)

---

## In Progress

- Phase 1 remaining product foundation: SQLite schema, structured logging, config paths, real app shell chrome (beyond smoke UI)

---

## Known Issues

| Issue | Severity | Notes |
|-------|----------|-------|
| `tauri build` WiX download timeout | Medium | App binary builds; MSI bundle step failed with `timeout: global` while downloading WiX 3.14. Retry later or vendor WiX offline. |
| Bundle id warning (resolved) | Low | Changed identifier from `com.memscope.app` → `com.memscope.workbench` (`.app` suffix conflicts on macOS). |
| npm audit high severity (frontend) | Low | Present after initial install; not investigated yet (dev-time scaffold). |
| No sample memory image | Info | Full Vol3 analysis against a dump not yet run (init-only smoke). |
| PATH does not permanently include cargo | Info | Shell sessions need `$env:USERPROFILE\.cargo\bin` or user PATH update. |

---

## Technical Debt

- Smoke UI only (no investigation chrome, Tailwind/shadcn not yet applied)
- Engine is minimal RPC surface; no jobs/SQLite/cache yet
- Placeholder icons (generated solid PNGs)
- `beforeBuildCommand` wiring uses `app/desktop/package.json` shim
- WiX bundling not verified end-to-end
- No CI workflows yet

---

## Architecture Decisions

| ID | Decision | Rationale | Status |
|----|----------|-----------|--------|
| AD-001 | Tauri 2 + React + TypeScript | Stack requirement | Accepted / scaffolded |
| AD-002 | Python engine sidecar + NDJSON JSON-RPC stdio | Isolation, offline, no open ports | Accepted / smoke-verified |
| AD-003 | Engine **Python 3.12.10 venv** (not host 3.13.7) | Dedicated stable runtime for Vol3; host remains 3.13 | **Accepted (verified)** |
| AD-004 | Volatility 3 **2.28.0** pinned in engine | Actual install that imports cleanly | Accepted |
| AD-005 | SQLite metadata only | Forensic correctness | Accepted (not implemented yet) |
| AD-006 | Optional providers via adapters | Licensing | Accepted (not implemented) |
| AD-007 | Apache-2.0 proposed for app code | Pending LICENSE file | Proposed |
| AD-008 | MSVC toolchain (`x86_64-pc-windows-msvc`) | Tauri/Windows default | Accepted / verified |

---

## Dependencies

### Host toolchains (verified 2026-09-04)

| Tool | Version | Notes |
|------|---------|-------|
| Windows | 10.0.26200 (win32 x64) | |
| Git | 2.51.0.windows.1 | Local identity: Emad Abedini / emad.ab3dini@gmail.com |
| Python (host) | 3.13.7 | Still installed; **not** used for engine |
| Python (engine) | **3.12.10** | `C:\Users\Stanly\AppData\Local\Programs\Python\Python312\python.exe` |
| Node.js | v22.18.0 | |
| npm | 10.9.3 | |
| rustup | 1.29.1 | |
| rustc / cargo | **1.98.1** (48a229cea 2026-09-01) | `stable-x86_64-pc-windows-msvc` |
| VS Build Tools | **17.14.39** (August 2026) | Path: `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools` |
| MSVC | 14.44.35207 | `cl.exe` / `link.exe` present (Hostx64/x64) |
| WebView2 | 139.0.3405.125 | |
| winget | v1.11.400 | |

### Engine venv (`engine/.venv`)

| Package | Version |
|---------|---------|
| Python | 3.12.10 |
| pip | 26.2.1 |
| volatility3 | **2.28.0** |
| pefile | 2024.8.26 |
| memscope-engine | 0.1.0.dev0 (editable) |

### Desktop / frontend (scaffolded)

| Package | Version |
|---------|---------|
| tauri (crate) | 2.11.5 |
| tauri-build | 2.6.x (resolved) |
| @tauri-apps/cli | 2.11.4 |
| @tauri-apps/api | 2.11.1 |
| vite | 7.1.3 |
| react / react-dom | 19.2.x |
| typescript | 5.9.2 |

---

## Build/Test Status

| Check | Result |
|-------|--------|
| `rustc` hello (MSVC link) | PASS (`msvc-ok`) |
| Engine `smoke.e2e` (PowerShell) | PASS — Vol3 2.28.0 |
| `tests/engine/test_smoke_e2e.py` | PASS |
| `cargo test engine_volatility_init_via_ipc` | PASS |
| `npm run build` (frontend) | PASS |
| `cargo build` / `tauri build --debug` binary | PASS → `memscope.exe` |
| MSI/NSIS bundle | FAIL (WiX download timeout) |
| CI | Not set up |

---

## Current Phase

**Phase 1 — Foundation** (environment + minimal shell done; product foundation next)

---

## Next Steps

1. Add LICENSE, README skeleton, root package/scripts
2. SQLite schema v1 + migrations in engine
3. Structured logging (app/analysis/tool)
4. App data directories via Tauri path API
5. Replace smoke UI with forensic workstation shell (nav + dark theme + Tailwind/shadcn)
6. Engine methods: evidence import stubs, job manager skeleton
7. Retry/fix Windows bundler (WiX) for installer artifact
8. Persist cargo bin on user PATH (optional convenience)
9. Begin Phase 2 (Volatility core analysis) after foundation solidifies

---

## Important Discoveries

1. **Python 3.13 was not used for Volatility** — engine locked to **3.12.10** venv by design after dedicated install (no 3.13 Vol3 trial forced; 3.12 is the supported engine runtime).
2. **VS Build Tools required elevation** — non-elevated winget failed (`0x80070642` / UAC declined). Elevated `Start-Process -Verb RunAs` succeeded.
3. **Rustup first install was interrupted** — required `rustup toolchain uninstall` + reinstall of `stable-x86_64-pc-windows-msvc`.
4. **Volatility 3 2.28.0** installs cleanly with `contexts`, `automagic`, `plugins`; **81** Windows plugin modules discovered via `pkgutil`.
5. **Tauri 2.11.5** compiles against WebView2 + MSVC on this machine; debug `memscope.exe` ~12 MB.
6. WiX bootstrap for MSI is network-sensitive in this environment.

---

## Unfinished Work

- Full Phase 1 product foundation (DB, logging, real shell)
- Phases 2–7 (analysis, UX, forensic features, providers, advanced mode, release)
- Sample/fixture memory images
- GitHub Actions
- LICENSE/CONTRIBUTING/SECURITY/CHANGELOG

---

## Session Notes

### 2026-09-04 — Environment setup + smoke

- Installed: rustup/Rust 1.98.1 MSVC, VS Build Tools 17.14.39, Python 3.12.10, Vol3 2.28.0
- Verified: engine IPC smoke, cargo test IPC, frontend build, Tauri debug binary
- Blocker cleared: MSVC/Rust/Vol3
- Remaining packaging: WiX timeout on `tauri build` bundle step
