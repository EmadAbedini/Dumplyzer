# Clean-machine validation (Windows x64)

Use a Windows 10 21H2+ or Windows 11 **x64** VM or spare host that does **not** have:

- developer Python
- Node.js
- Rust / cargo
- a MemScope source checkout
- PE-sieve / mal_unpack / yara-python

A memory image is not required. Do not fabricate forensic results.

## Status (2026-09-06)

**This checklist was not executed.** There was no clean Windows x64 VM available on the validation host.

Validation host (not a clean machine):

| Item | Value |
|------|--------|
| OS | Windows NT 10.0.26200.0 (Windows 11 Pro) x64 |
| Developer Python | Present (`Python312\python.exe`) |
| Node.js | Present |
| Rust | Present (`rustc` on PATH) |
| MemScope source | This repository checkout |
| WebView2 | Present — Evergreen **152.0.4191.66** |
| Hyper-V feature query | Requires elevation; not confirmed |
| VirtualBox / QEMU / vmconnect | Not installed |

Do not mark this document as passed. Do not treat developer-host pytest / `tauri build` as a substitute for this checklist.

## Unverified on a clean machine

Every installer/runtime step below remains unverified without a clean VM:

- NSIS per-user install into `%LOCALAPPDATA%\Programs\MemScope\`
- MSI install into `%ProgramFiles%\MemScope\`
- Start-menu launch of `MemScope.exe` without developer Python/Node/Rust
- Bundled `runtime\python.exe` used in a packaged process (developer-host tests cover the runtime **files**, not the installed application)
- Engine startup, Tauri ↔ Python IPC, Volatility import, Plugin Explorer discovery
- SQLite initialization and empty Evidence UI
- Optional provider unavailable states in the installed UI
- JSON/CSV/HTML export from the installed UI
- Logs under `%LOCALAPPDATA%\MemScope\logs\`
- Clean process exit (`MemScope.exe` and `python.exe` not left running)
- Launch with WebView2 already present vs missing vs offline
- Install-directory ACL / Program Files write behavior of the real installer

## Procedure (when a clean VM exists)

1. Copy only the NSIS `*-setup.exe` (preferred) or the MSI onto the machine.
2. Run the installer without extra command-line flags.
3. Confirm install path:
   - NSIS: `%LOCALAPPDATA%\Programs\MemScope\`
   - MSI: `%ProgramFiles%\MemScope\` (elevation likely)
4. Launch MemScope from the Start menu.
5. Confirm first launch created `%LOCALAPPDATA%\MemScope\` (`logs`, `artifacts`, `cache`, `exports`, `yara_rules`, `tools`).
6. Empty Evidence: the UI should load without an imported image.
7. If the UI exposes smoke/health via developer tools, `smoke.e2e` / `volatility.init` should report `ok` and Volatility **2.28.0**. Otherwise, confirm Plugin Explorer lists plugins (dynamic discovery).
8. Optional providers must show **unavailable** (no YARA, no PE-sieve EXE, no mal_unpack EXE).
9. Export options should list HTML / JSON / CSV. Generating a report without evidence may fail with an actionable error; that is acceptable. Do not invent findings.
10. Open `%LOCALAPPDATA%\MemScope\logs\` and confirm engine logs exist.
11. Exit MemScope. Confirm `MemScope.exe` and `python.exe` are not left running.
12. Re-launch. Existing `memscope.db` must still be present (upgrade/preservation).

## Pass / fail log

Record OS build, installer filename, SHA-256, and each step as pass/fail. Do not mark this document as passed unless the run happened.
