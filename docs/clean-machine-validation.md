# Clean-machine validation (Windows x64)

Use a Windows 10 21H2+ or Windows 11 **x64** VM or spare host that does **not** have:

- developer Python
- Node.js
- Rust / cargo
- a MemScope source checkout
- PE-sieve / mal_unpack / yara-python

A memory image is not required. Do not fabricate forensic results.

**Status:** this checklist was **not** executed in the 0.1.0 packaging milestone on a clean VM. Run it before calling the installer production-ready.

## Procedure

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
