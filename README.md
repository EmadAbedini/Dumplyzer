# MemScope

Offline Windows x64 desktop workbench for **Volatility 3** memory forensics.

React UI → Tauri 2 shell → bundled Python 3.12 engine → Volatility 3 APIs.

MemScope is not a CLI wrapper, not a cloud product, and does not score malware.

## Supported platform

| Item | Value |
|------|--------|
| OS | Windows 10 21H2+ / Windows 11 |
| Arch | x64 |
| App version | **0.1.0** |
| Engine runtime | CPython **3.12.10** (bundled in the installer) |
| Volatility 3 | **2.28.0** |
| WebView2 | **Required.** Evergreen Runtime. The installer embeds the bootstrapper, which can download the runtime if it is missing. A system with neither WebView2 nor network connectivity is not a supported launch environment |

Linux is not a supported release target yet.

## Install (end user)

You do **not** need Python, Node, Rust, or a source checkout.

1. Run the NSIS installer (`MemScope_0.1.0_x64-setup.exe`). It installs per-user and does not require administrator rights.
2. An MSI (`MemScope_0.1.0_x64_en-US.msi`) is also produced for managed deployment. MSI installs to Program Files and typically needs elevation.
3. Launch **MemScope** from the Start menu.

First launch creates the user data directory and starts the bundled engine. Optional YARA / PE-sieve / mal_unpack providers show as unavailable until you configure them.

A real memory image is optional. Empty Evidence is a valid state.

## Data locations

Install (binaries + engine runtime) and user data are separate. Forensic data is never stored inside the install tree.

| Kind | Location |
|------|----------|
| Per-user install (NSIS) | `%LOCALAPPDATA%\Programs\MemScope\` |
| Per-machine install (MSI) | `%ProgramFiles%\MemScope\` |
| User data | `%LOCALAPPDATA%\MemScope\` |
| Database | `%LOCALAPPDATA%\MemScope\memscope.db` |
| Logs | `%LOCALAPPDATA%\MemScope\logs\` |
| Cache | `%LOCALAPPDATA%\MemScope\cache\` |
| Artifacts | `%LOCALAPPDATA%\MemScope\artifacts\` |
| Exports | `%LOCALAPPDATA%\MemScope\exports\` |
| YARA rules | `%LOCALAPPDATA%\MemScope\yara_rules\` |
| Optional tools | `%LOCALAPPDATA%\MemScope\tools\` |

Override the data directory with `MEMSCOPE_DATA_DIR` only for tests or support.

Evidence files stay where you imported them. MemScope stores metadata and extracted artifacts, not a copy of the memory image.

## Optional providers

None are required. None are downloaded. None are bundled.

**YARA** — optional `yara-python` binding. Core install reports YARA unavailable. Rules must live under `yara_rules`. Scans artifact files only.

**PE-sieve** — user-supplied official EXE (`pe-sieve64.exe` / `pe-sieve.exe` / `pe-sieve32.exe`) under `tools\`. Allow-listed names only. Artifact workflows do not invoke it (the tool requires a live `/pid`).

**mal_unpack** — user-supplied official EXE under `tools\`. Native `/exe` executes the target; MemScope will not invoke it against investigation artifacts.

## Upgrade behavior

- Application version **0.1.0** is the first packaged release.
- SQLite migrations are additive. Opening an older `memscope.db` upgrades the schema (currently to **v9**) and keeps existing evidence rows.
- Uninstalling the application is not supposed to delete `%LOCALAPPDATA%\MemScope\` user data.
- If a previous development build stored a database under `%APPDATA%\com.memscope.workbench\`, first launch of 0.1.0 copies it into `%LOCALAPPDATA%\MemScope\` when the new database does not yet exist. The source is not deleted.

## Evidence handling

Treat memory images, dumps, and extracted artifacts as hostile. MemScope does not execute them. Exports are written only under the user data `exports\` directory.

## Developer build

See [CONTRIBUTING.md](CONTRIBUTING.md) for a source checkout.

Windows installer production:

```powershell
.\scripts\windows\build-release.ps1
```

Details, pinned versions, and verification: [docs/windows-release.md](docs/windows-release.md).

Clean-machine checklist: [docs/clean-machine-validation.md](docs/clean-machine-validation.md).

## License

MemScope application source is licensed under the Apache License 2.0. See [LICENSE](LICENSE).

The Windows installer also redistributes third-party components under their own terms (CPython PSF, Volatility 3 VSL, pefile MIT). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). MemScope does not relicense Volatility 3.

PE-sieve and mal_unpack binaries are not redistributed.

0.1.0 Windows installers are **unsigned**. SmartScreen or organization policy may warn on first run.

Clean-machine installation on a VM without developer toolchains has **not** been executed. See [docs/clean-machine-validation.md](docs/clean-machine-validation.md).
