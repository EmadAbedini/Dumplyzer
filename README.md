# Dumplyzer

Offline Windows x64 desktop workbench for **Volatility 3** memory forensics.

React UI → Tauri 2 shell → bundled Python 3.12 engine → Volatility 3 APIs.

Dumplyzer is not a CLI wrapper, not a cloud product, and does not score malware.

This product was previously named MemScope. The Python engine package remains
`memscope_engine`, and the SQLite file remains `memscope.db`.

## Supported platform

| Item | Value |
|------|--------|
| OS | Windows 10 21H2+ (build 19044) / Windows 11 x64. Install-tested on Windows 11 Pro 10.0.26100. Not install-tested on Windows 10. Runtime floor from WebView2 Evergreen is Windows 10 1809 (build 17763). |
| Arch | x64 |
| App version | **0.1.0** |
| Engine runtime | CPython **3.12.10** (bundled in the installer) |
| Volatility 3 | **2.28.0** |
| WebView2 | **Required** at runtime. The installer embeds the small Evergreen bootstrapper (~1–2 MB). If WebView2 is already installed, it is skipped. If it is missing, the bootstrapper downloads the runtime during setup (Internet required for that case only). |

Linux is not a supported release target yet.

## Install (end user)

You do **not** need Python, Node, Rust, or a source checkout.

1. Run the NSIS installer (`Dumplyzer_0.1.0_x64-setup.exe`). It defaults to `%ProgramFiles%\Dumplyzer` on the Windows system drive and requires administrator rights. Python, Volatility, and analysis tools are bundled. If WebView2 is missing, the embedded Evergreen bootstrapper downloads it during setup.
2. Launch **Dumplyzer** from the Start menu.

First launch creates the user data directory and starts the bundled engine. PE Extraction is part of the Volatility 3 engine. bulk_extractor, CAPA, FLOSS, and Signature Detection (bundled yara-python **4.5.4** plus curated rules) are included. You do not install Python or YARA separately.

A real memory image is optional. Empty Evidence is a valid state.

## Data locations

Install (binaries + engine runtime) and user data are separate. Forensic data is never stored inside the install tree.

| Kind | Location |
|------|----------|
| Install (NSIS default / MSI) | `%ProgramFiles%\Dumplyzer\` (Windows system drive) |
| User data | `%LOCALAPPDATA%\Dumplyzer\` |
| Database | `%LOCALAPPDATA%\Dumplyzer\memscope.db` |
| Logs | `%LOCALAPPDATA%\Dumplyzer\logs\` |
| Cache | `%LOCALAPPDATA%\Dumplyzer\cache\` |
| Artifacts | `%LOCALAPPDATA%\Dumplyzer\artifacts\` |
| Exports | `%LOCALAPPDATA%\Dumplyzer\exports\` |
| Signature Detection rules | `%LOCALAPPDATA%\Dumplyzer\rules\yara\` (`bundled\` shipped rules, `custom\` user rules) |
| Optional tools | `%LOCALAPPDATA%\Dumplyzer\tools\` |
| Analysis output | `%LOCALAPPDATA%\Dumplyzer\analysis\` |

Override the data directory with `DUMPLYZER_DATA_DIR` (or the legacy `MEMSCOPE_DATA_DIR` alias) only for tests or support.

Evidence files stay where you imported them. Dumplyzer stores metadata and extracted artifacts, not a copy of the memory image.

If `%LOCALAPPDATA%\MemScope\memscope.db` already exists and `%LOCALAPPDATA%\Dumplyzer\memscope.db` does not, first launch copies the older data directory into the new location. The source is not deleted.

## Analysis capabilities

**Memory dump**

- **Volatility 3** — bundled in the engine runtime.
- **PE Extraction** — dedicated workflow that reconstructs EXE/DLL images from process memory (Volatility 3 `windows.pedump` / VAD MZ / optional `windows.dumpfiles`). Output is labeled **Extracted PE Artifact**, not malware. Files are stored under `analysis\pe_extraction\<run-id>\`. Original evidence is not modified or executed.
- **bulk_extractor** — bundled official Windows EXE (`bulk_extractor64.exe` from [simsong/bulk_extractor](https://github.com/simsong/bulk_extractor) v2.2.0). GPL-3.0-or-later; Dumplyzer invokes it as a separate process and ships corresponding source beside the EXE. It scans the imported memory dump (read-only) and stores raw feature files under `analysis\bulk_extractor\<run-id>\`. Extracted URLs, domains, IPs, emails, and similar strings are IOC *candidates*, not confirmed malicious findings. A user-supplied EXE under `tools\` can override the bundled binary. Dumplyzer never downloads it at runtime.
- **Signature Detection (memory)** — bundled yara-python **4.5.4** scans the original dump with memory-oriented rules. This is an explicit operation; PE extraction does not run it automatically.

**Extracted PE / artifact**

- **Signature Detection (artifact)** — same bundled engine, artifact/PE-oriented rules, against extracted files only. Copy extra `.yar` / `.yara` files into `%LOCALAPPDATA%\Dumplyzer\rules\yara\custom\`. Custom rules are never overwritten on upgrade.
- **CAPA** — bundled official Windows standalone EXE (Mandiant CAPA **v9.4.0**, Apache-2.0). Analyzes extracted PE artifacts and reports *capabilities*, not malware verdicts.
- **FLOSS** — bundled official Windows standalone EXE (Mandiant FLOSS **v3.1.1**, Apache-2.0). Extracts static and deobfuscated strings from extracted PE artifacts. Strings are not malware findings.

None of these tools are downloaded at runtime. Extracted PE files are never executed automatically. Full Analysis does not auto-run Signature Detection / CAPA / FLOSS / bulk_extractor / PE Extraction.

## Upgrade behavior

- Application version **0.1.0** is the first packaged release.
- SQLite migrations are additive. Opening an older `memscope.db` upgrades the schema (currently to **v12**) and keeps existing evidence rows.
- Uninstalling the application is not supposed to delete `%LOCALAPPDATA%\Dumplyzer\` user data.
- If a previous development build stored a database under `%APPDATA%\com.memscope.workbench\` or `%LOCALAPPDATA%\MemScope\`, first launch copies it into `%LOCALAPPDATA%\Dumplyzer\` when the new database does not yet exist. The source is not deleted.

## Evidence handling

Treat memory images, dumps, and extracted artifacts as hostile. Dumplyzer does not execute them. Exports are written only under the user data `exports\` directory.

## Limitations

- Windows x64 only. Linux is not a supported release target.
- 0.1.0 installers are **unsigned**. SmartScreen or organization policy may warn on first run.
- WebView2 Evergreen is required. If it is missing, the installer bootstrapper needs Internet to download it.
- Signature Detection, CAPA, FLOSS, bulk_extractor, and PE Extraction are explicit jobs. They are not a malware verdict.

Architecture: [ARCHITECTURE.md](ARCHITECTURE.md). Security notes: [SECURITY.md](SECURITY.md).

## Developer build

See [CONTRIBUTING.md](CONTRIBUTING.md) for a source checkout.

React/Tailwind iteration on the **development host** (Vite HMR, no installer rebuild, does not touch the clean VM):

```powershell
cd app\desktop
npm run tauri dev
```

Windows installer production:

```powershell
.\scripts\windows\build-release.ps1
```

Details, pinned versions, and verification: [docs/windows-release.md](docs/windows-release.md).

Clean-machine checklist: [docs/clean-machine-validation.md](docs/clean-machine-validation.md).

## License

Dumplyzer application source is licensed under the Apache License 2.0. See [LICENSE](LICENSE).

The Windows installer also redistributes third-party components under their own terms (CPython PSF, Volatility 3 VSL, pefile MIT, bulk_extractor GPLv3, Mandiant CAPA/FLOSS Apache-2.0). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Dumplyzer does not relicense Volatility 3.

PE-sieve and mal_unpack are not part of Dumplyzer. bulk_extractor v2.2.0 is redistributed as a separate GPLv3 program with corresponding source. CAPA v9.4.0 and FLOSS v3.1.1 official Windows standalones are redistributed under Apache-2.0.

