# Clean-machine validation (Windows x64)

Product branding is **Dumplyzer**. The 2026-09-07 run below recorded a previous **MemScope** installer and is kept as a historical result. Repeat the procedure with `Dumplyzer_0.1.0_x64-setup.exe` / `dumplyzer.exe` and `%LOCALAPPDATA%\Programs\Dumplyzer\` / `%LOCALAPPDATA%\Dumplyzer\`.

Use a Windows 10 21H2+ or Windows 11 **x64** VM or spare host that does **not** have:

- developer Python
- Node.js
- Rust / cargo
- a Dumplyzer source checkout
- yara-python
- a separately installed CAPA / FLOSS / bulk_extractor / PE-sieve / mal_unpack

A memory image is not required. Do not fabricate forensic results.

## Status (2026-09-07)

**CLEAN-MACHINE PASS WITH LIMITATIONS**

Executed from the packaging host over SSH against a VMware Windows 11 x64 guest. Feature scope remained frozen; no product code was changed. NSIS `MemScope_0.1.0_x64-setup.exe` was transferred and installed. The application launched as an end user from the Start menu, used the bundled CPython runtime (not host/Store Python), and did not require the source tree.

Do not treat this as a substitute for Authenticode signing or for MSI / WebView2-absent testing.

### Validation target (VM)

| Item | Value |
|------|--------|
| Role | Clean-machine install target (not the build host) |
| Hypervisor | VMware Workstation (`Windows 11 x64.vmx`) |
| Access | SSH from host to `192.168.12.133` (Ethernet0) |
| OS | Microsoft Windows 11 Pro **10.0.26100** x64 |
| Computer name | JOHN |
| Interactive user | console session 1, logged on |
| Developer Python | Absent (only 0-byte WindowsApps Store aliases for `python.exe` / `python3.exe`) |
| Node.js / npm | Absent |
| Rust / cargo | Absent |
| Git / MSVC / VS | Absent |
| MemScope source | Absent |
| MemScope before test | Not installed |
| YARA / PE-sieve / mal_unpack | Absent |
| WebView2 | Present — Evergreen **141.0.3537.57** (supported launch path) |
| Snapshot before install | **Not taken.** `vmrun snapshot` requires the VMware disk-encryption password; the SSH credential is not that password. |

### Build host (not the clean machine)

| Item | Value |
|------|--------|
| OS | Windows NT 10.0.26200.0 (Windows 11 Pro) x64 |
| Git HEAD | `4b610774a356debc7f2f2c8378e246ec5c41f5b7` |
| Note | Previously recorded NSIS/MSI files were **not on disk**. Host `cargo`/`rustc` were also missing. Rust **1.98.1** (`x86_64-pc-windows-msvc`) was restored on the **host only**, then `scripts\windows\build-release.ps1 -SkipRuntime` rebuilt installers from the existing bundled runtime. Nothing was rebuilt on the VM. |

### Installer under test

| Item | Value |
|------|--------|
| File | `MemScope_0.1.0_x64-setup.exe` (NSIS per-user) |
| Size | 13.3 MB (13,948,576 bytes) |
| SHA-256 | `9c8aed368da3f9481bee9f56b393b8f6c55bf6f8e21f1d11769d69ab566daac4` |
| Host hash = VM hash after SCP | Yes |
| Authenticode | NotSigned (expected for 0.1.0) |
| MSI also produced, **not installed** | `MemScope_0.1.0_x64_en-US.msi` 17.6 MB SHA-256 `7ba6d2f578970c79f7d86acca997b4a03d014ff3535fceff112ae155f8eb6fe8` |
| Install command | NSIS silent `/S` (no operator at the GUI wizard). Default per-user layout, no custom `INSTDIR`. |

### Installed layout

```
%LOCALAPPDATA%\Programs\MemScope\
  memscope.exe
  uninstall.exe
  resources\runtime\     # bundled CPython 3.12.10 + site-packages
  resources\tools\README.txt
```

Start menu shortcut: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\MemScope.lnk`  
Uninstall registry: HKCU DisplayName `MemScope`, DisplayVersion `0.1.0`, InstallLocation the path above.

The conceptual docs still say `runtime\` next to the EXE. The packaged tree is `resources\runtime\`. The desktop launcher resolved `resources\runtime\python.exe` correctly (`python -m memscope_engine` as a child of `memscope.exe`).

---

## Pass / fail log

| # | Check | Result | Evidence |
|---|--------|--------|----------|
| 1 | Copy only the NSIS installer onto the VM | **PASS** | SCP of `MemScope_0.1.0_x64-setup.exe` only. SHA-256 matched host. No source tree, no Node/Rust/Python toolchain installed on the VM. |
| 2 | Run the installer | **PASS WITH LIMITATION** | `/S` silent because SSH cannot click the NSIS wizard. Exit code 0. Per-user install, no elevation. |
| 3 | Install path `%LOCALAPPDATA%\Programs\MemScope\` | **PASS** | Path confirmed. Runtime lives under `resources\runtime\` (Tauri resource dir), not `runtime\` beside the EXE. |
| 4 | Launch from Start menu | **PASS** | `.lnk` exists. Interactive-session launch: process started, window title **MemScope**. |
| 5 | First launch created `%LOCALAPPDATA%\MemScope\` | **PASS** | Created `logs`, `artifacts`, `cache`, `exports`, `yara_rules`, `tools`, `tmp`, and `memscope.db` (376,832 bytes). |
| 6 | Empty Evidence | **PASS WITH LIMITATION** | `evidence.list` returned `items: []`. GUI window titled MemScope loaded. The Evidence React tab was not click-driven; no memory image was imported. |
| 7 | Engine smoke / Volatility / Plugin Explorer | **PASS** | Packaged `smoke.e2e` `ok=true`. `volatility.init` ok. Volatility **2.28.0** from `...\resources\runtime\Lib\site-packages\volatility3`. `plugins.list`: **181** plugins, **14** import failures (expected without `full` extras). Engine child: bundled `python.exe -m memscope_engine`, parent = `memscope.exe`. Python **3.12.10**, `MEMSCOPE_PACKAGED=true`. |
| 8 | Optional providers unavailable | **PASS** | YARA: `available=false`, reason `yara-python is not installed`. PE-sieve / mal_unpack: `available=false`, tools-dir missing EXE. No `yara.pyd` / yara-python package; no `pe-sieve*.exe` / `mal_unpack*.exe` in the install tree. Volatility logs: yarascan not available. |
| 9 | Export HTML / JSON / CSV | **PASS** | `export.options` formats `json,csv,html`, `pdf=false`, destination application data `/exports`. Generate without evidence queued a job that **failed** with `evidence_missing` / "Evidence record not found." (isolated data dir; poll 0). No findings invented. |
| 10 | Logs under `%LOCALAPPDATA%\MemScope\logs\` | **PASS** | `logs\engine.jsonl` exists. First GUI launch logged `engine initialized` at 2026-09-07T08:42:01Z. |
| 11 | Clean process exit | **PASS WITH LIMITATION** | Interactive `CloseMainWindow` on the Start-menu instance: window closed, `memscope.exe` and bundled `python.exe` not left running. `CloseMainWindow` from an SSH session **cannot** close a console-session GUI (Windows session isolation), which is an environment limitation, not a packaging bug. |
| 12 | Re-launch preserves DB | **PASS** | Second launch: `memscope.db` still present, size unchanged (376,832). SQLite `schema_meta.schema_version` = **9**. |
| 13 | Bundled Python, not Store/dev Python | **PASS** | `sys.executable` is install-tree `resources\runtime\python.exe`. `python312._pth` enables `Lib\site-packages` + `import site`. Store `python.exe` is a 0-byte alias. |
| 14 | SQLite + IPC | **PASS** | JSON-RPC `health` / `smoke.e2e` / `app.paths` against the packaged engine. DB tables include evidence, jobs, exports, plugin_*, yara_*, pe_sieve_*, mal_unpack_*. `app.paths.root` = `%LOCALAPPDATA%\MemScope`. |
| 15 | Data vs install separation | **PASS** | No `memscope.db` in the install directory. Mutable data only under `%LOCALAPPDATA%\MemScope\`. |
| 16 | No source-tree / host-toolchain dependency | **PASS** | VM has no repo, no cargo/node/git. Engine modules load from the install `site-packages`. `MEMSCOPE_ENGINE_PYTHON` unset. |
| 17 | MSI install | **Not run** | NSIS is the documented preferred per-user path. |
| 18 | WebView2 missing + offline | **Not run** | WebView2 was already present. Documented unsupported environment remains untested. |

---

## Limitations (not treated as packaging blockers)

1. **No VM snapshot** — VMware encryption password was not available to `vmrun`.
2. **Silent NSIS `/S`** — not a click-through wizard.
3. **No UI click automation** for Plugin Explorer / Evidence / Export menus. Those surfaces were validated through the same JSON-RPC methods the desktop uses, plus a visible `MemScope` window from the Start menu shortcut.
4. **MSI not installed.**
5. **WebView2-absent offline launch not tested** (WebView2 141 already present).
6. **Installers unsigned** — expected; SmartScreen may still warn on other machines (SCP did not attach Mark of the Web).
7. **Docs vs tree:** install layout is `resources\runtime\` rather than `runtime\` beside the EXE. Runtime resolution worked.
8. **Stale job row:** an `export_report` job left `status=running` in the real user DB after an engine process was killed mid-job during probing. A fresh engine in an isolated data dir failed the same missing-evidence export immediately with `evidence_missing`. Pre-existing job-manager behavior (no crash-recovery of `running` rows), not a clean-machine packaging failure.
9. **Host rebuild:** validation used newly produced NSIS from HEAD `4b61077` + existing runtime, because the previously recorded installer files were gone.

## Procedure (when a clean VM exists)

1. Copy only the NSIS `Dumplyzer_*-setup.exe` (preferred) or the MSI onto the machine.
2. Run the installer without extra command-line flags.
3. Confirm install path:
   - NSIS: `%LOCALAPPDATA%\Programs\Dumplyzer\`
   - MSI: `%ProgramFiles%\Dumplyzer\` (elevation likely)
4. Launch Dumplyzer from the Start menu.
5. Confirm first launch created `%LOCALAPPDATA%\Dumplyzer\` (`logs`, `artifacts`, `cache`, `exports`, `yara_rules`, `tools`). If an older `%LOCALAPPDATA%\MemScope\` database exists and the new database does not, the copy into Dumplyzer should appear without deleting the source.
6. Empty Evidence: the UI should load without an imported image. A ~2 second Dumplyzer splash should appear first.
7. If the UI exposes smoke/health via developer tools, `smoke.e2e` / `volatility.init` should report `ok` and Volatility **2.28.0**. Otherwise, confirm Plugin Explorer lists plugins (dynamic discovery).
8. Memory-dump providers: Volatility 3 and PE Extraction should be available (bundled engine). bulk_extractor, CAPA, and FLOSS should be available from the installer bundle without a manual download. YARA should be **unavailable** (no yara-python). PE-sieve / mal_unpack must not appear in the UI.
9. Export options should list HTML / JSON / CSV. Generating a report without evidence may fail with an actionable error; that is acceptable. Do not invent findings.
10. Open `%LOCALAPPDATA%\Dumplyzer\logs\` and confirm engine logs exist.
11. Exit Dumplyzer. Confirm `dumplyzer.exe` and `python.exe` are not left running.
12. Re-launch. Existing `memscope.db` must still be present (upgrade/preservation).

When a memory dump is available on the clean machine, also record:

1. Import the dump (read-only).
2. Run PE Extraction; confirm extracted EXE/DLL counts and that files are labeled extracted PE artifacts.
3. Select an extracted PE and run Signature Detection, CAPA, and FLOSS. Signature Detection should be Available. Also run a memory-dump Signature Detection scan from Overview.
4. Confirm provenance: dump → process/PID → extracted PE → tool result.
5. Generate an HTML/JSON export and confirm PE Extraction / CAPA / FLOSS sections.

Record OS build, installer filename, SHA-256, and each step as pass/fail. Do not mark this document as passed unless the run happened. The 2026-09-07 historical table above is a previous MemScope NSIS run and does not cover PE Extraction / CAPA / FLOSS.
