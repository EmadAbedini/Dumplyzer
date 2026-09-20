# Clean-machine validation (Windows x64)

Product branding is **Dumplyzer**. There is one end-user installer: `Dumplyzer_0.1.0_x64-setup.exe`. Default install layout is `%ProgramFiles%\Dumplyzer\` on the Windows system drive, with user data in `%LOCALAPPDATA%\Dumplyzer\`.

Use a Windows 10 21H2+ or Windows 11 **x64** VM or spare host that does **not** have:

- developer Python
- Node.js
- Rust / cargo
- a Dumplyzer source checkout
- yara-python
- a separately installed CAPA / FLOSS / bulk_extractor / PE-sieve / mal_unpack

A memory image is not required. Do not fabricate forensic results.

## Status (2026-09-20, offline NSIS)

**CLEAN-MACHINE OFFLINE PASS WITH LIMITATIONS**

Executed from the packaging host over SSH against the Windows 11 x64 guest at `192.168.12.133`. Only `Dumplyzer_0.1.0_x64-setup.exe` was copied onto the guest for install. Outbound traffic was blocked with a Windows Firewall rule before install (`ping 8.8.8.8` failed). No Python, Node.js, Rust, Git, Volatility, YARA, CAPA, FLOSS, or bulk_extractor was installed by hand. Nothing was downloaded during install.

WebView2 Evergreen **153.0.4234.48** was already present. `setup.exe --force-uninstall` exited **93** and left the runtime installed, so the packed offline WebView2 payload was **not** exercised as a first-time WebView2 install. The generated NSIS script is `INSTALLWEBVIEW2MODE "offlineInstaller"` and packs `MicrosoftEdgeWebView2RuntimeInstallerX64.exe` (213,053,648 bytes). The installer does not use `downloadBootstrapper` / `embedBootstrapper`.

Windows 10 was **not** install-tested. Documented support is Windows 10 21H2+ / Windows 11 x64; the WebView2 Evergreen technical floor is Windows 10 1809 (build 17763). Authenticode remains unsigned.

### Validation target (VM)

| Item | Value |
|------|--------|
| Role | Clean-machine offline install target (not the build host) |
| Access | SSH from host to `192.168.12.133` |
| OS | Microsoft Windows 11 Pro **10.0.26100** x64 |
| Computer name | JOHN |
| Interactive user | `John Doe` |
| Developer Python / Node / Rust / Git | Absent |
| Dumplyzer source | Absent |
| Dumplyzer before test | Previous per-user `%LOCALAPPDATA%\Programs\Dumplyzer` uninstalled first. `%ProgramFiles%\Dumplyzer` was absent. |
| Internet during install | Unavailable (outbound firewall block `DumplyzerOfflineTestBlock`) |
| WebView2 before test | Present — Evergreen **153.0.4234.48** (could not be removed; exit 93) |
| Manual prerequisites installed | None |

### Installer under test

| Item | Value |
|------|--------|
| File | `Dumplyzer_0.1.0_x64-setup.exe` (single NSIS per-machine EXE) |
| Host path | `app\desktop\target\release\bundle\nsis\Dumplyzer_0.1.0_x64-setup.exe` |
| Size | 312.3 MB (327,510,849 bytes) |
| SHA-256 | `49bd1f759986f92de17a39589aed2dd122d612c379b3313f355de15e31b10f81` |
| Host hash = VM hash after SCP | Yes |
| Authenticode | NotSigned (expected for 0.1.0) |
| WebView2 payload | Packed Evergreen standalone `MicrosoftEdgeWebView2RuntimeInstallerX64.exe` (213,053,648 bytes, SHA-256 `ad9b350625e132481bc0953eee9e032810134df9fedbd7be364c3f4e0e4dbd64`) |
| Installer / app / uninstaller Explorer icon | Dumplyzer `icon.ico` (associated-icon hash `90c7b1918bab7e02794718a709dd49a0988e0a297b236d26c5939ccf0f44bf74` on setup EXE, `dumplyzer.exe`, and `uninstall.exe`) |
| Install command | NSIS silent `/S` (SSH cannot click the wizard). Default `%ProgramFiles%\Dumplyzer`. |

### Installed layout

```
%ProgramFiles%\Dumplyzer\
  dumplyzer.exe
  uninstall.exe
  resources\runtime\     # bundled CPython 3.12.10 + site-packages (Volatility 2.28.0, yara-python 4.5.4)
  resources\tools\       # bulk_extractor 2.2.0, CAPA 9.4.0, FLOSS 3.1.1
  resources\rules\       # bundled Signature Detection YARA rules
```

Start menu shortcut: `%ProgramData%\Microsoft\Windows\Start Menu\Programs\Dumplyzer.lnk` (target `C:\Program Files\Dumplyzer\dumplyzer.exe`).
Silent install also created `%Public%\Desktop\Dumplyzer.lnk`.
Uninstall registry: HKLM DisplayName `Dumplyzer`, DisplayVersion `0.1.0`, DisplayIcon `dumplyzer.exe`.
User data remained under `%LOCALAPPDATA%\Dumplyzer\`. Bundled Python `sys.path` contained no development-host paths.

### Pass / fail log (2026-09-20 offline)

| # | Check | Result | Evidence |
|---|--------|--------|----------|
| 1 | Copy only the NSIS installer onto the VM | **PASS** | SCP of `Dumplyzer_0.1.0_x64-setup.exe`. SHA-256 matched host. |
| 2 | Internet unavailable | **PASS** | Outbound block before install. `ping 8.8.8.8` = False. |
| 3 | Prerequisites not installed by hand | **PASS** | No Python/Node/Rust/WebView2/tools installed to make the test pass. |
| 4 | Run the installer | **PASS** | `/S` exit 0. `dumplyzer.exe` and bundled `python.exe` under Program Files. |
| 5 | WebView2 provided by installer | **PASS WITH LIMITATION** | Offline standalone is packed. Guest already had WebView2 153; uninstall failed (exit 93), so first-time WebView2 install was not observed. |
| 6 | Bundled engine / Volatility | **PASS** | Packaged smoke `ok=true`. Volatility **2.28.0**. Python **3.12.10** from `C:\Program Files\Dumplyzer\resources\runtime\python.exe`. **191** plugins. |
| 7 | Bundled optional tools | **PASS** | YARA, PE Extraction, CAPA, FLOSS, bulk_extractor all `available=true`. |
| 8 | Import a test memory image | **PASS** | `evidence.import` of `C:\Users\Public\memscope-import-test.raw` completed. Dump was not copied into Program Files. |
| 9 | Launch from Start Menu | **PASS WITH LIMITATION** | All-users shortcut started `dumplyzer.exe` with child `resources\runtime\python.exe -m memscope_engine`. `engine.jsonl`: `engine initialized` at 2026-09-20T11:48:21Z and again after reinstall at 11:49:07Z. SSH cannot read the interactive-desktop window title. |
| 10 | No development-machine paths | **PASS** | `sys.executable` and Volatility/engine modules are under Program Files. `rootman_in_syspath` False. |
| 11 | Uninstall | **PASS** | `uninstall.exe /S` exit 0. Program Files tree, Start Menu shortcut, and desktop shortcut removed. |
| 12 | Reinstall | **PASS** | Second `/S` exit 0. Shortcuts restored. `dumplyzer.exe` launched again (PID 1888). |

## Status (2026-09-20, earlier per-user online run)

**CLEAN-MACHINE PASS WITH LIMITATIONS (superseded installer)**

Executed from the packaging host over SSH against the Windows 11 x64 guest at `192.168.12.133`. NSIS `Dumplyzer_0.1.0_x64-setup.exe` was the artifact under test. No Python, Node.js, Rust, Git, or Volatility was installed on the guest. WebView2 Evergreen was already present. The installer, Start Menu shortcut, and `dumplyzer.exe` all use Dumplyzer `icons/icon.ico`.

This run used an older **per-user** NSIS (107.9 MB) without the packed Evergreen standalone. It is kept for history. The current end-user installer is the 312.3 MB offline NSIS above.

### Validation target (VM)

| Item | Value |
|------|--------|
| Role | Clean-machine install target (not the build host) |
| Access | SSH from host to `192.168.12.133` |
| OS | Microsoft Windows 11 Pro **10.0.26100** x64 |
| Computer name | JOHN |
| Interactive user | console session 1, `John Doe`, logged on |
| Developer Python | Absent (only 0-byte WindowsApps Store aliases for `python.exe` / `python3.exe`) |
| Node.js / npm / pnpm | Absent |
| Rust / cargo | Absent |
| Git / MSVC | Absent |
| Dumplyzer source | Absent |
| Dumplyzer before test | Not installed |
| Leftover MemScope | Previous `%LOCALAPPDATA%\Programs\MemScope` was uninstalled before this run. `%LOCALAPPDATA%\MemScope` user data remained and was copied into `%LOCALAPPDATA%\Dumplyzer\` on first launch (existing migration behavior). |
| WebView2 | Present — Evergreen **153.0.4234.48** (supported launch path) |

### Installer under test

| Item | Value |
|------|--------|
| File | `Dumplyzer_0.1.0_x64-setup.exe` (NSIS per-user) |
| Host path | `app\desktop\target\release\bundle\nsis\Dumplyzer_0.1.0_x64-setup.exe` |
| Size | 107.9 MB (113,120,281 bytes) |
| SHA-256 | `87479a07c3348d605784a448f3e5c3289bd71c598dfe88f840af6999b5523b93` |
| Host hash = VM hash after SCP | Yes |
| Authenticode | NotSigned (expected for 0.1.0) |
| Installer Explorer icon | Dumplyzer `icon.ico` (associated-icon hash matches `dumplyzer.exe`) |
| MSI also produced, **not installed** | `Dumplyzer_0.1.0_x64_en-US.msi` 119.6 MB (125,431,601 bytes) SHA-256 `108b00ee9d03fa214d752fa632cf1cd6085c6d2c951c57e5cbe8494b9a0cdded` |
| Install command | NSIS silent `/S` (SSH cannot click the wizard). Default per-user layout, no custom `INSTDIR`. |

### Installed layout

```
%LOCALAPPDATA%\Programs\Dumplyzer\
  dumplyzer.exe
  uninstall.exe
  resources\runtime\     # bundled CPython 3.12.10 + site-packages (Volatility 2.28.0, yara-python 4.5.4)
  resources\tools\       # bulk_extractor 2.2.0, CAPA 9.4.0, FLOSS 3.1.1
  resources\rules\       # bundled Signature Detection YARA rules
```

Start menu shortcut: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Dumplyzer.lnk` (target `dumplyzer.exe`, icon index 0).
Uninstall registry: HKCU DisplayName `Dumplyzer`, DisplayVersion `0.1.0`.

### Pass / fail log (2026-09-20)

| # | Check | Result | Evidence |
|---|--------|--------|----------|
| 1 | Copy only the NSIS installer onto the VM | **PASS** | SCP of `Dumplyzer_0.1.0_x64-setup.exe` only. SHA-256 matched host. |
| 2 | Prerequisites absent before install | **PASS** | No Node/Rust/Git/real Python/pnpm. Store `python.exe` is 0 bytes. WebView2 already present. |
| 3 | Run the installer | **PASS WITH LIMITATION** | `/S` silent because SSH cannot click the NSIS wizard. Exit code 0. Per-user, no elevation. |
| 4 | Install path `%LOCALAPPDATA%\Programs\Dumplyzer\` | **PASS** | `dumplyzer.exe`, bundled `resources\runtime\python.exe`, Volatility, tools, and YARA rules present. |
| 5 | Installer and app icons | **PASS** | Setup EXE and `dumplyzer.exe` associated-icon hashes match Dumplyzer artwork. Start Menu `.lnk` uses the EXE icon (index 0). |
| 6 | Bundled engine / Volatility | **PASS** | Packaged `smoke.e2e` `ok=true`. Volatility **2.28.0** from install-tree `resources\runtime`. Python **3.12.10**. `MEMSCOPE_PACKAGED=1`. **191** plugins. |
| 7 | Bundled optional tools | **PASS** | YARA, PE Extraction, CAPA, FLOSS, bulk_extractor all `available=true` from the installer bundle. |
| 8 | Import a test memory image | **PASS** | `evidence.import` of `C:\Users\Public\memscope-import-test.raw` (32 MiB) completed. Evidence row stored the original path; the dump was not copied into the install directory. |
| 9 | Launch from Start Menu | **PASS WITH LIMITATION** | Shortcut launch started `dumplyzer.exe` with child `resources\runtime\python.exe -m memscope_engine`. Engine log: `engine initialized` at 2026-09-20T10:42:31Z. SSH cannot read the interactive-desktop window title (session isolation). |
| 10 | Data vs install separation | **PASS** | Mutable data under `%LOCALAPPDATA%\Dumplyzer\`. No dump files under the Programs install tree. |
| 11 | Uninstall | **PASS WITH LIMITATION** | `uninstall.exe /S` exit 0. Start Menu shortcut and HKCU ARP entry removed. User data kept. Install directory still present immediately after uninstall (nested resource dirs / NSIS `RMDir`). Reinstall succeeded. |

## Status (2026-09-07)

**CLEAN-MACHINE PASS WITH LIMITATIONS (historical MemScope branding)**

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
   - NSIS default: `%ProgramFiles%\Dumplyzer\` (Windows system drive; elevation required)
   - MSI: `%ProgramFiles%\Dumplyzer\` (elevation required)
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
