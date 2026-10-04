# Clean-machine validation (Windows x64)

Confirms that the published NSIS installer runs on a machine that does **not** have
developer Python, Node.js, Rust, a Dumplyzer source checkout, or separately installed
analysis tools.

A memory image is optional. Empty Evidence is a valid state. Do not fabricate forensic results.

## Current installer

| Item | Value |
|------|--------|
| File | `Dumplyzer_0.1.1_x64-setup.exe` |
| Default install | `%ProgramFiles%\Dumplyzer` (elevation required) |
| User data | `%LOCALAPPDATA%\Dumplyzer\` |
| WebView2 | Small Evergreen bootstrapper packed (`embedBootstrapper`). If WebView2 is already present it is skipped. If it is missing, setup asks before downloading the runtime. |
| Authenticode | Unsigned for 0.1.1 |

MSI is not an end-user artifact.

## Latest executed run

**2026-10-04 — PASS** for `Dumplyzer_0.1.1_x64-setup.exe` (current packaging: per-machine NSIS, `embedBootstrapper` WebView2, unsigned).

Install-tested on the same Windows x64 hosts used for 0.1.0:

| Edition | Version | OS build | Experience pack |
|---------|---------|----------|-----------------|
| Windows 11 Pro | 24H2 | 26100.1742 | 1000.26100.18.0 |
| Windows 10 Pro | 22H2 | 19045.2006 | 120.2212.4180.0 |
| Windows 10 Education | 22H2 | 19045.6456 | — |

On each host the 0.1.1 setup installed, the app launched, and the install was usable. Default install path `%ProgramFiles%\Dumplyzer`. User data stayed under `%LOCALAPPDATA%\Dumplyzer\`. The installer remains unsigned; SmartScreen or organization policy may still warn.

This run used the shipping 0.1.1 payload (bundled CPython 3.12.10, Volatility 3 2.28.0, yara-python 4.5.4, CAPA 9.4.0, FLOSS 3.1.1, bulk_extractor 2.2.0). It does not replace a first-time WebView2 download observation: those hosts already had WebView2.

## Previous runs

**2026-09-20 — PASS WITH LIMITATIONS** for `Dumplyzer_0.1.0_x64-setup.exe` on Windows 11 Pro 10.0.26100 x64.

The guest had no developer toolchain. Silent NSIS `/S` installed to Program Files. The bundled
CPython 3.12.10 runtime started Volatility 3 2.28.0 (191 plugins). YARA, PE Extraction, CAPA,
FLOSS, and bulk_extractor reported available from the installer bundle. A test image under
`C:\Users\Public\` imported without copying the dump into Program Files. Uninstall and reinstall
succeeded. User data stayed under `%LOCALAPPDATA%\Dumplyzer\`.

Limitations of that run:

- WebView2 Evergreen was already present, so first-time WebView2 install was not observed.
- The installer under test packed the older offline WebView2 standalone payload. 0.1.1 uses
  `embedBootstrapper` instead.
- The installer is unsigned.

An earlier per-user NSIS (and a MemScope-branded build) was also installed on a Windows 11 guest.
Those results are superseded by the per-machine Dumplyzer installer.

## Procedure

Use a Windows 11 x64 VM or spare host.

1. Copy only `Dumplyzer_*-setup.exe` onto the machine.
2. Run the installer without extra flags (or `/S` when no GUI session is available).
3. Confirm install path `%ProgramFiles%\Dumplyzer\` (`dumplyzer.exe`, `resources\runtime\`,
   `resources\tools\`, `resources\rules\`).
4. Launch Dumplyzer from the Start menu.
5. Confirm first launch created `%LOCALAPPDATA%\Dumplyzer\` (`logs`, `artifacts`, `cache`,
   `exports`, `analysis`, `symbols`, `rules\yara`, `tools`, `tmp`, `webview`, `memscope.db`).
   If `%LOCALAPPDATA%\Dumplyzer\memscope.db` does not exist, first launch copies an older data
   directory from `%LOCALAPPDATA%\MemScope\` or `%APPDATA%\com.memscope.workbench\` when present.
   The source is not deleted.
6. Empty Evidence: the UI should load without an imported image. A short splash should appear first.
7. Memory-dump providers: Volatility 3 and PE Extraction should be available. bulk_extractor,
   CAPA, FLOSS, and Signature Detection should be available from the installer bundle.
8. Export options should list HTML / JSON / Excel / CSV. Generating a report without evidence may fail
   with an actionable error; that is acceptable.
9. Confirm engine logs under `%LOCALAPPDATA%\Dumplyzer\logs\`.
10. Exit. Confirm `dumplyzer.exe` and bundled `python.exe` are not left running.
11. Re-launch. Existing `memscope.db` must still be present.

When a memory dump is available:

1. Import the dump (read-only). Windows analysis asks before downloading the matching kernel PDB
   (Download & Continue) or accepting a local `.pdb` / ISF file.
2. Before PE Extraction or bulk_extractor, exclude `%LOCALAPPDATA%\Dumplyzer\` from real-time
   antivirus. Those jobs write reconstructed EXE/DLL images; scanners may quarantine the output
   and, by attributing the write, `dumplyzer.exe`. See [README](../README.md#antivirus-exclusions-carved-data).
3. Run PE Extraction; confirm extracted files are labeled extracted PE artifacts.
4. Run Signature Detection, CAPA, and FLOSS against an extracted PE, and a memory-dump
   Signature Detection scan from Overview.
5. Generate an HTML, JSON, Excel, or CSV export and confirm those sections appear when the jobs completed.
   From the IOCs view, confirm JSON, Excel, and CSV saves are offered.

Record OS build, installer filename, SHA-256, and each step as pass/fail. Do not mark a new
run as passed unless it happened.
