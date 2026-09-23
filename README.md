<p align="center">
  <img src="docs/assets/dumplyzer-logo.png" alt="Dumplyzer" width="180">
</p>

<h1 align="center">Dumplyzer</h1>
<h3 align="center">Advanced Memory Forensics Platform</h3>

<p align="center">
  <img src="https://img.shields.io/badge/release-v0.1.0-0B3D2E" alt="v0.1.0">
  <img src="https://img.shields.io/badge/platform-Windows%20x64-0078D6?logo=windows&logoColor=white" alt="Windows x64">
  <img src="https://img.shields.io/badge/runtime-offline-0B3D2E" alt="Offline">
  <a href="CONTRIBUTING.md#tests"><img src="https://img.shields.io/badge/engine%20tests-passing-brightgreen" alt="Engine tests passing"></a>
  <a href="CONTRIBUTING.md#tests"><img src="https://img.shields.io/badge/desktop%20tests-passing-brightgreen" alt="Desktop tests passing"></a>
  <a href="CONTRIBUTING.md#tests"><img src="https://img.shields.io/badge/frontend%20build-passing-brightgreen" alt="Frontend build passing"></a>
  <a href="docs/clean-machine-validation.md"><img src="https://img.shields.io/badge/install-Windows%2010%2F11%20x64-brightgreen" alt="Install tested on Windows 10 and 11 x64"></a>
  <a href="https://github.com/EmadAbedini/Dumplyzer"><img src="https://img.shields.io/badge/GitHub-EmadAbedini%2FDumplyzer-181717?logo=github&logoColor=white" alt="GitHub"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="Apache License 2.0"></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-policy-informational" alt="Security policy"></a>
  <a href="https://www.linkedin.com/in/emad-abedini"><img src="https://img.shields.io/badge/LinkedIn-0077B5?logo=linkedin&logoColor=white" alt="LinkedIn"></a>
</p>

Do you want to investigate a memory dump without assembling a forensic toolchain? Do you want processes, network activity, indicators, reconstructed binaries, and signatures in **one local workspace**?

You are in the right place.

**Dumplyzer** is an open-source, offline desktop workbench for memory forensics. It is built for DFIR analysts, threat hunters, and malware researchers who need to move from a raw dump to a structured investigation without sending evidence off the workstation.

<p align="center">
  <a href="docs/assets/screenshots/01-processes.png"><img src="docs/assets/screenshots/01-processes.png" alt="Process list with command lines" width="48%"></a>
  <a href="docs/assets/screenshots/02-network.png"><img src="docs/assets/screenshots/02-network.png" alt="Network artifacts recovered from the dump" width="48%"></a>
</p>
<p align="center">
  <a href="docs/assets/screenshots/03-timeline.png"><img src="docs/assets/screenshots/03-timeline.png" alt="Investigation timeline with time-range histogram" width="48%"></a>
  <a href="docs/assets/screenshots/04-memory.png"><img src="docs/assets/screenshots/04-memory.png" alt="Memory VAD regions for a selected process" width="48%"></a>
</p>

Analysis runs locally. The memory image stays where you imported it. There is no cloud account, no telemetry, and no malware score.

<p align="center">
  <a href="#install"><strong>Install</strong></a> ·
  <a href="#features"><strong>Features</strong></a> ·
  <a href="#windows-kernel-symbols"><strong>Kernel symbols</strong></a> ·
  <a href="#analysis-components"><strong>Analysis components</strong></a> ·
  <a href="#architecture"><strong>Architecture</strong></a> ·
  <a href="#documentation"><strong>Docs</strong></a>
</p>

---

## Features

Dumplyzer is a focused investigation UI, not a command-line wrapper and not a SaaS console.

- **One installer.** Python, the analysis engine, and supporting tools ship inside the Windows package. End users do not install a developer toolchain.
- **Offline by design.** No network listener, no account system, no phone-home. The two optional Microsoft downloads are explicit: WebView2 during setup if it is missing, and a **single kernel PDB** when you start Windows analysis (see [Kernel symbols](#windows-kernel-symbols)).
- **Evidence stays put.** Dumplyzer records path, hash, and metadata. It does not copy the dump into Program Files or the user-data tree.
- **Windows kernel symbols on demand.** Windows memory analysis needs type information for the NT kernel that was running when the dump was taken — the PDB (or Volatility ISF) for **that OS build**, not a generic pack. **Download & Continue** is the recommended path; you can instead browse to a matching file.
- **Windows and Linux images.** Import Windows crash dumps, LiME images, ELF cores, QEMU/VMware snapshots, and raw physical memory. Quick Triage and Complete Analysis run the Windows Volatility pipeline (processes, modules, handles, VAD, and related views). Linux dumps can be imported and examined with Plugin Explorer (`linux.*` plugins).
- **Two analysis modes, plus custom.** **Quick Triage** is a first look (OS/symbol status and the process list). **Complete Analysis** is the evidence-wide pass for processes, command lines, modules, network connections, handles, findings, IOCs, network artifacts, and timeline. **Custom Analysis** runs only the capabilities you select. Heavier jobs stay explicit so a triage run does not walk the whole dump or write reconstructed binaries.
- **Process intelligence.** Process list, command lines, loaded modules/DLLs, open handles, and parent/child relationships (PPID, with a per-process Family view).
- **Network.** Image-wide connections, harvested network indicators, and on-demand PCAP reconstruction (Ethernet/IP records carved from the dump; matching flows can be exported as `.pcap`). Connection metadata alone is not a packet capture.
- **IOCs.** Indicators extracted from stored process, module, network, and handle data — IPs, domains, URLs, mutexes, registry keys, paths, and MD5/SHA-256 hashes.
- **Search and timeline.** Indexed lookup across stored artifacts, plus an investigation timeline with time-range filtering. Search reads what analysis already stored; it does not rescan the dump.
- **Memory regions.** Inspect VAD / virtual-memory regions for a selected PID.
- **Signatures and capabilities.** YARA scans of the dump and/or extracted PE files (42 bundled Dumplyzer rules, plus your own `.yar` / `.yara` files). CAPA reports capabilities of reconstructed PE files — not malware verdicts.
- **Carved strings.** bulk_extractor recovers emails, phone numbers, URLs, IPs, MAC addresses, HTTP logs, AES key candidates, and similar features from the dump.
- **PE reconstruction.** Rebuild EXE/DLL images from process memory. Extracted files are labeled **extracted artifacts**, not malware, and are never executed.
- **Plugin Explorer.** Discover and run supported Volatility 3 plugins from the UI, with cached results and job history.
- **Reports.** Export HTML, JSON, or Excel under the user-data `exports\` directory. HTML reports are static (no JavaScript, no CDN).
- **Hostile-input hygiene.** Memory images and extracted artifacts are treated as untrusted. Dumplyzer does not execute them. Matches, strings, and carved features are investigation indicators — not verdicts.

Complete Analysis does **not** auto-run PE reconstruction, signature detection, CAPA, FLOSS, bulk_extractor, or PCAP reconstruction. Start those from the workspace when you need them.

## Investigation workspace

| View | What you get |
|------|----------------|
| Overview | Case snapshot and coverage of what has already run |
| Processes | Process list, command lines, parent/child, and per-process deep dive |
| Network | Connections, harvested network indicators, optional PCAP reconstruction |
| Modules / Memory | Loaded modules, handles, and VAD regions |
| Findings / IOCs / Search | Heuristics, extracted indicators, and cross-view search |
| Timeline | Investigation timeline built from stored records, with time-range filter |
| Carved Data | Reconstructed PE images and carved feature files |
| Signatures | Memory-dump and artifact signature scans, including your own rules |
| Plugins | Advanced plugin execution against the imported image |
| Export | HTML / JSON / Excel reports of completed analysis |
| Jobs | Background work with real progress when the engine knows it |

A memory image is optional. Empty Evidence is a valid first-launch state.

## Analysis components

Dumplyzer integrates established open-source engines. They are **bundled in the installer** and invoked locally. They are not downloaded when you run a job. The only optional analysis-time download is a Windows kernel PDB, and only after you agree ([Kernel symbols](#windows-kernel-symbols)).

| Capability | Role | Bundled implementation |
|------------|------|------------------------|
| Memory analysis | Processes, modules, network, VAD, plugin explorer | [Volatility 3](https://github.com/volatilityfoundation/volatility3) **2.28.0** (Python APIs, not `vol.py` stdout) |
| PE reconstruction | Rebuild EXE/DLL images from process memory | Engine workflow on top of the memory-analysis runtime (`windows.pedump` / VAD MZ / optional `windows.dumpfiles`) |
| Artifact extraction | Carve URLs, domains, IPs, emails, MAC addresses, HTTP logs, AES key candidates, and similar strings from the dump | [bulk_extractor](https://github.com/simsong/bulk_extractor) **2.2.0** (separate process, GPLv3, corresponding source shipped) |
| Signature detection | Scan the dump and/or extracted PE files | yara-python **4.5.4** plus **42** original Dumplyzer rules (memory + artifact). Copy extra `.yar` / `.yara` files into the custom rules folder |
| Capability analysis | Report capabilities of reconstructed PE files | [CAPA](https://github.com/mandiant/capa) **9.4.0** (separate process) |
| String analysis | Static and deobfuscated strings from reconstructed PE files | [FLOSS](https://github.com/mandiant/flare-floss) **3.1.1** (separate process) |

## Architecture

```
React + TypeScript UI
        │  Tauri commands / events
Tauri 2 desktop shell
        │  JSON-RPC (NDJSON over stdio — no localhost HTTP port)
Local Python engine
        │  read-only access
Memory image on disk
```

The UI consumes normalized application data. Forensic output lives under `%LOCALAPPDATA%\Dumplyzer\`, never inside the install tree.

```
app/frontend/     Investigation UI (Vite, React, TypeScript)
app/desktop/      Tauri 2 shell, installer, bundled resources
engine/           Analysis engine (Python package name: memscope_engine)
tests/engine/     Engine tests
packaging/        Windows runtime manifest
scripts/          Release and tool-prep scripts
docs/             Release and clean-machine validation
```

Details: [ARCHITECTURE.md](ARCHITECTURE.md).

## Install

There are two ways to get Dumplyzer. **If you want to use the product, use the Windows installer.** Building from source is for contributors.

### 1. Windows installer (recommended)

You do **not** need Python, Node, Rust, or a source checkout. This is the supported way to run Dumplyzer.

1. Download `Dumplyzer_0.1.0_x64-setup.exe` from [Releases](https://github.com/EmadAbedini/Dumplyzer/releases).
2. Run the installer. It defaults to `%ProgramFiles%\Dumplyzer` and requires administrator rights.
3. Launch **Dumplyzer** from the Start menu.

The Microsoft Edge **WebView2** runtime is required. If it is already installed, setup skips it. If it is missing, setup asks whether to download it now or whether you will install WebView2 yourself and run the installer again. Cancelling that download exits setup.

Windows dumps also need a matching kernel PDB the first time you analyze a given OS build. That is handled in the app, not by the installer — see [Windows kernel symbols](#windows-kernel-symbols).

0.1.0 installers are **unsigned**. SmartScreen or organization policy may warn on first run.

#### Supported platform

| | |
|---|---|
| Desktop app | Windows 10 22H2+ / Windows 11, x64 |
| Arch | x64 only |
| Evidence | Windows and Linux memory images (crash dump, LiME, ELF core, raw / QEMU / VMware, …) |
| App | **0.1.0** |
| Engine runtime | Bundled CPython **3.12.10** |
| Linux / macOS hosts | Not a release target yet |

Additional hosts where the installed app was run:

| Edition | Version | OS build | Experience |
|---------|---------|----------|------------|
| Windows 11 Pro | 24H2 | 26100.1742 | Windows Feature Experience Pack 1000.26100.18.0 |
| Windows 10 Pro | 22H2 | 19045.2006 | Windows Feature Experience Pack 120.2212.4180.0 |
| Windows 10 Education | 22H2 | 19045.6456 | |

A separate clean-machine NSIS checklist (no developer toolchain on the guest) is recorded for Windows 11 Pro 10.0.26100 in [docs/clean-machine-validation.md](docs/clean-machine-validation.md).

### 2. Build from source

Use this path only if you are developing Dumplyzer. It needs a full Windows developer toolchain. For everyday use, go back to [the installer](#1-windows-installer-recommended).

#### Prerequisites

| Tool | Version |
|------|---------|
| Windows | x64 |
| Python | **3.12.10** (`py -3.12`) — do not use 3.13 for the engine |
| Node.js / npm | **22.18.0** / 10.9.3 |
| Rust / cargo | **1.98.1** (`stable-x86_64-pc-windows-msvc`) |
| MSVC Build Tools | VS 2022 |
| WebView2 | Evergreen |

#### Run the desktop app

From the repository root:

```powershell
py -3.12 -m venv engine\.venv
.\engine\.venv\Scripts\python.exe -m pip install -U pip
.\engine\.venv\Scripts\python.exe -m pip install -e ".\engine[dev]"

cd app\frontend
npm ci
cd ..\desktop
npm ci
npm run tauri dev
```

That starts the investigation UI against the local Python engine. To keep this session's data separate from an installed copy of Dumplyzer:

```powershell
$env:DUMPLYZER_DATA_DIR = "$env:TEMP\dumplyzer-dev"
cd app\desktop
npm run tauri dev
```

#### Produce the Windows installer

This step is heavier: it downloads the pinned CPython embeddable runtime and bundled tools, then builds the NSIS setup EXE.

```powershell
.\scripts\windows\build-release.ps1
```

The installer lands at `app\desktop\target\release\bundle\nsis\Dumplyzer_0.1.0_x64-setup.exe`.

Tests, engine notes, and packaging details: [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/windows-release.md](docs/windows-release.md).

## Windows kernel symbols

Volatility 3 cannot walk a Windows dump without type information for the kernel that produced it. That information is **build-specific**: a dump from Windows 11 24H2 (for example build 26100.1742) needs the PDB for that kernel, not a Windows 10 22H2 symbol file, and not a generic "Windows symbols" archive.

The NSIS installer does **not** ship Microsoft PDBs or the large Volatility `windows.zip` pack. Dumplyzer asks the first time you start **Quick Triage**, **Complete Analysis**, or **Custom Analysis** on a Windows image whose symbols are not already cached. Linux images do not use this path.

Two ways to continue. **Download is the recommended one.**

| Path | When to use |
|------|-------------|
| **Download & Continue** (recommended) | The machine can reach Microsoft. Dumplyzer fetches **only that dump's kernel PDB**, verifies it, converts it to a Volatility ISF, and caches it. Later dumps from the same build reuse the cache. Faster, and you do not have to hunt for the right file. |
| **Browse File** | Air-gapped or policy-blocked networks, or you already have the matching `.pdb` or ISF (`.json` / `.json.xz` / `.json.gz`). The file must match the captured kernel; a PDB from a different build will not analyze that dump. |

Download never starts by itself. You confirm in the dialog. Closing the prompt keeps the imported dump; you can run analysis again when you are ready.

Cached symbols live under `%LOCALAPPDATA%\Dumplyzer\symbols\`, not in Program Files. Uninstall does not remove them unless **Delete app data** is checked.

## Data locations

Install binaries and user data are separate.

| Kind | Location |
|------|----------|
| Install | `%ProgramFiles%\Dumplyzer\` |
| User data | `%LOCALAPPDATA%\Dumplyzer\` |
| Database | `%LOCALAPPDATA%\Dumplyzer\memscope.db` |
| Logs / cache / artifacts / exports | under the user-data directory |
| UI profile (WebView2) | `%LOCALAPPDATA%\Dumplyzer\webview\` |
| Kernel symbols | `%LOCALAPPDATA%\Dumplyzer\symbols\` (per-build PDB/ISF after Download & Continue, or a file you browse to) |
| Signature rules | `%LOCALAPPDATA%\Dumplyzer\rules\yara\` (`bundled\` refreshed on upgrade, `custom\` never overwritten) |

Override the data directory with `DUMPLYZER_DATA_DIR` only for tests or support.

Uninstall keeps user data unless **Delete app data** is checked. That option removes `%LOCALAPPDATA%\Dumplyzer\` (database, logs, cache, WebView2 profile) and leftover identifier folders such as `%LOCALAPPDATA%\com.dumplyzer.workbench\`. SQLite migrations are additive; opening an older `memscope.db` upgrades the schema and keeps existing evidence.

This product was previously named MemScope. The engine import path remains `memscope_engine`, and the database file remains `memscope.db`. If `%LOCALAPPDATA%\MemScope\memscope.db` exists and the Dumplyzer database does not, first launch copies the older data directory. The source is not deleted.

## Documentation

| Document | Contents |
|----------|----------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Layers, IPC, jobs, schema |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Source setup, tests, packaging notes |
| [SECURITY.md](SECURITY.md) | Process model, path confinement, reporting |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | Redistributed components and licenses |
| [docs/windows-release.md](docs/windows-release.md) | How the NSIS installer is built |
| [docs/clean-machine-validation.md](docs/clean-machine-validation.md) | Clean-machine install checklist |

## Security and limitations

- Treat dumps and extracted artifacts as hostile.
- Dumplyzer does not score malware and does not claim a verdict from signatures, capabilities, or strings.
- The desktop application is Windows x64. Linux and macOS hosts are not a release target yet. Evidence is not limited to Windows dumps.
- Unsigned 0.1.0 artifacts may be blocked by SmartScreen until a signed build is published.
- If WebView2 is absent, setup asks before downloading it. Cancelling that download exits the installer.
- Windows analysis needs the kernel PDB for **that dump's OS build**. Dumplyzer asks before downloading it. **Download & Continue** is the recommended path; you can instead browse to a matching `.pdb` or ISF. See [Windows kernel symbols](#windows-kernel-symbols).

See [SECURITY.md](SECURITY.md).

## License

Dumplyzer application source is licensed under the [Apache License 2.0](LICENSE).

The Windows installer also redistributes third-party components under their own terms (CPython PSF, Volatility Software License, pefile MIT, bulk_extractor GPLv3, CAPA/FLOSS Apache-2.0). Dumplyzer does not relicense those projects. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Acknowledgements

Dumplyzer stands on open-source memory-forensics and reverse-engineering work, including [Volatility 3](https://github.com/volatilityfoundation/volatility3), [bulk_extractor](https://github.com/simsong/bulk_extractor), [CAPA](https://github.com/mandiant/capa), [FLOSS](https://github.com/mandiant/flare-floss), and [YARA](https://github.com/VirusTotal/yara).

---

Developed by [Emad Abedini](https://github.com/EmadAbedini) · [LinkedIn](https://www.linkedin.com/in/emad-abedini)
