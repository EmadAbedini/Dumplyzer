# Third-party notices

Dumplyzer application source (`app/`, `engine/memscope_engine/`, `tests/` except vendored
fixtures, and project documentation) is licensed under Apache-2.0. See `LICENSE`.

The Windows installer also redistributes third-party components. The notes below
are taken from **package metadata present in this repository / prepared runtime**,
not from assumed licenses.

## Redistributed with the Windows engine runtime

| Component | Version | Metadata inspected | License as recorded |
|-----------|---------|--------------------|---------------------|
| CPython embeddable (Windows x64) | 3.12.10 | `app/desktop/resources/runtime/LICENSE.txt` after `prepare-engine-runtime.ps1`; Python.org SPDX `licenseConcluded: PSF-2.0` | Python Software Foundation License (PSF) as shipped in the embeddable zip |
| volatility3 | 2.28.0 | `volatility3-2.28.0.dist-info/METADATA` field `License: VSL`; `LICENSE.txt` titled “Volatility Software License Version 1.0 dated October 3, 2019” | Volatility Software License 1.0 (Volatility Foundation). Full text: https://www.volatilityfoundation.org/license/vsl-v1.0 |
| pefile | 2024.8.26 | `pefile-2024.8.26.dist-info/METADATA` field `License: MIT`; `LICENSE` is the MIT License, Copyright (c) 2004-2024 Ero Carrera | MIT |
| yara-python | 4.5.4 | `yara_python-4.5.4.dist-info/METADATA` field `License: Apache 2.0`; libyara is BSD-3-Clause (VirusTotal / Victor M. Alvarez) | Apache-2.0 (Python bindings). libyara remains BSD-3-Clause. |

Volatility 3’s VSL is **not** Apache-2.0. Redistribution of Volatility 3 must keep that license text (the runtime payload includes `LICENSE.txt`). Dumplyzer does not relicense Volatility.

## Not redistributed

| Component | Notes |
|-----------|--------|
| PE-sieve | Not integrated. Previously considered as a user-supplied optional EXE; Dumplyzer does not ship or invoke it. |
| mal_unpack | Not integrated. Previously considered as a user-supplied optional EXE; Dumplyzer does not ship or invoke it. |

## Redistributed bulk_extractor (separate program)

| Component | Version | Metadata inspected | License as recorded |
|-----------|---------|--------------------|---------------------|
| bulk_extractor | 2.2.0 | Upstream `LICENSE.md` at tag v2.2.0; official GitHub release asset `bulk_extractor64.exe` (SHA-256 `dfcc678ee3b7da111e8fba6259c4e842ffffcbe42dd96e6c6e6cc238d74bd911`); corresponding source `bulk_extractor-2.2.0.tar.gz` | **GPL-3.0-or-later** for post-NPS project-authored code. Original NPS material described in `LICENSE.md` is not subject to U.S. copyright. Dumplyzer invokes the EXE as a separate process and does not link against it. License texts and corresponding source are shipped under `resources/tools/bulk_extractor/`. |

## Redistributed CAPA and FLOSS (separate programs)

| Component | Version | Metadata inspected | License as recorded |
|-----------|---------|--------------------|---------------------|
| CAPA | 9.4.0 | Official GitHub Windows zip `capa-v9.4.0-windows.zip` (SHA-256 `670ab1a58b81f59cb57533bf4021ac1e7033fbe9b5d5cc180f796976081e3bb5`); upstream `LICENSE.txt` at tag v9.4.0 | **Apache-2.0**. Dumplyzer invokes `capa.exe` as a separate process against extracted PE artifacts only. License text is shipped under `resources/tools/capa/`. |
| FLOSS | 3.1.1 | Official GitHub Windows zip `floss-v3.1.1-windows.zip` (SHA-256 `6c71089b8c629c69424b042769f1565f71adc6cd24b2f8d3713c96fa7fdac2fb`, as recorded in the winget installer manifest); upstream `LICENSE.txt` at tag v3.1.1 | **Apache-2.0**. Dumplyzer invokes `floss.exe` as a separate process against extracted PE artifacts only. License text is shipped under `resources/tools/floss/`. |

## Other build-time / UI dependencies
Frontend (`app/frontend/package-lock.json`) and desktop (`app/desktop/Cargo.lock`, `package-lock.json`) packages record their own license fields (commonly MIT and Apache-2.0 for Tauri/React/Vite). Those lockfiles are the source of truth. This file does not invent license names for packages whose metadata was not opened for this notice.

## Installer toolchain (not shipped to end users)

WiX Toolset 3.14.1 binaries are recorded for optional MSI experiments on the **build machine** only (`packaging/windows/runtime-manifest.json`). The shipped installer is NSIS, cached by the Tauri 2.11 CLI. They are not Dumplyzer application code.
