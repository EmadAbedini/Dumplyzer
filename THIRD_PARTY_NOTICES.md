# Third-party notices

MemScope application source (`app/`, `engine/memscope_engine/`, `tests/` except vendored
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

Volatility 3’s VSL is **not** Apache-2.0. Redistribution of Volatility 3 must keep that license text (the runtime payload includes `LICENSE.txt`). MemScope does not relicense Volatility.

## Not redistributed

| Component | Notes |
|-----------|--------|
| yara-python | Optional extra. Not installed into the shipped runtime. Upstream license is not reproduced here because the binary/wheel is not bundled. |
| PE-sieve | User-supplied official EXE. Not bundled. Upstream project states BSD-2-Clause; MemScope does not ship the binary. |
| mal_unpack | User-supplied official EXE. Not bundled. Upstream project states BSD-2-Clause; MemScope does not ship the binary. |

## Other build-time / UI dependencies

Frontend (`app/frontend/package-lock.json`) and desktop (`app/desktop/Cargo.lock`, `package-lock.json`) packages record their own license fields (commonly MIT and Apache-2.0 for Tauri/React/Vite). Those lockfiles are the source of truth. This file does not invent license names for packages whose metadata was not opened for this notice.

## Installer toolchain (not shipped to end users)

WiX Toolset 3.14.1 binaries are used on the **build machine** only (`packaging/windows/runtime-manifest.json`). NSIS is cached by the Tauri 2.11 CLI. They are not MemScope application code.
