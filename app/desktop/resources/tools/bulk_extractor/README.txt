bulk_extractor (official Windows build)

This folder is application resources, not user evidence.

Dumplyzer ships the official GitHub release asset:

  https://github.com/simsong/bulk_extractor/releases/tag/v2.2.0
  bulk_extractor64.exe  (SHA-256 dfcc678ee3b7da111e8fba6259c4e842ffffcbe42dd96e6c6e6cc238d74bd911)

The Windows executable is a MinGW-w64 cross-compile from upstream CI. Native
MSVC builds are not supported upstream. The PE is checked not to import
MinGW/RE2/Abseil/Expat/zlib/GNU crypto DLLs; no extra runtime installer is
required on a clean Windows 11 x64 system.

License: GPL-3.0-or-later (see LICENSE.md and LICENSE.GPLv3). Dumplyzer invokes
this program as a separate process and does not link against it.

Corresponding source required by the GPL is bulk_extractor-2.2.0.tar.gz in
this folder (same release). Fetch both files with:

  .\scripts\windows\prepare-bulk-extractor.ps1
