# Security

Dumplyzer is a local-first, single-user forensic workstation. Memory images, extracted artifacts, and plugin output are treated as untrusted.

## Process model

- The UI never imports Volatility and never shells out to `vol`.
- The Tauri shell starts the Python engine with an argument array (no shell).
- Packaged builds use the application-local CPython 3.12.10 runtime with `python312._pth` isolation, `PYTHONNOUSERSITE=1`, and `PYTHONPATH` / `PYTHONHOME` removed.
- Engine temp files are directed at `%LOCALAPPDATA%\Dumplyzer\tmp`.

## Paths and data

- Canonical user data: `%LOCALAPPDATA%\Dumplyzer\`.
- Current install tree is `%ProgramFiles%\Dumplyzer`. Install trees must not hold databases, artifacts, evidence, or optional tool EXEs.
- UI profile (WebView2) lives under `%LOCALAPPDATA%\Dumplyzer\webview`.
- Export destinations supplied by the UI are rejected. Reports are written only under `exports\`.
- Artifact, cache, and export writers confine paths to their roots (no `..` traversal).
- `app.init` ignores a client `data_dir` when `DUMPLYZER_DATA_DIR` or `MEMSCOPE_DATA_DIR` is already set by the desktop shell.

## Optional / bundled tools

| Tool | Policy |
|------|--------|
| Signature Detection | Bundled yara-python 4.5.4. Memory dump and extracted-artifact scan modes are explicit jobs. Rules: `%LOCALAPPDATA%\Dumplyzer\rules\yara\` (`bundled\` refreshed, `custom\` never overwritten). Does not execute artifacts. |
| PE Extraction | Volatility 3 workflow (bundled engine). Reconstructs PE images from the imported dump. Does not execute extracts. Labels them extracted PE artifacts, not malware. |
| CAPA | Bundled official `capa.exe` (v9.4.0, Apache-2.0). Invoked as a separate process against extracted PE artifacts only. Reports capabilities, not malware verdicts. No runtime download. |
| FLOSS | Bundled official `floss.exe` (v3.1.1, Apache-2.0). Invoked as a separate process against extracted PE artifacts only. Strings are not malware findings. No runtime download. |
| bulk_extractor | Bundled official `bulk_extractor64.exe` (v2.2.0). GPL-3.0-or-later; invoked as a separate process. Corresponding source ships beside the EXE. User-supplied override allowed under the tools directory. No runtime download. Scans the imported memory image read-only. Extracted bytes are never executed. |

## Reports and logs

- HTML reports are static, with `html.escape` on forensic strings, no JavaScript, no CDN.
- Structured engine logs are JSON. stderr is appended to `logs\engine-stderr.log` (NUL bytes stripped).
- Do not log raw memory contents.

## Packaging

- Engine runtime zip is pinned by SHA-256 (see `packaging/windows/runtime-manifest.json`).
- NSIS defaults to `%ProgramFiles%\Dumplyzer` and requires administrator rights. The engine is spawned by absolute path and does not add that directory to `PATH`. WiX/MSI remains in the runtime manifest for optional experiments; it is not an end-user artifact.
- DLL search for `python.exe` uses the runtime directory. Packaged engine `PATH` is reduced to `System32`.
- Startup writes logs/tmp/database under `%LOCALAPPDATA%\Dumplyzer\`, not under Program Files.

## WebView2

The desktop UI requires the Microsoft Edge WebView2 Runtime. The Windows bundle uses Tauri `webviewInstallMode.embedBootstrapper`. The small Evergreen bootstrapper is packed into `Dumplyzer_0.1.0_x64-setup.exe`. If WebView2 is missing, setup asks before downloading. Agreeing runs Microsoft's installer UI. Declining or cancelling that download exits Dumplyzer setup. If WebView2 is already present, the bootstrapper is skipped.

Dumplyzer itself does not phone home. The WebView2 bootstrapper is Microsoft's installer, not Dumplyzer telemetry.

## Kernel symbols

Windows analysis may download **one** kernel PDB from `https://msdl.microsoft.com/download/symbols` after the user agrees in the app (Download & Continue). The Microsoft response may redirect to Azure Blob Storage; Dumplyzer follows that only over HTTPS to `msdl.microsoft.com` or `*.blob.core.windows.net`, then accepts the bytes only if they verify as a PDB (or expand to one). Download never starts by itself. User-provided `.pdb` / ISF files stay under `%LOCALAPPDATA%\Dumplyzer\symbols`.

## Authenticode

0.1.0 release artifacts are **unsigned**. There is no `certificateThumbprint` or `signCommand` in `tauri.conf.json`. Unsigned NSIS and `dumplyzer.exe` files must not be described as signed. The signing procedure for a future trusted build is in `docs/windows-release.md`.

## License

Dumplyzer application source is Apache-2.0. Redistributed Volatility 3 remains under the Volatility Software License. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.

## Reporting issues

File security issues against the repository. Dumplyzer has no telemetry, account system, or network listener. The only optional Microsoft downloads are WebView2 during setup if the runtime is missing, and one kernel PDB after in-app consent.
