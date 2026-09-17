# Windows release build

Application version: **0.1.0**  
Python runtime: official CPython **3.12.10** Windows embeddable x64  
Volatility 3: **2.28.0**  
Installers: NSIS per-user + WiX 3.14 MSI

This procedure produces installers. It does **not** perform a clean-machine installation test. Produced NSIS and MSI files are **unsigned** unless a certificate is supplied outside this repository.

## Why embeddable CPython (not PyInstaller)

The engine must keep the existing React → Tauri → Python → Volatility 3 API path, including dynamic plugin discovery (`import_files` / `list_plugins`). A relocatable embeddable CPython plus `site-packages` preserves that model. PyInstaller is not used because Volatility plugin imports are dynamic. The engine is not rewritten in Rust. `vol.py` is not used.

YARA / Signature Detection (yara-python **4.5.4**) is installed into the Python runtime from the pinned lockfile. bulk_extractor v2.2.0, CAPA v9.4.0, and FLOSS v3.1.1 are bundled as separate programs under `resources/tools/`. Curated rules ship under `resources/rules/yara/bundled/`.

## Developer prerequisites

| Tool | Version | Notes |
|------|---------|--------|
| Windows x64 | 10 21H2+ / 11 | Build host |
| Python (host, for pip --target) | 3.12.10 | `py -3.12` — not shipped to users |
| Node.js / npm | 22.18.0 / 10.9.3 | `npm ci` |
| Rust | 1.98.1 `x86_64-pc-windows-msvc` | `rust-toolchain.toml` |
| VS Build Tools | 2022 MSVC | Tauri / Rust |
| WebView2 | Evergreen | Runtime on the build machine |
| VBScript optional feature | enabled | Required by WiX `light.exe` ICE |
| Git | any | Clean tree preferred |

Do not use an arbitrary Python from another user profile. The previous `engine\.venv` in this checkout pointed at a non-portable 3.13 path and is not a release input.

## Pinned download (hash-verified)

Only these remote zips/binaries are fetched, and only after SHA-256 verification (`packaging/windows/runtime-manifest.json`):

1. `https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip`  
   SHA-256 `4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3` (Python.org SPDX)
2. `https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip`  
   SHA-256 `6ac824e1642d6f7277d0ed7ea09411a508f6116ba6fae0aa5f2c7daa2ff43d31`  
   Extracted to `%LOCALAPPDATA%\tauri\WixTools314` (Tauri 2.11 cache layout)
3. `https://github.com/simsong/bulk_extractor/releases/download/v2.2.0/bulk_extractor64.exe` (and corresponding source tarball)
4. `https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-windows.zip`  
   SHA-256 `670ab1a58b81f59cb57533bf4021ac1e7033fbe9b5d5cc180f796976081e3bb5`
5. `https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-windows.zip`  
   SHA-256 `6c71089b8c629c69424b042769f1565f71adc6cd24b2f8d3713c96fa7fdac2fb`

YARA rules and `yara-python` are never downloaded. bulk_extractor64.exe, capa.exe, and floss.exe are fetched at **build time** from official GitHub releases with pinned SHA-256.

The Tauri CLI may also cache NSIS into `%LOCALAPPDATA%\tauri\` on first `tauri build`. That is the official Tauri 2.11 bundler toolchain, not a Dumplyzer malware-tool fetch.

## Commands

From the repository root:

```powershell
# 1. Recreate a local 3.12 venv for tests (not shipped)
py -3.12 -m venv --clear engine\.venv
.\engine\.venv\Scripts\python.exe -m pip install -U pip
.\engine\.venv\Scripts\python.exe -m pip install -e ".\engine[dev]"

# 2. Tests / typecheck
.\engine\.venv\Scripts\python.exe -m pytest tests\engine
cd app\frontend; npm ci; npm run build; cd ..\..
cd app\desktop; cargo test; cargo build; cd ..\..

# 3. Release payload + installers
.\scripts\windows\build-release.ps1
```

`build-release.ps1` runs:

1. `prepare-engine-runtime.ps1` — embeddable CPython + locked deps + `memscope-engine` into `app/desktop/resources/runtime/` (gitignored)
2. `prepare-bulk-extractor.ps1` — official `bulk_extractor64.exe` v2.2.0 + corresponding source into `app/desktop/resources/tools/bulk_extractor/` (always, even with `-SkipRuntime`)
3. `prepare-wix-tools.ps1` — WiX 3.14.1 into the Tauri cache
4. `npm ci` in `app/frontend` (the release script calls `npm.cmd` / `npx.cmd` so Windows PowerShell StrictMode does not hit Node's `npm.ps1`)
5. `npx tauri build --bundles nsis` then `--bundles msi` in `app/desktop` (sequential so a WebView2 download glitch cannot abort NSIS)
6. `verify-installer.ps1`

## Generated artifacts (not committed)

| Path | Meaning |
|------|---------|
| `app/desktop/resources/runtime/` | Bundled engine runtime |
| `app/desktop/target/release/dumplyzer.exe` | Unpackaged desktop binary |
| `app/desktop/target/release/bundle/nsis/*-setup.exe` | Per-user NSIS installer |
| `app/desktop/target/release/bundle/msi/*.msi` | WiX MSI |
| `$env:CARGO_TARGET_DIR/release/bundle/` | Same artifacts if `CARGO_TARGET_DIR` is overridden |
| `packaging/cache/` | Downloaded zips |

Version stamping: `0.1.0` in `tauri.conf.json`, `app/desktop/Cargo.toml`, frontend/desktop `package.json`, `engine/pyproject.toml`, and `memscope_engine.version.APP_VERSION`. Report schema v1 and SQLite schema v10 stay independent.

## Installed layout (conceptual)

NSIS current-user default:

```
%LOCALAPPDATA%\Programs\Dumplyzer\
  dumplyzer.exe
  resources\runtime\   # CPython + site-packages (volatility3, memscope_engine)
  resources\tools\bulk_extractor\  # bundled bulk_extractor64.exe v2.2.0 + GPL corresponding source
```

User data (writable, not removed as part of a normal uninstall of binaries):

```
%LOCALAPPDATA%\Dumplyzer\
  memscope.db
  logs\
  cache\
  artifacts\
  exports\
  rules\yara\        # bundled\ refreshed on launch; custom\ never overwritten
  tools\            # optional overrides for bundled CAPA / FLOSS / bulk_extractor
  analysis\          # bulk_extractor raw output (and similar analysis trees)
  tmp\
```

## Verification after a local build

`verify-installer.ps1` checks:

- `python.exe` and `python312._pth` exist
- `import memscope_engine, volatility3, yara` succeeds; yara-python is **4.5.4**
- PE-sieve / mal_unpack EXEs are absent from the Python runtime
- bundled `resources/tools/{bulk_extractor,capa,floss}` EXEs are present
- bundled `resources/rules/yara/bundled` memory and artifact rules are present
- bundled `resources/tools/bulk_extractor/bulk_extractor64.exe` is present with matching SHA-256
- NSIS and MSI files exist; prints size and SHA-256

It does not install the MSI/NSIS onto a clean VM.

## License files in the bundle

`tauri.conf.json` `bundle.licenseFile` points at the repository `LICENSE` (Apache-2.0 for Dumplyzer application source). Redistributed runtime licenses stay inside `resources/runtime` (CPython `LICENSE.txt`, volatility3 `LICENSE.txt`, pefile `LICENSE`). End-user notices: `THIRD_PARTY_NOTICES.md`.

## WebView2

Configured in `tauri.conf.json` as:

```json
"webviewInstallMode": { "type": "embedBootstrapper", "silent": true }
```

| Environment | Expected behavior |
|-------------|-------------------|
| Windows 10 21H2+ / 11 x64 with WebView2 already installed | Application can launch. The bootstrapper should not need a download. **This is the intended supported environment.** |
| WebView2 missing, network available | Embedded Evergreen bootstrapper can download and install the Microsoft runtime during install/first launch. |
| WebView2 missing, **no network** | Launch **cannot be guaranteed**. This is an explicit supported-environment limitation, not a tested success path. |
| Offline machine that already has WebView2 | Launch depends only on the already-installed runtime (not verified on a clean VM in this milestone). |

Dumplyzer does not switch to Tauri `offlineInstaller` (large Microsoft Evergreen standalone). Do not describe 0.1.0 as “offline WebView2 self-contained.”

## Authenticode / signing (not configured)

`digestAlgorithm` is `sha256`. There is **no** `certificateThumbprint`, `timestampUrl`, or `signCommand` in `tauri.conf.json`. Builds from this repository are **unsigned**.

Do not invent or commit a certificate. Do not mark artifacts as signed.

### Artifacts that must be signed for a trusted public release

Sign all of the following with the same Authenticode certificate, **after** a successful `tauri build`:

1. `dumplyzer.exe` (the application binary inside the install tree / pre-bundle `target/release/dumplyzer.exe`)
2. NSIS `Dumplyzer_0.1.0_x64-setup.exe`
3. MSI `Dumplyzer_0.1.0_x64_en-US.msi`

Signing only the installer and leaving `Dumplyzer.exe` unsigned is incomplete.

### Required signing properties

- Digest: **SHA-256** (`/fd SHA256`)
- Timestamp: **RFC 3161** (`/tr` timestamp URL + `/td SHA256`), so signatures remain valid after the certificate expires
- Store: organization code-signing certificate in the Windows certificate store (or a `.pfx` passed to `signtool` / Tauri `signCommand`) — **not present in this repo**

Example (replace thumbprint and timestamp URL with values from the certificate issuer):

```powershell
signtool sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com /sha1 <THUMBPRINT> Dumplyzer.exe
signtool sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com /sha1 <THUMBPRINT> Dumplyzer_0.1.0_x64-setup.exe
signtool sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com /sha1 <THUMBPRINT> Dumplyzer_0.1.0_x64_en-US.msi
```

Tauri equivalent once a cert exists: set `bundle.windows.certificateThumbprint` and `bundle.windows.timestampUrl` (and `tsp: true` for RFC 3161). Verify with `signtool verify /pa /v <file>` and confirm a timestamp is present.

Until that is done, SmartScreen and some enterprise policies will treat the installers as unknown publishers. That is expected for unsigned 0.1.0 builds.

## Known limitations

- Clean-machine NSIS install was executed on a Windows 11 x64 VM. See `docs/clean-machine-validation.md` (**PASS WITH LIMITATIONS**). MSI and WebView2-absent-offline were not part of that run.
- Per-user install directories are user-writable (Windows per-user reality).
- WebView2 Evergreen is required. Offline WebView2-absent machines are unsupported with `embedBootstrapper`.
- Volatility plugins that need capstone or pycryptodome may appear as import failures. That is intentional: those extras are not bundled. Failed imports must not be marked available. yara-python 4.5.4 **is** bundled, so Volatility YARA plugins may become available as a side effect.
- Code signing / Authenticode is not configured. Artifacts are unsigned.
- Linux packaging is out of scope.
