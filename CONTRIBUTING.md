# Contributing

MemScope is feature-frozen on forensic workflows. Prefer packaging, reliability, security, tests, and documentation unless a change is a clear bug fix.

## Developer machine (source)

Required:

| Tool | Pinned / tested |
|------|-----------------|
| Windows x64 | 10 21H2+ / 11 |
| Python | **3.12.10** (`py -3.12`) |
| Node.js / npm | **22.18.0** / 10.9.3 |
| Rust / cargo | **1.98.1** (`stable-x86_64-pc-windows-msvc`) |
| MSVC Build Tools | VS 2022 |
| WebView2 | Evergreen |

Do not use a global Python 3.13 environment for the engine.

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

`tauri dev` still launches `engine\.venv\Scripts\python.exe`. The bundled embeddable runtime is for release installers only.

## Tests

From the repository root, using the engine venv:

```powershell
.\engine\.venv\Scripts\python.exe -m pytest tests\engine
cd app\frontend
npm run build
cd ..\desktop
cargo test
cargo build
```

Release installer build (downloads official CPython embeddable + WiX 3.14.1 with SHA-256 checks):

```powershell
.\scripts\windows\build-release.ps1
```

See [docs/windows-release.md](docs/windows-release.md).

## Security notes for contributors

- No `shell=True` / NSIS `Exec` of user paths from the engine.
- Do not bundle or auto-download PE-sieve, mal_unpack, or YARA rulesets.
- Do not execute artifacts.
- Keep Volatility integration on Python APIs (`construct_plugin` / TreeGrid), not `vol.py` stdout.
- User data stays under `%LOCALAPPDATA%\MemScope\`, never inside the install/runtime tree.
