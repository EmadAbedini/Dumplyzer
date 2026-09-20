# Contributing

Prefer packaging, reliability, security, tests, and documentation unless a change is a clear bug fix or a discussed forensic feature. Architecture: [ARCHITECTURE.md](ARCHITECTURE.md).

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

First-time source setup (tests + optional venv):

```powershell
py -3.12 -m venv engine\.venv
.\engine\.venv\Scripts\python.exe -m pip install -U pip
.\engine\.venv\Scripts\python.exe -m pip install -e ".\engine[dev]"
cd app\frontend
npm ci
cd ..\desktop
npm ci
```

## UI/UX iteration (`tauri dev`)

Work on the **development host** only. Do not install Node/Rust/Python on the clean-machine VM, and do not rebuild or copy the Windows installer for React/Tailwind tweaks.

```powershell
cd app\desktop
npm run tauri dev
```

What that command does:

1. `beforeDevCommand` starts Vite in `app/frontend` on port **1420**.
2. The Tauri window loads `devUrl` `http://127.0.0.1:1420`. React Fast Refresh / Vite HMR updates the running window without a Rust or NSIS rebuild.
3. The desktop process still spawns `python -m memscope_engine` and speaks the existing stdio JSON-RPC. React → Tauri → Python engine → Volatility 3 APIs is unchanged.

Engine Python (first existing file wins): `DUMPLYZER_ENGINE_PYTHON` or `MEMSCOPE_ENGINE_PYTHON`, then runtime next to `dumplyzer.exe`, then source-tree `app\desktop\resources\runtime\python.exe`, then `engine\.venv\Scripts\python.exe`. `tauri dev` uses the source-tree embeddable runtime when it is present (created by `scripts\windows\build-release.ps1`). The venv is for `pytest`, not a second architecture.

User data is **this host's** `%LOCALAPPDATA%\Dumplyzer\` (or `DUMPLYZER_DATA_DIR` / the legacy `MEMSCOPE_DATA_DIR` alias). `tauri dev` does not contact the clean VM. To keep host-dev data separate from a locally installed Dumplyzer:

```powershell
$env:DUMPLYZER_DATA_DIR = "$env:TEMP\dumplyzer-dev"
cd app\desktop
npm run tauri dev
```

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

Release installer build (downloads official CPython embeddable and bundled tools with SHA-256 checks):

```powershell
.\scripts\windows\build-release.ps1
```

See [docs/windows-release.md](docs/windows-release.md).

## Security notes for contributors

- No `shell=True` / NSIS `Exec` of user paths from the engine.
- Do not dump third-party YARA repositories into the tree. Ship only the curated Dumplyzer-authored rules under `engine/memscope_engine/rules/yara/bundled/`. Never download rules at application runtime. See `engine/memscope_engine/rules/yara/RULES.md`.
- bulk_extractor v2.2.0, CAPA v9.4.0, and FLOSS v3.1.1 are bundled via SHA-256 pinned official GitHub assets (`prepare-bulk-extractor.ps1`, `prepare-capa.ps1`, `prepare-floss.ps1`). Do not download them at application runtime.
- Do not execute artifacts.
- Keep Volatility integration on Python APIs (`construct_plugin` / TreeGrid), not `vol.py` stdout.
- User data stays under `%LOCALAPPDATA%\Dumplyzer\`, never inside the install/runtime tree.
