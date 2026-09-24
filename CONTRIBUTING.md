# Contributing

End users should install Dumplyzer from the Windows setup EXE ([README](README.md#install)). This document is for people changing the source.

Prefer packaging, reliability, security, tests, and documentation unless a change is a clear bug fix or a discussed forensic feature. Architecture: [ARCHITECTURE.md](ARCHITECTURE.md).

## Developer machine

| Tool | Pinned / tested |
|------|-----------------|
| Windows x64 | 10 21H2+ / 11 |
| Python | **3.12.10** (`py -3.12`) |
| Node.js / npm | **22.18.0** / 10.9.3 |
| Rust / cargo | **1.98.1** (`stable-x86_64-pc-windows-msvc`) |
| MSVC Build Tools | VS 2022 |
| WebView2 | Evergreen |

Do not use a global Python 3.13 environment for the engine. `rust-toolchain.toml` pins Rust **1.98.1** for this repository.

### First-time setup

From the repository root:

```powershell
py -3.12 -m venv engine\.venv
.\engine\.venv\Scripts\python.exe -m pip install -U pip
.\engine\.venv\Scripts\python.exe -m pip install -e ".\engine[dev]"
cd app\frontend
npm ci
cd ..\desktop
npm ci
```

## Run from source (`tauri dev`)

Work on the development host. Do not install Node, Rust, or Python on a clean-machine validation VM, and do not rebuild the Windows installer for React/Tailwind tweaks.

From the repository root:

```powershell
cd app\desktop
npm run tauri dev
```

The first `tauri dev` compiles the Rust shell and can take several minutes.

What that command does:

1. `beforeDevCommand` starts Vite in `app/frontend` on port **1420**.
2. The Tauri window loads `devUrl` `http://127.0.0.1:1420`. React Fast Refresh / Vite HMR updates the running window without a Rust or NSIS rebuild.
3. The desktop process launches the Python engine over stdio JSON-RPC. React → Tauri → Python engine → Volatility 3 APIs is unchanged.

Engine Python (first existing file wins): `DUMPLYZER_ENGINE_PYTHON` or `MEMSCOPE_ENGINE_PYTHON`, then `runtime\python.exe` next to `dumplyzer.exe` or under the resource dir, then source-tree `app\desktop\resources\runtime\python.exe`, then `engine\.venv\Scripts\python.exe`. On a fresh clone, `tauri dev` uses the venv from first-time setup. After `scripts\windows\build-release.ps1`, `tauri dev` prefers that embeddable runtime and overlays the source `engine\` tree so IPC matches the checkout. Use the same venv for `pytest`. Do not ship the venv; the NSIS payload uses the embeddable runtime.

User data is **this host's** `%LOCALAPPDATA%\Dumplyzer\` (or `DUMPLYZER_DATA_DIR` / the legacy `MEMSCOPE_DATA_DIR` alias). `tauri dev` does not contact the clean VM. To keep host-dev data separate from a locally installed Dumplyzer, start from the repository root:

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

## Windows installer

This is a separate, heavier step than `tauri dev`. It downloads official CPython embeddable and bundled tools (SHA-256 pinned) and produces `Dumplyzer_0.1.0_x64-setup.exe`. Run it from the repository root. Stop `tauri dev` first if that process is still running.

```powershell
.\scripts\windows\build-release.ps1
```

The installer lands at `app\desktop\target\release\bundle\nsis\Dumplyzer_0.1.0_x64-setup.exe`. See [docs/windows-release.md](docs/windows-release.md).

## Security notes for contributors

- No `shell=True` / NSIS `Exec` of user paths from the engine.
- Do not dump third-party YARA repositories into the tree. Ship only the curated Dumplyzer-authored rules under `engine/memscope_engine/rules/yara/bundled/`. Never download rules at application runtime. See `engine/memscope_engine/rules/yara/RULES.md`.
- bulk_extractor v2.2.0, CAPA v9.4.0, and FLOSS v3.1.1 are bundled via SHA-256 pinned official GitHub assets (`prepare-bulk-extractor.ps1`, `prepare-capa.ps1`, `prepare-floss.ps1`). Do not download them at application runtime.
- Do not execute artifacts.
- Keep Volatility integration on Python APIs (`construct_plugin` / TreeGrid), not `vol.py` stdout.
- User data stays under `%LOCALAPPDATA%\Dumplyzer\`, never inside the install/runtime tree.
