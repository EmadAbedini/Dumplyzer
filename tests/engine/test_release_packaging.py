"""Release packaging, first-launch paths, upgrades, and optional providers."""

from __future__ import annotations

import json
import os
import sqlite3
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from memscope_engine.paths import (
    AppPaths,
    default_data_dir,
    is_canonical_user_data_dir,
    maybe_migrate_legacy_data,
)
from memscope_engine.providers.capa import CapaProvider
from memscope_engine.providers.yara_provider import detect_yara
from memscope_engine.server import HANDLERS, handle_app_init
from memscope_engine.storage import Database
from memscope_engine.storage.schema import MIGRATIONS, SCHEMA_VERSION
from memscope_engine.version import APP_NAME, APP_VERSION
from support import bundled_runtime_python, engine_python


def test_windows_icon_assets_exist() -> None:
    icons = Path(__file__).resolve().parents[2] / "app" / "desktop" / "icons"
    ico = icons / "icon.ico"
    png32 = icons / "32x32.png"
    assert ico.is_file()
    assert png32.is_file()
    assert (icons / "Dumplyzer.png").is_file()
    splash = Path(__file__).resolve().parents[2] / "app" / "frontend" / "src" / "assets" / "dumplyzer-splash.jpg"
    assert splash.is_file()
    assert splash.read_bytes()[:3] == b"\xff\xd8\xff"
    assert (splash.parents[2] / "splash.html").is_file()
    assert (splash.parents[2] / "splash.js").is_file()
    assert (icons / "128x128.png").is_file()
    assert (icons / "128x128@2x.png").is_file()
    data = ico.read_bytes()
    assert data[:4] == b"\x00\x00\x01\x00"
    png32_bytes = png32.read_bytes()
    assert png32_bytes[:8] == b"\x89PNG\r\n\x1a\n"
    # 32x32 must be RGBA PNG so the taskbar/window icon can be transparent.
    assert png32_bytes[25] == 6
    # Desktop shortcuts use 16/32/48. Those frames must be 32bpp BMP+AND,
    # not PNG-in-ICO (Explorer often paints PNG frames as an opaque square).
    count = struct.unpack_from("<H", data, 4)[0]
    assert count >= 9
    # Tauri uses ICO entries[0] as the live window/taskbar bitmap.
    assert data[6] == 0
    png_magic = b"\x89PNG\r\n\x1a\n"
    seen: set[int] = set()
    for i in range(count):
        width, _height, _cc, _res, _planes, bpp, size, offset = struct.unpack_from(
            "<BBBBHHII", data, 6 + 16 * i
        )
        assert bpp == 32
        assert size > 0
        payload = data[offset : offset + max(8, size)]
        if width == 0:
            seen.add(256)
            assert payload[:8] == png_magic
        else:
            seen.add(width)
            assert struct.unpack_from("<I", payload, 0)[0] == 40
            bitcount = struct.unpack_from("<H", payload, 14)[0]
            assert bitcount == 32
    assert seen >= {16, 20, 24, 32, 40, 48, 64, 128, 256}


def test_nsis_installer_uses_dumplyzer_icon() -> None:
    conf_path = Path(__file__).resolve().parents[2] / "app" / "desktop" / "tauri.conf.json"
    conf = json.loads(conf_path.read_text(encoding="utf-8"))
    nsis = conf["bundle"]["windows"]["nsis"]
    assert conf["bundle"]["targets"] == ["nsis"]
    assert conf["bundle"]["windows"]["webviewInstallMode"]["type"] == "embedBootstrapper"
    assert conf["bundle"]["windows"]["webviewInstallMode"]["silent"] is False
    assert nsis["installMode"] == "perMachine"
    assert nsis["installerIcon"] == "icons/icon.ico"
    assert nsis["uninstallerIcon"] == "icons/icon.ico"
    ico = Path(__file__).resolve().parents[2] / "app" / "desktop" / nsis["installerIcon"]
    assert ico.is_file()
    assert ico.read_bytes()[:4] == b"\x00\x00\x01\x00"


def test_nsis_template_stops_runtime_without_powershell_command_braces() -> None:
    nsi = (
        Path(__file__).resolve().parents[2]
        / "packaging"
        / "windows"
        / "nsis"
        / "installer.nsi"
    )
    text = nsi.read_text(encoding="utf-8")
    assert "StopDumplyzerRuntime" in text
    assert "stop-dumplyzer-runtime.ps1" in text
    assert "-File" in text
    assert '-Command "& {' not in text
    assert r"$LOCALAPPDATA\Dumplyzer" in text
    assert r'RMDir /r /REBOOTOK "$INSTDIR"' in text
    uninstall = text.split("Section Uninstall", 1)[-1]
    assert "{{#each resources}}" not in uninstall
    assert 'rmdir /S /Q "$INSTDIR"' in uninstall
    assert """ExecWait '"$6" ${WEBVIEW2INSTALLERARGS} /install'""" in text
    assert 'ExecWait "$6 ${WEBVIEW2INSTALLERARGS} /install"' not in text
    assert "MB_YESNO" in text
    assert "WebView2 is required" in text
    assert "SetErrorLevel" in text
    assert r"%LOCALAPPDATA%\Dumplyzer\symbols" in text
    assert "Download & Continue" in text
    assert not any(
        line.strip().lower().startswith("file ") and "windows.zip" in line.lower()
        for line in text.splitlines()
    )


def test_app_version_is_release_coherent() -> None:
    assert APP_NAME == "Dumplyzer"
    assert APP_VERSION == "0.1.0"
    assert SCHEMA_VERSION == 14


def test_first_launch_creates_directories(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "Dumplyzer").ensure()
    for attr in (
        "root",
        "logs",
        "artifacts",
        "cache",
        "tmp",
        "yara_rules",
        "tools",
        "exports",
        "analysis",
        "symbols",
        "volatility_cache",
    ):
        assert getattr(paths, attr).is_dir()
    assert paths.yara_rules_bundled.is_dir()
    assert paths.yara_rules_custom.is_dir()
    assert (paths.yara_rules_bundled / "memory").is_dir()
    assert (paths.yara_rules_bundled / "artifact").is_dir()
    assert (paths.yara_rules_bundled / "catalog.json").is_file()
    assert list((paths.yara_rules_bundled / "memory").glob("*.yar"))
    assert (paths.yara_rules_custom / "README.txt").is_file()
    assert (paths.tools / "capa").is_dir()
    assert (paths.tools / "floss").is_dir()
    assert (paths.tools / "bulk_extractor").is_dir()
    assert (paths.analysis / "bulk_extractor").is_dir()
    assert (paths.analysis / "pe_extraction").is_dir()
    assert (paths.analysis / "pcap").is_dir()
    assert (paths.cache / "plugin_results").is_dir()
    assert (paths.symbols / "windows").is_dir()
    assert (paths.symbols / "linux").is_dir()
    assert (paths.symbols / "README.txt").is_file()
    readme = (paths.symbols / "README.txt").read_text(encoding="utf-8")
    assert "windows.zip" in readme
    assert "800" in readme
    assert (paths.volatility_cache / "symbols" / "windows").is_dir()
    assert (paths.tools / "README.txt").is_file()
    assert not paths.db_path.exists()


def test_default_data_dir_is_localappdata_memscope(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("MEMSCOPE_DATA_DIR", raising=False)
    monkeypatch.delenv("DUMPLYZER_DATA_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    got = default_data_dir()
    assert got == (tmp_path / "Local" / APP_NAME)


def test_explicit_root_does_not_use_developer_home(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    assert paths.root == (tmp_path / "data").resolve()


def test_non_canonical_ensure_does_not_copy_legacy(tmp_path: Path, monkeypatch) -> None:
    legacy = tmp_path / "roaming" / "com.memscope.workbench"
    legacy.mkdir(parents=True)
    (legacy / "memscope.db").write_bytes(b"legacy")
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    dest = tmp_path / "isolated"
    AppPaths(dest).ensure()
    assert not (dest / "memscope.db").exists()


def test_legacy_migration_preserves_source(tmp_path: Path, monkeypatch) -> None:
    local = tmp_path / "Local"
    roaming = tmp_path / "Roaming"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("APPDATA", str(roaming))
    monkeypatch.delenv("MEMSCOPE_DATA_DIR", raising=False)
    monkeypatch.delenv("DUMPLYZER_DATA_DIR", raising=False)
    legacy = roaming / "com.memscope.workbench"
    legacy.mkdir(parents=True)
    (legacy / "memscope.db").write_text("keep-me", encoding="utf-8")
    (legacy / "notes.txt").write_text("legacy", encoding="utf-8")
    dest = local / APP_NAME
    migrated = maybe_migrate_legacy_data(dest)
    assert migrated == legacy.resolve()
    assert (dest / "memscope.db").read_text(encoding="utf-8") == "keep-me"
    assert (legacy / "memscope.db").read_text(encoding="utf-8") == "keep-me"
    again = maybe_migrate_legacy_data(dest)
    assert again is None


def test_memscope_data_dir_migrates_into_dumplyzer(tmp_path: Path, monkeypatch) -> None:
    local = tmp_path / "Local"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.delenv("MEMSCOPE_DATA_DIR", raising=False)
    monkeypatch.delenv("DUMPLYZER_DATA_DIR", raising=False)
    old = local / "MemScope"
    old.mkdir(parents=True)
    (old / "memscope.db").write_text("from-memscope", encoding="utf-8")
    dest = local / APP_NAME
    migrated = maybe_migrate_legacy_data(dest)
    assert migrated == old.resolve()
    assert (dest / "memscope.db").read_text(encoding="utf-8") == "from-memscope"
    assert (old / "memscope.db").read_text(encoding="utf-8") == "from-memscope"


def test_canonical_flag(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    assert is_canonical_user_data_dir((tmp_path / "Local" / APP_NAME))
    assert not is_canonical_user_data_dir(tmp_path / "other")


def test_existing_sqlite_migrates_and_preserves_evidence(tmp_path: Path) -> None:
    db_path = tmp_path / "old.db"
    conn = sqlite3.connect(str(db_path))
    conn.executescript(MIGRATIONS[1])
    conn.execute("INSERT INTO schema_meta(key, value) VALUES('schema_version', '1')")
    conn.execute(
        """
        INSERT INTO evidence(
          id, path, filename, size_bytes, sha256, symbol_status,
          import_status, import_timestamp, metadata_json
        ) VALUES (?, ?, ?, ?, ?, 'unknown', 'imported', '2020-01-01T00:00:00Z', '{}')
        """,
        ("ev-legacy", r"C:\evidence\sample.raw", "sample.raw", 32, "a" * 64),
    )
    conn.commit()
    conn.close()

    db = Database(db_path)
    assert db.schema_version() == SCHEMA_VERSION
    row = db.fetchone("SELECT filename, sha256 FROM evidence WHERE id = ?", ("ev-legacy",))
    assert row is not None
    assert row["filename"] == "sample.raw"
    assert row["sha256"] == "a" * 64
    db.close()


def test_client_data_dir_ignored_when_env_set(tmp_path: Path, monkeypatch) -> None:
    env_dir = tmp_path / "from-env"
    other = tmp_path / "from-client"
    monkeypatch.setenv("MEMSCOPE_DATA_DIR", str(env_dir))
    result = handle_app_init({"data_dir": str(other)})
    assert Path(result["paths"]["root"]) == env_dir.resolve()
    assert not (other / "memscope.db").exists()


def _provider_unavailable(payload: dict) -> bool:
    blob = json.dumps(payload).lower()
    if payload.get("available") is False:
        return True
    if payload.get("ok") is False:
        return True
    if str(payload.get("status", "")).lower() in {
        "unavailable",
        "missing",
        "not_installed",
        "disabled",
    }:
        return True
    if "unavailable" in blob:
        return True
    return payload.get("exe_path") in (None, "") and "yara-python" not in blob


def test_optional_providers_unavailable_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DUMPLYZER_BUNDLE_TOOLS", raising=False)
    isolated = tmp_path / "isolated-python.exe"
    isolated.write_bytes(b"")
    monkeypatch.setattr(sys, "executable", str(isolated))
    init = handle_app_init({"data_dir": str(tmp_path / "ipc")})
    assert "pe_extraction" in init
    assert "capa" in init
    assert "floss" in init
    assert "bulk_extractor" in init
    pe = HANDLERS["pe_extraction.status"]({})
    capa = HANDLERS["capa.status"]({})
    floss = HANDLERS["floss.status"]({})
    yara = HANDLERS["yara.status"]({})
    be = HANDLERS["bulk_extractor.status"]({})
    assert "available" in pe
    assert capa.get("available") is False
    assert capa.get("executable_path") in (None, "")
    assert floss.get("available") is False
    assert floss.get("executable_path") in (None, "")
    assert be.get("available") is False
    assert be.get("executable_path") in (None, "")
    assert be.get("license", {}).get("bundled_in_memscope") is True
    assert capa.get("license", {}).get("bundled_in_memscope") is True
    assert floss.get("license", {}).get("bundled_in_memscope") is True
    # Signature Detection is bundled (yara-python 4.5.4). Report availability honestly.
    assert "available" in yara
    assert yara.get("provider") == "yara" or yara.get("available") in (True, False)
    if detect_yara()["available"]:
        assert yara.get("available") is True
        assert yara.get("yara_version") == "4.5.4"
        assert int(yara.get("bundled_rule_file_count") or 0) >= 1
        assert int(yara.get("custom_rule_file_count") or 0) == 0
        assert "bundled" in (yara.get("status_summary") or "")


def test_capabilities_status_rpc(tmp_path: Path) -> None:
    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    caps = HANDLERS["capabilities.status"]({})
    assert caps["volatility"]["ok"] is True
    assert caps["volatility"].get("volatility3_version")
    for key in ("pe_extraction", "capa", "floss", "yara", "bulk_extractor"):
        assert "available" in caps[key]


def test_plugin_explorer_discovers_without_evidence(tmp_path: Path) -> None:
    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    listed = HANDLERS["plugins.list"]({})
    assert listed["plugin_count"] >= 1
    assert listed["volatility_version"]
    assert isinstance(listed["items"], list)


def test_export_options_available_on_fresh_install(tmp_path: Path) -> None:
    handle_app_init({"data_dir": str(tmp_path / "ipc")})
    opts = HANDLERS["export.options"]({})
    assert "html" in opts["formats"]
    assert "json" in opts["formats"]


def test_smoke_ipc_subprocess(tmp_path: Path, monkeypatch) -> None:
    python = engine_python()
    monkeypatch.setenv("MEMSCOPE_DATA_DIR", str(tmp_path / "smoke"))
    monkeypatch.setenv("PYTHONNOUSERSITE", "1")
    monkeypatch.delenv("PYTHONPATH", raising=False)
    req = json.dumps({"jsonrpc": "2.0", "id": "t1", "method": "smoke.e2e", "params": {}}) + "\n"
    proc = subprocess.run(
        [str(python), "-m", "memscope_engine"],
        input=req,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
        env=os.environ.copy(),
    )
    assert proc.returncode == 0, proc.stderr
    line = next((ln for ln in proc.stdout.splitlines() if ln.strip()), "")
    msg = json.loads(line)
    assert "error" not in msg, msg
    result = msg["result"]
    assert result["ok"] is True
    assert result["volatility"]["ok"] is True
    assert result["volatility"]["volatility3_version"]
    assert result["volatility"]["engine_version"] == APP_VERSION


def test_bundled_runtime_exposes_yara_reload() -> None:
    python = bundled_runtime_python()
    if python is None:
        pytest.skip("bundled Windows runtime is not prepared")
    server = python.parent / "Lib" / "site-packages" / "memscope_engine" / "server.py"
    assert server.is_file(), server
    text = server.read_text(encoding="utf-8")
    assert '"yara.reload"' in text


def test_bundled_runtime_isolated_when_prepared(tmp_path: Path) -> None:
    python = bundled_runtime_python()
    if python is None:
        pytest.skip("bundled Windows runtime is not prepared")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(tmp_path / "does-not-exist")
    env["PYTHONNOUSERSITE"] = "1"
    env["MEMSCOPE_PACKAGED"] = "1"
    env["MEMSCOPE_DATA_DIR"] = str(tmp_path / "bundled-smoke")
    req = json.dumps({"jsonrpc": "2.0", "id": "t1", "method": "smoke.e2e", "params": {}}) + "\n"
    proc = subprocess.run(
        [str(python), "-m", "memscope_engine"],
        input=req,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
        env=env,
        cwd=str(python.parent),
    )
    assert proc.returncode == 0, proc.stderr
    line = next((ln for ln in proc.stdout.splitlines() if ln.strip()), "")
    msg = json.loads(line)
    assert "error" not in msg, msg
    result = msg["result"]
    assert result["volatility"]["ok"] is True
    packaged = result.get("runtime", {}).get("packaged") or result["volatility"].get("packaged")
    assert packaged is True
    providers = result.get("providers") or {}
    if "yara" in providers:
        assert providers["yara"].get("available") is True
        assert providers["yara"].get("yara_version") == "4.5.4"
    be = providers.get("bulk_extractor")
    be_exe = python.parent.parent / "tools" / "bulk_extractor" / "bulk_extractor64.exe"
    if isinstance(be, dict) and "available" in be and be_exe.is_file():
        assert be.get("available") is True
        assert be.get("source") == "bundled"


def test_user_data_is_separate_from_install_dirs(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("MEMSCOPE_DATA_DIR", raising=False)
    monkeypatch.delenv("DUMPLYZER_DATA_DIR", raising=False)
    local = tmp_path / "Local"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    data = default_data_dir()
    nsis_install = local / "Programs" / "Dumplyzer"
    program_files = tmp_path / "Program Files" / "Dumplyzer"
    assert data == local / APP_NAME
    assert data != nsis_install
    assert data != program_files
    nsis_install.mkdir(parents=True)
    program_files.mkdir(parents=True)
    AppPaths().ensure()
    assert data.is_dir()
    assert (data / "logs").is_dir()
    assert list(nsis_install.iterdir()) == []
    assert list(program_files.iterdir()) == []


def test_capa_ignores_install_tree_executables(tmp_path: Path) -> None:
    install = tmp_path / "Programs" / "Dumplyzer"
    install.mkdir(parents=True)
    decoy = install / "capa.exe"
    decoy.write_bytes(b"MZ" + b"\x00" * 256)
    paths = AppPaths(tmp_path / "data").ensure()
    provider = CapaProvider(tools_dir=paths.tools, artifacts_dir=paths.artifacts)
    assert provider._resolved_executable() is None
    avail = provider.availability()
    assert avail["available"] is False
    assert avail["executable_path"] in (None, "")


def test_bundled_runtime_optional_volatility_extras(tmp_path: Path) -> None:
    python = bundled_runtime_python()
    if python is None:
        pytest.skip("bundled Windows runtime is not prepared")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(tmp_path / "does-not-exist")
    env["PYTHONNOUSERSITE"] = "1"
    env["MEMSCOPE_PACKAGED"] = "1"
    env["MEMSCOPE_DATA_DIR"] = str(tmp_path / "vol-opt")
    probe = r"""
import json, importlib
missing = []
for name in ("yara", "capstone", "Crypto"):
    try:
        importlib.import_module(name)
    except ImportError:
        missing.append(name)
from memscope_engine.volatility.discovery import discover_plugins, plugin_runnable_with_evidence
catalog = discover_plugins(force_refresh=True)
available_ids = [i["id"] for i in catalog["items"] if i["available"]]
unavailable = [i for i in catalog["items"] if not i["available"]]
failures = catalog["import_failures"]
pslist = next(i for i in catalog["items"] if i["id"] == "windows.pslist.PsList")
runnable = plugin_runnable_with_evidence(pslist, None)
yara_available = [i["id"] for i in catalog["items"] if i["available"] and "yara" in i["id"].lower()]
print(json.dumps({
    "missing_extras": missing,
    "plugin_count": catalog["plugin_count"],
    "volatility_version": catalog["volatility_version"],
    "import_failure_count": len(failures),
    "import_failures": failures[:20],
    "unavailable_count": len(unavailable),
    "pslist_available": pslist["available"],
    "pslist_runnable_without_evidence": runnable["runnable"],
    "yara_available_ids": yara_available,
    "available_contains_failed_import": any(
        str(f) in available_ids for f in failures
    ),
}))
"""
    proc = subprocess.run(
        [str(python), "-c", probe],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=env,
        cwd=str(python.parent),
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["volatility_version"]
    assert payload["plugin_count"] >= 50
    assert payload["pslist_available"] is True
    assert payload["pslist_runnable_without_evidence"] is False
    assert payload["available_contains_failed_import"] is False
    assert "yara" not in payload["missing_extras"]
    assert "capstone" in payload["missing_extras"]
    assert "Crypto" in payload["missing_extras"]
    # Import failures must be listed, not turned into fake plugin rows.
    assert isinstance(payload["import_failures"], list)


def test_release_scripts_pin_cargo_target_dir() -> None:
    root = Path(__file__).resolve().parents[2]
    build = (root / "scripts" / "windows" / "build-release.ps1").read_text(encoding="utf-8")
    verify = (root / "scripts" / "windows" / "verify-installer.ps1").read_text(encoding="utf-8")
    prepare = (root / "scripts" / "windows" / "prepare-engine-runtime.ps1").read_text(encoding="utf-8")
    assert "CARGO_TARGET_DIR" in build
    assert "Join-Path $Desktop" in build
    assert "target" in build
    assert r"release\resources" in build
    assert "Removing stale release resources" in build
    assert "Refusing to verify a different directory" in verify
    assert "Removing previous runtime" in prepare
    assert "3.12.10" in verify
    assert "2.28.0" in verify
    assert "9.4.0" in verify
    assert "3.1.1" in verify
    assert "4.5.4" in verify
    assert "pe_sieve" in verify
    assert "mal_unpack" in verify
    assert "windows.zip ISF pack must not be shipped" in verify
    assert "231d69735b9a5482b16bdbf1ec356e0a95574c44079e68dfb02ebddb34d55f3e" in verify
    assert "save_microsoft_pdb" in verify
    assert "msdl.microsoft.com/download/symbols" in verify
    assert r"%LOCALAPPDATA%\Dumplyzer\symbols" in verify
    assert "WebView2 is required" in (
        Path(__file__).resolve().parents[2] / "packaging" / "windows" / "nsis" / "installer.nsi"
    ).read_text(encoding="utf-8")
    assert "4.5.4" in prepare
    assert "yara-python" in prepare
    assert "memscope_engine.volatility.kernel_symbols" in prepare
    assert "memscope_engine.volatility.symbol_pack" in prepare
    assert "resources\\rules" in prepare or "resources/rules" in prepare or "bundled_yara_rules" in prepare

