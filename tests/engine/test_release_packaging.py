"""Release packaging, first-launch paths, upgrades, and optional providers."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
from pathlib import Path

import pytest

from memscope_engine.paths import (
    APP_NAME,
    AppPaths,
    default_data_dir,
    is_canonical_user_data_dir,
    maybe_migrate_legacy_data,
)
from memscope_engine.providers.pe_sieve import PeSieveProvider
from memscope_engine.server import HANDLERS, handle_app_init
from memscope_engine.storage import Database
from memscope_engine.storage.schema import MIGRATIONS, SCHEMA_VERSION
from memscope_engine.version import APP_VERSION
from support import bundled_runtime_python, engine_python


def test_app_version_is_release_coherent() -> None:
    assert APP_VERSION == "0.1.0"
    assert SCHEMA_VERSION == 9


def test_first_launch_creates_directories(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "MemScope").ensure()
    for attr in (
        "root",
        "logs",
        "artifacts",
        "cache",
        "tmp",
        "yara_rules",
        "tools",
        "exports",
    ):
        assert getattr(paths, attr).is_dir()
    assert (paths.tools / "pe-sieve").is_dir()
    assert (paths.tools / "mal_unpack").is_dir()
    assert (paths.cache / "plugin_results").is_dir()
    assert (paths.tools / "README.txt").is_file()
    assert not paths.db_path.exists()


def test_default_data_dir_is_localappdata_memscope(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("MEMSCOPE_DATA_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    got = default_data_dir()
    assert got == (tmp_path / "Local" / APP_NAME)
    assert "Rootman" not in str(got)


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


def test_optional_providers_unavailable_by_default(tmp_path: Path) -> None:
    init = handle_app_init({"data_dir": str(tmp_path / "ipc")})
    pe = init["pe_sieve"]
    mu = init["mal_unpack"]
    yara = init["yara"]
    assert pe.get("available") is False
    assert pe.get("executable_path") in (None, "")
    assert mu.get("available") is False
    assert mu.get("executable_path") in (None, "")
    # YARA is an optional Python extra. Report availability honestly; never bundle an EXE.
    assert "available" in yara
    assert yara.get("provider") == "yara" or yara.get("available") in (True, False)


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
        assert _provider_unavailable(providers["yara"])


def test_user_data_is_separate_from_install_dirs(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("MEMSCOPE_DATA_DIR", raising=False)
    local = tmp_path / "Local"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    data = default_data_dir()
    nsis_install = local / "Programs" / "MemScope"
    program_files = tmp_path / "Program Files" / "MemScope"
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


def test_pe_sieve_ignores_install_tree_executables(tmp_path: Path) -> None:
    install = tmp_path / "Programs" / "MemScope"
    install.mkdir(parents=True)
    decoy = install / "pe-sieve64.exe"
    decoy.write_bytes(b"MZ" + b"\x00" * 256)
    paths = AppPaths(tmp_path / "data").ensure()
    provider = PeSieveProvider(tools_dir=paths.tools, artifacts_dir=paths.artifacts)
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
    assert payload["yara_available_ids"] == []
    assert "yara" in payload["missing_extras"]
    assert "capstone" in payload["missing_extras"]
    assert "Crypto" in payload["missing_extras"]
    # Import failures must be listed, not turned into fake plugin rows.
    assert isinstance(payload["import_failures"], list)

