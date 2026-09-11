"""Inventory, detection, false-positive, packaging, and performance tests for bundled YARA rules."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from memscope_engine.paths import AppPaths, sync_bundled_yara_rules
from memscope_engine.providers.yara_provider import (
    KIND_ARTIFACT,
    KIND_MEMORY,
    YaraProvider,
    detect_yara,
    discover_rule_files,
    list_rule_names,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINE_BUNDLED = (
    REPO_ROOT / "engine" / "memscope_engine" / "rules" / "yara" / "bundled"
)
DESKTOP_BUNDLED = (
    REPO_ROOT / "app" / "desktop" / "resources" / "rules" / "yara" / "bundled"
)
CATALOG_PATH = ENGINE_BUNDLED / "catalog.json"


def _require_yara() -> None:
    info = detect_yara()
    if not info["available"]:
        pytest.fail("yara-python 4.5.4 must be installed in the engine environment")


def _catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def _provider(paths: AppPaths) -> YaraProvider:
    return YaraProvider(
        default_rules_dir=paths.yara_rules,
        bundled_dir=paths.yara_rules_bundled,
        custom_dir=paths.yara_rules_custom,
    )


def _declared_names() -> list[str]:
    names: list[str] = []
    for path in discover_rule_files([ENGINE_BUNDLED]):
        names.extend(list_rule_names(path))
    return names


POSITIVE_FIXTURES: dict[str, bytes] = {
    "dumplyzer_credtheft_mimikatz_memory": b"sekurlsa::logonpasswords\x00lsadump::sam",
    "dumplyzer_credtheft_rubeus_memory": b"Rubeus\x00kerberoast\x00asktgt",
    "dumplyzer_credtheft_safetykatz_memory": b"SafetyKatz\x00sekurlsa::logonpasswords",
    "dumplyzer_credtheft_nanodump_memory": b"NanoDumpWriteDump",
    "dumplyzer_credtheft_pypykatz_memory": b"pypykatz\x00lsa_decryptor",
    "dumplyzer_script_amsi_bypass_memory": (
        b"System.Management.Automation.AmsiUtils\x00amsiInitFailed\x00NonPublic,Static"
    ),
    "dumplyzer_script_encoded_powershell_memory": b"powershell -nop -w hidden -file x.ps1",
    "dumplyzer_script_powersploit_memory": b"Invoke-Mimikatz -DumpCreds",
    "dumplyzer_c2_cobaltstrike_beacon_memory": b"%s.beacon_%d.dll",
    "dumplyzer_c2_cobaltstrike_pipe_memory": b"MSSE-%d-server",
    "dumplyzer_c2_meterpreter_memory": b"stdapi_fs_ls\x00metsrv.dll",
    "dumplyzer_c2_sliver_memory": b"sliverpb.\x00sliver.proto",
    "dumplyzer_c2_havoc_memory": b"Havoc\x00SleepObf\x00IndirectSyscall",
    "dumplyzer_c2_empire_memory": b"Invoke-Empire\x00EmpireAgent",
    "dumplyzer_c2_covenant_memory": b"GruntStager\x00GruntWorker",
    "dumplyzer_c2_bruteratel_memory": b"Brute Ratel\x00BRc4",
    "dumplyzer_inject_reflective_loader_memory": b"ReflectiveLoader",
    "dumplyzer_inject_donut_memory": b"DONUT_INSTANCE\x00DONUT_MODULE",
    "dumplyzer_inject_srdi_memory": b"ConvertTo-Shellcode\x00Get-FunctionRVA",
    "dumplyzer_inject_ror13_apihash_memory": bytes.fromhex("8e4e0eec")
    + (b"\x00" * 16)
    + bytes.fromhex("aafc0d7c"),
    "dumplyzer_malware_quasar_memory": b"Quasar.Common\x00Quasar.Client",
    "dumplyzer_malware_asyncrat_memory": b"AsyncRAT\x00AsyncClient",
    "dumplyzer_malware_remcos_memory": b"Remcos\x00remcos.exe",
    "dumplyzer_malware_nanocore_memory": b"NanoCore.ClientPluginHost",
    "dumplyzer_malware_redline_memory": b"RedLine.Reborn\x00RedLine Stealer",
    "dumplyzer_recon_sharphound_memory": b"SharpHound\x00BloodHound",
    "dumplyzer_credtheft_mimikatz_pe": b"MZ" + (b"\x00" * 32) + b"mimikatz\x00sekurlsa::logonpasswords",
    "dumplyzer_credtheft_rubeus_pe": b"MZ" + (b"\x00" * 32) + b"Rubeus\x00kerberoast\x00asktgt",
    "dumplyzer_credtheft_nanodump_pe": b"MZ" + (b"\x00" * 32) + b"NanoDumpWriteDump",
    "dumplyzer_credtheft_safetykatz_pe": b"MZ" + (b"\x00" * 32) + b"SafetyKatz\x00sekurlsa::logonpasswords",
    "dumplyzer_script_embedded_powershell_pe": b"MZ"
    + (b"\x00" * 32)
    + b"powershell -nop -w hidden",
    "dumplyzer_script_amsi_bypass_pe": b"MZ"
    + (b"\x00" * 32)
    + b"System.Management.Automation.AmsiUtils\x00amsiInitFailed\x00NonPublic,Static",
    "dumplyzer_c2_cobaltstrike_beacon_pe": b"MZ" + (b"\x00" * 32) + b"%s.beacon_%d.dll",
    "dumplyzer_c2_meterpreter_pe": b"MZ" + (b"\x00" * 32) + b"stdapi_fs_ls\x00metsrv.dll",
    "dumplyzer_c2_sliver_pe": b"MZ" + (b"\x00" * 32) + b"sliverpb.\x00sliver.proto",
    "dumplyzer_c2_covenant_pe": b"MZ" + (b"\x00" * 32) + b"GruntStager\x00GruntWorker",
    "dumplyzer_inject_reflective_loader_pe": b"MZ" + (b"\x00" * 32) + b"ReflectiveLoader",
    "dumplyzer_inject_donut_pe": b"MZ" + (b"\x00" * 32) + b"DONUT_INSTANCE\x00DONUT_MODULE",
    "dumplyzer_malware_quasar_pe": b"MZ" + (b"\x00" * 32) + b"Quasar.Common\x00Quasar.Client",
    "dumplyzer_malware_asyncrat_pe": b"MZ" + (b"\x00" * 32) + b"AsyncRAT\x00AsyncClient",
    "dumplyzer_malware_nanocore_pe": b"MZ" + (b"\x00" * 32) + b"NanoCoreClient",
    "dumplyzer_malware_redline_pe": b"MZ" + (b"\x00" * 32) + b"RedLine.Reborn\x00RedLine Stealer",
}

BENIGN_MEMORY = (
    b"kernel32.dll\x00KERNEL32.dll\x00ntdll.dll\x00user32.dll\x00"
    b"GetProcAddress\x00LoadLibraryA\x00LoadLibraryW\x00VirtualAlloc\x00"
    b"VirtualAllocEx\x00VirtualProtect\x00CreateRemoteThread\x00"
    b"WriteProcessMemory\x00ReadProcessMemory\x00NtCreateThreadEx\x00"
    b"RtlCreateUserThread\x00CreateProcessW\x00OpenProcess\x00"
    b"System.Management.Automation.dll\x00"
    b"System.Management.Automation.AmsiUtils\x00"
    b"AmsiScanBuffer\x00amsiInitFailed\x00"
    b"System.Reflection.Assembly.Load\x00"
    b"Invoke-Expression\x00FromBase64String\x00EncodedCommand\x00"
    b"powershell.exe\x00cmd.exe\x00explorer.exe\x00"
    b"NonPublic, Static\x00"
)

BENIGN_PE = (
    b"MZ"
    + b"This program cannot be run in DOS mode.\r\n$"
    + b"kernel32.dll\x00GetProcAddress\x00LoadLibraryA\x00"
    + b"VirtualAllocEx\x00CreateRemoteThread\x00WriteProcessMemory\x00"
    + b"System.Management.Automation.dll\x00AmsiScanBuffer\x00"
    + b"amsiInitFailed\x00Invoke-Expression\x00"
    + b"powershell.exe\x00"
)


def test_catalog_matches_declared_rule_names() -> None:
    catalog = _catalog()
    catalog_names = [row["name"] for row in catalog["rules"]]
    declared = _declared_names()
    assert len(catalog_names) == len(set(catalog_names))
    assert sorted(declared) == sorted(catalog_names)
    assert len(declared) == len(set(declared))
    files = {row["file"] for row in catalog["rules"]}
    for rel in files:
        assert (ENGINE_BUNDLED / rel).is_file()
    for row in catalog["rules"]:
        assert row["origin"] == "original"
        assert row["license"] == "Apache-2.0"
        assert row["target"] in {KIND_MEMORY, KIND_ARTIFACT}
        assert row["category"]


def test_all_bundled_files_compile() -> None:
    _require_yara()
    import yara

    skipped = []
    for path in discover_rule_files([ENGINE_BUNDLED]):
        try:
            yara.compile(filepath=str(path))
        except Exception as exc:  # noqa: BLE001
            skipped.append(f"{path.name}: {exc}")
    assert skipped == []


def test_provider_bundled_count_matches_catalog(tmp_path: Path) -> None:
    _require_yara()
    paths = AppPaths(tmp_path / "data").ensure()
    catalog_n = len(_catalog()["rules"])
    avail = _provider(paths).availability()
    assert avail["available"] is True
    assert avail["bundled_rule_count"] == catalog_n
    assert avail["loaded_rule_count"] == catalog_n
    assert avail["custom_rule_count"] == 0
    assert avail["skipped_rule_file_count"] == 0


def test_positive_fixture_for_every_catalog_rule(tmp_path: Path) -> None:
    _require_yara()
    catalog = _catalog()["rules"]
    missing = [row["name"] for row in catalog if row["name"] not in POSITIVE_FIXTURES]
    assert missing == [], f"no positive fixture for {missing}"
    paths = AppPaths(tmp_path / "data").ensure()
    p = _provider(paths)
    failed: list[str] = []
    for row in catalog:
        name = row["name"]
        kind = row["target"]
        sample = tmp_path / f"{name}.bin"
        sample.write_bytes(POSITIVE_FIXTURES[name])
        if kind == KIND_MEMORY:
            res = p.scan_memory_image(sample)
        else:
            res = p.scan_file(sample, kind=KIND_ARTIFACT)
        names = {m["rule_name"] for m in res["matches"]}
        if name not in names:
            failed.append(f"{name}: matched {sorted(names)}")
    assert failed == []


def test_benign_windows_strings_do_not_match(tmp_path: Path) -> None:
    _require_yara()
    paths = AppPaths(tmp_path / "data").ensure()
    p = _provider(paths)
    mem = tmp_path / "benign_mem.bin"
    mem.write_bytes(BENIGN_MEMORY)
    mem_res = p.scan_memory_image(mem)
    assert mem_res["match_count"] == 0, [m["rule_name"] for m in mem_res["matches"]]
    pe = tmp_path / "benign_pe.bin"
    pe.write_bytes(BENIGN_PE)
    pe_res = p.scan_file(pe, kind=KIND_ARTIFACT)
    assert pe_res["match_count"] == 0, [m["rule_name"] for m in pe_res["matches"]]


def _windows_system_files() -> list[Path]:
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    candidates = [
        root / "System32" / "ntdll.dll",
        root / "System32" / "kernel32.dll",
        root / "System32" / "kernelbase.dll",
        root / "System32" / "user32.dll",
        root / "System32" / "amsi.dll",
        root / "System32" / "cmd.exe",
        root / "System32" / "notepad.exe",
        root / "explorer.exe",
        root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
        root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe.config",
    ]
    return [p for p in candidates if p.is_file()]


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows artifacts")
def test_bundled_rules_do_not_match_windows_system_files(tmp_path: Path) -> None:
    _require_yara()
    files = _windows_system_files()
    assert files, "expected at least one Windows system file"
    paths = AppPaths(tmp_path / "data").ensure()
    p = _provider(paths)
    hits: list[str] = []
    for path in files:
        mem_res = p.scan_memory_image(path)
        if mem_res["match_count"]:
            hits.append(
                f"memory {path.name}: {[m['rule_name'] for m in mem_res['matches']]}"
            )
        art_res = p.scan_file(path, kind=KIND_ARTIFACT)
        if art_res["match_count"]:
            hits.append(
                f"artifact {path.name}: {[m['rule_name'] for m in art_res['matches']]}"
            )
    assert hits == []


def test_stale_bundled_yar_removed_on_sync(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    stale = paths.yara_rules_bundled / "memory" / "dumplyzer_retired_rule.yar"
    stale.write_text("rule dumplyzer_retired_rule { condition: true }\n", encoding="utf-8")
    assert stale.is_file()
    custom = paths.yara_rules_custom / "keep_me.yar"
    custom.write_text("rule KeepMe { condition: true }\n", encoding="utf-8")
    sync_bundled_yara_rules(paths.yara_rules_bundled)
    assert not stale.exists()
    assert custom.is_file()
    assert (paths.yara_rules_bundled / "catalog.json").is_file()


def test_engine_and_desktop_bundled_trees_match() -> None:
    assert ENGINE_BUNDLED.is_dir()
    assert DESKTOP_BUNDLED.is_dir()
    engine_files = {
        p.relative_to(ENGINE_BUNDLED).as_posix().lower()
        for p in ENGINE_BUNDLED.rglob("*")
        if p.is_file()
    }
    desktop_files = {
        p.relative_to(DESKTOP_BUNDLED).as_posix().lower()
        for p in DESKTOP_BUNDLED.rglob("*")
        if p.is_file()
    }
    assert engine_files == desktop_files
    for rel in engine_files:
        left = (ENGINE_BUNDLED / rel).read_bytes()
        right = (DESKTOP_BUNDLED / rel).read_bytes()
        assert left == right, rel


def test_rules_md_and_catalog_are_packaged() -> None:
    rules_md = REPO_ROOT / "engine" / "memscope_engine" / "rules" / "yara" / "RULES.md"
    assert rules_md.is_file()
    text = rules_md.read_text(encoding="utf-8")
    assert "Apache-2.0" in text
    assert "original" in text.lower()
    assert CATALOG_PATH.is_file()
    assert (ENGINE_BUNDLED / "README.md").is_file()


def test_scan_performance_on_representative_buffer(tmp_path: Path) -> None:
    _require_yara()
    paths = AppPaths(tmp_path / "data").ensure()
    p = _provider(paths)
    blob = (BENIGN_MEMORY + os.urandom(64)) * 8000
    assert len(blob) >= 4 * 1024 * 1024
    target = tmp_path / "perf.bin"
    target.write_bytes(blob)
    started = time.perf_counter()
    res = p.scan_memory_image(target)
    elapsed = time.perf_counter() - started
    assert res["status"] == "completed"
    assert res["match_count"] == 0
    assert elapsed < 15.0, f"bundled memory scan took {elapsed:.2f}s"
