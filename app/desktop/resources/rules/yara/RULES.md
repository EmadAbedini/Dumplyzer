# Dumplyzer bundled YARA rules

These rules are **original Dumplyzer signatures** (Apache-2.0). They encode
publicly documented tool and malware indicator strings used in memory
forensics. They are **not** copied from VirusTotal, signature-base,
Yara-Rules, Elastic, CAPE, or other third-party rule repositories.

Matches are investigation indicators, not a malware verdict.

| Field | Value |
|-------|--------|
| License | Apache-2.0 (same as Dumplyzer) |
| Origin | Original Dumplyzer rules |
| Redistribution | Permitted under Apache-2.0 |
| Attribution | `author = "Dumplyzer"` in each rule |
| Runtime download | None. Rules are static application resources. |

Machine-readable inventory: `bundled/catalog.json`.

## Scan targets

| Folder | Used when |
|--------|-----------|
| `bundled/memory/` | Scanning the original memory dump. No `pe` module, no `filesize`, no `$mz at 0`. |
| `bundled/artifact/` | Scanning extracted PE artifacts. `$mz at 0` only; no `pe` module (reconstructed images may be incomplete). |

Custom rules stay in `%LOCALAPPDATA%\Dumplyzer\rules\yara\custom\` and are never overwritten.

## Counts

The Settings UI and `yara.status` report the **number of valid compiled rules**, not a marketing figure. See `bundled_rule_count` / `custom_rule_count` / `loaded_rule_count`.

## Categories

| Category | Memory | PE / artifact | Purpose |
|----------|--------|---------------|---------|
| credential_theft | 5 | 4 | Mimikatz, Rubeus, SafetyKatz, NanoDump, pypykatz |
| command_script | 3 | 2 | AMSI bypass one-liner, hidden/encoded PowerShell, PowerSploit cmdlets |
| c2 | 8 | 4 | Cobalt Strike, Meterpreter, Sliver, Havoc, Empire, Covenant, Brute Ratel |
| injection | 4 | 2 | ReflectiveLoader, Donut, sRDI, ror13 API-hash stub |
| malware | 5 | 4 | Quasar, AsyncRAT, Remcos, NanoCore, RedLine |
| recon | 1 | 0 | SharpHound / BloodHound collector |

**Total: 42 rules** (26 memory, 16 artifact). Quality was preferred over hitting a round number.

## Rule inventory

Every rule below is original Dumplyzer work. Indicator strings are facts published with the tools or in public DFIR reporting. No third-party YARA source file was imported.

### Credential theft

| Rule | Target | Purpose | Origin | License |
|------|--------|---------|--------|---------|
| `dumplyzer_credtheft_mimikatz_memory` | memory | Mimikatz `module::command` / `kuhl_m_*` / `gentilkiwi` | original | Apache-2.0 |
| `dumplyzer_credtheft_rubeus_memory` | memory | Rubeus + Kerberos abuse commands | original | Apache-2.0 |
| `dumplyzer_credtheft_safetykatz_memory` | memory | SafetyKatz wrapper + Mimikatz CLI | original | Apache-2.0 |
| `dumplyzer_credtheft_nanodump_memory` | memory | `NanoDumpWriteDump` / NanoDump | original | Apache-2.0 |
| `dumplyzer_credtheft_pypykatz_memory` | memory | pypykatz decryptor module paths | original | Apache-2.0 |
| `dumplyzer_credtheft_mimikatz_pe` | artifact | Same Mimikatz indicators in a PE | original | Apache-2.0 |
| `dumplyzer_credtheft_rubeus_pe` | artifact | Rubeus in a PE | original | Apache-2.0 |
| `dumplyzer_credtheft_nanodump_pe` | artifact | NanoDump in a PE | original | Apache-2.0 |
| `dumplyzer_credtheft_safetykatz_pe` | artifact | SafetyKatz in a PE | original | Apache-2.0 |

### Command and script execution

| Rule | Target | Purpose | Origin | License |
|------|--------|---------|--------|---------|
| `dumplyzer_script_amsi_bypass_memory` | memory | Graeber AMSI one-liner (`AmsiUtils` + `amsiInitFailed` + `NonPublic,Static`) | original | Apache-2.0 |
| `dumplyzer_script_encoded_powershell_memory` | memory | Contiguous `-nop -w hidden` / `-enc` command lines | original | Apache-2.0 |
| `dumplyzer_script_powersploit_memory` | memory | `Invoke-Mimikatz` and related PowerSploit cmdlets | original | Apache-2.0 |
| `dumplyzer_script_embedded_powershell_pe` | artifact | Hidden PS command or `EncodedCommand`+`FromBase64String` in one PE | original | Apache-2.0 |
| `dumplyzer_script_amsi_bypass_pe` | artifact | AMSI one-liner inside a PE | original | Apache-2.0 |

### C2 / post-exploitation

| Rule | Target | Purpose | Origin | License |
|------|--------|---------|--------|---------|
| `dumplyzer_c2_cobaltstrike_beacon_memory` | memory | Beacon format strings / `www.cobaltstrike.com` | original | Apache-2.0 |
| `dumplyzer_c2_cobaltstrike_pipe_memory` | memory | `MSSE-%d-server` / `msagent_` pipe formats | original | Apache-2.0 |
| `dumplyzer_c2_meterpreter_memory` | memory | `stdapi_*` / `metsrv.dll` | original | Apache-2.0 |
| `dumplyzer_c2_sliver_memory` | memory | `sliverpb.` / BishopFox module path | original | Apache-2.0 |
| `dumplyzer_c2_havoc_memory` | memory | Havoc + Demon config keys (`SleepObf`, `IndirectSyscall`) | original | Apache-2.0 |
| `dumplyzer_c2_empire_memory` | memory | Empire agent/module names | original | Apache-2.0 |
| `dumplyzer_c2_covenant_memory` | memory | `GruntStager` / `Covenant.API` | original | Apache-2.0 |
| `dumplyzer_c2_bruteratel_memory` | memory | `Brute Ratel` / `BRc4` | original | Apache-2.0 |
| `dumplyzer_c2_cobaltstrike_beacon_pe` | artifact | Beacon strings in a PE | original | Apache-2.0 |
| `dumplyzer_c2_meterpreter_pe` | artifact | Meterpreter strings in a PE | original | Apache-2.0 |
| `dumplyzer_c2_sliver_pe` | artifact | Sliver strings in a PE | original | Apache-2.0 |
| `dumplyzer_c2_covenant_pe` | artifact | Covenant strings in a PE | original | Apache-2.0 |

### Injection / in-memory execution

| Rule | Target | Purpose | Origin | License |
|------|--------|---------|--------|---------|
| `dumplyzer_inject_reflective_loader_memory` | memory | `ReflectiveLoader` export name (not kernel32 APIs) | original | Apache-2.0 |
| `dumplyzer_inject_donut_memory` | memory | `DONUT_INSTANCE` / `DONUT_MODULE` | original | Apache-2.0 |
| `dumplyzer_inject_srdi_memory` | memory | sRDI `ConvertTo-Shellcode` / `Get-FunctionRVA` | original | Apache-2.0 |
| `dumplyzer_inject_ror13_apihash_memory` | memory | Bounded ror13 `LoadLibraryA`+`GetProcAddress` hash pair | original | Apache-2.0 |
| `dumplyzer_inject_reflective_loader_pe` | artifact | `ReflectiveLoader` in a PE | original | Apache-2.0 |
| `dumplyzer_inject_donut_pe` | artifact | Donut types in a PE | original | Apache-2.0 |

The ror13 DWORD pair (`0xEC0E4E8E`, `0x7C0DFCAA`) is the publicly documented Metasploit `block_api` hash of `LoadLibraryA` / `GetProcAddress` (Skape / H D Moore). The rule requires both hashes within 2048 bytes. It is an original Dumplyzer condition, not an imported YARA file.

### Malware / loaders

| Rule | Target | Purpose | Origin | License |
|------|--------|---------|--------|---------|
| `dumplyzer_malware_quasar_memory` | memory | Quasar .NET namespaces | original | Apache-2.0 |
| `dumplyzer_malware_asyncrat_memory` | memory | AsyncRAT product + client types | original | Apache-2.0 |
| `dumplyzer_malware_remcos_memory` | memory | Remcos product string combination | original | Apache-2.0 |
| `dumplyzer_malware_nanocore_memory` | memory | `NanoCore.ClientPluginHost` / `NanoCoreClient` | original | Apache-2.0 |
| `dumplyzer_malware_redline_memory` | memory | RedLine.Reborn / product strings | original | Apache-2.0 |
| `dumplyzer_malware_quasar_pe` | artifact | Quasar in a PE | original | Apache-2.0 |
| `dumplyzer_malware_asyncrat_pe` | artifact | AsyncRAT in a PE | original | Apache-2.0 |
| `dumplyzer_malware_nanocore_pe` | artifact | NanoCore in a PE | original | Apache-2.0 |
| `dumplyzer_malware_redline_pe` | artifact | RedLine in a PE | original | Apache-2.0 |

### Recon

| Rule | Target | Purpose | Origin | License |
|------|--------|---------|--------|---------|
| `dumplyzer_recon_sharphound_memory` | memory | SharpHound / BloodHound collector strings | original | Apache-2.0 |

## Existing rules that were rewritten

The previous eight bundled rules were reviewed in place:

| Previous rule | Verdict |
|---------------|---------|
| `Dumplyzer_Mimikatz_Memory` / `_PE` | Kept as an idea; tightened and renamed. Unique CLI / `kuhl_m_*` strings are sound. |
| `Dumplyzer_CobaltStrike_Beacon_Memory` / `_PE` | Kept as an idea; dropped lone `ReflectiveLoader` pairing; kept Beacon-specific format strings. |
| `Dumplyzer_PowerShell_InMemory` | **Replaced.** `System.Management.Automation.dll` + `AmsiScanBuffer` matches legitimate PowerShell. |
| `Dumplyzer_Reflective_Injection_Memory` | **Replaced.** `CreateRemoteThread` / `VirtualAllocEx` / `WriteProcessMemory` are kernel32 export names present in every Windows process. |
| `Dumplyzer_CallPop_Shellcode_Stub_Memory` | **Replaced.** `E8 00 00 00 00 59` plus `kernel32.dll`/`GetProcAddress` is too common. |
| `Dumplyzer_Suspicious_Script_PE` | **Replaced.** Would match `powershell.exe` (`System.Management.Automation` + `Invoke-Expression`). |

## Intentionally excluded

| Candidate | Reason |
|-----------|--------|
| Generic `CreateRemoteThread` + `VirtualAllocEx` + `WriteProcessMemory` | Present in kernel32; matches every Windows process |
| Generic PowerShell runtime (`SMA.dll`, `AmsiScanBuffer`) | Present in legitimate PowerShell |
| `EncodedCommand` + `FromBase64String` as a **memory** rule | Those strings live in different legitimate modules and would fire on a normal PowerShell process dump |
| Emotet / TrickBot / IcedID family packers | Version-volatile; weak memory stability |
| Agent Tesla / njRAT single-name rules | Unstable or high FP |
| Nighthawk | Insufficient public high-quality strings to justify a bundled rule |
| UPX / generic packed-PE heuristics | Hits legitimate packed software |
| Third-party repositories (signature-base, Yara-Rules, CAPE, Elastic) | Not licensed for wholesale redistribution here; not curated for memory |
| YARA `pe` module on raw dumps | Does not apply to crash dumps / raw images; reconstructed PEs are often incomplete |
| Unbounded regex / huge hex wildcards | Too expensive on multi-GB dumps |

## Verification stance

Rules are **fixture-tested** (synthetic positives + benign Windows-string buffers, and Windows system files when the test host has them). They are **not** claimed as malware-sample-validated. Dumplyzer does not download malware to test signatures.

## Packaging

Shipped copies:

- `engine/memscope_engine/rules/yara/bundled/` (Python package data)
- `app/desktop/resources/rules/yara/bundled/` (installer resources)

`AppPaths.ensure()` copies bundled rules into `%LOCALAPPDATA%\Dumplyzer\rules\yara\bundled\` and deletes retired `.yar` files. Custom rules are never touched. No network access is used.
