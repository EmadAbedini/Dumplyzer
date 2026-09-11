/*
 * Dumplyzer original Signature Detection rules (Apache-2.0).
 * Post-exploitation / C2 framework strings for raw memory.
 * Not copied from a third-party YARA repository.
 */

rule dumplyzer_c2_cobaltstrike_beacon_memory : c2 memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "c2"
        target = "memory"
        description = "Cobalt Strike Beacon module and format-string indicators in raw memory"
        origin = "original"
    strings:
        $s1 = "%s.beacon_%d.dll" ascii wide
        $s2 = "beacon.x64.dll" ascii wide nocase
        $s3 = "www.cobaltstrike.com" ascii wide nocase
        $s4 = "beacon.dll" ascii wide nocase
        $s5 = "CobaltStrike" ascii wide nocase
    condition:
        $s1 or $s3 or 2 of ($s2, $s4, $s5)
}

rule dumplyzer_c2_cobaltstrike_pipe_memory : c2 memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "c2"
        target = "memory"
        description = "Cobalt Strike named-pipe format strings in raw memory"
        origin = "original"
    strings:
        $s1 = "MSSE-%d-server" ascii wide
        $s2 = "\\\\.\\pipe\\msagent_" ascii wide
        $s3 = "post-http" ascii wide
        $s4 = "beacon.dll" ascii wide nocase
    condition:
        $s1 or $s2 or ($s3 and $s4)
}

rule dumplyzer_c2_meterpreter_memory : c2 memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "c2"
        target = "memory"
        description = "Metasploit Meterpreter stdapi / metsrv strings in raw memory"
        origin = "original"
    strings:
        $s1 = "stdapi_fs_ls" ascii
        $s2 = "stdapi_sys_process_get_processes" ascii
        $s3 = "stdapi_net_config_get_interfaces" ascii
        $s4 = "stdapi_sys_config_getuid" ascii
        $s5 = "metsrv.dll" ascii nocase
        $s6 = "stdapi_railgun_api" ascii
    condition:
        2 of them
}

rule dumplyzer_c2_sliver_memory : c2 memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "c2"
        target = "memory"
        description = "Sliver implant protobuf / module path strings in raw memory"
        origin = "original"
    strings:
        $s1 = "sliverpb." ascii
        $s2 = "github.com/bishopfox/sliver" ascii
        $s3 = "sliver.proto" ascii
    condition:
        2 of them
}

rule dumplyzer_c2_havoc_memory : c2 memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "c2"
        target = "memory"
        description = "Havoc Demon profile/config key combination in raw memory"
        origin = "original"
    strings:
        $s1 = "Havoc" ascii wide
        $s2 = "SleepObf" ascii wide
        $s3 = "IndirectSyscall" ascii wide
        $s4 = "StackDuplication" ascii wide
    condition:
        $s1 and 2 of ($s2, $s3, $s4)
}

rule dumplyzer_c2_empire_memory : c2 memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "c2"
        target = "memory"
        description = "PowerShell Empire agent / module strings in raw memory"
        origin = "original"
    strings:
        $s1 = "Invoke-Empire" ascii wide nocase
        $s2 = "EmpireAgent" ascii wide
        $s3 = "Get-EmpireModule" ascii wide nocase
        $s4 = "Invoke-EmpireAgent" ascii wide nocase
    condition:
        2 of them
}

rule dumplyzer_c2_covenant_memory : c2 memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "c2"
        target = "memory"
        description = "Covenant Grunt stager / worker type names in raw memory"
        origin = "original"
    strings:
        $s1 = "GruntStager" ascii wide
        $s2 = "GruntWorker" ascii wide
        $s3 = "Covenant.API" ascii wide
        $s4 = "ExecuteStager" ascii wide
    condition:
        2 of them
}

rule dumplyzer_c2_bruteratel_memory : c2 memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "c2"
        target = "memory"
        description = "Brute Ratel C4 / BRc4 product strings in raw memory"
        origin = "original"
    strings:
        $s1 = "Brute Ratel" ascii wide nocase
        $s2 = "BRc4" ascii wide
        $s3 = "badger_metadata" ascii wide
        $s4 = "BruteRatel" ascii wide
    condition:
        2 of them
}
