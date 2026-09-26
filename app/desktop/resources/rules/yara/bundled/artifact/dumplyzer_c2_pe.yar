/*
 * Dumplyzer original Signature Detection rules (Apache-2.0).
 * C2 / post-exploitation framework strings in extracted PE images.
 * Not copied from a third-party YARA repository.
 */

rule dumplyzer_c2_cobaltstrike_beacon_pe : c2 artifact
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "c2"
        severity = "high"
        target = "artifact"
        description = "Cobalt Strike Beacon module strings in an extracted PE image"
        origin = "original"
    strings:
        $mz = { 4D 5A }
        $s1 = "%s.beacon_%d.dll" ascii wide
        $s2 = "beacon.x64.dll" ascii wide nocase
        $s3 = "www.cobaltstrike.com" ascii wide nocase
        $s4 = "beacon.dll" ascii wide nocase
    condition:
        $mz at 0 and ($s1 or $s3 or 2 of ($s2, $s4))
}

rule dumplyzer_c2_meterpreter_pe : c2 artifact
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "c2"
        severity = "high"
        target = "artifact"
        description = "Meterpreter stdapi / metsrv strings in an extracted PE image"
        origin = "original"
    strings:
        $mz = { 4D 5A }
        $s1 = "stdapi_fs_ls" ascii
        $s2 = "stdapi_sys_process_get_processes" ascii
        $s3 = "stdapi_net_config_get_interfaces" ascii
        $s4 = "stdapi_sys_config_getuid" ascii
        $s5 = "metsrv.dll" ascii nocase
    condition:
        $mz at 0 and 2 of ($s*)
}

rule dumplyzer_c2_sliver_pe : c2 artifact
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "c2"
        severity = "high"
        target = "artifact"
        description = "Sliver protobuf / module path strings in an extracted PE image"
        origin = "original"
    strings:
        $mz = { 4D 5A }
        $s1 = "sliverpb." ascii
        $s2 = "github.com/bishopfox/sliver" ascii
        $s3 = "sliver.proto" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}

rule dumplyzer_c2_covenant_pe : c2 artifact
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "c2"
        severity = "high"
        target = "artifact"
        description = "Covenant Grunt type names in an extracted PE image"
        origin = "original"
    strings:
        $mz = { 4D 5A }
        $s1 = "GruntStager" ascii wide
        $s2 = "GruntWorker" ascii wide
        $s3 = "Covenant.API" ascii wide
    condition:
        $mz at 0 and 2 of ($s*)
}

rule dumplyzer_c2_havoc_pe : c2 artifact
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "c2"
        severity = "high"
        target = "artifact"
        description = "Havoc Demon profile/config key combination in an extracted PE image"
        origin = "original"
    strings:
        $mz = { 4D 5A }
        $s1 = "Havoc" ascii wide
        $s2 = "SleepObf" ascii wide
        $s3 = "IndirectSyscall" ascii wide
        $s4 = "StackDuplication" ascii wide
    condition:
        $mz at 0 and $s1 and 2 of ($s2, $s3, $s4)
}

rule dumplyzer_c2_bruteratel_pe : c2 artifact
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "c2"
        severity = "high"
        target = "artifact"
        description = "Brute Ratel C4 / BRc4 product strings in an extracted PE image"
        origin = "original"
    strings:
        $mz = { 4D 5A }
        $s1 = "Brute Ratel" ascii wide nocase
        $s2 = "BRc4" ascii wide
        $s3 = "badger_metadata" ascii wide
        $s4 = "BruteRatel" ascii wide
    condition:
        $mz at 0 and 2 of ($s*)
}

rule dumplyzer_c2_mythic_pe : c2 artifact
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "c2"
        severity = "high"
        target = "artifact"
        description = "Mythic C2 RPC / Apollo agent type names in an extracted PE image"
        origin = "original"
    strings:
        $mz = { 4D 5A }
        $s1 = "MythicRPC" ascii
        $s2 = "mythic_payload" ascii
        $s3 = "Apollo.Jobs" ascii wide
        $s4 = "Mythic.Crypto" ascii wide
    condition:
        $mz at 0 and 1 of ($s*)
}
