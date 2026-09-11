/*
 * Dumplyzer original Signature Detection rules (Apache-2.0).
 * In-memory loaders and shellcode API-hash stubs.
 * Does not treat common kernel32 export names as injection by themselves.
 * Not copied from a third-party YARA repository.
 */

rule dumplyzer_inject_reflective_loader_memory : inject memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "injection"
        target = "memory"
        description = "Stephen Fewer ReflectiveLoader export name in raw memory"
        origin = "original"
    strings:
        $s1 = "ReflectiveLoader" ascii wide
        $s2 = "reflective_dll" ascii wide nocase
        $s3 = "ReflectiveDll" ascii wide
    condition:
        $s1 or 2 of ($s2, $s3)
}

rule dumplyzer_inject_donut_memory : inject memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "injection"
        target = "memory"
        description = "Donut in-memory .NET / PE loader type names in raw memory"
        origin = "original"
    strings:
        $s1 = "DONUT_INSTANCE" ascii
        $s2 = "DONUT_MODULE" ascii
        $s3 = "DONUT_ERROR" ascii
        $s4 = "PDONUT_" ascii
    condition:
        2 of them
}

rule dumplyzer_inject_srdi_memory : inject memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "injection"
        target = "memory"
        description = "sRDI ConvertTo-Shellcode helper strings in raw memory"
        origin = "original"
    strings:
        $s1 = "ConvertTo-Shellcode" ascii wide nocase
        $s2 = "Get-FunctionRVA" ascii wide nocase
        $s3 = "sRDI" ascii wide
        $s4 = "Start-srdiFunction" ascii wide nocase
    condition:
        2 of them
}

rule dumplyzer_inject_ror13_apihash_memory : inject memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "injection"
        target = "memory"
        description = "Classic ror13 LoadLibraryA/GetProcAddress hashes within 2 KiB (Metasploit-style block_api)"
        origin = "original"
    strings:
        // 0xEC0E4E8E LoadLibraryA and 0x7C0DFCAA GetProcAddress, little-endian, bounded gap.
        $pair1 = { 8E 4E 0E EC [0-2048] AA FC 0D 7C }
        $pair2 = { AA FC 0D 7C [0-2048] 8E 4E 0E EC }
    condition:
        $pair1 or $pair2
}
