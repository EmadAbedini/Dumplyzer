/*
 * Dumplyzer original Signature Detection rules (Apache-2.0).
 * Offensive PowerShell / AMSI-bypass indicators for raw memory.
 * Intentionally does not match a normal PowerShell runtime (SMA.dll + amsi.dll).
 * Not copied from a third-party YARA repository.
 */

rule dumplyzer_script_amsi_bypass_memory : script memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "command_script"
        severity = "medium"
        target = "memory"
        description = "Matt Graeber-style AMSI bypass reflection one-liner in raw memory"
        origin = "original"
    strings:
        $t = "System.Management.Automation.AmsiUtils" ascii wide
        $f = "amsiInitFailed" ascii wide
        $b = "NonPublic,Static" ascii wide
    condition:
        all of them
}

rule dumplyzer_script_encoded_powershell_memory : script memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "command_script"
        severity = "medium"
        target = "memory"
        description = "Hidden / encoded PowerShell command-line patterns in raw memory"
        origin = "original"
    strings:
        $s1 = "powershell -nop -w hidden" ascii wide nocase
        $s2 = "powershell.exe -nop -w hidden" ascii wide nocase
        $s3 = "-nop -w hidden -enc" ascii wide nocase
        $s4 = "powershell -w hidden -nop" ascii wide nocase
        $s5 = "powershell -nop -exec bypass" ascii wide nocase
    condition:
        1 of them
}

rule dumplyzer_script_powersploit_memory : script memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "command_script"
        severity = "medium"
        target = "memory"
        description = "PowerSploit / offensive PowerShell cmdlet names in raw memory"
        origin = "original"
    strings:
        $s1 = "Invoke-Mimikatz" ascii wide nocase
        $s2 = "Invoke-NinjaCopy" ascii wide nocase
        $s3 = "Invoke-ReflectivePEInjection" ascii wide nocase
        $s4 = "Invoke-TokenManipulation" ascii wide nocase
        $s5 = "Get-GPPPassword" ascii wide nocase
        $s6 = "Invoke-Shellcode" ascii wide nocase
    condition:
        1 of them
}
