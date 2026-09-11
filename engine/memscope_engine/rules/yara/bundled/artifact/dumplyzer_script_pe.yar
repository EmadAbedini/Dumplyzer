/*
 * Dumplyzer original Signature Detection rules (Apache-2.0).
 * Offensive PowerShell / AMSI indicators embedded in extracted PE images.
 * Does not treat a normal powershell.exe / SMA.dll as a match.
 * Not copied from a third-party YARA repository.
 */

rule dumplyzer_script_embedded_powershell_pe : script artifact
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "command_script"
        target = "artifact"
        description = "Hidden PowerShell command line or Invoke-Mimikatz embedded in a PE"
        origin = "original"
    strings:
        $mz = { 4D 5A }
        $s1 = "powershell -nop -w hidden" ascii wide nocase
        $s2 = "-nop -w hidden -enc" ascii wide nocase
        $s3 = "Invoke-Mimikatz" ascii wide nocase
        $enc = "EncodedCommand" ascii wide nocase
        $b64 = "FromBase64String" ascii wide
    condition:
        $mz at 0 and (1 of ($s*) or ($enc and $b64))
}

rule dumplyzer_script_amsi_bypass_pe : script artifact
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "command_script"
        target = "artifact"
        description = "AMSI bypass reflection one-liner embedded in an extracted PE"
        origin = "original"
    strings:
        $mz = { 4D 5A }
        $t = "System.Management.Automation.AmsiUtils" ascii wide
        $f = "amsiInitFailed" ascii wide
        $b = "NonPublic,Static" ascii wide
    condition:
        $mz at 0 and all of ($t, $f, $b)
}
