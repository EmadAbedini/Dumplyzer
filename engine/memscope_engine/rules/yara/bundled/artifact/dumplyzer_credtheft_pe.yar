/*
 * Dumplyzer original Signature Detection rules (Apache-2.0).
 * Credential-theft strings in extracted PE / memory-resident images.
 * Requires an MZ header at offset 0. No pe module (reconstructed PEs may be incomplete).
 * Not copied from a third-party YARA repository.
 */

rule dumplyzer_credtheft_mimikatz_pe : credtheft artifact
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "credential_theft"
        severity = "high"
        target = "artifact"
        description = "Mimikatz CLI or kuhl_m_* strings in an extracted PE image"
        origin = "original"
    strings:
        $mz = { 4D 5A }
        $cli1 = "sekurlsa::logonpasswords" ascii wide
        $cli2 = "lsadump::sam" ascii wide
        $cli3 = "kerberos::ptt" ascii wide
        $auth = "gentilkiwi" ascii wide
        $name = "mimikatz" ascii wide nocase
        $mod1 = "kuhl_m_sekurlsa" ascii
        $mod2 = "kuhl_m_lsadump" ascii
    condition:
        $mz at 0 and (2 of ($cli*) or 2 of ($mod*) or $auth or ($name and 1 of ($cli*, $mod*)))
}

rule dumplyzer_credtheft_rubeus_pe : credtheft artifact
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "credential_theft"
        severity = "high"
        target = "artifact"
        description = "Rubeus Kerberos abuse tooling strings in an extracted PE image"
        origin = "original"
    strings:
        $mz = { 4D 5A }
        $name = "Rubeus" ascii wide
        $c1 = "kerberoast" ascii wide nocase
        $c2 = "asktgt" ascii wide nocase
        $c3 = "asreproast" ascii wide nocase
        $c4 = "currentluid" ascii wide nocase
        $c5 = "GoldenTicket" ascii wide
    condition:
        $mz at 0 and $name and 2 of ($c*)
}

rule dumplyzer_credtheft_nanodump_pe : credtheft artifact
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "credential_theft"
        severity = "high"
        target = "artifact"
        description = "NanoDump helper strings in an extracted PE image"
        origin = "original"
    strings:
        $mz = { 4D 5A }
        $s1 = "NanoDumpWriteDump" ascii wide
        $s2 = "duplicate-elevate" ascii wide
        $s3 = "NanoDump" ascii wide
    condition:
        $mz at 0 and ($s1 or ($s2 and $s3))
}

rule dumplyzer_credtheft_safetykatz_pe : credtheft artifact
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "credential_theft"
        severity = "high"
        target = "artifact"
        description = "SafetyKatz wrapper strings in an extracted PE image"
        origin = "original"
    strings:
        $mz = { 4D 5A }
        $s1 = "SafetyKatz" ascii wide
        $s2 = "sekurlsa::logonpasswords" ascii wide
        $s3 = "kuhl_m_sekurlsa" ascii
    condition:
        $mz at 0 and $s1 and 1 of ($s2, $s3)
}
