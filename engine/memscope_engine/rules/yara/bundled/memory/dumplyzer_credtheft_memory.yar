/*
 * Dumplyzer original Signature Detection rules (Apache-2.0).
 * Publicly documented credential-theft indicator strings for raw memory.
 * Not copied from a third-party YARA repository.
 */

rule dumplyzer_credtheft_mimikatz_memory : credtheft memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "credential_theft"
        target = "memory"
        description = "Mimikatz CLI modules, internal kuhl_m_* names, or gentilkiwi in raw memory"
        origin = "original"
    strings:
        $cli1 = "sekurlsa::logonpasswords" ascii wide
        $cli2 = "lsadump::sam" ascii wide
        $cli3 = "kerberos::ptt" ascii wide
        $cli4 = "privilege::debug" ascii wide
        $cli5 = "sekurlsa::tickets" ascii wide
        $auth = "gentilkiwi" ascii wide
        $name = "mimikatz" ascii wide nocase
        $mod1 = "kuhl_m_sekurlsa" ascii
        $mod2 = "kuhl_m_lsadump" ascii
        $mod3 = "kuhl_m_kerberos" ascii
        $mod4 = "kuhl_m_privilege" ascii
    condition:
        2 of ($cli*) or 2 of ($mod*) or $auth or ($name and 1 of ($cli*, $mod*))
}

rule dumplyzer_credtheft_rubeus_memory : credtheft memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "credential_theft"
        target = "memory"
        description = "Rubeus Kerberos abuse tooling strings in raw memory"
        origin = "original"
    strings:
        $name = "Rubeus" ascii wide
        $c1 = "kerberoast" ascii wide nocase
        $c2 = "asktgt" ascii wide nocase
        $c3 = "asreproast" ascii wide nocase
        $c4 = "currentluid" ascii wide nocase
        $c5 = "s4u /" ascii wide nocase
        $c6 = "GoldenTicket" ascii wide
    condition:
        $name and 2 of ($c*)
}

rule dumplyzer_credtheft_safetykatz_memory : credtheft memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "credential_theft"
        target = "memory"
        description = "SafetyKatz (GhostPack Mimikatz wrapper) strings in raw memory"
        origin = "original"
    strings:
        $s1 = "SafetyKatz" ascii wide
        $s2 = "sekurlsa::logonpasswords" ascii wide
        $s3 = "kuhl_m_sekurlsa" ascii
    condition:
        $s1 and 1 of ($s2, $s3)
}

rule dumplyzer_credtheft_nanodump_memory : credtheft memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "credential_theft"
        target = "memory"
        description = "NanoDump LSASS dump helper strings in raw memory"
        origin = "original"
    strings:
        $s1 = "NanoDumpWriteDump" ascii wide
        $s2 = "duplicate-elevate" ascii wide
        $s3 = "NanoDump" ascii wide
    condition:
        $s1 or ($s2 and $s3)
}

rule dumplyzer_credtheft_pypykatz_memory : credtheft memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "credential_theft"
        target = "memory"
        description = "pypykatz LSASS decryptor module strings in raw memory"
        origin = "original"
    strings:
        $s1 = "pypykatz" ascii wide
        $s2 = "lsa_decryptor" ascii
        $s3 = "pypykatz.lsadecryptor" ascii
        $s4 = "pypykatz.registry" ascii
    condition:
        2 of them
}
