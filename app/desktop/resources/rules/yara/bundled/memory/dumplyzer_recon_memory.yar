/*
 * Dumplyzer original Signature Detection rules (Apache-2.0).
 * AD reconnaissance tooling commonly found in memory during DFIR.
 * Not copied from a third-party YARA repository.
 */

rule dumplyzer_recon_sharphound_memory : recon memory
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "recon"
        severity = "medium"
        target = "memory"
        description = "SharpHound / BloodHound collector strings in raw memory"
        origin = "original"
    strings:
        $s1 = "SharpHound" ascii wide
        $s2 = "BloodHound" ascii wide
        $s3 = "CollectionMethod" ascii wide
        $s4 = "Invoke-BloodHound" ascii wide nocase
    condition:
        2 of them
}
