/*
 * Dumplyzer original Signature Detection rules (Apache-2.0).
 * Reflective / Donut loader strings in extracted PE images.
 * Not copied from a third-party YARA repository.
 */

rule dumplyzer_inject_reflective_loader_pe : inject artifact
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "injection"
        target = "artifact"
        description = "ReflectiveLoader export name in an extracted PE image"
        origin = "original"
    strings:
        $mz = { 4D 5A }
        $s1 = "ReflectiveLoader" ascii wide
        $s2 = "reflective_dll" ascii wide nocase
        $s3 = "ReflectiveDll" ascii wide
    condition:
        $mz at 0 and ($s1 or 2 of ($s2, $s3))
}

rule dumplyzer_inject_donut_pe : inject artifact
{
    meta:
        author = "Dumplyzer"
        license = "Apache-2.0"
        category = "injection"
        target = "artifact"
        description = "Donut loader type names in an extracted PE image"
        origin = "original"
    strings:
        $mz = { 4D 5A }
        $s1 = "DONUT_INSTANCE" ascii
        $s2 = "DONUT_MODULE" ascii
        $s3 = "DONUT_ERROR" ascii
        $s4 = "PDONUT_" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}
