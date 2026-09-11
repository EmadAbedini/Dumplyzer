# Dumplyzer bundled Signature Detection rules

These rules are authored for Dumplyzer (Apache-2.0). They encode publicly
documented indicator strings used in memory forensics. They are not copied
from third-party rule repositories.

Full provenance, exclusions, and licensing: see
`engine/memscope_engine/rules/yara/RULES.md` in the source tree (also shipped
as package data). Machine-readable inventory: `catalog.json`.

Memory rules do not use the YARA `pe` module or PE-header-only conditions.
Artifact rules require `MZ` at offset 0 and still avoid the `pe` module.
Matches are indicators for investigation, not a malware verdict.

User-managed rules belong in `%LOCALAPPDATA%\Dumplyzer\rules\yara\custom\` and
are never overwritten on upgrade.
