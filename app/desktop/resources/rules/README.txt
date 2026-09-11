Dumplyzer Signature Detection rules (shipped with the installer)

bundled\  Curated memory and artifact rules. Copied into
          %LOCALAPPDATA%\Dumplyzer\rules\yara\bundled\ on launch.
          See bundled\README.md for sources, licenses, and scan targets.

User-managed rules belong in:

  %LOCALAPPDATA%\Dumplyzer\rules\yara\custom\

That custom folder is never overwritten on upgrade. Dumplyzer never downloads
rules at runtime.
