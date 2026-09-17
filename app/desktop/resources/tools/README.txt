Dumplyzer bundled analysis tools

This install directory holds application binaries and the bundled Python engine
runtime. Do not store evidence, databases, or extracted artifacts here.

Bundled tools (prepared at installer build time; never downloaded at runtime):

  resources\tools\bulk_extractor\bulk_extractor64.exe
  resources\tools\capa\capa.exe
  resources\tools\floss\floss.exe

PE Extraction is a Volatility 3 workflow, not a separate EXE in this folder.

YARA / Signature Detection is bundled as yara-python 4.5.4 in the Python runtime.
Curated rules ship under resources\rules\yara\bundled\. User rules:

  %LOCALAPPDATA%\Dumplyzer\rules\yara\custom\

User-supplied overrides may be placed under:

  %LOCALAPPDATA%\Dumplyzer\tools\

Dumplyzer never downloads these tools at runtime, will not execute investigation
artifacts, and writes analysis output only under %LOCALAPPDATA%\Dumplyzer\analysis\.
