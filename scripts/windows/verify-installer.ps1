# Verify the prepared runtime and built Windows installers without installing them.

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Runtime = Join-Path $Root "app\desktop\resources\runtime"
$Python = Join-Path $Runtime "python.exe"
$Pth = Join-Path $Runtime "python312._pth"
$DesktopTarget = Join-Path $Root "app\desktop\target\release\bundle"
$CargoTarget = $env:CARGO_TARGET_DIR
if ($CargoTarget) {
    $Bundle = Join-Path $CargoTarget "release\bundle"
    if (-not (Test-Path $Bundle)) {
        throw "CARGO_TARGET_DIR is set ($CargoTarget) but installer bundle was not found at $Bundle. Refusing to verify a different directory."
    }
} else {
    $Bundle = $DesktopTarget
    if (-not (Test-Path $Bundle)) {
        throw "installer bundle directory not found: $Bundle"
    }
}
Write-Host "verify_bundle $Bundle"

if (-not (Test-Path $Python)) { throw "missing bundled python: $Python" }
if (-not (Test-Path $Pth)) { throw "missing python312._pth" }

$pthText = Get-Content -Raw $Pth
if ($pthText -notmatch "Lib\\site-packages") { throw "python._pth does not include site-packages" }
if ($pthText -notmatch "import site") { throw "python._pth does not enable site" }

Get-ChildItem -Path $Runtime -Recurse -File | ForEach-Object {
    $name = $_.Name.ToLowerInvariant()
    if ($name -like "pe-sieve*.exe" -or $name -like "mal_unpack*.exe") {
        throw "removed provider EXE must not be present in the Python runtime: $($_.FullName)"
    }
    if ($name -like "bulk_extractor*.exe" -or $name -eq "capa.exe" -or $name -eq "floss.exe") {
        throw "optional-tool EXE must live under resources/tools, not the Python runtime: $($_.FullName)"
    }
}

$probe = & $Python -c @"
import importlib, sys
from importlib.metadata import version
from memscope_engine.version import APP_VERSION
from memscope_engine.providers.pe_extraction import PeExtractionProvider
pyver = sys.version.split()[0]
vol = version('volatility3')
if pyver != '3.12.10':
    raise SystemExit('python version must be 3.12.10, got ' + pyver)
if vol != '2.28.0':
    raise SystemExit('volatility3 must be 2.28.0, got ' + vol)
for gone in ('memscope_engine.providers.pe_sieve', 'memscope_engine.providers.mal_unpack'):
    try:
        importlib.import_module(gone)
        raise SystemExit(gone + ' must not be packaged')
    except ImportError:
        pass
pe = PeExtractionProvider().availability()
if not pe.get('available'):
    raise SystemExit('PE Extraction must be available in the bundled runtime')
import yara
from importlib.metadata import version as _pkg_version
yp = _pkg_version('yara-python')
if yp != '4.5.4':
    raise SystemExit('yara-python must be 4.5.4, got ' + yp)
print('runtime_ok', APP_VERSION, pyver, vol, 'pe_extraction', 'yara', yp)
"@
if ($LASTEXITCODE -ne 0) { throw "runtime import probe failed: $probe" }
Write-Host "runtime_probe $probe"
Write-Host "bundled_python 3.12.10"
Write-Host "bundled_volatility3 2.28.0"
Write-Host "bundled_pe_extraction available"
Write-Host "bundled_yara_python 4.5.4"

$YaraRules = Join-Path $Root "app\desktop\resources\rules\yara\bundled"
$YaraMem = Join-Path $YaraRules "memory"
$YaraArt = Join-Path $YaraRules "artifact"
$YaraReadme = Join-Path $YaraRules "README.md"
if (-not (Test-Path $YaraMem)) { throw "bundled Signature Detection memory rules missing: $YaraMem" }
if (-not (Test-Path $YaraArt)) { throw "bundled Signature Detection artifact rules missing: $YaraArt" }
if (-not (Test-Path $YaraReadme)) { throw "bundled Signature Detection rule README missing: $YaraReadme" }
$memCount = @(Get-ChildItem -Path $YaraMem -Filter "*.yar" -ErrorAction SilentlyContinue).Count
$artCount = @(Get-ChildItem -Path $YaraArt -Filter "*.yar" -ErrorAction SilentlyContinue).Count
if ($memCount -lt 1) { throw "no bundled memory .yar rules" }
if ($artCount -lt 1) { throw "no bundled artifact .yar rules" }
Write-Host "bundled_yara_rules memory=$memCount artifact=$artCount"

$BeDir = Join-Path $Root "app\desktop\resources\tools\bulk_extractor"
$BeExe = Join-Path $BeDir "bulk_extractor64.exe"
$BeLic = Join-Path $BeDir "LICENSE.md"
$BeGpl = Join-Path $BeDir "LICENSE.GPLv3"
$BeSrc = Join-Path $BeDir "bulk_extractor-2.2.0.tar.gz"
if (-not (Test-Path $BeExe)) { throw "bundled bulk_extractor64.exe missing: $BeExe" }
if (-not (Test-Path $BeLic)) { throw "bundled bulk_extractor LICENSE.md missing" }
if (-not (Test-Path $BeGpl)) { throw "bundled bulk_extractor LICENSE.GPLv3 missing" }
if (-not (Test-Path $BeSrc)) { throw "bundled bulk_extractor corresponding source missing: $BeSrc" }
$beHash = (Get-FileHash -Path $BeExe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($beHash -ne "dfcc678ee3b7da111e8fba6259c4e842ffffcbe42dd96e6c6e6cc238d74bd911") {
    throw "bundled bulk_extractor64.exe SHA-256 mismatch: $beHash"
}
Write-Host "bulk_extractor_bundle $BeExe sha256=$beHash"

$CapaExe = Join-Path $Root "app\desktop\resources\tools\capa\capa.exe"
$FlossExe = Join-Path $Root "app\desktop\resources\tools\floss\floss.exe"
if (-not (Test-Path $CapaExe)) { throw "bundled capa.exe missing: $CapaExe" }
if (-not (Test-Path $FlossExe)) { throw "bundled floss.exe missing: $FlossExe" }
function Assert-MzHeader([string]$Path) {
    $fs = [System.IO.File]::OpenRead($Path)
    try {
        $buf = New-Object byte[] 2
        if ($fs.Read($buf, 0, 2) -lt 2 -or $buf[0] -ne 0x4D -or $buf[1] -ne 0x5A) {
            throw "bundled tool is not a PE: $Path"
        }
    } finally {
        $fs.Dispose()
    }
}
Assert-MzHeader $CapaExe
Assert-MzHeader $FlossExe
$capaVer = (& $CapaExe --version 2>&1 | Out-String).Trim()
$flossVer = (& $FlossExe --version 2>&1 | Out-String).Trim()
if ($capaVer -notmatch "9\.4\.0") { throw "bundled CAPA version is not 9.4.0: $capaVer" }
if ($flossVer -notmatch "3\.1\.1") { throw "bundled FLOSS version is not 3.1.1: $flossVer" }
Write-Host "capa_bundle $CapaExe version=9.4.0 ($capaVer)"
Write-Host "floss_bundle $FlossExe version=3.1.1 ($flossVer)"
Write-Host "bulk_extractor_version 2.2.0"

$nsis = @(Get-ChildItem -Path (Join-Path $Bundle "nsis") -Filter "*.exe" -ErrorAction SilentlyContinue)
$msi = @(Get-ChildItem -Path (Join-Path $Bundle "msi") -Filter "*.msi" -ErrorAction SilentlyContinue)

if ($nsis.Count -eq 0) { throw "NSIS installer not found under $Bundle\nsis" }
if ($msi.Count -eq 0) { throw "MSI installer not found under $Bundle\msi" }

foreach ($item in ($nsis + $msi)) {
    if ($item.Name -like "MemScope*") {
        throw "installer still uses old MemScope branding: $($item.Name)"
    }
    if ($item.Name -notlike "Dumplyzer*") {
        throw "installer name is not Dumplyzer-branded: $($item.Name)"
    }
    $sha = (Get-FileHash $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $sizeMb = [math]::Round($item.Length / 1MB, 1)
    Write-Host ("installer_path {0}" -f $item.FullName)
    Write-Host ("installer_size_bytes {0} {1}" -f $item.Name, $item.Length)
    Write-Host ("installer {0} {1} MB sha256={2}" -f $item.Name, $sizeMb, $sha)
}

$releaseRoot = Split-Path $Bundle -Parent
$bePackaged = @(Get-ChildItem -Path $releaseRoot -Recurse -Filter "bulk_extractor64.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '[\\/]tools[\\/]bulk_extractor[\\/]' })
if ($bePackaged.Count -eq 0) {
    throw "bulk_extractor64.exe was not copied into the release tree under $releaseRoot"
}
$packHash = (Get-FileHash $bePackaged[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if ($packHash -ne "dfcc678ee3b7da111e8fba6259c4e842ffffcbe42dd96e6c6e6cc238d74bd911") {
    throw "packaged bulk_extractor64.exe SHA-256 mismatch: $packHash"
}
Write-Host "packaged_bulk_extractor $($bePackaged[0].FullName)"

$capaPackaged = @(Get-ChildItem -Path $releaseRoot -Recurse -Filter "capa.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '[\\/]tools[\\/]capa[\\/]' })
if ($capaPackaged.Count -eq 0) {
    throw "capa.exe was not copied into the release tree under $releaseRoot"
}
$flossPackaged = @(Get-ChildItem -Path $releaseRoot -Recurse -Filter "floss.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '[\\/]tools[\\/]floss[\\/]' })
if ($flossPackaged.Count -eq 0) {
    throw "floss.exe was not copied into the release tree under $releaseRoot"
}
Write-Host "packaged_capa $($capaPackaged[0].FullName)"
Write-Host "packaged_floss $($flossPackaged[0].FullName)"

$nsi = Get-ChildItem -Path $releaseRoot -Recurse -Filter "installer.nsi" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $nsi) { throw "generated NSIS script not found under $releaseRoot" }
$nsiText = Get-Content -Raw $nsi.FullName
if ($nsiText -notmatch "bulk_extractor64\.exe") {
    throw "generated NSIS script does not install bulk_extractor64.exe"
}
if ($nsiText -notmatch "bulk_extractor-2\.2\.0\.tar\.gz") {
    throw "generated NSIS script does not install bulk_extractor corresponding source"
}
if ($nsiText -notmatch "capa\.exe") {
    throw "generated NSIS script does not install capa.exe"
}
if ($nsiText -notmatch "floss\.exe") {
    throw "generated NSIS script does not install floss.exe"
}
Write-Host "nsis_script_includes_bulk_extractor_capa_floss $($nsi.FullName)"

$wxs = Get-ChildItem -Path $releaseRoot -Recurse -Filter "*.wxs" -ErrorAction SilentlyContinue |
    Where-Object { (Get-Content -Raw $_.FullName) -match "bulk_extractor64\.exe" } |
    Select-Object -First 1
if (-not $wxs) {
    $harvest = Get-ChildItem -Path $releaseRoot -Recurse -Filter "*.wxs" -ErrorAction SilentlyContinue
    if ($harvest.Count -eq 0) {
        Write-Host "warning: no WiX source found to grep; MSI file list will be checked after light.exe"
    } else {
        throw "generated WiX sources do not mention bulk_extractor64.exe"
    }
} else {
    Write-Host "wix_source_includes_bulk_extractor $($wxs.FullName)"
}

$removed = @(Get-ChildItem -Path $Runtime -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^(pe_sieve|mal_unpack|pe-sieve)' })
$removed += @(Get-ChildItem -Path $releaseRoot -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^(pe_sieve|mal_unpack|pe-sieve)' -and $_.Extension -in '.py', '.exe', '.pyd' })
if ($removed.Count -gt 0) {
    throw "removed PE-sieve/mal_unpack payload still present: $($removed[0].FullName)"
}
Write-Host "removed_providers_absent pe_sieve mal_unpack"

Write-Host "VERIFY_OK"
