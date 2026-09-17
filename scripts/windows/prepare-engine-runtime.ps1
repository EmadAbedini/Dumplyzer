# Prepare the relocatable Windows x64 Python engine runtime.
# Downloads only the official CPython embeddable zip and verifies SHA-256.
# Installs pinned lockfile deps including yara-python 4.5.4.
# CAPA, FLOSS, and bulk_extractor are prepared separately.

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ManifestPath = Join-Path $Root "packaging\windows\runtime-manifest.json"
$CacheDir = Join-Path $Root "packaging\cache"
$Dest = Join-Path $Root "app\desktop\resources\runtime"
$EngineDir = Join-Path $Root "engine"
$LockFile = Join-Path $EngineDir "requirements.lock.txt"
$HostPy = "py"

$manifest = Get-Content -Raw -Path $ManifestPath | ConvertFrom-Json
$pyUrl = $manifest.python.url
$pySha = $manifest.python.sha256.ToLowerInvariant()
$pyFile = Join-Path $CacheDir $manifest.python.filename

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null

if ($Force -and (Test-Path $Dest)) {
    Remove-Item -Recurse -Force $Dest
}

if (-not (Test-Path $pyFile)) {
    Write-Host "Downloading official CPython embeddable runtime..."
    Invoke-WebRequest -Uri $pyUrl -OutFile $pyFile -UseBasicParsing
}

$hash = Get-Sha256 $pyFile
if ($hash -ne $pySha) {
    Remove-Item -Force $pyFile
    throw "Python embeddable SHA-256 mismatch. Expected $pySha got $hash"
}

if (Test-Path $Dest) {
    Write-Host "Removing previous runtime at $Dest for a deterministic rebuild"
    Remove-Item -Recurse -Force $Dest
}
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Expand-Archive -LiteralPath $pyFile -DestinationPath $Dest -Force

$pth = Get-ChildItem -Path $Dest -Filter "python*._pth" | Select-Object -First 1
if (-not $pth) {
    throw "python*._pth missing from embeddable runtime"
}
@"
python312.zip
.
Lib\site-packages
import site
"@ | Set-Content -Path $pth.FullName -Encoding ascii

$site = Join-Path $Dest "Lib\site-packages"
New-Item -ItemType Directory -Force -Path $site | Out-Null

& $HostPy -3.12 -m pip install `
    --target $site `
    --no-cache-dir `
    --no-compile `
    --no-warn-script-location `
    -r $LockFile
if ($LASTEXITCODE -ne 0) { throw "runtime dependency install failed" }

Get-ChildItem -Path $env:TEMP -Directory -Filter "pip-ephem-wheel-cache-*" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force
$engineBuild = Join-Path $EngineDir "build"
if (Test-Path $engineBuild) {
    Write-Host "Removing leftover engine build directory $engineBuild"
    Remove-Item -Recurse -Force $engineBuild
}
$enginePkg = Join-Path $site "memscope_engine"
if (Test-Path $enginePkg) {
    Write-Host "Removing previous engine package at $enginePkg"
    cmd /c "rmdir /s /q `"$enginePkg`""
    if (Test-Path $enginePkg) { throw "Could not remove previous memscope_engine package" }
}
Get-ChildItem -Path $site -Directory -Filter "memscope_engine-*.dist-info" | ForEach-Object {
    Remove-Item -LiteralPath $_.FullName -Recurse -Force
}

& $HostPy -3.12 -m pip install `
    --target $site `
    --upgrade `
    --no-cache-dir `
    --no-compile `
    --no-deps `
    --no-warn-script-location `
    $EngineDir
if ($LASTEXITCODE -ne 0) { throw "engine package install failed" }

$stale = @(
    "providers\pe_sieve.py",
    "providers\mal_unpack.py",
    "analysis\pe_sieve_workflows.py",
    "analysis\mal_unpack_workflows.py"
)
foreach ($rel in $stale) {
    $leftover = Join-Path $enginePkg $rel
    if (Test-Path $leftover) {
        throw "removed provider is still in the packaged engine: $leftover (wipe engine/build and rebuild)"
    }
    $pycDir = Join-Path $enginePkg ((Split-Path $rel) + "\__pycache__")
    $pycName = ((Split-Path $rel -Leaf) -replace '\.py$', '') + ".cpython-312.pyc"
    $pyc = Join-Path $pycDir $pycName
    if (Test-Path $pyc) { throw "removed provider pyc is still packaged: $pyc" }
}

$runtimePy = Join-Path $Dest "python.exe"
$info = Join-Path $Dest "runtime-info.json"
@"
{
  "app_version": "$($manifest.engine.version)",
  "python_version": "$($manifest.python.version)",
  "volatility3": "$($manifest.engine.volatility3)",
    "pefile": "$($manifest.engine.pefile)",
  "yara_python": "$($manifest.engine.yara_python)",
  "prepared_utc": "$((Get-Date).ToUniversalTime().ToString('o'))"
}
"@ | Set-Content -Path $info -Encoding utf8

$probe = & $runtimePy -c @"
import importlib, sys
mods = ['memscope_engine', 'volatility3', 'pefile', 'yara']
for m in mods:
    importlib.import_module(m)
import yara
if getattr(yara, '__version__', '') != '4.5.4':
    raise SystemExit('yara-python must be 4.5.4, got ' + str(getattr(yara, '__version__', None)))
for gone in ('memscope_engine.providers.pe_sieve', 'memscope_engine.providers.mal_unpack'):
    try:
        importlib.import_module(gone)
        raise SystemExit(gone + ' must not be packaged')
    except ImportError:
        pass
for needed in (
    'memscope_engine.providers.pe_extraction',
    'memscope_engine.providers.capa',
    'memscope_engine.providers.floss',
    'memscope_engine.volatility.pe_dump',
):
    importlib.import_module(needed)
from memscope_engine.version import APP_VERSION
from importlib.metadata import version
pyver = sys.version.split()[0]
vol = version('volatility3')
if pyver != '3.12.10':
    raise SystemExit('python version must be 3.12.10, got ' + pyver)
if vol != '2.28.0':
    raise SystemExit('volatility3 must be 2.28.0, got ' + vol)
yp = version('yara-python')
if yp != '4.5.4':
    raise SystemExit('yara-python must be 4.5.4, got ' + yp)
print('runtime_ok', APP_VERSION, vol, pyver, yp)
"@
if ($LASTEXITCODE -ne 0) {
    throw "bundled runtime probe failed: $probe"
}
Write-Host $probe

$rulesSrc = Join-Path $enginePkg "rules\yara\bundled"
if (-not (Test-Path $rulesSrc)) {
    $rulesSrc = Join-Path $EngineDir "memscope_engine\rules\yara\bundled"
}
$rulesDest = Join-Path $Root "app\desktop\resources\rules\yara\bundled"
if (-not (Test-Path $rulesSrc)) {
    throw "packaged Signature Detection rules missing: $rulesSrc"
}
if (Test-Path $rulesDest) {
    Remove-Item -Recurse -Force $rulesDest
}
New-Item -ItemType Directory -Force -Path (Split-Path $rulesDest) | Out-Null
Copy-Item -Recurse -Force $rulesSrc $rulesDest
Write-Host "bundled_yara_rules $rulesDest"

Write-Host "Engine runtime ready at $Dest"
