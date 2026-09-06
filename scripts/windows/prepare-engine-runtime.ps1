# Prepare the relocatable Windows x64 Python engine runtime.
# Downloads only the official CPython embeddable zip and verifies SHA-256.
# Does not download PE-sieve, mal_unpack, YARA, or other malware-analysis tools.

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

if (-not (Test-Path (Join-Path $Dest "python.exe")) -or $Force) {
    if (Test-Path $Dest) {
        Remove-Item -Recurse -Force $Dest
    }
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    Expand-Archive -LiteralPath $pyFile -DestinationPath $Dest -Force
}

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
    --no-compile `
    --no-warn-script-location `
    -r $LockFile
if ($LASTEXITCODE -ne 0) { throw "runtime dependency install failed" }

& $HostPy -3.12 -m pip install `
    --target $site `
    --no-compile `
    --no-deps `
    --no-warn-script-location `
    $EngineDir
if ($LASTEXITCODE -ne 0) { throw "engine package install failed" }

$runtimePy = Join-Path $Dest "python.exe"
$info = Join-Path $Dest "runtime-info.json"
@"
{
  "app_version": "$($manifest.engine.version)",
  "python_version": "$($manifest.python.version)",
  "volatility3": "$($manifest.engine.volatility3)",
  "pefile": "$($manifest.engine.pefile)",
  "prepared_utc": "$((Get-Date).ToUniversalTime().ToString('o'))"
}
"@ | Set-Content -Path $info -Encoding utf8

$probe = & $runtimePy -c @"
import importlib, sys
mods = ['memscope_engine', 'volatility3', 'pefile']
for m in mods:
    importlib.import_module(m)
try:
    import yara  # noqa: F401
    raise SystemExit('yara-python must not be bundled')
except ImportError:
    pass
from memscope_engine.version import APP_VERSION
from importlib.metadata import version
print('runtime_ok', APP_VERSION, version('volatility3'), sys.version.split()[0])
"@
if ($LASTEXITCODE -ne 0) {
    throw "bundled runtime probe failed: $probe"
}
Write-Host $probe
Write-Host "Engine runtime ready at $Dest"
