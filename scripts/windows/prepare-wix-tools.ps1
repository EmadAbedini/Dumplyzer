# Prefetch WiX Toolset 3.14.1 into the Tauri bundler cache with SHA-256 verification.
# Official binaries: https://github.com/wixtoolset/wix3/releases/tag/wix3141rtm

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Manifest = Get-Content -Raw -Path (Join-Path $Root "packaging\windows\runtime-manifest.json") | ConvertFrom-Json
$Url = $Manifest.wix.url
$Expected = $Manifest.wix.sha256.ToLowerInvariant()
$CacheDir = Join-Path $Root "packaging\cache"
$CacheZip = Join-Path $CacheDir $Manifest.wix.filename
$Dest = Join-Path $env:LOCALAPPDATA "tauri\WixTools314"
$Required = @(
    "candle.exe",
    "candle.exe.config",
    "darice.cub",
    "light.exe",
    "light.exe.config",
    "wconsole.dll",
    "winterop.dll",
    "wix.dll",
    "WixUIExtension.dll",
    "WixUtilExtension.dll"
)

function Test-WixComplete {
    foreach ($name in $Required) {
        if (-not (Test-Path (Join-Path $Dest $name))) { return $false }
    }
    return $true
}

if (-not $Force -and (Test-WixComplete)) {
    Write-Host "WiX 3.14 already present: $Dest"
    exit 0
}

New-Item -ItemType Directory -Force -Path (Split-Path $CacheZip) | Out-Null
if (-not (Test-Path $CacheZip) -or $Force) {
    Write-Host "Downloading WiX 3.14.1 binaries..."
    Invoke-WebRequest -Uri $Url -OutFile $CacheZip -UseBasicParsing
}

$hash = (Get-FileHash -Path $CacheZip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne $Expected) {
    Remove-Item -Force $CacheZip -ErrorAction SilentlyContinue
    throw "WiX SHA-256 mismatch. Expected $Expected got $hash"
}

if (Test-Path $Dest) {
    Remove-Item -Recurse -Force $Dest
}
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Expand-Archive -LiteralPath $CacheZip -DestinationPath $Dest -Force

if (-not (Test-WixComplete)) {
    throw "WiX extract incomplete under $Dest"
}
Write-Host "WiX 3.14 ready: $Dest"
