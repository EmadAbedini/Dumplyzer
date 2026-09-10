# Fetch the official Mandiant FLOSS Windows standalone zip (Apache-2.0).
# SHA-256 is pinned from the winget installer manifest for v3.1.1.
# Does not run at application startup.

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ManifestPath = Join-Path $Root "packaging\windows\runtime-manifest.json"
$CacheDir = Join-Path $Root "packaging\cache"
$Dest = Join-Path $Root "app\desktop\resources\tools\floss"
$ExtractDir = Join-Path $CacheDir "floss-extract"

$manifest = Get-Content -Raw -Path $ManifestPath | ConvertFrom-Json
$tool = $manifest.floss
$zipUrl = $tool.zip_url
$zipSha = $tool.zip_sha256.ToLowerInvariant()
$zipCache = Join-Path $CacheDir $tool.zip_filename
$licenseUrl = $tool.license_url

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-PinnedFile([string]$Url, [string]$Path, [string]$Expected) {
    if (-not (Test-Path $Path) -or $Force) {
        Write-Host "Downloading $Url"
        Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing
    }
    $hash = Get-Sha256 $Path
    if ($hash -ne $Expected) {
        Remove-Item -Force $Path
        throw "SHA-256 mismatch for $(Split-Path -Leaf $Path). Expected $Expected got $hash"
    }
}

New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
if (Test-Path $ExtractDir) { Remove-Item -Recurse -Force $ExtractDir }
New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null

Get-PinnedFile $zipUrl $zipCache $zipSha
Expand-Archive -LiteralPath $zipCache -DestinationPath $ExtractDir -Force

$exe = Get-ChildItem -Path $ExtractDir -Recurse -Filter "floss.exe" | Select-Object -First 1
if (-not $exe) { throw "floss.exe not found inside $($tool.zip_filename)" }
Copy-Item -Force $exe.FullName (Join-Path $Dest "floss.exe")

$licenseCopied = $false
Get-ChildItem -Path $ExtractDir -Recurse -File | Where-Object {
    $_.Name -match '^(LICENSE|NOTICE)(\..+)?$'
} | ForEach-Object {
    Copy-Item -Force $_.FullName (Join-Path $Dest $_.Name)
    $licenseCopied = $true
}
if (-not $licenseCopied -and $licenseUrl) {
    $licPath = Join-Path $Dest "LICENSE.txt"
    Invoke-WebRequest -Uri $licenseUrl -OutFile $licPath -UseBasicParsing
}

@(
    "Mandiant FLOSS v$($tool.version)",
    "License: $($tool.license)",
    "Source: $($tool.project)",
    "Asset: $($tool.zip_filename)",
    "SHA-256: $($tool.zip_sha256)",
    "Dumplyzer invokes floss.exe as a separate process against extracted PE artifacts only.",
    "Dumplyzer does not download FLOSS at runtime."
) | Set-Content -Path (Join-Path $Dest "README.txt") -Encoding UTF8

Write-Host "FLOSS v$($tool.version) ready at $Dest"
