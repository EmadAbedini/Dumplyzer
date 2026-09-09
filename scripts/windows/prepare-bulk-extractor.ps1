# Fetch the official simsong/bulk_extractor v2.2.0 Windows EXE and GPLv3 corresponding source.
# SHA-256 is pinned from the GitHub release SHA256SUMS. Does not run at application startup.

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ManifestPath = Join-Path $Root "packaging\windows\runtime-manifest.json"
$CacheDir = Join-Path $Root "packaging\cache"
$Dest = Join-Path $Root "app\desktop\resources\tools\bulk_extractor"

$manifest = Get-Content -Raw -Path $ManifestPath | ConvertFrom-Json
$be = $manifest.bulk_extractor
$exeUrl = $be.exe_url
$exeSha = $be.exe_sha256.ToLowerInvariant()
$srcUrl = $be.source_url
$srcSha = $be.source_sha256.ToLowerInvariant()
$exeCache = Join-Path $CacheDir $be.exe_filename
$srcCache = Join-Path $CacheDir $be.source_filename

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

Get-PinnedFile $exeUrl $exeCache $exeSha
Get-PinnedFile $srcUrl $srcCache $srcSha

Copy-Item -Force $exeCache (Join-Path $Dest "bulk_extractor64.exe")
Copy-Item -Force $srcCache (Join-Path $Dest $be.source_filename)

Write-Host "bulk_extractor v$($be.version) ready at $Dest"
