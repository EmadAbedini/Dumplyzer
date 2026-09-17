# Build Windows NSIS + MSI installers with a pinned engine runtime.
# Downloads official CPython embeddable, bulk_extractor64.exe, CAPA, and FLOSS (SHA-256 pinned).
# yara-python 4.5.4 is installed from the pinned lockfile into the embeddable runtime.

[CmdletBinding()]
param(
    [switch]$SkipRuntime,
    [switch]$SkipWix
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root

# Node's npm.ps1 / npx.ps1 read $MyInvocation.Statement, which StrictMode Latest
# rejects on Windows PowerShell 5.1. Use the cmd shims instead.
$NpmCmd = (Get-Command npm.cmd -ErrorAction Stop).Source
$NpxCmd = (Get-Command npx.cmd -ErrorAction Stop).Source

if (-not $SkipRuntime) {
    & (Join-Path $PSScriptRoot "prepare-engine-runtime.ps1")
}
& (Join-Path $PSScriptRoot "prepare-bulk-extractor.ps1")
& (Join-Path $PSScriptRoot "prepare-capa.ps1")
& (Join-Path $PSScriptRoot "prepare-floss.ps1")
if (-not $SkipWix) {
    & (Join-Path $PSScriptRoot "prepare-wix-tools.ps1")
}

$Frontend = Join-Path $Root "app\frontend"
$Desktop = Join-Path $Root "app\desktop"
# Always build and verify the same tree. Cursor/CI may export CARGO_TARGET_DIR
# to a sandbox cache; override it so NSIS/MSI land under app\desktop\target.
$env:CARGO_TARGET_DIR = Join-Path $Desktop "target"
Write-Host "CARGO_TARGET_DIR=$($env:CARGO_TARGET_DIR)"
$staleBundle = Join-Path $env:CARGO_TARGET_DIR "release\bundle"
if (Test-Path $staleBundle) {
    Write-Host "Removing stale installer bundle $staleBundle"
    Remove-Item -LiteralPath $staleBundle -Recurse -Force
}
$staleResources = Join-Path $env:CARGO_TARGET_DIR "release\resources"
if (Test-Path $staleResources) {
    Write-Host "Removing stale release resources $staleResources"
    Remove-Item -LiteralPath $staleResources -Recurse -Force
}

Push-Location $Frontend
try {
    & $NpmCmd ci
    if ($LASTEXITCODE -ne 0) { throw "frontend npm ci failed" }
} finally {
    Pop-Location
}

Push-Location $Desktop
try {
    if (-not (Test-Path "node_modules")) {
        & $NpmCmd ci
        if ($LASTEXITCODE -ne 0) { throw "desktop npm ci failed" }
    }
    # Build NSIS then MSI separately so a WebView2 download glitch cannot
    # abort makensis while it is packing the 90+ MB bulk_extractor payload.
    & $NpxCmd tauri build --bundles nsis
    if ($LASTEXITCODE -ne 0) { throw "tauri NSIS build failed" }
    & $NpxCmd tauri build --bundles msi
    if ($LASTEXITCODE -ne 0) { throw "tauri MSI build failed" }
} finally {
    Pop-Location
}

& (Join-Path $PSScriptRoot "verify-installer.ps1")
if (-not $?) { throw "installer verification failed" }
