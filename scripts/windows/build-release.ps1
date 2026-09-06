# Build Windows NSIS + MSI installers with a pinned engine runtime.
# Does not download PE-sieve, mal_unpack, or YARA.

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
if (-not $SkipWix) {
    & (Join-Path $PSScriptRoot "prepare-wix-tools.ps1")
}

$Frontend = Join-Path $Root "app\frontend"
$Desktop = Join-Path $Root "app\desktop"

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
    & $NpxCmd tauri build --bundles nsis,msi
    if ($LASTEXITCODE -ne 0) { throw "tauri build failed" }
} finally {
    Pop-Location
}

& (Join-Path $PSScriptRoot "verify-installer.ps1")
if (-not $?) { throw "installer verification failed" }
