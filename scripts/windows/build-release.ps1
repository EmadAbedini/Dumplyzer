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

if (-not $SkipRuntime) {
    & (Join-Path $PSScriptRoot "prepare-engine-runtime.ps1")
    if ($LASTEXITCODE -ne 0) { throw "prepare-engine-runtime failed" }
}
if (-not $SkipWix) {
    & (Join-Path $PSScriptRoot "prepare-wix-tools.ps1")
    if ($LASTEXITCODE -ne 0) { throw "prepare-wix-tools failed" }
}

$Frontend = Join-Path $Root "app\frontend"
$Desktop = Join-Path $Root "app\desktop"

Push-Location $Frontend
try {
    npm ci
    if ($LASTEXITCODE -ne 0) { throw "frontend npm ci failed" }
} finally {
    Pop-Location
}

Push-Location $Desktop
try {
    if (-not (Test-Path "node_modules")) {
        npm ci
        if ($LASTEXITCODE -ne 0) { throw "desktop npm ci failed" }
    }
    npx tauri build --bundles nsis,msi
    if ($LASTEXITCODE -ne 0) { throw "tauri build failed" }
} finally {
    Pop-Location
}

& (Join-Path $PSScriptRoot "verify-installer.ps1")
if ($LASTEXITCODE -ne 0) { throw "installer verification failed" }
