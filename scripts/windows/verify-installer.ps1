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
$BundleCandidates = @($DesktopTarget)
if ($CargoTarget) {
    $BundleCandidates += (Join-Path $CargoTarget "release\bundle")
}
$Bundle = $BundleCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Bundle) {
    throw "installer bundle directory not found (checked: $($BundleCandidates -join ', '))"
}

if (-not (Test-Path $Python)) { throw "missing bundled python: $Python" }
if (-not (Test-Path $Pth)) { throw "missing python312._pth" }

$pthText = Get-Content -Raw $Pth
if ($pthText -notmatch "Lib\\site-packages") { throw "python._pth does not include site-packages" }
if ($pthText -notmatch "import site") { throw "python._pth does not enable site" }

$forbidden = @(
    "yara_python*",
    "pe-sieve*.exe",
    "mal_unpack*.exe"
)
Get-ChildItem -Path $Runtime -Recurse -File | ForEach-Object {
    $name = $_.Name.ToLowerInvariant()
    if ($name -like "yara*.pyd" -or $name -eq "yara.py") {
        throw "YARA must not be bundled: $($_.FullName)"
    }
    if ($name -like "pe-sieve*.exe" -or $name -like "mal_unpack*.exe") {
        throw "malware-analysis EXE must not be bundled: $($_.FullName)"
    }
}

$probe = & $Python -c "import memscope_engine, volatility3; from memscope_engine.version import APP_VERSION; print(APP_VERSION)"
if ($LASTEXITCODE -ne 0) { throw "runtime import probe failed" }
Write-Host "runtime_probe $probe"

$nsis = Get-ChildItem -Path (Join-Path $Bundle "nsis") -Filter "*.exe" -ErrorAction SilentlyContinue
$msi = Get-ChildItem -Path (Join-Path $Bundle "msi") -Filter "*.msi" -ErrorAction SilentlyContinue

if (-not $nsis) { throw "NSIS installer not found under $Bundle\nsis" }
if (-not $msi) { throw "MSI installer not found under $Bundle\msi" }

foreach ($item in @($nsis + $msi)) {
    $sizeMb = [math]::Round($item.Length / 1MB, 1)
    Write-Host ("installer {0} {1} MB sha256={2}" -f $item.Name, $sizeMb, (Get-FileHash $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant())
}

Write-Host "VERIFY_OK"
