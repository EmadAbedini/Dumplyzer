# Standalone headless smoke: Tauri-side logic equivalent via cargo test later.
# This script exercises engine IPC the same way the desktop layer does.

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Bundled = Join-Path $Root "app\desktop\resources\runtime\python.exe"
$Venv = Join-Path $Root "engine\.venv\Scripts\python.exe"
if (Test-Path $Bundled) { $Py = $Bundled }
elseif (Test-Path $Venv) { $Py = $Venv }
else { throw "Missing engine Python (bundled runtime or engine\.venv)" }

$req = '{"jsonrpc":"2.0","id":"1","method":"smoke.e2e","params":{}}'
$out = $req | & $Py -m memscope_engine
Write-Host $out
$obj = $out | ConvertFrom-Json
if ($obj.error) { throw "engine error: $($obj.error | ConvertTo-Json -Compress)" }
if (-not $obj.result.volatility.ok) { throw "volatility init failed" }
Write-Host "SMOKE_OK volatility3=$($obj.result.volatility.volatility3_version) python=$($obj.result.volatility.python_version)"
