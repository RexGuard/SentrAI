<#
.SYNOPSIS
  Starts the new web console next to SentrAI (the classic Streamlit dashboard keeps running as before).

.DESCRIPTION
  Start SentrAI first (..\run.ps1). This builds the console when its source changed, then serves it on
  http://127.0.0.1:5173, passing /api to the core. Sign in with the same account as the classic console.

.EXAMPLE
  .\run-web.ps1                       # core on http://127.0.0.1:8000
  .\run-web.ps1 -Core http://127.0.0.1:8100
#>
param([string]$Core = $(if ($env:SENTRAI_CORE_PORT) { "http://127.0.0.1:$($env:SENTRAI_CORE_PORT)" } else { "http://127.0.0.1:8000" }))

$ErrorActionPreference = "Stop"
$App = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "app"
Push-Location $App
try {
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { Write-Host "Node.js (npm) is needed: https://nodejs.org" -ForegroundColor Red; exit 2 }
    if (-not (Test-Path "node_modules")) { npm ci; if ($LASTEXITCODE) { exit $LASTEXITCODE } }
    $built = Get-Item "dist\index.html" -ErrorAction SilentlyContinue
    $newest = Get-ChildItem src, index.html, vite.config.ts -Recurse -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $built -or $newest.LastWriteTime -gt $built.LastWriteTime) { npm run build; if ($LASTEXITCODE) { exit $LASTEXITCODE } }
    $env:VITE_CORE_URL = $Core
    Write-Host "Web console: http://127.0.0.1:5173  (core: $Core)" -ForegroundColor Green
    npx vite preview
} finally { Pop-Location }
