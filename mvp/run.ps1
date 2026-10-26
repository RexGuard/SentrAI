<#
.SYNOPSIS
  Starts SentrAI on this laptop (Windows PowerShell 5.1 compatible).

.DESCRIPTION
  Opens one titled window per component:
    core       FastAPI risk engine + agents     http://127.0.0.1:8000  (-CorePort)
    collector  tails the logs you approved -> core
    notifier   Telegram bot (console mode if TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID are not set)
    dashboard  Streamlit                        http://127.0.0.1:8501  (-DashboardPort)
  Window PIDs are saved to mvp\.run_pids.json so stop.ps1 stops only these.

.EXAMPLE
  .\run.ps1                     # real time: one real hour is one hour on the timers
  .\run.ps1 -Speed 60           # faster timers for testing (1 real minute = 1 hour)
  .\run.ps1 -CorePort 8100      # when 8000 is taken (or set CACTAI_CORE_PORT / CACTAI_DASHBOARD_PORT)
#>
param(
    [Alias("DemoSpeed")] [double]$Speed = $(if ($env:DEMO_SPEED) { [double]$env:DEMO_SPEED } else { 1 }),
    [switch]$NoDashboard,
    [switch]$NoBrowser,
    [int]$CorePort = $(if ($env:CACTAI_CORE_PORT) { [int]$env:CACTAI_CORE_PORT } else { 8000 }),
    [int]$DashboardPort = $(if ($env:CACTAI_DASHBOARD_PORT) { [int]$env:CACTAI_DASHBOARD_PORT } else { 8501 })
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$PidFile = Join-Path $Root ".run_pids.json"
if ($CorePort -eq $DashboardPort) {
    Write-Host "Core and dashboard need two different ports." -ForegroundColor Red
    exit 2
}
$Core = "http://127.0.0.1:$CorePort"
$Dash = "http://127.0.0.1:$DashboardPort"

if (Test-Path $PidFile) {
    Write-Host "SentrAI seems to be running already (found .run_pids.json). Run .\stop.ps1 first." -ForegroundColor Yellow
    exit 1
}

function Ensure-Venv([string]$Component) {
    $dir = Join-Path $Root $Component
    $py = Join-Path $dir ".venv\Scripts\python.exe"
    $req = Join-Path $dir "requirements.txt"
    # Remembers which requirements.txt the venv was built from, so packages added later
    # (for example the AI packages Cyanide needs) are installed on the next start.
    $stamp = Join-Path $dir ".venv\requirements.installed"
    if (-not (Test-Path $py)) {
        Write-Host "Creating venv for $Component ..." -ForegroundColor Cyan
        & python -m venv (Join-Path $dir ".venv")
        & $py -m pip install -q --upgrade pip
    }
    $want = (Get-FileHash $req -Algorithm SHA256).Hash
    $have = if (Test-Path $stamp) { (Get-Content $stamp -Raw).Trim() } else { "" }
    if ($want -ne $have) {
        Write-Host "Installing packages for $Component ..." -ForegroundColor Cyan
        & $py -m pip install -q -r $req
        if ($LASTEXITCODE -eq 0) { Set-Content -Path $stamp -Value $want -Encoding ASCII }
        else { Write-Host "pip could not install everything for $Component (see above)." -ForegroundColor Yellow }
    }
    return $py
}

function Test-Port([int]$Port) {
    $c = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    return [bool]$c
}

foreach ($p in $CorePort, $DashboardPort) {
    if (Test-Port $p) {
        Write-Host "Port $p is already in use. Close whatever is using it (or run .\stop.ps1), or pick another port with -CorePort / -DashboardPort, and try again." -ForegroundColor Red
        exit 1
    }
}

$pyCore = Ensure-Venv "core"
$pyLab = Ensure-Venv "lab"
$pyDash = Ensure-Venv "dashboard"
$pyNotif = Ensure-Venv "notifier"

# First run on this machine: ask for the settings (logs, rules, responder, alerts) once.
# Every component reads the saved file itself; explicit env vars below still win.
& $pyLab (Join-Path $Root "cactai_config.py")
if ($LASTEXITCODE -ne 0) { exit 1 }

# The core API token (made and saved on first use). Every window gets the same one.
$env:CACTAI_API_TOKEN = (& $pyLab (Join-Path $Root "cactai_config.py") token | Select-Object -Last 1).Trim()
if (-not $env:CACTAI_API_TOKEN) { Write-Host "Could not read the API token (python cactai_config.py token)." -ForegroundColor Red; exit 1 }
# Who may sign in to the dashboard; on a new machine, a one-time setup code for creating the Owner.
$signIn = & $pyLab (Join-Path $Root "cactai_config.py") admin
if ($LASTEXITCODE -ne 0) { Write-Host "Could not set up the dashboard sign-in." -ForegroundColor Red; exit 1 }
$authHeader = @{ Authorization = "Bearer $($env:CACTAI_API_TOKEN)" }

# Shared environment for every child window.
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$env:DEMO_SPEED = "$Speed"
$env:CACTAI_CORE_URL = $Core
if (-not $env:CACTAI_PUBLIC_URL) { $env:CACTAI_PUBLIC_URL = $Core }

$started = @()

function Start-Component([string]$Title, [string]$WorkDir, [string]$Command) {
    $full = "`$host.UI.RawUI.WindowTitle = 'SentrAI - $Title'; Set-Location '$WorkDir'; $Command"
    $proc = Start-Process powershell -PassThru -WorkingDirectory $WorkDir -ArgumentList @("-NoExit", "-NoProfile", "-Command", $full)
    Write-Host ("  started {0,-10} (window pid {1})" -f $Title, $proc.Id)
    return @{ name = $Title; pid = $proc.Id }
}

function Wait-Http([string]$Url, [int]$Seconds = 40) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
            if ($r.StatusCode -eq 200) { return $true }
        } catch { }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

Write-Host ""
if ($Speed -eq 1) { Write-Host "SentrAI  (real time)" -ForegroundColor Green }
else { Write-Host "SentrAI  (DEMO_SPEED=$Speed -> 1 real minute = $([math]::Round($Speed/60,2)) hours on the timers)" -ForegroundColor Green }

$started += Start-Component "core" (Join-Path $Root "core") "& '$pyCore' -m uvicorn app.main:app --host 127.0.0.1 --port $CorePort"
if (-not (Wait-Http "$Core/health")) {
    Write-Host "Core did not come up on :$CorePort. Check the 'SentrAI - core' window." -ForegroundColor Red
}
$started += Start-Component "collector" (Join-Path $Root "lab") "& '$pyLab' -m collector.collector"
$started += Start-Component "notifier" (Join-Path $Root "notifier") "& '$pyNotif' notifier.py"

if (-not $NoDashboard) {
    $dashDir = Join-Path $Root "dashboard"
    $started += Start-Component "dashboard" $dashDir "& '$pyDash' -m streamlit run app.py --server.port $DashboardPort --server.headless true --browser.gatherUsageStats false"
    if ((Wait-Http $Dash 60) -and (-not $NoBrowser)) {
        Start-Process $Dash
    }
}

$started | ConvertTo-Json | Set-Content -Path $PidFile -Encoding ASCII

Write-Host ""
Write-Host "All components started." -ForegroundColor Green
Write-Host "Core API:  $Core"
Write-Host "Dashboard: $Dash"
if (-not $NoDashboard) { $signIn | ForEach-Object { Write-Host $_ -ForegroundColor Yellow } }
Write-Host "Stop everything with .\stop.ps1"
