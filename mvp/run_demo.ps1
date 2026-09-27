<#
.SYNOPSIS
  Starts the whole CactAI demo on this laptop (Windows PowerShell 5.1 compatible).

.DESCRIPTION
  Opens one titled window per component:
    core       FastAPI risk engine + agents     http://127.0.0.1:8000
    target     Aegis Academy portal (fake)      http://127.0.0.1:5000
    collector  tails the portal logs -> core
    notifier   Telegram bot (console mode if TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID are not set)
    dashboard  Streamlit                        http://127.0.0.1:8501
  Window PIDs are saved to mvp\.demo_pids.json so stop_demo.ps1 stops only these.

.EXAMPLE
  .\run_demo.ps1                     # live mode, 1 real minute = 1 demo hour
  .\run_demo.ps1 -DemoSpeed 600      # faster inaction penalty (1 real minute = 10 demo hours)
  .\run_demo.ps1 -Mode replay        # no collector; use replay\simulate.py instead of live attacks
#>
param(
    [ValidateSet("live", "replay")] [string]$Mode = "live",
    [double]$DemoSpeed = 60,
    [switch]$NoDashboard,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$PidFile = Join-Path $Root ".demo_pids.json"

if (Test-Path $PidFile) {
    Write-Host "A demo seems to be running already (found .demo_pids.json). Run .\stop_demo.ps1 first." -ForegroundColor Yellow
    exit 1
}

function Ensure-Venv([string]$Component) {
    $dir = Join-Path $Root $Component
    $py = Join-Path $dir ".venv\Scripts\python.exe"
    if (-not (Test-Path $py)) {
        Write-Host "Creating venv for $Component ..." -ForegroundColor Cyan
        & python -m venv (Join-Path $dir ".venv")
        & $py -m pip install -q --upgrade pip
        & $py -m pip install -q -r (Join-Path $dir "requirements.txt")
    }
    return $py
}

function Test-Port([int]$Port) {
    $c = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    return [bool]$c
}

foreach ($p in 8000, 5000, 8501) {
    if (Test-Port $p) {
        Write-Host "Port $p is already in use. Close whatever is using it (or run .\stop_demo.ps1) and try again." -ForegroundColor Red
        exit 1
    }
}

$pyCore = Ensure-Venv "core"
$pyLab = Ensure-Venv "lab"
$pyDash = Ensure-Venv "dashboard"
$pyNotif = Ensure-Venv "notifier"

# Shared environment for every child window.
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$env:DEMO_SPEED = "$DemoSpeed"
$env:CACTAI_CORE_URL = "http://127.0.0.1:8000"

$started = @()

function Start-Component([string]$Title, [string]$WorkDir, [string]$Command) {
    $full = "`$host.UI.RawUI.WindowTitle = 'CactAI - $Title'; Set-Location '$WorkDir'; $Command"
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
Write-Host "CactAI demo  (mode: $Mode, DEMO_SPEED=$DemoSpeed -> 1 real minute = $([math]::Round($DemoSpeed/60,2)) demo hours)" -ForegroundColor Green

$started += Start-Component "core" (Join-Path $Root "core") "& '$pyCore' -m uvicorn app.main:app --host 127.0.0.1 --port 8000"
if (-not (Wait-Http "http://127.0.0.1:8000/health")) {
    Write-Host "Core did not come up on :8000. Check the 'CactAI - core' window." -ForegroundColor Red
}
# Fresh audit chain and incident state for this take.
try { Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/demo/reset" -TimeoutSec 5 | Out-Null } catch { }

$labDir = Join-Path $Root "lab"
$logsDir = Join-Path $labDir "logs"
if (Test-Path $logsDir) { Get-ChildItem $logsDir -Filter *.jsonl | Remove-Item -Force }

$started += Start-Component "target" $labDir "& '$pyLab' -m target_app"
if (-not (Wait-Http "http://127.0.0.1:5000/healthz")) {
    Write-Host "Target app did not come up on :5000. Check the 'CactAI - target' window." -ForegroundColor Red
}

if ($Mode -eq "live") {
    $started += Start-Component "collector" $labDir "& '$pyLab' -m collector.collector"
}
$started += Start-Component "notifier" (Join-Path $Root "notifier") "& '$pyNotif' notifier.py"

if (-not $NoDashboard) {
    $dashDir = Join-Path $Root "dashboard"
    $started += Start-Component "dashboard" $dashDir "& '$pyDash' -m streamlit run app.py --server.port 8501 --server.headless true --browser.gatherUsageStats false"
    if ((Wait-Http "http://127.0.0.1:8501" 60) -and (-not $NoBrowser)) {
        Start-Process "http://127.0.0.1:8501"
    }
}

$started | ConvertTo-Json | Set-Content -Path $PidFile -Encoding ASCII

Write-Host ""
Write-Host "All components started. Next, from mvp\lab:" -ForegroundColor Green
if ($Mode -eq "live") {
    Write-Host "  .\.venv\Scripts\python.exe scenario.py                         # full story, narrated"
    Write-Host "  or step by step:"
    Write-Host "  .\.venv\Scripts\python.exe -m attacks.benign"
    Write-Host "  .\.venv\Scripts\python.exe -m attacks.brute_force --count 8 --delay 0.3"
    Write-Host "  .\.venv\Scripts\python.exe -m attacks.sqli --count 3"
} else {
    Write-Host "  .\.venv\Scripts\python.exe -m replay.simulate                  # scripted replay (say so on camera)"
}
Write-Host ""
Write-Host "Portal:    http://127.0.0.1:5000"
Write-Host "Dashboard: http://127.0.0.1:8501"
Write-Host "Stop everything with .\stop_demo.ps1"
