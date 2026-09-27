<#
.SYNOPSIS
  Stops only the CactAI demo windows started by run_demo.ps1 (PIDs from mvp\.demo_pids.json).
#>
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$PidFile = Join-Path $Root ".demo_pids.json"

if (-not (Test-Path $PidFile)) {
    Write-Host "No running demo recorded (mvp\.demo_pids.json not found)."
    exit 0
}

$items = Get-Content $PidFile -Raw | ConvertFrom-Json
foreach ($item in @($items)) {
    $p = Get-Process -Id $item.pid -ErrorAction SilentlyContinue
    if ($p) {
        # /T stops the window and the Python process running inside it.
        & taskkill.exe /PID $item.pid /T /F | Out-Null
        Write-Host ("  stopped {0,-10} (pid {1})" -f $item.name, $item.pid)
    } else {
        Write-Host ("  {0,-10} was already stopped" -f $item.name)
    }
}
Remove-Item $PidFile -Force
Write-Host "CactAI demo stopped."
