# CI check of the Windows agent installer on a real Windows runner (as Administrator):
# start a panel core, make a join code, install the agent as a service, see it report in,
# switch to -Enforce, put one real netsh block in place, then uninstall and check it is all gone.
# Run from mvp\ with the core venv at core\.venv.
$ErrorActionPreference = "Stop"
$Port = 8765
$Panel = "http://127.0.0.1:$Port"
$Token = "ci-panel-token"
$Headers = @{ Authorization = "Bearer $Token" }
$Mvp = (Get-Location).Path
$Prefix = Join-Path $env:ProgramFiles "SentrAI"
$State = Join-Path $env:ProgramData "SentrAI\agent"
$Xml = Join-Path $Prefix "SentrAIAgent.xml"
$TestIp = "203.0.113.77"

function Fail([string]$Message) { throw "FAILED: $Message" }
function Wait-For([string]$What, [scriptblock]$Check, [int]$Seconds = 90) {
    $until = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $until) {
        try { if (& $Check) { Write-Host "ok: $What"; return } } catch { }
        Start-Sleep -Seconds 2
    }
    Fail "timed out waiting for: $What"
}

# --- a panel to join -------------------------------------------------------
$env:SENTRAI_CONFIG = Join-Path $env:RUNNER_TEMP "panel-config.json"
$env:SENTRAI_API_TOKEN = $Token
$env:SENTRAI_FIREWALL = "off"
$env:SENTRAI_RISK_SCOPE = "host"
$core = Start-Process -FilePath (Join-Path $Mvp "core\.venv\Scripts\python.exe") -PassThru -NoNewWindow `
    -WorkingDirectory (Join-Path $Mvp "core") -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "$Port" `
    -RedirectStandardOutput (Join-Path $env:RUNNER_TEMP "core.out.log") -RedirectStandardError (Join-Path $env:RUNNER_TEMP "core.err.log")
foreach ($k in "SENTRAI_CONFIG", "SENTRAI_API_TOKEN", "SENTRAI_FIREWALL", "SENTRAI_RISK_SCOPE") { Remove-Item "env:$k" }
Wait-For "panel core is up" { Invoke-RestMethod "$Panel/health" | Out-Null; $true }
$code = (Invoke-RestMethod -Method Post "$Panel/fleet/join-codes" -Headers $Headers -ContentType "application/json" `
    -Body '{"operator": "ci", "name": "ci-win"}').code
Write-Host "join code $code"

try {
    # --- first install: join, service, dry run ---------------------------------
    & .\deploy\install-agent.ps1 -Panel $Panel -Code $code -AllowHttp -Protect 203.0.113.10
    if ($LASTEXITCODE) { Fail "install-agent.ps1 exited $LASTEXITCODE" }
    Wait-For "service is running" { (Get-Service SentrAIAgent).Status -eq "Running" }
    $svc = Get-CimInstance Win32_Service -Filter "Name='SentrAIAgent'"
    if ($svc.StartName -ne "LocalSystem" -or $svc.StartMode -ne "Auto") { Fail "service runs as $($svc.StartName), start $($svc.StartMode)" }
    Wait-For "the machine reports to the panel from the service" {
        $m = @(Invoke-RestMethod "$Panel/machines" -Headers $Headers) | Where-Object { $_.host -eq "ci-win" }
        $m -and $m.services_at
    }
    $acl = (Get-Acl $State).Access | ForEach-Object { $_.IdentityReference.Value }
    if ($acl | Where-Object { $_ -notmatch "SYSTEM|Administrators" }) { Fail "state folder is open to: $($acl -join ', ')" }
    if (-not (Select-String -Path $Xml -SimpleMatch 'name="SENTRAI_FIREWALL_ENFORCE" value="0"' -Quiet)) { Fail "first install is not a dry run" }
    if (-not (Select-String -Path $Xml -SimpleMatch '203.0.113.10' -Quiet)) { Fail "-Protect was not kept" }

    # --- upgrade in place with -Enforce (no join code: the machine stays joined) ---
    & .\deploy\install-agent.ps1 -Enforce
    if ($LASTEXITCODE) { Fail "reinstall with -Enforce exited $LASTEXITCODE" }
    if (-not (Select-String -Path $Xml -SimpleMatch 'name="SENTRAI_FIREWALL_ENFORCE" value="1"' -Quiet)) { Fail "-Enforce was not saved" }
    if (-not (Select-String -Path $Xml -SimpleMatch '203.0.113.10' -Quiet)) { Fail "-Protect was lost on upgrade" }
    Wait-For "service is running after the upgrade" { (Get-Service SentrAIAgent).Status -eq "Running" }
    # A service stop must stop the agent itself, not only the wrapper.
    Stop-Service SentrAIAgent
    Start-Sleep -Seconds 2
    $left = @(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*-m agent run*" })
    if ($left) { Fail "the agent kept running after Stop-Service: $($left.CommandLine -join '; ')" }
    Start-Service SentrAIAgent
    Wait-For "the agent reports in again after a restart" {
        $m = @(Invoke-RestMethod "$Panel/machines" -Headers $Headers) | Where-Object { $_.host -eq "ci-win" }
        $m -and ([datetimeoffset]$m.last_seen).UtcDateTime -gt [datetime]::UtcNow.AddSeconds(-15)
    }
    if (@(Invoke-RestMethod "$Panel/fleet/agents" -Headers $Headers).Count -ne 1) { Fail "the upgrade joined a second time" }

    # --- one real Windows Firewall block through the agent's own netsh commands ---
    Push-Location (Join-Path $Prefix "mvp\lab")
    & .\.venv\Scripts\python.exe -c "from agent.agent import Enforcer; e = Enforcer('netsh', True, set()); print(e.sync({'$TestIp'}), e.log); assert e.applied == {'$TestIp'}, e.log"
    $rc = $LASTEXITCODE
    Pop-Location
    if ($rc) { Fail "the netsh block failed" }
    $rule = Get-NetFirewallRule -DisplayName "SentrAI-block-$TestIp" -ErrorAction SilentlyContinue
    if (-not $rule -or $rule.Action -ne "Block" -or $rule.Direction -ne "Inbound") { Fail "no inbound block rule for $TestIp" }
    if ((Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule).RemoteAddress -ne $TestIp) { Fail "the rule blocks the wrong address" }
    Write-Host "ok: Windows Firewall rule SentrAI-block-$TestIp"
} finally {
    Write-Host "--- agent service output ---"
    Get-ChildItem (Join-Path $State "service") -Filter *.log -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "== $($_.Name)"
        # The running service keeps its logs open; share the file, and never fail the job over a log.
        try {
            $stream = [IO.File]::Open($_.FullName, "Open", "Read", "ReadWrite")
            try { (New-Object IO.StreamReader($stream)).ReadToEnd() -split "`n" | Select-Object -Last 40 | Write-Host }
            finally { $stream.Dispose() }
        } catch { Write-Host "(could not read it: $($_.Exception.Message))" }
    }
}

# --- uninstall: service, code and blocks go; the key stays until -Purge ---------
& .\deploy\uninstall-agent.ps1
if (Get-Service SentrAIAgent -ErrorAction SilentlyContinue) { Fail "service still installed" }
$left = @(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*-m agent run*" })
if ($left) { Fail "the agent kept running after the service was removed: $($left.CommandLine -join '; ')" }
if (Test-Path $Prefix) { Fail "$Prefix still there" }
if (Get-NetFirewallRule -DisplayName "SentrAI-block-*" -ErrorAction SilentlyContinue) { Fail "block rules left behind" }
if (-not (Test-Path (Join-Path $State "agent.json"))) { Fail "uninstall deleted the machine key without -Purge" }
& .\deploy\uninstall-agent.ps1 -Purge
if (Test-Path $State) { Fail "-Purge left $State" }
Stop-Process -Id $core.Id -Force
Write-Host "Windows agent installer: all checks passed"
