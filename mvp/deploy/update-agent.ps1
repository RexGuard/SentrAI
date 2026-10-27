<#
.SYNOPSIS
  Updates the SentrAI agent on this Windows machine to the newest code, keeping its join and settings.

.DESCRIPTION
  The Windows twin of sentrai-update (deploy/update.sh). install-agent.ps1 copies it next to the
  service, so from an Administrator PowerShell:

    & "C:\Program Files\SentrAI\update-agent.ps1"            update to the newest main
    & "C:\Program Files\SentrAI\update-agent.ps1" -Check     only say whether a newer version is out

  What an update does:
    1. asks GitHub which commit the branch or tag points at, and downloads that code
    2. stops the agent and saves the code, its Python packages, the service settings and the agent's
       data (not its logs) to C:\ProgramData\SentrAI\backups\<time> (the newest 2 are kept)
    3. runs the new install-agent.ps1 (no join code: the machine stays joined, -Enforce/-Protect stay)
    4. checks the service runs and keeps running for 20 seconds; if not, puts everything back

.PARAMETER Ref
  Branch, tag or commit to follow (saved for next time; default main).
.PARAMETER Repo
  The GitHub repository (https://github.com/owner/repo; saved; default the one it was installed from).
.PARAMETER From
  Install from this local checkout instead of downloading.
.PARAMETER Force
  Reinstall even when it is already up to date.
.PARAMETER Check
  Only compare with the newest version (exit 10 when an update is out).
.PARAMETER Rollback
  Put back the version saved before the last update.
.PARAMETER Prefix
  Where the agent is installed (default C:\Program Files\SentrAI).
#>
[CmdletBinding()]
param(
    [string]$Ref = "",
    [string]$Repo = "",
    [string]$From = "",
    [switch]$Force,
    [switch]$Check,
    [switch]$Rollback,
    [string]$Prefix = (Join-Path $env:ProgramFiles "SentrAI")
)

$ErrorActionPreference = "Stop"
$ServiceId = "SentrAIAgent"
$DefaultRepo = "https://github.com/RexGuard/SentrAI"
$Mvp = Join-Path $Prefix "mvp"
$Data = Join-Path $env:ProgramData "SentrAI"
$State = Join-Path $Data "agent"
$Settings = Join-Path $Data "update.json"
$Backups = Join-Path $Data "backups"
$Keep = 2

function Die([string]$Message) {
    Write-Host "update-agent.ps1: $Message" -ForegroundColor Red
    exit 1
}
function Native {
    $ErrorActionPreference = "Continue"
    $exe = $args[0]
    $rest = @($args | Select-Object -Skip 1)
    & $exe @rest
}

$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Die "run it from an Administrator PowerShell"
}
if (-not (Get-Service -Name $ServiceId -ErrorAction SilentlyContinue)) {
    Die "the SentrAI agent is not installed here; install it first (deploy\install-agent.ps1)"
}
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Read-Version([string]$File, [string]$Key) {
    if (-not (Test-Path $File)) { return "" }
    $line = Get-Content $File | Where-Object { $_ -like "$Key=*" } | Select-Object -Last 1
    if ($line) { return $line.Substring($Key.Length + 1) } else { return "" }
}
$Installed = Read-Version (Join-Path $Mvp "VERSION") "commit"

# --- where updates come from (saved in update.json) ---------------------------
$saved = if (Test-Path $Settings) { Get-Content $Settings -Raw | ConvertFrom-Json } else { $null }
if (-not $Repo -and $saved) { $Repo = $saved.repo }
if (-not $Repo) { $Repo = Read-Version (Join-Path $Mvp "VERSION") "repo" }
if (-not $Repo) { $Repo = $DefaultRepo }
if ($Repo -match '^git@github\.com:(.+)$') { $Repo = "https://github.com/$($Matches[1])" }
if (-not $Ref -and $saved) { $Ref = $saved.ref }
if (-not $Ref) { $Ref = "main" }
$Slug = ""
if ($Repo -match '^https://github\.com/([^/]+/[^/]+?)(\.git)?/?$') { $Slug = $Matches[1] }
elseif (-not $From) { Die "-Repo must be a https://github.com/owner/repo address (got $Repo); or use -From <checkout>" }

function Latest-Commit {
    if ($Ref -match '^[0-9a-f]{40}$') { return $Ref }
    $headers = @{ Accept = "application/vnd.github.sha"; "User-Agent" = "sentrai-update" }
    $r = Invoke-WebRequest -Uri "https://api.github.com/repos/$Slug/commits/$Ref" -Headers $headers -UseBasicParsing
    return ([string]$r.Content).Trim()
}

# --- -Check ---------------------------------------------------------------------
if ($Check) {
    try { $latest = Latest-Commit } catch { Die "could not check for updates: $($_.Exception.Message)" }
    if ($latest -ne $Installed) {
        Write-Host "An update is available: $($Installed.Substring(0, [Math]::Min(7, $Installed.Length))) -> $($latest.Substring(0, 7)) ($Ref). Run: update-agent.ps1"
        exit 10
    }
    Write-Host "The SentrAI agent is up to date ($($latest.Substring(0, 7)), $Ref)."
    exit 0
}

# --- backup and restore -----------------------------------------------------------
function Stop-Agent {
    $svc = Get-Service -Name $ServiceId
    if ($svc.Status -ne "Stopped") {
        Stop-Service -Name $ServiceId -Force
        $svc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
}
function Mirror([string]$A, [string]$B, [string[]]$Extra = @()) {
    Native robocopy.exe $A $B /MIR /NFL /NDL /NJH /NJS /NP /R:2 /W:2 @Extra | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "copying $A to $B failed (robocopy exit $LASTEXITCODE)" }
}
function Save-Backup([string]$Dir) {
    Write-Host "Saving the current version to $Dir ..."
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    Mirror $Mvp (Join-Path $Dir "mvp")
    Copy-Item -Force (Join-Path $Prefix "$ServiceId.xml") $Dir
    Mirror $State (Join-Path $Dir "agent") @("/XD", (Join-Path $State "logs"), (Join-Path $State "service"))
    Set-Content -Path (Join-Path $Dir "INFO") -Value "commit=$Installed`r`nsaved=$((Get-Date).ToUniversalTime().ToString('s'))Z" -Encoding ASCII
}
function Restore-Backup([string]$Dir) {
    Write-Host "Putting back the version saved in $Dir ..."
    Stop-Agent
    Mirror (Join-Path $Dir "mvp") $Mvp
    Copy-Item -Force (Join-Path $Dir "$ServiceId.xml") $Prefix
    # Not /MIR here: the logs the backup left out stay.
    Native robocopy.exe (Join-Path $Dir "agent") $State /E /NFL /NDL /NJH /NJS /NP /R:2 /W:2 | Out-Null
    Start-Service -Name $ServiceId
}
function Agent-Pid {
    $p = Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" | Where-Object { $_.CommandLine -like "*-m agent run*" } | Select-Object -First 1
    if ($p) { return $p.ProcessId } else { return $null }
}
function Test-Healthy {
    Write-Host "Checking that the agent works ..."
    $until = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $until -and -not ((Get-Service $ServiceId).Status -eq "Running" -and (Agent-Pid))) { Start-Sleep -Seconds 2 }
    $first = Agent-Pid
    if ((Get-Service $ServiceId).Status -ne "Running" -or -not $first) { Write-Host "  FAILED: the service is not running"; return $false }
    # Running is not enough: it may not crash and restart over the next 20 seconds.
    Start-Sleep -Seconds 20
    if ((Get-Service $ServiceId).Status -ne "Running" -or (Agent-Pid) -ne $first) { Write-Host "  FAILED: the agent keeps restarting"; return $false }
    Write-Host "  ok: the agent is running"
    return $true
}

if ($Rollback) {
    $last = Get-ChildItem $Backups -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "*.restored" } | Sort-Object Name | Select-Object -Last 1
    if (-not $last) { Die "no saved version in $Backups" }
    Restore-Backup $last.FullName
    if (-not (Test-Healthy)) { Die "the saved version does not pass its checks either" }
    Rename-Item $last.FullName "$($last.Name).restored"
    Write-Host "Rolled back to $(Read-Version (Join-Path $Mvp 'VERSION') 'commit')." -ForegroundColor Green
    exit 0
}

# --- 1. get the code ----------------------------------------------------------------
$tmp = $null
if ($From) {
    $NewSrc = (Resolve-Path $From).Path
    $New = "local"
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $out = Native git -c safe.directory=* -C $NewSrc rev-parse HEAD
        if ($LASTEXITCODE -eq 0 -and $out) { $New = ([string]$out).Trim() }
    }
    $RefName = $NewSrc
} else {
    try { $New = Latest-Commit } catch { Die "could not ask GitHub for $Ref ($($_.Exception.Message))" }
    if ($New -eq $Installed -and -not $Force) {
        Write-Host "The SentrAI agent is already up to date ($($New.Substring(0, 7)), $Ref). -Force reinstalls it anyway."
        exit 0
    }
    Write-Host "Downloading $Slug at $($New.Substring(0, 7)) ($Ref) ..."
    $tmp = Join-Path $env:TEMP "sentrai-update-$PID"
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        Invoke-WebRequest -Uri "https://codeload.github.com/$Slug/zip/$New" -OutFile (Join-Path $tmp "code.zip") -UseBasicParsing
    } catch { Die "could not download $Slug at $New ($($_.Exception.Message))" }
    Expand-Archive -Path (Join-Path $tmp "code.zip") -DestinationPath (Join-Path $tmp "src")
    $NewSrc = (Get-ChildItem (Join-Path $tmp "src") -Directory | Select-Object -First 1).FullName
    $RefName = $Ref
    New-Item -ItemType Directory -Force -Path $Data | Out-Null
    @{ repo = $Repo; ref = $Ref } | ConvertTo-Json | Set-Content -Path $Settings -Encoding UTF8
}
$installer = Join-Path $NewSrc "mvp\deploy\install-agent.ps1"
if (-not (Test-Path $installer)) { Die "$NewSrc has no mvp\deploy\install-agent.ps1" }
Write-Host "Updating the SentrAI agent: $(if ($Installed) { $Installed } else { 'unknown' }) -> $New"

# --- 2. save what runs now ------------------------------------------------------------
Stop-Agent
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$short = if ($Installed) { $Installed.Substring(0, [Math]::Min(7, $Installed.Length)) } else { "unknown" }
$Backup = Join-Path $Backups "$stamp-$short"
try { Save-Backup $Backup } catch { Start-Service -Name $ServiceId; Die "could not save the current version ($($_.Exception.Message)); nothing was changed" }

# --- 3. install, 4. check, else roll back ----------------------------------------------
$env:SENTRAI_SOURCE_COMMIT = $New
$env:SENTRAI_SOURCE_REF = $RefName
$env:SENTRAI_SOURCE_REPO = $Repo
$ok = $true
try {
    # A separate PowerShell: the installer ends with exit, which would end this script too.
    Native powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer -Prefix $Prefix
    if ($LASTEXITCODE -ne 0) { Write-Host "The installer stopped with an error ($LASTEXITCODE)."; $ok = $false }
} finally {
    foreach ($k in "SENTRAI_SOURCE_COMMIT", "SENTRAI_SOURCE_REF", "SENTRAI_SOURCE_REPO") { Remove-Item "env:$k" -ErrorAction SilentlyContinue }
    if ($tmp) { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
}
if ($ok -and (Test-Healthy)) {
    Get-ChildItem $Backups -Directory | Sort-Object Name | Select-Object -SkipLast $Keep | Remove-Item -Recurse -Force
    Write-Host "SentrAI agent updated to $($New.Substring(0, [Math]::Min(7, $New.Length))). The previous version is saved in $Backup (-Rollback puts it back)." -ForegroundColor Green
    exit 0
}
Restore-Backup $Backup
if (Test-Healthy) {
    Rename-Item $Backup "$(Split-Path -Leaf $Backup).restored"
    Die "the new version failed its checks, so the previous one ($short) is running again"
}
Die "the update failed AND the previous version does not start; the saved copy is in $Backup"
