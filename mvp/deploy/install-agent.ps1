<#
.SYNOPSIS
  Installs the SentrAI agent on a Windows machine as a background Windows service.

.DESCRIPTION
  The Windows twin of install-agent.sh. This machine joins a central SentrAI panel with a one-time
  join code, then a Windows service ("SentrAI agent") sends its logs to the panel and puts the
  panel's blocks for this machine into Windows Firewall (netsh advfirewall). Only outgoing HTTPS,
  no open port. Blocks are a dry run (the commands are only logged) unless you pass -Enforce.

  Run it from an Administrator PowerShell, inside a SentrAI checkout:

    On the panel:  Machines > Add machine gives a one-time join code and the panel's certificate pin.
    Here:          powershell -ExecutionPolicy Bypass -File .\deploy\install-agent.ps1 `
                       -Panel https://panel.example.com:8443 -Code ABCD-EFGH-JKLM -Pin sha256:...

  Run it again from a newer checkout to upgrade (no -Code needed: the machine stays joined), or
  let the updater it installs do that: & "C:\Program Files\SentrAI\update-agent.ps1"
  (downloads the newest code, keeps the join and settings, rolls back if the agent fails to run).
  Remove it with deploy\uninstall-agent.ps1.

  What it creates:
    C:\Program Files\SentrAI\mvp          the code and its Python venv (-Prefix moves it)
    C:\Program Files\SentrAI\SentrAIAgent.exe/.xml
                                          the service wrapper (WinSW 2.12.0, checked by SHA-256)
                                          and its settings (PROTECTED_IPS, enforce on/off, paths)
    C:\ProgramData\SentrAI\agent          machine key, read positions, blocks in force, service logs
                                          (SYSTEM and Administrators only); INDEX.md lists every file
  The service runs as LocalSystem (Windows Firewall rules need it), starts with Windows and
  restarts itself 10 seconds after a crash.

.PARAMETER Panel
  The panel's core address (https://). Required on a first install.
.PARAMETER Code
  The one-time join code from the panel's Machines page. Required on a first install.
.PARAMETER Name
  This machine's name on the panel (default: its computer name).
.PARAMETER Pin
  The panel's certificate pin (sha256:...), shown with the join code: the agent then talks to that
  certificate and nothing else.
  On a machine that already joined, sets the new pin after the panel's certificate changed.
.PARAMETER Ca
  The panel's certificate file, instead of a pin.
.PARAMETER AllowHttp
  Accept a plain http:// panel (private test networks only).
.PARAMETER Enforce
  Really change Windows Firewall. Without it blocks are only logged.
.PARAMETER DryRun
  Go back to logging blocks only (undoes an earlier -Enforce).
.PARAMETER Protect
  Never block these IPs or networks here (comma separated or repeated). The panel's own address
  and this machine (127.0.0.1, ::1) are always kept.
.PARAMETER Prefix
  Where the code goes (default C:\Program Files\SentrAI).
.PARAMETER WinSW
  Path to a WinSW 2.12.0 WinSW.NET461.exe you downloaded yourself (for machines without internet
  access to github.com). It is checked against the same SHA-256.
.PARAMETER NoStart
  Install the service but do not start it.

.EXAMPLE
  .\deploy\install-agent.ps1 -Panel https://panel.example.com:8443 -Code ABCD-EFGH-JKLM -Protect 203.0.113.10
.EXAMPLE
  .\deploy\install-agent.ps1 -Enforce     # later: turn real blocking on, keeps the join
#>
[CmdletBinding()]
param(
    [string]$Panel = "",
    [string]$Code = "",
    [string]$Name = "",
    [string]$Pin = "",
    [string]$Ca = "",
    [switch]$AllowHttp,
    [switch]$Enforce,
    [switch]$DryRun,
    [string[]]$Protect = @(),
    [string]$Prefix = (Join-Path $env:ProgramFiles "SentrAI"),
    [string]$WinSW = "",
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$ServiceId = "SentrAIAgent"
$WinSWUrl = "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW.NET461.exe"
$WinSWSha256 = "B5066B7BBDFBA1293E5D15CDA3CAAEA88FBEAB35BD5B38C41C913D492AADFC4F"

# Runs a program; what it writes to stderr (pip warnings) is shown, not taken as a failure.
# Callers check $LASTEXITCODE.
function Native {
    $ErrorActionPreference = "Continue"
    $exe = $args[0]
    $rest = @($args | Select-Object -Skip 1)
    & $exe @rest
}

function Die([string]$Message) {
    Write-Host "install-agent.ps1: $Message" -ForegroundColor Red
    exit 1
}

$PipHelp = "could not download the Python packages (pip's message is above). This machine must reach pypi.org over HTTPS (behind a proxy, set `$env:HTTPS_PROXY first); then run the installer again."

# --- checks -----------------------------------------------------------------
$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Die "run it from an Administrator PowerShell (right-click PowerShell > Run as administrator)"
}
if ($Enforce -and $DryRun) { Die "pick one of -Enforce and -DryRun" }
$Src = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not (Test-Path (Join-Path $Src "lab\agent\agent.py"))) {
    Die "run it from a SentrAI checkout (mvp\deploy\install-agent.ps1)"
}
$Mvp = Join-Path $Prefix "mvp"
if ([IO.Path]::GetFullPath($Mvp).TrimEnd('\') -eq [IO.Path]::GetFullPath($Src).TrimEnd('\')) {
    Die "-Prefix must differ from this checkout"
}
$State = Join-Path $env:ProgramData "SentrAI\agent"
$AgentFile = Join-Path $State "agent.json"
$ServiceExe = Join-Path $Prefix "$ServiceId.exe"
$ServiceXml = Join-Path $Prefix "$ServiceId.xml"
$Venv = Join-Path $Mvp "lab\.venv"
$VenvPy = Join-Path $Venv "Scripts\python.exe"
if (-not (Test-Path $AgentFile) -and (-not $Panel -or -not $Code)) {
    Die "a first install needs -Panel URL and -Code CODE (from the panel's Machines page)"
}

# Python 3.10+ that the SYSTEM account can run too (not the per-user Microsoft Store one).
function Find-Python {
    $ErrorActionPreference = "Continue"  # a broken python on PATH writes to stderr: try the next one
    foreach ($cmd in @("python", "py -3", "python3")) {
        $exe, $pre = $cmd.Split(" ")
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        $out = & $exe @($pre | Where-Object { $_ }) -c "import sys, venv, ensurepip; print(sys.version_info >= (3, 10)); print(sys.executable)" 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $out) { continue }
        $lines = @($out)
        if ($lines[0] -ne "True") { continue }
        if ($lines[1] -like "*\WindowsApps\*") { continue }
        return $lines[1]
    }
    return $null
}

# Agents an older install left running: the venv launcher's child outlived the service stop.
function Stop-LeftoverAgents {
    $alive = @(Get-Process | ForEach-Object { $_.Id })
    Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" |
        Where-Object { $_.CommandLine -like "*-m agent run*" -and ($_.ExecutablePath -like "$Prefix\*" -or $alive -notcontains $_.ParentProcessId) } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

# --- stop an older install while files change --------------------------------
$existing = Get-Service -Name $ServiceId -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne "Stopped") {
    Write-Host "Stopping the running agent ..."
    Stop-Service -Name $ServiceId -Force
    $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
}
Stop-LeftoverAgents

# --- folders (the machine key lives in $State: SYSTEM and Administrators only; what is
#     created inside later inherits that) ---
New-Item -ItemType Directory -Force -Path $Prefix, $Mvp, $State, (Join-Path $State "logs"), (Join-Path $State "service") | Out-Null
# Only the folder gets its own list; everything in it inherits it. (Granting the same (OI)(CI) entries
# file by file with /T left existing files with no usable entry: even SYSTEM was denied its logs.)
Native icacls.exe $State /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /Q | Out-Null
if ($LASTEXITCODE -ne 0) { Die "could not limit access to $State" }
if (Get-ChildItem $State -Force) {
    Native icacls.exe (Join-Path $State "*") /reset /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "could not reset access inside $State" }
}

# --- code and venv (the agent uses the lab venv, plus the core's firewall module) ---
Write-Host "Copying code to $Mvp ..."
function Copy-Tree([string]$From, [string]$To, [string[]]$Extra = @()) {
    # /MIR mirrors; the excluded folders (the venv) are neither copied nor deleted on the other side.
    Native robocopy.exe $From $To /MIR /NFL /NDL /NJH /NJS /NP /R:2 /W:2 /XD .venv __pycache__ .pytest_cache @Extra | Out-Null
    if ($LASTEXITCODE -ge 8) { Die "copying $From failed (robocopy exit $LASTEXITCODE)" }
}
# Not the checkout's own logs, approved log list, proposals or recorded trails (2*.jsonl: named by
# date; the example trails are copied).
Copy-Tree (Join-Path $Src "lab") (Join-Path $Mvp "lab") @((Join-Path $Src "lab\logs"), "/XF", "sources.json", "pending.json", "2*.jsonl")
Copy-Tree (Join-Path $Src "core\app") (Join-Path $Mvp "core\app")
foreach ($f in "sentrai_config.py", "sentrai_llm.py", "sentrai_env.py", "sentrai_paths.py", "sentrai_extensions.py") { Copy-Item -Force (Join-Path $Src $f) (Join-Path $Mvp $f) }
# Which code is installed (update-agent.ps1 compares it with the newest), and the updater itself.
function Git-Out([string[]]$GitArgs) {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { return "" }
    $out = Native git -c safe.directory=* -C (Split-Path -Parent $Src) @GitArgs 2>$null
    if ($LASTEXITCODE -eq 0 -and $out) { return ([string]$out).Trim() } else { return "" }
}
$commit = if ($env:SENTRAI_SOURCE_COMMIT) { $env:SENTRAI_SOURCE_COMMIT } else { Git-Out @("rev-parse", "HEAD") }
$ref = if ($env:SENTRAI_SOURCE_REF) { $env:SENTRAI_SOURCE_REF } else { Git-Out @("rev-parse", "--abbrev-ref", "HEAD") }
$repo = if ($env:SENTRAI_SOURCE_REPO) { $env:SENTRAI_SOURCE_REPO } else { Git-Out @("remote", "get-url", "origin") }
$repo = $repo -replace '://[^@/]*@', '://'  # never keep a token from the clone URL
if (-not $commit) { $commit = "unknown" }
Set-Content -Path (Join-Path $Mvp "VERSION") -Encoding ASCII `
    -Value "commit=$commit`r`nref=$ref`r`nrepo=$repo`r`ninstalled=$((Get-Date).ToUniversalTime().ToString('s'))Z"
Copy-Item -Force (Join-Path $Src "deploy\update-agent.ps1") (Join-Path $Prefix "update-agent.ps1")

if (-not (Test-Path $VenvPy)) {
    $python = Find-Python
    if (-not $python) {
        Die "Python 3.10 or newer is needed, installed for all users (python.org installer, 'Install for all users'). The Microsoft Store Python cannot be used by a Windows service."
    }
    if ($python -like "$env:SystemDrive\Users\*") {
        Write-Host "Note: Python is installed in a user profile ($python). The service still runs, but reinstall Python 'for all users' if that account may be removed." -ForegroundColor Yellow
    }
    Write-Host "Creating venv with $python ..."
    Native $python -m venv $Venv
    if ($LASTEXITCODE -ne 0) { Die "could not create the venv" }
    Native $VenvPy -m pip install -q --upgrade pip
    if ($LASTEXITCODE -ne 0) { Remove-Item -Recurse -Force $Venv -ErrorAction SilentlyContinue; Die $PipHelp }
}
# The service runs the venv's base interpreter with the venv's packages on PYTHONPATH. The venv's
# own python.exe on Windows is only a launcher that starts the base one as a child, and that child
# outlives a service stop (it kept running and kept its log files open).
$home_ = (Get-Content (Join-Path $Venv "pyvenv.cfg") | Where-Object { $_ -match '^\s*home\s*=' } | Select-Object -First 1) -replace '^\s*home\s*=\s*', ''
$BasePy = Join-Path $home_.Trim() "python.exe"
if (-not (Test-Path $BasePy)) { Die "the venv's Python ($BasePy) is gone; delete $Venv and run the installer again" }
$req = Join-Path $Mvp "lab\requirements.txt"
$stamp = Join-Path $Venv "requirements.installed"
$want = (Get-FileHash $req -Algorithm SHA256).Hash
$have = if (Test-Path $stamp) { (Get-Content $stamp -Raw).Trim() } else { "" }
if ($want -ne $have) {
    Write-Host "Installing packages ..."
    Native $VenvPy -m pip install -q -r $req
    if ($LASTEXITCODE -ne 0) { Die $PipHelp }
    Set-Content -Path $stamp -Value $want -Encoding ASCII
}

# --- service wrapper (WinSW: runs python as a real Windows service) ----------
if ($WinSW) {
    if (-not (Test-Path $WinSW)) { Die "-WinSW file not found: $WinSW" }
    $download = $WinSW
} elseif ((Test-Path $ServiceExe) -and (Get-FileHash $ServiceExe -Algorithm SHA256).Hash -eq $WinSWSha256) {
    $download = $null
} else {
    $download = Join-Path $env:TEMP "WinSW.NET461-$PID.exe"
    Write-Host "Downloading the service wrapper (WinSW 2.12.0) ..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    try {
        Invoke-WebRequest -Uri $WinSWUrl -OutFile $download -UseBasicParsing
    } catch {
        Die "could not download $WinSWUrl ($($_.Exception.Message)). Download it on another machine and pass -WinSW <file>."
    }
}
if ($download) {
    if ((Get-FileHash $download -Algorithm SHA256).Hash -ne $WinSWSha256) {
        Die "the service wrapper's SHA-256 does not match WinSW 2.12.0 ($download); not installing it"
    }
    Copy-Item -Force $download $ServiceExe
    if (-not $WinSW) { Remove-Item -Force $download }
}

# --- settings (kept in the service's XML; options passed now change them) ---
function Read-Setting([string]$Key, [string]$Default) {
    if (Test-Path $ServiceXml) {
        # A service installed before the CactAI -> SentrAI rename saved CACTAI_* names.
        $old = $Key -replace "^SENTRAI_", "CACTAI_"
        $envs = ([xml](Get-Content $ServiceXml -Raw)).service.env
        $node = $envs | Where-Object { $_.name -eq $Key }
        if (-not $node) { $node = $envs | Where-Object { $_.name -eq $old } }
        if ($node) { return $node.value }
    }
    return $Default
}
$enforceValue = Read-Setting "SENTRAI_FIREWALL_ENFORCE" "0"
if ($Enforce) { $enforceValue = "1" }
if ($DryRun) { $enforceValue = "0" }
$protected = Read-Setting "PROTECTED_IPS" "127.0.0.1,::1,localhost"
foreach ($p in ($Protect -join ",").Split(",")) {
    $p = $p.Trim()
    if ($p -and ($protected.Split(",") -notcontains $p)) { $protected += ",$p" }
}
if ($Ca) {
    if (-not (Test-Path $Ca)) { Die "-Ca file not found: $Ca" }
    Copy-Item -Force $Ca (Join-Path $State "panel-ca.pem")
    $Ca = Join-Path $State "panel-ca.pem"
}

$settings = [ordered]@{
    SENTRAI_HOME             = $State
    SENTRAI_AGENT_FILE       = $AgentFile
    SENTRAI_CONFIG           = (Join-Path $State "config.json")
    SENTRAI_COLLECTOR_STATE  = (Join-Path $State "collector-state.json")
    SENTRAI_SCOUT_SOURCES    = (Join-Path $State "sources.json")
    SENTRAI_LAB_LOGS         = (Join-Path $State "logs")
    SENTRAI_FIREWALL         = "netsh"
    SENTRAI_FIREWALL_ENFORCE = $enforceValue
    PROTECTED_IPS           = $protected
    PYTHONPATH              = (Join-Path $Venv "Lib\site-packages")
    PYTHONUNBUFFERED        = "1"
    PYTHONUTF8              = "1"
    PYTHONIOENCODING        = "utf-8"
}

function Esc([string]$s) { [Security.SecurityElement]::Escape($s) }
$envLines = ($settings.GetEnumerator() | ForEach-Object { "  <env name=`"$($_.Key)`" value=`"$(Esc $_.Value)`"/>" }) -join "`r`n"
$xml = @"
<!-- SentrAI agent service (install-agent.ps1). Change settings by running the installer again
     (-Enforce, -DryRun, -Protect), or edit this file and restart: Restart-Service $ServiceId -->
<service>
  <id>$ServiceId</id>
  <name>SentrAI agent</name>
  <description>Sends this machine's logs to the central SentrAI panel and applies its blocks in Windows Firewall.</description>
  <executable>$(Esc $BasePy)</executable>
  <arguments>-m agent run</arguments>
  <workingdirectory>$(Esc (Join-Path $Mvp "lab"))</workingdirectory>
  <startmode>Automatic</startmode>
  <delayedAutoStart>true</delayedAutoStart>
  <onfailure action="restart" delay="10 sec"/>
  <resetfailure>1 hour</resetfailure>
  <stoptimeout>15 sec</stoptimeout>
  <logpath>$(Esc (Join-Path $State "service"))</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>5</keepFiles>
  </log>
$envLines
</service>
"@
Set-Content -Path $ServiceXml -Value $xml -Encoding UTF8

# --- join (as this Administrator, with the service's settings) -------------
foreach ($kv in $settings.GetEnumerator()) { Set-Item -Path "env:$($kv.Key)" -Value $kv.Value }
Push-Location (Join-Path $Mvp "lab")
try {
    if ($Code) {
        $joinArgs = @("-m", "agent", "join", "--panel", $Panel, "--code", $Code)
        if ($Name) { $joinArgs += @("--name", $Name) }
        if ($Pin) { $joinArgs += @("--pin", $Pin) }
        if ($Ca) { $joinArgs += @("--ca", $Ca) }
        if ($AllowHttp) { $joinArgs += "--allow-http" }
        Native $VenvPy @joinArgs
        if ($LASTEXITCODE -ne 0) { Die "could not join the panel (see the message above)" }
    } elseif ($Pin) {
        # Already joined: take the panel's new certificate pin (after the panel's certificate changed).
        Native $VenvPy -m agent pin $Pin
        if ($LASTEXITCODE -ne 0) { Die "could not set the new pin (see the message above)" }
    }
    Native $VenvPy -m collector.collector --add-system-logs
    if ($LASTEXITCODE -ne 0) { Write-Host "No known logs found yet; approve logs later with Scout." }
} finally {
    Pop-Location
}
# --- data index (INDEX.md in $State lists every file and where it is) ---------
# Files older versions kept elsewhere move into $State first. Runs with the service's paths, and
# the environment is put back afterwards.
$envBefore = @{}
foreach ($kv in $settings.GetEnumerator()) {
    if ($kv.Key -like "SENTRAI_*") {
        $envBefore[$kv.Key] = [Environment]::GetEnvironmentVariable($kv.Key)
        Set-Item -Path "env:$($kv.Key)" -Value $kv.Value
    }
}
try {
    Native $VenvPy (Join-Path $Mvp "sentrai_paths.py") index | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "could not write $(Join-Path $State "INDEX.md") (python sentrai_paths.py index)" }
} finally {
    foreach ($k in $envBefore.Keys) {
        if ($null -eq $envBefore[$k]) { Remove-Item -Path "env:$k" -ErrorAction SilentlyContinue }
        else { Set-Item -Path "env:$k" -Value $envBefore[$k] }
    }
}
# --- service ----------------------------------------------------------------
if (-not (Get-Service -Name $ServiceId -ErrorAction SilentlyContinue)) {
    Native $ServiceExe install
    if ($LASTEXITCODE -ne 0) { Die "could not register the Windows service" }
}
# WinSW 2 only sets the start mode when it registers: make an upgrade match the XML too.
Native sc.exe config $ServiceId start= delayed-auto | Out-Null
if (-not $NoStart) {
    Start-Service -Name $ServiceId
    Write-Host "SentrAI agent started. Status: Get-Service $ServiceId" -ForegroundColor Green
    Write-Host "  Its output: $(Join-Path $State "service\$ServiceId.out.log")"
} else {
    Write-Host "SentrAI agent installed (not started): Start-Service $ServiceId"
}
if ($enforceValue -ne "1") {
    Write-Host "Blocks are a dry run (logged only). Run the installer again with -Enforce to change Windows Firewall." -ForegroundColor Yellow
}
exit 0
