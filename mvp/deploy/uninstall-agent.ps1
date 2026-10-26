<#
.SYNOPSIS
  Removes the SentrAI agent Windows service installed by install-agent.ps1.

.DESCRIPTION
  Stops and removes the "SentrAI agent" service, takes every block it put into Windows Firewall
  out again (rules named SentrAI-block-*), and deletes the code in C:\Program Files\SentrAI.
  The machine key and logs in C:\ProgramData\SentrAI\agent are kept, so a reinstall without a new
  join code still works; -Purge deletes them too. Also revoke the machine on the panel
  (Machines > Revoke) when it should never report again.

    powershell -ExecutionPolicy Bypass -File .\deploy\uninstall-agent.ps1 [-Purge]

.PARAMETER Purge
  Also delete C:\ProgramData\SentrAI\agent (the machine key, read positions and service logs).
.PARAMETER KeepBlocks
  Leave the SentrAI-block-* firewall rules in place.
.PARAMETER Prefix
  Where install-agent.ps1 put the code (default C:\Program Files\SentrAI).
#>
[CmdletBinding()]
param(
    [switch]$Purge,
    [switch]$KeepBlocks,
    [string]$Prefix = (Join-Path $env:ProgramFiles "SentrAI")
)

$ErrorActionPreference = "Stop"
$ServiceId = "SentrAIAgent"
$State = Join-Path $env:ProgramData "SentrAI\agent"

$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "uninstall-agent.ps1: run it from an Administrator PowerShell" -ForegroundColor Red
    exit 1
}

$svc = Get-Service -Name $ServiceId -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne "Stopped") {
        Write-Host "Stopping the agent ..."
        Stop-Service -Name $ServiceId -Force
    }
    $exe = Join-Path $Prefix "$ServiceId.exe"
    if (Test-Path $exe) { & { $ErrorActionPreference = "Continue"; & $exe uninstall } | Out-Null }
    if (Get-Service -Name $ServiceId -ErrorAction SilentlyContinue) { & { $ErrorActionPreference = "Continue"; & sc.exe delete $ServiceId } | Out-Null }
    Write-Host "Removed the $ServiceId service."
} else {
    Write-Host "The $ServiceId service is not installed."
}

if (-not $KeepBlocks) {
    # netsh "name=" is the rule's display name; the agent names each rule SentrAI-block-<ip>.
    $rules = @(Get-NetFirewallRule -DisplayName "SentrAI-block-*" -ErrorAction SilentlyContinue)
    if ($rules.Count) {
        $rules | Remove-NetFirewallRule
        Write-Host "Removed $($rules.Count) SentrAI block rule(s) from Windows Firewall."
    }
}

if (Test-Path $Prefix) {
    Remove-Item -Recurse -Force $Prefix
    Write-Host "Deleted $Prefix."
}
if ($Purge -and (Test-Path $State)) {
    Remove-Item -Recurse -Force $State
    $parent = Split-Path -Parent $State
    if (-not (Get-ChildItem $parent -Force -ErrorAction SilentlyContinue)) { Remove-Item -Force $parent }
    Write-Host "Deleted $State (machine key and logs)."
} elseif (Test-Path $State) {
    Write-Host "Kept $State (machine key and logs). -Purge deletes it."
}
Write-Host "SentrAI agent removed. Revoke this machine on the panel too if it should not rejoin." -ForegroundColor Green
