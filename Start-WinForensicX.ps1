#requires -version 5.1
<#
.SYNOPSIS
    Starts WinForensicX: loads the module and opens the menu.
    Start it from a PowerShell window (Run as administrator recommended):
        cd <folder>; .\Start-WinForensicX.ps1
    (Explorer's right-click "Run with PowerShell" is not supported: it asks to change the execution policy with
    "No" as the default, never elevates, and closes the window as soon as PowerShell refuses the script.)
    This launcher never relaunches itself, never elevates itself and never changes the execution policy.
.PARAMETER NoElevate   Accepted for compatibility; does nothing.
.PARAMETER OutputPath  Folder for case output (default: Desktop\WinForensicX). External media recommended.
#>
[CmdletBinding()]
param([switch]$NoElevate, [string]$OutputPath = '')
$null = $NoElevate

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$host.UI.RawUI.WindowTitle = 'WinForensicX'

$isWindows5 = $PSVersionTable.PSVersion.Major -le 5
$onWindows = $isWindows5 -or $IsWindows
$isAdmin = $false
if ($onWindows) {
    try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}
}

if ($onWindows -and -not $isAdmin) {
    Write-Host ''
    Write-Host '  Running WITHOUT administrator rights - some data will be missing' -ForegroundColor Yellow
    Write-Host '  (Security event log, other users'' processes, Prefetch, BitLocker, Defender exclusions ...).' -ForegroundColor Gray
    Write-Host '  For full visibility: close this window, open "Windows PowerShell" with "Run as administrator",' -ForegroundColor Gray
    Write-Host ('  then run:  cd "{0}"; .\Start-WinForensicX.ps1' -f $here) -ForegroundColor Gray
    Write-Host ''
}

try {
    $module = Join-Path $here 'WinForensicX\WinForensicX.psd1'
    $single = Join-Path $here 'dist\WinForensicX.ps1'
    if (Test-Path -LiteralPath $module) { Import-Module $module -Force -DisableNameChecking }
    elseif (Test-Path -LiteralPath $single) { . $single -NoAuto }
    else { throw "WinForensicX files not found next to this launcher (expected WinForensicX\WinForensicX.psd1 or dist\WinForensicX.ps1). Extract the whole archive, then run Start-WinForensicX.ps1 from that folder." }
    Show-WfxMenu -OutputPath $OutputPath
} catch {
    Write-Host ''
    Write-Host "  WinForensicX could not start: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  at: $($_.InvocationInfo.PositionMessage)" -ForegroundColor DarkGray
    Write-Host '  If antivirus quarantined a file, restore it from the release archive and verify its SHA-256.' -ForegroundColor Gray
    [void](Read-Host '  Press Enter to close')
    exit 1
}
