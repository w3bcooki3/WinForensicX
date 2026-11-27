#requires -version 5.1
<#
.SYNOPSIS
    Starts WinForensicX: loads the module, offers to restart as administrator, then opens the menu.
    Start it from a PowerShell window:
        cd <folder>; .\Start-WinForensicX.ps1
    (Explorer's right-click "Run with PowerShell" is not supported: it asks to change the execution policy with
    "No" as the default and closes the window as soon as PowerShell refuses the script.)
    Without administrator rights it asks once: restart as administrator (through the normal Windows prompt),
    continue without, or quit. It never elevates without asking and never changes the execution policy.
.PARAMETER Elevate     Restart as administrator without asking first (Windows still asks you to confirm).
.PARAMETER NoElevate   Do not offer to restart as administrator.
.PARAMETER OutputPath  Folder for case output (default: Desktop\WinForensicX). External media recommended.
#>
[CmdletBinding()]
param([switch]$Elevate, [switch]$NoElevate, [string]$OutputPath = '')

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$host.UI.RawUI.WindowTitle = 'WinForensicX'

try {
    $module = Join-Path $here 'WinForensicX\WinForensicX.psd1'
    $single = Join-Path $here 'dist\WinForensicX.ps1'
    if (Test-Path -LiteralPath $module) { Import-Module $module -Force -DisableNameChecking }
    elseif (Test-Path -LiteralPath $single) { . $single -NoAuto }
    else { throw "WinForensicX files not found next to this launcher (expected WinForensicX\WinForensicX.psd1 or dist\WinForensicX.ps1). Extract the whole archive, then run Start-WinForensicX.ps1 from that folder." }
    # The start-up helpers are internal to the module: run them in its scope (or here, for the single file).
    $wfx = Get-Module WinForensicX
    $inWfx = { param([scriptblock]$Block, [object[]]$ArgList) if ($wfx) { & $wfx $Block @ArgList } else { & $Block @ArgList } }
    $go = & $inWfx { param($p, $o, $e, $n) Request-WfxElevation -ScriptPath $p -Parameters @{ OutputPath = $o } -Elevate:$e -NoElevate:$n } @($MyInvocation.MyCommand.Path, $OutputPath, [bool]$Elevate, [bool]$NoElevate)
    if ($go -eq 'Elevated') {
        Write-Host ''
        Write-Host '  WinForensicX opened in a new administrator window. You can close this one.' -ForegroundColor Green
        return
    }
    if ($go -eq 'Quit') { return }
    & $inWfx {
        if ((Test-WfxWindows) -and -not (Test-WfxAdmin)) {
            Write-Host ''
            Write-Host '  Running WITHOUT administrator rights: some data will be missing (listed in each report as gaps).' -ForegroundColor Yellow
        }
        Write-WfxIntegrityLine (Test-WfxIntegrity)
    } @()
    Show-WfxMenu -OutputPath $OutputPath
} catch {
    Write-Host ''
    Write-Host "  WinForensicX could not start: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  at: $($_.InvocationInfo.PositionMessage)" -ForegroundColor DarkGray
    Write-Host '  If antivirus quarantined a file, restore it from the release archive and verify its SHA-256.' -ForegroundColor Gray
    [void](Read-Host '  Press Enter to close')
    exit 1
}
