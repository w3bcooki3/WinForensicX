function Show-WfxMenu {
    <#
    .SYNOPSIS
        Interactive menu for the common WinForensicX workflows — the simplest way for an analyst to drive
        the toolkit without memorizing parameters. Everything it runs is read-only.
    .EXAMPLE
        Show-WfxMenu
    #>
    [CmdletBinding()]
    param([string]$OutputPath = '')
    $script:WfxQuiet = $false
    while ($true) {
        Write-WfxBanner
        Write-WfxConsole '  Select an action:' -Kind Head
        Write-WfxConsole ''
        Write-WfxConsole '   1  Quick triage (this host)'
        Write-WfxConsole '   2  Full triage (this host + file & exposure scan)'
        Write-WfxConsole '   3  Triage a remote host (WinRM)'
        Write-WfxConsole '   4  Offline: analyze exported event logs (.evtx)'
        Write-WfxConsole '   5  Re-analyze a saved case'
        Write-WfxConsole '   6  Live monitor'
        Write-WfxConsole '   7  Hunt for IOCs'
        Write-WfxConsole '   8  Collect evidence only (no analysis)'
        Write-WfxConsole '   9  Open last case folder'
        Write-WfxConsole '   F  File triage (what is this file?)'
        Write-WfxConsole '   D  Decode an encoded command / Base64'
        Write-WfxConsole '   T  Export a case timeline (CSV)'
        Write-WfxConsole '   C  Compare two cases (baseline diff)'
        Write-WfxConsole '   H  Help — how to use, commands, limitations (opens the guide)'
        Write-WfxConsole '   Q  Quit'
        Write-WfxConsole ''
        $choice = (Read-Host '  Choice').Trim()
        Write-WfxConsole ''
        try {
        switch ($choice.ToUpper()) {
            '1' { Invoke-WfxTriage -OutputPath $OutputPath | Out-Null }
            '2' { Invoke-WfxTriage -OutputPath $OutputPath -FileScan -ExposureScan | Out-Null }
            '3' {
                $cn = (Read-Host '  Remote host name(s), comma-separated').Trim()
                if ($cn) {
                    $useCred = (Read-Host '  Use alternate credentials? (y/N)').Trim()
                    $cred = if ($useCred -match '^(y|yes)$') { Get-Credential } else { $null }
                    $tparams = @{ ComputerName = ($cn -split '\s*,\s*'); OutputPath = $OutputPath }
                    if ($cred) { $tparams.Credential = $cred }
                    Invoke-WfxTriage @tparams
                }
            }
            '4' { $p = (Read-Host '  Path to .evtx file or folder').Trim('"', ' '); if ($p) { Invoke-WfxTriage -EvtxPath $p -OutputPath $OutputPath | Out-Null } }
            '5' { $p = (Read-Host '  Path to saved case folder or bundle.json').Trim('"', ' '); if ($p) { Invoke-WfxTriage -InputPath $p -OutputPath $OutputPath } }
            '6' {
                $d = (Read-Host '  Duration in seconds (blank = until Ctrl+C)').Trim()
                $dur = 0; [void][int]::TryParse($d, [ref]$dur)
                Start-WfxMonitor -Duration $dur -OutputPath $OutputPath
            }
            '7' {
                $i = (Read-Host '  IOC(s), comma-separated (hash / IP / domain / name), or @path to an IOC file').Trim()
                if ($i -like '@*') { Invoke-WfxHunt -IocFile $i.Substring(1).Trim('"') -OutputPath $OutputPath }
                elseif ($i) { Invoke-WfxHunt -Ioc ($i -split '\s*,\s*') -OutputPath $OutputPath }
            }
            'F' { $p = (Read-Host '  File path').Trim('"', ' '); if ($p) { Get-WfxFileTriage -Path $p -Strings | Format-List Path, Size, FileType, ExtensionMismatch, SHA256, MD5, Entropy, EntropyHint, Zone, HostUrl, AlternateStreams, Signature, PE, Iocs | Out-Host } }
            'D' { $p = (Read-Host '  Paste the command line or Base64').Trim(); if ($p) { $d = ConvertFrom-WfxEncodedCommand -InputObject $p; if ($d) { $d.Layers | Format-List | Out-Host; if ($d.Rules) { Write-WfxConsole ('  Matched rules: ' + ($d.Rules -join '; ')) -Kind Warn } } } }
            'T' { $p = (Read-Host '  Case folder').Trim('"', ' '); if ($p) { Export-WfxTimeline -InputPath $p } }
            'C' { $a = (Read-Host '  Baseline case folder').Trim('"', ' '); $b = (Read-Host '  Current case folder').Trim('"', ' '); if ($a -and $b) { Compare-WfxCase -Baseline $a -Current $b | Format-Table -AutoSize | Out-Host } }
            '8' { Save-WfxEvidence -OutputPath $OutputPath -FileScan -ExposureScan | Out-Null }
            '9' {
                $root = if ($OutputPath) { $OutputPath } else { Get-WfxDefaultOutputRoot }
                if (Test-Path -LiteralPath $root) {
                    $recent = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($recent) { Write-WfxConsole "  Most recent case: $($recent.FullName)" -Kind Info; if (Test-WfxWindows) { try { Start-Process explorer.exe $recent.FullName } catch {} } }
                    else { Write-WfxConsole '  No cases found yet.' -Kind Dim }
                } else { Write-WfxConsole '  No cases found yet.' -Kind Dim }
            }
            'H' { Show-WfxHelp -Html }
            'Q' { return }
            default { Write-WfxConsole '  Unknown choice.' -Kind Warn }
        }
        } catch { Write-WfxConsole "  Error: $($_.Exception.Message)" -Kind Bad }
        Write-WfxConsole ''
        [void](Read-Host '  Press Enter to continue')
    }
}
