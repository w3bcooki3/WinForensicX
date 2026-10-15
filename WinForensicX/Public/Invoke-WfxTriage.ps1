function Get-WfxPortableSource {
    <# Returns the module's collection source as one self-contained string, so it can be sent to a remote
       WinRM session and dot-sourced there. Works whether WinForensicX is loaded from files (module) or
       from the single-file build (one script). Only the Private + Collectors layers are needed to collect. #>
    $files = @(Get-Command -CommandType Function -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'Wfx' -and $_.ScriptBlock.File } |
            ForEach-Object { $_.ScriptBlock.File } | Sort-Object -Unique)
    $sel = @($files | Where-Object { $_ -match '[\\/](Private|Collectors)[\\/]' })
    if (-not $sel.Count) { $sel = $files }   # single-file build: everything lives in one script
    ($sel | ForEach-Object { Get-Content -LiteralPath $_ -Raw }) -join "`n`n"
}

function Invoke-WfxTriage {
    <#
    .SYNOPSIS
        One-shot incident triage for a Windows host: collect → analyze → score → report, with a full
        chain-of-custody case folder. The main entry point.
    .DESCRIPTION
        Four modes, chosen by parameters:
          • Local   (default)        — collect and analyze this host.
          • Remote  (-ComputerName)  — collect over WinRM on one or more hosts, analyze locally.
          • Offline (-EvtxPath)      — analyze exported event logs (plus whatever live data is available).
          • Re-analyze (-InputPath)  — re-run analysis over a previously saved case/bundle (no collection).
        Everything is read-only. Credential exposure is audited and REDACTED, never extracted.
    .PARAMETER OutputPath   Where the case folder is created (default: Desktop\WinForensicX).
    .PARAMETER CaseName     Optional label folded into the case folder name.
    .PARAMETER Hours        Event look-back window in hours (default 72).
    .PARAMETER FileScan     Also scan web roots / user drop folders for web shells, droppers, ransom notes.
    .PARAMETER ExposureScan Also scan common config files for clear-text secrets (redacted).
    .PARAMETER ComputerName One or more remote hosts to triage over WinRM.
    .PARAMETER Credential   Credential for the remote session.
    .PARAMETER EvtxPath     Folder or .evtx file to analyze offline.
    .PARAMETER InputPath    A previous case folder or bundle.json to re-analyze.
    .PARAMETER Quiet        Suppress console output (results still written).
    .PARAMETER NoReport     Skip the HTML report (JSON/CSV still written).
    .PARAMETER PassThru     Return the result object(s).
    .EXAMPLE
        Invoke-WfxTriage -FileScan
    .EXAMPLE
        Invoke-WfxTriage -ComputerName srv01,srv02 -Credential (Get-Credential)
    .EXAMPLE
        Invoke-WfxTriage -EvtxPath D:\evidence\Security.evtx -CaseName acme-ir
    .EXAMPLE
        Invoke-WfxTriage -InputPath 'C:\cases\WFX_host_20260101-000000Z'
    #>
    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param(
        [string]$OutputPath = '',
        [string]$CaseName = '',
        [int]$Hours = 72,
        [switch]$FileScan,
        [switch]$ExposureScan,
        [Parameter(ParameterSetName = 'Remote', Mandatory)][string[]]$ComputerName,
        [Parameter(ParameterSetName = 'Remote')][System.Management.Automation.PSCredential]$Credential,
        [Parameter(ParameterSetName = 'Offline')][string]$EvtxPath,
        [Parameter(ParameterSetName = 'Reanalyze', Mandatory)][string]$InputPath,
        [switch]$Quiet,
        [switch]$NoReport,
        [switch]$PassThru
    )

    $script:WfxQuiet = [bool]$Quiet
    Write-WfxBanner

    # ── Re-analyze: no collection, just re-run analyzers over saved evidence ──
    if ($PSCmdlet.ParameterSetName -eq 'Reanalyze') {
        Write-WfxConsole "Re-analyzing saved evidence: $InputPath" -Kind Info
        $result = Invoke-WfxAnalyze -Bundle $InputPath
        $rname = if ($CaseName) { $CaseName } else { 'reanalysis' }
        $case = New-WfxCase -OutputPath $OutputPath -Name $rname -HostName $result.HostName
        Save-WfxResult -Result $result -Case $case -NoReport:$NoReport
        Complete-WfxCase
        Write-WfxResultSummary -Result $result -Case $case
        if ($PassThru) { return $result }
        return
    }

    # ── Remote: collect each host over WinRM, analyze locally ──
    if ($PSCmdlet.ParameterSetName -eq 'Remote') {
        $results = New-Object System.Collections.Generic.List[object]
        $src = Get-WfxPortableSource
        $sb = {
            param($Source, $Hours, $EvtxPath, $FileScan, $ExposureScan)
            Invoke-Expression $Source
            $b = Get-WfxCollectionBundle -Hours $Hours -EvtxPath $EvtxPath -FileScan:$FileScan -ExposureScan:$ExposureScan
            # Return JSON (not live objects) so deep nesting survives remoting serialization intact.
            $b | ConvertTo-Json -Depth 12 -Compress
        }
        foreach ($cn in $ComputerName) {
            Write-WfxConsole "Collecting from $cn over WinRM..." -Kind Info
            try {
                $icmArgs = @{ ComputerName = $cn; ScriptBlock = $sb; ArgumentList = @($src, $Hours, $EvtxPath, [bool]$FileScan, [bool]$ExposureScan); ErrorAction = 'Stop' }
                if ($Credential) { $icmArgs.Credential = $Credential }
                $json = Invoke-Command @icmArgs
                $bundle = $json | ConvertFrom-Json
                $result = Invoke-WfxAnalyze -Bundle $bundle -HostName $cn
                $rname = if ($CaseName) { $CaseName } else { 'remote' }
                $case = New-WfxCase -OutputPath $OutputPath -Name $rname -HostName $cn
                Save-WfxJson -InputObject $bundle -Path (Join-Path (Join-Path $case.Path 'raw') 'bundle.json') -Depth 12
                Save-WfxResult -Result $result -Case $case -NoReport:$NoReport
                Complete-WfxCase
                Write-WfxResultSummary -Result $result -Case $case
                $results.Add($result)
            } catch {
                Write-WfxConsole "  Failed on $cn`: $($_.Exception.Message)" -Kind Bad
                Add-WfxGap -Source "remote:$cn" -Reason $_.Exception.Message -Fix 'Confirm WinRM is enabled (Enable-PSRemoting) and the account has access.'
            }
        }
        if ($PassThru) { return $results.ToArray() }
        return
    }

    # ── Local / Offline ──
    $hn = [Environment]::MachineName
    $case = New-WfxCase -OutputPath $OutputPath -Name $CaseName -HostName $hn
    Write-WfxConsole "Case: $($case.Path)" -Kind Dim
    if (-not $case.Admin) { Write-WfxConsole 'Running without administrator rights — some data will be limited (recorded as gaps).' -Kind Warn }

    Write-WfxSection 'Collecting'
    $bundle = Get-WfxCollectionBundle -Hours $Hours -EvtxPath ([string]$EvtxPath) -FileScan:$FileScan -ExposureScan:$ExposureScan
    Save-WfxJson -InputObject $bundle -Path (Join-Path (Join-Path $case.Path 'raw') 'bundle.json') -Depth 12

    Write-WfxSection 'Analyzing'
    $result = Invoke-WfxAnalyze -Bundle $bundle -HostName $hn

    Save-WfxResult -Result $result -Case $case -NoReport:$NoReport
    Complete-WfxCase
    Write-WfxResultSummary -Result $result -Case $case
    if ($PassThru) { return $result }
}

function Write-WfxBanner {
    if ($script:WfxQuiet) { return }
    Write-WfxConsole ''
    Write-WfxConsole '  WinForensicX' -Kind Head -NoNewline
    Write-WfxConsole "  v$script:WfxVersion  —  read-only DFIR triage" -Kind Dim
    Write-WfxConsole ''
}

function Save-WfxResult {
    <# Writes findings.json, findings.csv and result.json into the case outputs, plus the HTML report. #>
    param($Result, $Case, [switch]$NoReport)
    $root = $Case.Path
    Save-WfxJson -InputObject $Result -Path (Join-Path $root 'result.json') -Depth 10
    Save-WfxJson -InputObject @($Result.Findings) -Path (Join-Path $root 'findings.json') -Depth 10
    # Flat CSV for triage in a spreadsheet / SIEM import.
    $rows = foreach ($f in @($Result.Findings)) {
        [pscustomobject]@{
            Severity = $f.Severity; Confidence = $f.Confidence; Score = $f.Score; Id = $f.Id
            Title = $f.Title; Category = $f.Category; Technique = (@($f.Technique) -join '; ')
            Entity = $f.Entity; Host = $f.Host; Occurrences = (Get-WfxValue $f 'Occurrences' 1); Recommendation = $f.Recommendation
        }
    }
    try { @($rows) | Export-Csv -Path (Join-Path $root 'findings.csv') -NoTypeInformation -Encoding UTF8 } catch {}
    if (-not $NoReport -and (Get-Command New-WfxReport -ErrorAction SilentlyContinue)) {
        try { New-WfxReport -Result $Result -Path (Join-Path $root 'report.html') | Out-Null }
        catch { Add-WfxGap -Source 'report' -Reason $_.Exception.Message }
    }
}

function Write-WfxResultSummary {
    param($Result, $Case)
    if ($script:WfxQuiet) { return }
    $r = $Result.Risk
    $kind = switch ($r.Level) { 'Critical' { 'Bad' } 'High' { 'Bad' } 'Elevated' { 'Warn' } default { 'Ok' } }
    Write-WfxSection 'Result'
    Write-WfxConsole ("Host {0}   Risk {1}/100 ({2})" -f $Result.HostName, $r.Score, $r.Level) -Kind $kind
    $s = $Result.Summary
    Write-WfxConsole ("Findings  Critical {0}  High {1}  Medium {2}  Low {3}  Info {4}" -f $s.Critical, $s.High, $s.Medium, $s.Low, $s.Info) -Kind Plain
    $top = @($Result.Findings | Select-Object -First 8)
    if ($top.Count) {
        Write-WfxConsole ''
        foreach ($f in $top) {
            $fk = switch ($f.Severity) { 'Critical' { 'Bad' } 'High' { 'Bad' } 'Medium' { 'Warn' } default { 'Dim' } }
            Write-WfxConsole ("  [{0,-8}] {1}" -f $f.Severity, $f.Title) -Kind $fk
        }
    }
    $gaps = @($Result.Gaps)
    if ($gaps.Count) { Write-WfxConsole ''; Write-WfxConsole ("{0} collection gap(s) recorded — see the report so 'nothing found' is read correctly." -f $gaps.Count) -Kind Warn }
    Write-WfxConsole ''
    Write-WfxConsole ("Outputs:  {0}" -f $Case.Path) -Kind Info
    $reportPath = Join-Path $Case.Path 'report.html'
    if (Test-Path -LiteralPath $reportPath) {
        # Printed as a file:// link so the terminal makes it Ctrl/Cmd-clickable.
        Write-WfxConsole ("Report:   {0}" -f (ConvertTo-WfxFileUri $reportPath)) -Kind Info
        Write-WfxConsole '          (open it to filter findings, see ATT&CK coverage, the timeline and the limitations)' -Kind Dim
    }
    Write-WfxConsole ''
    Write-WfxConsole 'Reminder: findings are leads, not verdicts — read them next to the collection gaps.' -Kind Dim
    Write-WfxConsole 'How to use / commands / limits:  Show-WfxHelp   (add -Html to open the guide)' -Kind Dim
}
