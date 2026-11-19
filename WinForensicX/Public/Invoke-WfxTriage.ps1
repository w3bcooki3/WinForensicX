function Get-WfxPortableSource {
    <# Returns ONLY the collection code (Private + Collectors layers) as one string, so it can be sent to a
       remote WinRM session. Works whether WinForensicX is loaded as a module or from the single-file build
       (where layers are delimited by "# ===== <Layer>/<File> =====" markers). The single-file entry point,
       menus, analyzers and report code are never sent. #>
    $wanted = '^(?:Private|Collectors)/'
    if ($script:WfxSingleFilePath -and (Test-Path -LiteralPath $script:WfxSingleFilePath)) {
        $text = Get-Content -LiteralPath $script:WfxSingleFilePath -Raw
        $parts = [regex]::Split($text, '(?m)^# ===== ')
        $sel = foreach ($p in $parts) {
            if ($p -match "$wanted\S+ =====") { $p.Substring($p.IndexOf("`n") + 1) }
        }
        return ($sel -join "`n`n")
    }
    if (-not $script:WfxModuleRoot) { throw 'Cannot locate WinForensicX source for remote collection.' }
    $files = foreach ($layer in 'Private', 'Collectors') {
        Get-ChildItem -LiteralPath (Join-Path $script:WfxModuleRoot $layer) -Filter *.ps1 | Sort-Object Name
    }
    ($files | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n`n"
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
          • Offline (-EvtxPath)      — analyze exported event logs ONLY. Nothing is collected from the machine
                                       running the tool, so the analyst's workstation never contaminates the case.
          • Re-analyze (-InputPath)  — re-run analysis over a previously saved case/bundle (no collection).
          • Artifacts (-ArtifactPath)— analyze a folder of collected files (hives, Jump Lists, .evtx, ...).
        Everything is read-only. Credential exposure is audited and REDACTED, never extracted.
    .PARAMETER OutputPath    Where the case folder is created (default: Desktop\WinForensicX). Prefer external media.
    .PARAMETER CaseName      Optional label folded into the case folder name.
    .PARAMETER Hours         Event look-back window in hours (default 72, max 8760).
    .PARAMETER FileScan      Also scan web roots / user drop folders for web shells, droppers, ransom notes.
    .PARAMETER ExposureScan  Also scan common config files (and the domain SYSVOL) for clear-text secrets (redacted).
    .PARAMETER ComputerName  One or more remote hosts to triage over WinRM.
    .PARAMETER Credential    Credential for the remote session.
    .PARAMETER EvtxPath      Folder or .evtx file to analyze offline.
    .PARAMETER InputPath     A previous case folder or bundle.json to re-analyze.
    .PARAMETER ArtifactPath  A folder of evidence collected from another system (KAPE / Velociraptor output, a
                             mounted image, CTF files): registry hives, Amcache, Jump Lists, .lnk, browser
                             databases, Prefetch, PCA / Defender logs and .evtx files are found and parsed.
    .PARAMETER AllowlistPath JSON allowlist of known-good findings (default $env:WFX_ALLOWLIST).
    .PARAMETER SigmaPath     Folder(s) of Sigma rules to run over the collected events too (default $env:WFX_SIGMA).
    .PARAMETER YaraRules     YARA rule file(s) / folder(s) (default $env:WFX_YARA). Live: scans the programs that are
                             running, autostart, recently executed and (-FileScan) the scanned files. -ArtifactPath:
                             scans the evidence folder. Needs a yara executable you provide (-YaraExe / PATH).
    .PARAMETER YaraExe       Path to yara64.exe / yara (default $env:WFX_YARA_EXE, then PATH).
    .PARAMETER Quiet         Suppress console output (results still written).
    .PARAMETER NoReport      Skip the HTML report (JSON/CSV still written).
    .PARAMETER PassThru      Return the result object(s).
    .EXAMPLE
        Invoke-WfxTriage -FileScan -OutputPath E:\cases
    .EXAMPLE
        Invoke-WfxTriage -ComputerName srv01,srv02 -Credential (Get-Credential)
    .EXAMPLE
        Invoke-WfxTriage -EvtxPath D:\evidence\logs -CaseName acme-ir
    .EXAMPLE
        Invoke-WfxTriage -InputPath 'C:\cases\WFX_host_20260101-000000Z' -AllowlistPath .\allow.json
    .EXAMPLE
        Invoke-WfxTriage -ArtifactPath D:\kape\C -CaseName ctf-challenge
    #>
    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param(
        [string]$OutputPath = '',
        [string]$CaseName = '',
        [ValidateRange(1, 8760)][int]$Hours = 72,
        [Parameter(ParameterSetName = 'Local')][Parameter(ParameterSetName = 'Remote')][switch]$FileScan,
        [Parameter(ParameterSetName = 'Local')][Parameter(ParameterSetName = 'Remote')][switch]$ExposureScan,
        [Parameter(ParameterSetName = 'Remote', Mandatory)][ValidateNotNullOrEmpty()][string[]]$ComputerName,
        [Parameter(ParameterSetName = 'Remote')][System.Management.Automation.PSCredential]$Credential,
        [Parameter(ParameterSetName = 'Offline', Mandatory)][ValidateNotNullOrEmpty()][string]$EvtxPath,
        [Parameter(ParameterSetName = 'Reanalyze', Mandatory)][ValidateNotNullOrEmpty()][string]$InputPath,
        [Parameter(ParameterSetName = 'Artifacts', Mandatory)][ValidateNotNullOrEmpty()][string]$ArtifactPath,
        [string]$AllowlistPath = $env:WFX_ALLOWLIST,
        [string[]]$SigmaPath = @($env:WFX_SIGMA | Where-Object { $_ }),
        [string[]]$YaraRules = @($env:WFX_YARA | Where-Object { $_ }),
        [string]$YaraExe = '',
        [switch]$Quiet,
        [switch]$NoReport,
        [switch]$PassThru
    )

    $script:WfxQuiet = [bool]$Quiet
    Write-WfxBanner
    $script:WfxSigmaEventQuery = @()
    if (@($SigmaPath).Count) {
        $sr = Get-WfxSigmaRuleSet -Path $SigmaPath
        $extra = Set-WfxSigmaEventQuery -Rule $sr
        Write-WfxConsole ("Sigma: {0} rule(s) loaded{1}" -f @($sr).Count, $(if ($extra) { "; collecting $extra extra event query(ies) they need" })) -Kind Dim
    }
    $params = @{ Hours = $Hours; FileScan = [bool]$FileScan; ExposureScan = [bool]$ExposureScan; Mode = $PSCmdlet.ParameterSetName; Allowlist = [string]$AllowlistPath; Sigma = (@($SigmaPath) -join '; '); Yara = (@($YaraRules) -join '; ') }

    # ── Re-analyze: no collection, just re-run analyzers over saved evidence ──
    if ($PSCmdlet.ParameterSetName -eq 'Reanalyze') {
        $src = Resolve-WfxBundlePath -Path $InputPath
        Write-WfxConsole "Re-analyzing saved evidence: $src" -Kind Info
        $bundle = Get-Content -LiteralPath $src -Raw -Encoding UTF8 | ConvertFrom-Json
        $hn = [string](Get-WfxValue $bundle 'HostName' 'unknown')
        $params.InputPath = $src
        $case = New-WfxCase -OutputPath $OutputPath -Name ($(if ($CaseName) { $CaseName } else { 'reanalysis' })) -HostName $hn -Mode 'reanalyze' -Parameters $params
        Add-WfxCaseSource -Path $src -Role 'source-bundle'
        $srcManifest = Join-Path (Split-Path -Parent (Split-Path -Parent $src)) 'manifest.json'
        if (-not (Test-Path -LiteralPath $srcManifest)) { $srcManifest = Join-Path (Split-Path -Parent $src) 'manifest.json' }
        if (Test-Path -LiteralPath $srcManifest) { Add-WfxCaseSource -Path $srcManifest -Role 'source-manifest' }
        Copy-Item -LiteralPath $src -Destination (Join-Path (Join-Path $case.Path 'raw') 'bundle.json')
        $result = Invoke-WfxAnalyze -Bundle $bundle -HostName $hn -AllowlistPath $AllowlistPath -SigmaPath $SigmaPath
        Save-WfxResult -Result $result -Case $case -NoReport:$NoReport
        $null = Complete-WfxCase
        Write-WfxResultSummary -Result $result -Case $case
        if ($PassThru) { return $result }
        return
    }

    # ── Remote: collect each host over WinRM, analyze locally ──
    if ($PSCmdlet.ParameterSetName -eq 'Remote') {
        $results = [System.Collections.Generic.List[object]]::new()
        $src = Get-WfxPortableSource
        $srcHash = -join ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($src)) | ForEach-Object { $_.ToString('x2') })
        $sb = {
            param($Source, $Hours, $FileScan, $ExposureScan)
            $ErrorActionPreference = 'Stop'
            . ([scriptblock]::Create($Source))
            $b = Get-WfxCollectionBundle -Hours $Hours -FileScan:$FileScan -ExposureScan:$ExposureScan
            # Return JSON (not live objects) so deep nesting survives remoting serialization intact.
            $b | ConvertTo-Json -Depth 12 -Compress
        }
        foreach ($cn in $ComputerName) {
            Write-WfxConsole "Collecting from $cn over WinRM..." -Kind Info
            $rname = if ($CaseName) { $CaseName } else { 'remote' }
            $case = New-WfxCase -OutputPath $OutputPath -Name $rname -HostName $cn -Mode 'remote' -Parameters ($params + @{ ComputerName = $cn; CollectorSha256 = $srcHash })
            Write-WfxLog -Event 'remote-collector' -Data @{ sha256 = $srcHash; bytes = $src.Length }
            try {
                $icmArgs = @{ ComputerName = $cn; ScriptBlock = $sb; ArgumentList = @($src, $Hours, [bool]$FileScan, [bool]$ExposureScan); ErrorAction = 'Stop' }
                if ($Credential) { $icmArgs.Credential = $Credential }
                $json = Invoke-Command @icmArgs
                $rawPath = Join-Path (Join-Path $case.Path 'raw') 'bundle.json'
                [IO.File]::WriteAllText($rawPath, [string]$json, (New-Object Text.UTF8Encoding($false)))
                $bundle = [string]$json | ConvertFrom-Json
                $result = Invoke-WfxAnalyze -Bundle $bundle -HostName $cn -AllowlistPath $AllowlistPath -SigmaPath $SigmaPath
                Save-WfxResult -Result $result -Case $case -NoReport:$NoReport
                $null = Complete-WfxCase
                Write-WfxResultSummary -Result $result -Case $case
                $results.Add($result)
            } catch {
                Write-WfxConsole "  Failed on $cn`: $($_.Exception.Message)" -Kind Bad
                Add-WfxGap -Source "remote:$cn" -Reason $_.Exception.Message -Fix 'Confirm WinRM is enabled (Enable-PSRemoting) and the account has access.'
                Save-WfxJson -InputObject ([pscustomobject]@{ Host = $cn; Error = $_.Exception.Message; Gaps = @(Get-WfxGap | Expand-WfxRecord) }) -Path (Join-Path $case.Path 'error.json')
                $null = Complete-WfxCase
            }
        }
        if ($PassThru) { return $results.ToArray() }
        return
    }

    # ── Offline: exported event logs only ──
    if ($PSCmdlet.ParameterSetName -eq 'Offline') {
        if (-not (Test-Path -LiteralPath $EvtxPath)) { throw "EvtxPath not found: $EvtxPath" }
        $params.EvtxPath = $EvtxPath
        $case = New-WfxCase -OutputPath $OutputPath -Name ($(if ($CaseName) { $CaseName } else { 'offline' })) -HostName 'offline' -Mode 'offline' -Parameters $params
        Write-WfxSection 'Reading exported event logs'
        $bundle = Get-WfxOfflineBundle -EvtxPath $EvtxPath
        foreach ($f in @($bundle.Meta.EvtxFiles)) { Add-WfxCaseSource -Path $f -Role 'evtx' }
        $case.Host = $bundle.HostName
        Save-WfxJson -InputObject $bundle -Path (Join-Path (Join-Path $case.Path 'raw') 'bundle.json') -Depth 12
        Write-WfxSection 'Analyzing'
        $result = Invoke-WfxAnalyze -Bundle $bundle -HostName $bundle.HostName -AllowlistPath $AllowlistPath -SigmaPath $SigmaPath
        Save-WfxResult -Result $result -Case $case -NoReport:$NoReport
        $null = Complete-WfxCase
        Write-WfxResultSummary -Result $result -Case $case
        if ($PassThru) { return $result }
        return
    }

    # ── Artifacts: a folder of files collected elsewhere ──
    if ($PSCmdlet.ParameterSetName -eq 'Artifacts') {
        if (-not (Test-Path -LiteralPath $ArtifactPath)) { throw "ArtifactPath not found: $ArtifactPath" }
        $params.ArtifactPath = $ArtifactPath
        $case = New-WfxCase -OutputPath $OutputPath -Name ($(if ($CaseName) { $CaseName } else { 'artifacts' })) -HostName 'offline' -Mode 'artifacts' -Parameters $params
        Write-WfxSection 'Parsing collected artifacts'
        $bundle = Get-WfxArtifactBundle -Path $ArtifactPath
        Write-WfxConsole ("  {0} artifact records, {1} event-log file(s)" -f @($bundle.Artifacts).Count, @($bundle.Meta.EvtxFiles).Count) -Kind Dim
        if (@($YaraRules).Count) {
            Write-WfxConsole '  YARA scan of the evidence folder...' -Kind Dim
            $bundle | Add-Member -NotePropertyName Yara -NotePropertyValue @(Invoke-WfxYaraScan -Rules $YaraRules -Folder @($ArtifactPath) -YaraExe $YaraExe | Expand-WfxRecord) -Force
            $bundle.Gaps = @(Get-WfxGap | Expand-WfxRecord)
        }
        foreach ($f in @($bundle.Meta.EvtxFiles)) { Add-WfxCaseSource -Path $f -Role 'evtx' }
        $case.Host = $bundle.HostName
        Save-WfxJson -InputObject $bundle -Path (Join-Path (Join-Path $case.Path 'raw') 'bundle.json') -Depth 12
        Write-WfxSection 'Analyzing'
        $result = Invoke-WfxAnalyze -Bundle $bundle -HostName $bundle.HostName -AllowlistPath $AllowlistPath -SigmaPath $SigmaPath
        Save-WfxResult -Result $result -Case $case -NoReport:$NoReport
        $null = Complete-WfxCase
        Write-WfxResultSummary -Result $result -Case $case
        if ($PassThru) { return $result }
        return
    }

    # ── Local ──
    if (-not (Test-WfxWindows)) { throw 'Live triage requires Windows. On other systems use -InputPath (re-analyze) or Invoke-WfxAnalyze.' }
    $hn = [Environment]::MachineName
    $case = New-WfxCase -OutputPath $OutputPath -Name $CaseName -HostName $hn -Mode 'local' -Parameters $params
    Write-WfxConsole "Case: $($case.Path)" -Kind Dim
    if (-not $case.Admin) { Write-WfxConsole 'Running without administrator rights — some data will be limited (recorded as gaps).' -Kind Warn }
    $missing = Test-WfxRulePackSet
    if ($missing.Count) { Write-WfxConsole ("Rule pack(s) missing or invalid: {0} — dependent detections will be skipped and recorded as gaps." -f ($missing -join ', ')) -Kind Bad }

    Write-WfxSection 'Collecting'
    $bundle = Get-WfxCollectionBundle -Hours $Hours -FileScan:$FileScan -ExposureScan:$ExposureScan
    if (@($YaraRules).Count) {
        $targets = @(@($bundle.Process | ForEach-Object { $_.Path }) + @($bundle.Persistence | ForEach-Object { $_.Path }) + @($bundle.Files | ForEach-Object { $_.Path }) +
            @($bundle.Artifacts | Where-Object { $_.Evidence -in 'Execution', 'Download' -and $_.Path -match '^[A-Za-z]:\\' } | ForEach-Object { $_.Path }) | Where-Object { $_ } | Sort-Object -Unique)
        Write-WfxConsole ("  YARA scan of {0} file path(s)..." -f $targets.Count) -Kind Dim
        $bundle | Add-Member -NotePropertyName Yara -NotePropertyValue @(Invoke-WfxYaraScan -Rules $YaraRules -Target $targets -YaraExe $YaraExe -ListDir (Join-Path $case.Path 'raw') | Expand-WfxRecord) -Force
        $bundle.Gaps = @(Get-WfxGap | Expand-WfxRecord)
    }
    Save-WfxJson -InputObject $bundle -Path (Join-Path (Join-Path $case.Path 'raw') 'bundle.json') -Depth 12

    Write-WfxSection 'Analyzing'
    $result = Invoke-WfxAnalyze -Bundle $bundle -HostName $hn -AllowlistPath $AllowlistPath -SigmaPath $SigmaPath

    Save-WfxResult -Result $result -Case $case -NoReport:$NoReport
    $null = Complete-WfxCase
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
    <# Writes findings.json, findings.csv, result.json and the HTML report into the case. #>
    param($Result, $Case, [switch]$NoReport)
    $root = $Case.Path
    $Result | Add-Member -NotePropertyName Case -NotePropertyValue ([pscustomobject]@{
            Id = $Case.Id; Name = $Case.Name; Mode = $Case.Mode; Started = $Case.StartedUtc; Operator = $Case.Operator
            OperatorHost = $Case.OperatorHost; Admin = $Case.Admin; PowerShell = "$($Case.PSVersion) $($Case.PSEdition)"
            Parameters = $Case.Parameters; Sources = @($Case.Sources); OutputOnSystemDrive = $Case.OutputOnSystemDrive
        }) -Force
    Save-WfxJson -InputObject $Result -Path (Join-Path $root 'result.json') -Depth 10
    Save-WfxJson -InputObject @($Result.Findings) -Path (Join-Path $root 'findings.json') -Depth 10
    # Flat CSV for triage in a spreadsheet / SIEM import.
    $rows = foreach ($f in @($Result.Findings)) {
        [pscustomobject]@{
            Severity = $f.Severity; Confidence = $f.Confidence; Score = $f.Score; Id = $f.Id
            Title = $f.Title; Category = $f.Category; Technique = (@($f.Technique) -join '; ')
            Entity = $f.Entity; Host = $f.Host; TimeUtc = $f.Time; Occurrences = (Get-WfxValue $f 'Occurrences' 1); Recommendation = $f.Recommendation
        }
    }
    try { @($rows) | Export-Csv -Path (Join-Path $root 'findings.csv') -NoTypeInformation -Encoding UTF8 }
    catch { Add-WfxGap -Source 'output:csv' -Reason $_.Exception.Message }
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
    Write-WfxConsole ("Host {0}   Compromise risk {1}/100 ({2})   Posture gaps {3}/100 ({4})" -f $Result.HostName, $r.Score, $r.Level, $Result.Posture.Score, $Result.Posture.Level) -Kind $kind
    $s = $Result.Summary
    Write-WfxConsole ("Findings  Critical {0}  High {1}  Medium {2}  Low {3}  Info {4}" -f $s.Critical, $s.High, $s.Medium, $s.Low, $s.Info) -Kind Plain
    if (@($Result.Suppressed).Count) { Write-WfxConsole ("{0} finding(s) suppressed by the allowlist (listed in the report)." -f @($Result.Suppressed).Count) -Kind Dim }
    $top = @($Result.Findings | Where-Object { -not (Test-WfxPostureFinding $_) } | Select-Object -First 8)
    if ($top.Count) {
        Write-WfxConsole ''
        foreach ($f in $top) {
            $fk = switch ($f.Severity) { 'Critical' { 'Bad' } 'High' { 'Bad' } 'Medium' { 'Warn' } default { 'Dim' } }
            Write-WfxConsole ("  [{0,-8}] {1}" -f $f.Severity, $f.Title) -Kind $fk
        }
    }
    $gaps = @($Result.Gaps)
    if ($gaps.Count) { Write-WfxConsole ''; Write-WfxConsole ("{0} collection/analysis gap(s) recorded — see the report so 'nothing found' is read correctly." -f $gaps.Count) -Kind Warn }
    Write-WfxConsole ''
    Write-WfxConsole ("Outputs:  {0}" -f $Case.Path) -Kind Info
    $reportPath = Join-Path $Case.Path 'report.html'
    if (Test-Path -LiteralPath $reportPath) {
        Write-WfxConsole ("Report:   {0}" -f (ConvertTo-WfxFileUri $reportPath)) -Kind Info
    }
    $mp = Join-Path $Case.Path 'manifest.json'
    if (Test-Path -LiteralPath $mp) { Write-WfxConsole ("Manifest SHA-256 (record this out-of-band): {0}" -f (Get-FileHash -LiteralPath $mp -Algorithm SHA256).Hash.ToLowerInvariant()) -Kind Dim }
    Write-WfxConsole ''
    Write-WfxConsole 'Reminder: findings are leads, not verdicts — read them next to the collection gaps.' -Kind Dim
}
