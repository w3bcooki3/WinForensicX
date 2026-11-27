function Invoke-WfxAnalyze {
    <#
    .SYNOPSIS
        Runs every analyzer over a collection bundle and returns a scored result. Pure and OS-neutral:
        it works on any machine, so an analyst can re-analyze evidence collected elsewhere.
    .DESCRIPTION
        Each analyzer is isolated: if one fails (e.g. a rule pack is missing or a record is malformed) the
        failure is recorded as an analysis gap and the remaining analyzers still run.
        Two scores are produced:
          • Risk    — evidence of compromise / attacker activity (what an incident responder acts on first).
          • Posture — hardening and visibility gaps (what an administrator should fix).
    .PARAMETER Bundle
        A bundle object from Get-WfxCollectionBundle, OR a path to a bundle JSON file (raw/bundle.json),
        OR a directory that contains one.
    .PARAMETER HostName
        Override the host label (defaults to the bundle's HostName).
    .PARAMETER AllowlistPath
        JSON allowlist of known-good findings to suppress (see Read-WfxAllowlist). Defaults to $env:WFX_ALLOWLIST.
    .PARAMETER SigmaPath
        Folder(s) or file(s) of Sigma rules (YAML) to run over the collected events as well. Defaults to
        $env:WFX_SIGMA. Rules for data the tool does not collect are skipped and counted as a gap.
    .OUTPUTS
        [pscustomobject] winforensicx.result/2
    .EXAMPLE
        Invoke-WfxAnalyze -Bundle 'D:\cases\WFX_host_20260101\raw\bundle.json'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Bundle,
        [string]$HostName = '',
        [string]$AllowlistPath = $env:WFX_ALLOWLIST,
        [string[]]$SigmaPath = @($env:WFX_SIGMA | Where-Object { $_ })
    )

    process {
        if ($Bundle -is [string]) { $Bundle = Read-WfxBundle -Path $Bundle }
        if (-not $HostName) { $HostName = [string](Get-WfxValue $Bundle 'HostName' ([Environment]::MachineName)) }
        $gaps = [System.Collections.Generic.List[object]]::new()
        # Older bundles stored the gap list nested one level deep; flatten it.
        foreach ($g in @(@(Get-WfxValue $Bundle 'Gaps' @()) | Expand-WfxRecord | Expand-WfxRecord)) { if ($g -and $g.PSObject.Properties['Source']) { $gaps.Add($g) } }

        $all = [System.Collections.Generic.List[object]]::new()
        $run = {
            param([string]$Name, [scriptblock]$Body)
            try { foreach ($f in @(& $Body | ForEach-Object { $_ } | Where-Object { $_ })) { $all.Add($f) } }
            catch { $gaps.Add([pscustomobject]@{ Source = "analyzer:$Name"; Reason = $_.Exception.Message; Fix = 'Restore the missing/invalid rule pack or report the malformed record.' }) }
        }

        $events = @(Get-WfxValue $Bundle 'Events' @())
        # DNS evidence: the DNS cache plus Sysmon 22 (DNS query) events, when present.
        $dns = @(Get-WfxValue $Bundle 'Dns' @()) + @($events | Where-Object { (ConvertTo-WfxInt (Get-WfxValue $_ 'Id' 0)) -eq 22 -and [string](Get-WfxValue $_ 'Log' '') -match 'Sysmon' } | ForEach-Object {
                $q = [string](Get-WfxValue (Get-WfxValue $_ 'Fields' @{}) 'QueryName' '')
                if ($q) { [pscustomobject]@{ Name = $q; Type = 'Sysmon22'; Data = '' } } })
        $dnsMap = Get-WfxDnsAddressMap -DnsEntry $dns

        & $run 'process'     { Invoke-WfxProcessAnalyzer     -Process    @(Get-WfxValue $Bundle 'Process' @())     -HostName $HostName }
        & $run 'volatile'    { Invoke-WfxVolatileAnalyzer    -Volatile   (Get-WfxValue $Bundle 'Volatile' $null)   -HostName $HostName }
        & $run 'network'     { Invoke-WfxNetworkAnalyzer     -Connection @(Get-WfxValue $Bundle 'Network' @())     -HostName $HostName -DnsMap $dnsMap }
        & $run 'dns'         { Invoke-WfxDnsAnalyzer         -DnsEntry   $dns                                      -HostName $HostName }
        & $run 'persistence' { Invoke-WfxPersistenceAnalyzer -Autostart  @(Get-WfxValue $Bundle 'Persistence' @()) -HostName $HostName }
        & $run 'events'      { Invoke-WfxEventAnalyzer       -Event      $events                                   -HostName $HostName }
        & $run 'logintegrity' { Invoke-WfxLogIntegrityAnalyzer -Event    $events                                   -HostName $HostName }
        if (@($SigmaPath).Count) {
            & $run 'sigma' { $sr = Get-WfxSigmaRuleSet -Path $SigmaPath; Invoke-WfxSigmaAnalyzer -Event $events -Rule $sr -HostName $HostName }
        }
        $activity = @(Get-WfxValue $Bundle 'Activity' @())
        & $run 'activity'    { Invoke-WfxActivityAnalyzer    -Activity   $activity                                 -HostName $HostName }
        & $run 'files'       { Invoke-WfxFileAnalyzer        -File       @(Get-WfxValue $Bundle 'Files' @())       -HostName $HostName }
        & $run 'exposure'    { Invoke-WfxExposureAnalyzer    -Exposure   @(Get-WfxValue $Bundle 'Exposure' @())    -HostName $HostName }
        & $run 'posture'     { Invoke-WfxPostureAnalyzer     -Posture    (Get-WfxValue $Bundle 'Security' $null)   -HostName $HostName }
        $yara = @(Get-WfxValue $Bundle 'Yara' @())
        if ($yara.Count) { & $run 'yara' { Invoke-WfxYaraAnalyzer -Hit $yara -HostName $HostName } }
        $artifacts = @(Get-WfxValue $Bundle 'Artifacts' @())
        & $run 'artifacts'   { Invoke-WfxArtifactAnalyzer    -Artifacts  $artifacts                                -HostName $HostName }
        $ransom = Get-WfxValue $Bundle 'Ransom' $null
        if ($ransom) {
            & $run 'ransomware' { Invoke-WfxRansomwareAnalyzer -Note @(Get-WfxValue $ransom 'Note' @()) -RecentFile @(Get-WfxValue $ransom 'RecentFile' @()) -HostName $HostName }
        }

        # Gaps raised while loading rules / analyzing (custom-pack parse errors, rejected rules) belong to this result.
        foreach ($g in @(Get-WfxGap | Expand-WfxRecord)) { if ($g -and -not ($gaps | Where-Object { $_.Source -eq $g.Source -and $_.Reason -eq $g.Reason })) { $gaps.Add($g) } }

        $merged = Merge-WfxFinding -Finding $all.ToArray()
        $allow = @()
        if ($AllowlistPath) {
            try { $allow = Read-WfxAllowlist -Path $AllowlistPath }
            catch { $gaps.Add([pscustomobject]@{ Source = 'allowlist'; Reason = $_.Exception.Message; Fix = 'Fix the allowlist path / JSON.' }) }
        }
        $split = Split-WfxAllowlisted -Finding $merged -Allowlist $allow
        $findings = @($split.Kept)
        # Independent sources that record the same program raise confidence (and are shown as such in the report).
        try { $findings = @(Add-WfxCorroboration -Finding $findings -Bundle $Bundle -Event $events -Artifact $artifacts | Expand-WfxRecord) }
        catch { $gaps.Add([pscustomobject]@{ Source = 'analyzer:corroboration'; Reason = $_.Exception.Message; Fix = 'Report the record that caused this; findings are unaffected.' }) }
        # Who started whom: the ancestry of each process finding, from Sysmon 1, 4688 and the process list.
        try { $findings = @(Add-WfxProcessLineage -Finding $findings -Event $events -Process @(Get-WfxValue $Bundle 'Process' @()) | Expand-WfxRecord) }
        catch { $gaps.Add([pscustomobject]@{ Source = 'analyzer:process-tree'; Reason = $_.Exception.Message; Fix = 'Report the record that caused this; findings are unaffected.' }) }

        $compromise = @($findings | Where-Object { -not (Test-WfxPostureFinding $_) })
        $postureF = @($findings | Where-Object { Test-WfxPostureFinding $_ })
        $risk = Get-WfxRiskScore -Finding $compromise
        $posture = Get-WfxRiskScore -Finding $postureF
        $summary = Get-WfxSeveritySummary -Finding $findings

        # ATT&CK coverage: distinct techniques observed, resolved to tactic/name.
        $techIds = @($findings | ForEach-Object { $_.Technique } | Where-Object { $_ } | Sort-Object -Unique)
        $coverage = foreach ($t in $techIds) { Get-WfxAttackTechnique $t }

        # Memory-capture readiness (live and remote bundles only): checks and the incident card, never scored.
        $readiness = @(); $readySummary = ''; $card = @()
        $readyData = Get-WfxValue (Get-WfxValue $Bundle 'Security' $null) 'Readiness' $null
        if ($readyData) {
            try {
                $readiness = @(Get-WfxReadinessCheck -Data $readyData | Expand-WfxRecord)
                $readySummary = Get-WfxReadinessSummary -Check $readiness
                $card = @(Get-WfxIncidentCard -Check $readiness | Expand-WfxRecord)
            } catch { $gaps.Add([pscustomobject]@{ Source = 'analyzer:readiness'; Reason = $_.Exception.Message; Fix = '' }) }
        }

        [pscustomobject]@{
            Schema         = 'winforensicx.result/2'
            HostName       = $HostName
            Analyzed       = (Get-WfxUtcNow)
            Collected      = (ConvertTo-WfxUtcString (Get-WfxValue $Bundle 'Collected' ''))
            ToolVersion    = $script:WfxVersion
            Host           = (Get-WfxValue $Bundle 'Host' $null)
            Risk           = $risk
            Posture        = $posture
            Summary        = $summary
            Findings       = @($findings)
            Suppressed     = @($split.Suppressed)
            Activity       = @($activity | Sort-Object { [string]$_.Time } -Descending | Select-Object -First 3000)
            ActivityTotal  = $activity.Count
            Artifacts      = @($artifacts | Sort-Object { [string]$_.Time } -Descending | Select-Object -First 5000)
            ArtifactTotal  = $artifacts.Count
            AttackCoverage = @($coverage)
            Incidents      = @(Get-WfxIncident -Finding $findings | Expand-WfxRecord)
            # Summaries for comparing hosts (fleet report): programs seen, remote access in and out, own addresses.
            Programs       = @(try { Get-WfxProgramSummary -Bundle $Bundle -Event $events -Artifact $artifacts | Expand-WfxRecord } catch { $gaps.Add([pscustomobject]@{ Source = 'analyzer:programs'; Reason = $_.Exception.Message; Fix = 'Fleet rarity will skip this host.' }) })
            Logons         = @(try { Get-WfxLogonSummary -Event $events | Expand-WfxRecord } catch { $gaps.Add([pscustomobject]@{ Source = 'analyzer:logons'; Reason = $_.Exception.Message; Fix = 'Fleet movement will skip this host.' }) })
            Addresses      = @(try { Get-WfxHostAddress -Bundle $Bundle | Expand-WfxRecord } catch { })
            Readiness      = @($readiness)
            ReadinessSummary = $readySummary
            IncidentCard   = @($card)
            Gaps           = @($gaps.ToArray())
            Meta           = (Get-WfxValue $Bundle 'Meta' $null)
        }
    }
}

function Read-WfxBundle {
    <# Loads a bundle from a bundle.json path or a case folder (looks for bundle.json and raw/bundle.json). #>
    param([Parameter(Mandatory)][string]$Path)
    $p = Resolve-WfxBundlePath -Path $Path
    Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Resolve-WfxBundlePath {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $cand = @((Join-Path $Path 'bundle.json'), (Join-Path (Join-Path $Path 'raw') 'bundle.json'))
        $p = @($cand | Where-Object { Test-Path -LiteralPath $_ }) | Select-Object -First 1
        if (-not $p) { throw "No bundle.json found under '$Path'." }
        return (Resolve-Path -LiteralPath $p).Path
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Bundle path not found: $Path" }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Get-WfxDnsAddressMap {
    <# IP -> resolved names, built from DNS-cache A/AAAA records. Used to name connection endpoints offline,
       so the tool never has to send its own reverse-DNS queries from the host under investigation. #>
    param([object[]]$DnsEntry)
    $map = @{}
    foreach ($d in @($DnsEntry | Where-Object { $_ })) {
        $data = [string](Get-WfxValue $d 'Data' '')
        $name = [string](Get-WfxValue $d 'Name' '')
        if (-not $data -or -not $name) { continue }
        $ip = $null
        if ([System.Net.IPAddress]::TryParse($data, [ref]$ip)) {
            if (-not $map.ContainsKey($data)) { $map[$data] = New-Object System.Collections.Generic.List[string] }
            if (-not $map[$data].Contains($name.ToLowerInvariant())) { $map[$data].Add($name.ToLowerInvariant()) }
        }
    }
    $map
}
