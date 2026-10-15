function Invoke-WfxAnalyze {
    <#
    .SYNOPSIS
        Runs every analyzer over a collection bundle and returns a scored result. Pure and OS-neutral:
        it works on any machine, so an analyst can re-analyze evidence collected elsewhere.
    .PARAMETER Bundle
        A bundle object from Get-WfxCollectionBundle, OR a path to a bundle JSON file (raw/bundle.json),
        OR a directory that contains one.
    .PARAMETER HostName
        Override the host label (defaults to the bundle's HostName).
    .OUTPUTS
        [pscustomobject] with Findings, Risk, Summary, AttackCoverage, Gaps, Host, HostName, Analyzed.
    .EXAMPLE
        Invoke-WfxAnalyze -Bundle 'D:\cases\WFX_host_20260101\raw\bundle.json'
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)]$Bundle, [string]$HostName = '')

    process {
        # Accept an object, a JSON file, or a case directory.
        if ($Bundle -is [string]) {
            $p = $Bundle
            if (Test-Path -LiteralPath $p -PathType Container) {
                $cand = @(Join-Path $p 'bundle.json'), (Join-Path $p 'raw\bundle.json'), (Join-Path $p 'raw/bundle.json')
                $p = @($cand | Where-Object { Test-Path -LiteralPath $_ }) | Select-Object -First 1
                if (-not $p) { throw "No bundle.json found under '$Bundle'." }
            }
            if (-not (Test-Path -LiteralPath $p)) { throw "Bundle path not found: $Bundle" }
            $Bundle = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json
        }
        if (-not $HostName) { $HostName = [string](Get-WfxValue $Bundle 'HostName' ([Environment]::MachineName)) }

        $all = New-Object System.Collections.Generic.List[object]
        $add = { param($set) foreach ($f in @($set | Where-Object { $_ })) { $all.Add($f) } }

        & $add (Invoke-WfxProcessAnalyzer    -Process     @(Get-WfxValue $Bundle 'Process' @())     -HostName $HostName)
        & $add (Invoke-WfxNetworkAnalyzer    -Connection  @(Get-WfxValue $Bundle 'Network' @())     -HostName $HostName)
        & $add (Invoke-WfxDnsAnalyzer        -DnsEntry    @(Get-WfxValue $Bundle 'Dns' @())         -HostName $HostName)
        & $add (Invoke-WfxPersistenceAnalyzer -Autostart  @(Get-WfxValue $Bundle 'Persistence' @()) -HostName $HostName)
        & $add (Invoke-WfxEventAnalyzer      -Event       @(Get-WfxValue $Bundle 'Events' @())      -HostName $HostName)
        & $add (Invoke-WfxFileAnalyzer       -File        @(Get-WfxValue $Bundle 'Files' @())       -HostName $HostName)
        & $add (Invoke-WfxExposureAnalyzer   -Exposure    @(Get-WfxValue $Bundle 'Exposure' @())    -HostName $HostName)
        & $add (Invoke-WfxPostureAnalyzer    -Posture     (Get-WfxValue $Bundle 'Security' $null)   -HostName $HostName)

        $ransom = Get-WfxValue $Bundle 'Ransom' $null
        if ($ransom) {
            & $add (Invoke-WfxRansomwareAnalyzer -Note @(Get-WfxValue $ransom 'Note' @()) -RecentFile @(Get-WfxValue $ransom 'RecentFile' @()) -HostName $HostName)
        }

        $findings = Merge-WfxFinding -Finding $all.ToArray()
        $risk = Get-WfxRiskScore -Finding $findings
        $summary = Get-WfxSeveritySummary -Finding $findings

        # ATT&CK coverage: distinct techniques observed, resolved to tactic/name.
        $techIds = @($findings | ForEach-Object { $_.Technique } | Where-Object { $_ } | Sort-Object -Unique)
        $coverage = foreach ($t in $techIds) { Get-WfxAttackTechnique $t }

        [pscustomobject]@{
            Schema         = 'winforensicx.result/1'
            HostName       = $HostName
            Analyzed       = (Get-Date).ToUniversalTime().ToString('o')
            ToolVersion    = $script:WfxVersion
            Host           = (Get-WfxValue $Bundle 'Host' $null)
            Risk           = $risk
            Summary        = $summary
            Findings       = @($findings)
            AttackCoverage = @($coverage)
            Gaps           = @(Get-WfxValue $Bundle 'Gaps' @())
            Meta           = (Get-WfxValue $Bundle 'Meta' $null)
        }
    }
}
