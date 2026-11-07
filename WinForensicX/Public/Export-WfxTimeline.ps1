function Get-WfxTimeline {
    <#
    .SYNOPSIS Builds a single, UTC-sorted timeline from a case or bundle: host boot/install, process starts,
    connection creation, event-log records, file writes/creations, and (when result.json is present) findings.
    .PARAMETER InputPath  A case folder or bundle.json.
    .PARAMETER From/To    Optional UTC window.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$InputPath, [datetime]$From = [datetime]::MinValue, [datetime]$To = [datetime]::MaxValue)
    $bundlePath = Resolve-WfxBundlePath -Path $InputPath
    $b = Get-Content -LiteralPath $bundlePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $hn = [string](Get-WfxValue $b 'HostName' '')
    $rows = New-Object System.Collections.Generic.List[object]
    $add = {
        param($Time, $Source, $Type, $Summary, $Detail = '')
        $t = ConvertTo-WfxDateTime $Time
        if (-not $t -or $t -lt $From.ToUniversalTime() -or $t -gt $To.ToUniversalTime()) { return }
        $d = [string]$Detail; if ($d.Length -gt 1000) { $d = $d.Substring(0, 1000) + ' …' }
        $rows.Add([pscustomobject]@{ TimeUtc = (ConvertTo-WfxUtcString $t); Host = $hn; Source = $Source; Type = $Type; Summary = [string]$Summary; Detail = $d; _t = $t })
    }
    $h = Get-WfxValue $b 'Host' $null
    if ($h) { & $add (Get-WfxValue $h 'BootUtc' (Get-WfxValue $h 'Boot' '')) 'host' 'boot' 'System boot'; & $add (Get-WfxValue $h 'InstallUtc' '') 'host' 'install' 'Windows installed' }
    foreach ($p in @(Get-WfxValue $b 'Process' @())) { & $add $p.CreateTime 'process' 'process-start' "$($p.Name) (pid $($p.Pid), parent $($p.ParentName))" $p.CommandLine }
    foreach ($c in @(Get-WfxValue $b 'Network' @())) { & $add (Get-WfxValue $c 'CreatedUtc' '') 'network' "$($c.Protocol)-$($c.State)" "$($c.Process) $($c.LocalAddress):$($c.LocalPort) → $($c.RemoteAddress):$($c.RemotePort)" }
    foreach ($e in @(Get-WfxValue $b 'Events' @())) {
        $fl = Get-WfxValue $e 'Fields' $null
        $keys = @('TargetUserName', 'SubjectUserName', 'IpAddress', 'LogonType', 'NewProcessName', 'Image', 'CommandLine', 'ServiceName', 'ImagePath', 'TaskName', 'Threat Name', 'QueryName', 'DestinationIp', 'TargetObject')
        $kv = @(foreach ($k in $keys) { $v = [string](Get-WfxValue $fl $k ''); if ($v -and $v -ne '-') { "$k=$v" } }) -join '; '
        $msg = [string](Get-WfxValue $e 'Message' ''); $first = ($msg -split "`r?`n")[0]
        & $add $e.TimeCreated "evt:$($e.Log)" "event-$($e.Id)" "$($e.Id) $first" $kv
    }
    foreach ($a in @(Get-WfxValue $b 'Activity' @())) { & $add $a.Time "activity:$($a.Category)" $a.Action $a.Target "$($a.Detail) $(if ($a.Actor) { "by $($a.Actor)" }) [$($a.Source)]" }
    foreach ($f in @(Get-WfxValue $b 'Files' @())) {
        & $add $f.LastWrite 'file' 'file-modified' $f.Path "sha256=$(Get-WfxValue $f 'SHA256' '') zone=$(Get-WfxValue $f 'Zone' '') $(Get-WfxValue $f 'HostUrl' '')"
        & $add (Get-WfxValue $f 'Created' '') 'file' 'file-created' $f.Path
    }
    $resultPath = Join-Path (Split-Path -Parent (Split-Path -Parent $bundlePath)) 'result.json'
    if (Test-Path -LiteralPath $resultPath) {
        $r = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($f in @($r.Findings)) { & $add $f.Time 'finding' "finding-$($f.Severity)" "[$($f.Severity)] $($f.Title)" "$($f.Id) $($f.Entity)" }
    }
    $rows | Sort-Object _t | Select-Object TimeUtc, Host, Source, Type, Summary, Detail
}

function Export-WfxTimeline {
    <#
    .SYNOPSIS Writes the case timeline (see Get-WfxTimeline) to CSV or JSON for Excel, Timeline Explorer or a SIEM.
    By default the file is written NEXT TO the case folder (<case>-timeline.csv), so a completed, hashed case
    folder is never modified.
    .EXAMPLE
        Export-WfxTimeline -InputPath C:\cases\WFX_host_20260101-000000Z
    .EXAMPLE
        Export-WfxTimeline -InputPath .\case -Format Json -From '2026-11-01' -OutputPath .\tl.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [string]$OutputPath = '',
        [ValidateSet('Csv', 'Json')][string]$Format = 'Csv',
        [datetime]$From = [datetime]::MinValue,
        [datetime]$To = [datetime]::MaxValue,
        [switch]$PassThru
    )
    $rows = Get-WfxTimeline -InputPath $InputPath -From $From -To $To
    if (-not $OutputPath) {
        $bp = Resolve-WfxBundlePath -Path $InputPath
        $caseDir = Split-Path -Parent (Split-Path -Parent $bp)
        if ((Split-Path -Leaf (Split-Path -Parent $bp)) -ne 'raw') { $caseDir = Split-Path -Parent $bp }
        $OutputPath = Join-Path (Split-Path -Parent $caseDir) ("{0}-timeline.{1}" -f (Split-Path -Leaf $caseDir), $Format.ToLowerInvariant())
    }
    if ($Format -eq 'Csv') { @($rows) | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
    else { Save-WfxJson -InputObject @($rows) -Path $OutputPath -Depth 4 }
    Write-WfxConsole ("Timeline: {0} entries → {1}" -f @($rows).Count, $OutputPath) -Kind Info
    if ($PassThru) { return $rows }
}
