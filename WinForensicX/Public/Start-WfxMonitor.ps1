function Start-WfxMonitor {
    <#
    .SYNOPSIS
        Live monitoring: takes a baseline of processes and network connections, then watches for NEW
        ones and runs the process / network / beacon analyzers over just the changes, alerting as they
        happen. Read-only. Stop with Ctrl+C or a time limit.
    .PARAMETER Interval     Seconds between polls (default 5).
    .PARAMETER Duration     Total seconds to run; 0 = until Ctrl+C (default 0).
    .PARAMETER MinSeverity  Only alert at or above this severity (default Medium).
    .PARAMETER OutputPath   Case folder location (an alerts.jsonl is appended there).
    .PARAMETER CaseName     Optional case label.
    .PARAMETER Quiet        Suppress console output (alerts still written to the case).
    .EXAMPLE
        Start-WfxMonitor -Interval 5 -Duration 300
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(2, 3600)][int]$Interval = 5,
        [ValidateRange(0, 2592000)][int]$Duration = 0,
        [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')][string]$MinSeverity = 'Medium',
        [string]$OutputPath = '',
        [string]$CaseName = '',
        [switch]$Quiet
    )
    if (-not (Test-WfxWindows)) { Write-WfxConsole 'Live monitor requires Windows.' -Kind Bad; return }
    $script:WfxQuiet = [bool]$Quiet
    Write-WfxBanner
    $rank = @{ Info = 4; Low = 3; Medium = 2; High = 1; Critical = 0 }
    $minRank = $rank[$MinSeverity]
    $hn = [Environment]::MachineName
    $case = New-WfxCase -OutputPath $OutputPath -Name ($(if ($CaseName) { $CaseName } else { 'monitor' })) -HostName $hn -Mode 'monitor' -Parameters @{ Interval = $Interval; Duration = $Duration; MinSeverity = $MinSeverity }
    $alertPath = Join-Path $case.Path 'alerts.jsonl'

    Write-WfxConsole "Monitoring $hn — baseline..." -Kind Info
    $seenPid = @{}
    $seenConn = @{}
    $beacon = @{}                      # remote -> [List[datetime]] of NEW-connection times (not poll times)
    $alerted = @{}                     # Id|Entity already alerted (no repeats)
    foreach ($p in @(Get-WfxProcessData)) { $seenPid["$($p.Pid):$($p.Name)"] = $true }
    foreach ($c in @(Get-WfxNetworkData)) { $seenConn[(ConnKey $c)] = $true }
    Write-WfxConsole ("Baseline: {0} processes, {1} connections. Polling every {2}s. Ctrl+C to stop." -f $seenPid.Count, $seenConn.Count, $Interval) -Kind Dim
    Write-WfxConsole ''

    $deadline = if ($Duration -gt 0) { (Get-Date).AddSeconds($Duration) } else { [datetime]::MaxValue }
    $alertCount = 0; $iter = 0
    try {
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds $Interval
            $iter++
            $newProcs = @(); $newConns = @()
            # Only processes not seen before are enriched (signature/owner lookups are the expensive part).
            foreach ($p in @(Get-WfxProcessData -Skip $seenPid)) {
                $k = "$($p.Pid):$($p.Name)"
                if (-not $seenPid.ContainsKey($k)) { $seenPid[$k] = $true; $newProcs += $p }
            }
            foreach ($c in @(Get-WfxNetworkData)) {
                $k = ConnKey $c
                if ($seenConn.ContainsKey($k)) { continue }
                $seenConn[$k] = $true; $newConns += $c
                # Beaconing = repeated NEW connections (new source port) to the same destination. A single
                # long-lived connection observed on every poll is not a beacon.
                if ($c.State -match 'Establish' -and $c.RemoteAddress -and -not (Test-WfxPrivateIp $c.RemoteAddress)) {
                    $rk = "$($c.RemoteAddress):$($c.RemotePort)"
                    if (-not $beacon.ContainsKey($rk)) { $beacon[$rk] = New-Object System.Collections.Generic.List[datetime] }
                    $t = ConvertTo-WfxDateTime (Get-WfxValue $c 'CreatedUtc' '')
                    $beacon[$rk].Add($(if ($t) { $t } else { (Get-Date).ToUniversalTime() }))
                    if ($beacon[$rk].Count -gt 200) { $beacon[$rk].RemoveAt(0) }
                }
            }

            $hits = New-Object System.Collections.Generic.List[object]
            # NB: analyzers return their findings as ONE array object; iterate the parenthesized result directly
            # (wrapping it in @() would yield a single nested array and garble alerts).
            if ($newProcs.Count) { foreach ($f in (Invoke-WfxProcessAnalyzer -Process $newProcs -HostName $hn)) { $hits.Add($f) } }
            if ($newConns.Count) { foreach ($f in (Invoke-WfxNetworkAnalyzer -Connection $newConns -HostName $hn)) { $hits.Add($f) } }
            # Periodically re-evaluate beaconing (needs several samples).
            if ($iter % 6 -eq 0) {
                $bIn = foreach ($rk in $beacon.Keys) { if ($beacon[$rk].Count -ge 6) { [pscustomobject]@{ Remote = $rk; Times = @($beacon[$rk]) } } }
                foreach ($f in (Invoke-WfxBeaconAnalyzer -Beacon @($bIn) -HostName $hn)) { $hits.Add($f) }
            }

            foreach ($f in @($hits | Where-Object { $_ -and $rank[[string]$_.Severity] -le $minRank })) {
                $ak = "$($f.Id)|$($f.Entity)"
                if ($alerted.ContainsKey($ak)) { continue }
                $alerted[$ak] = $true
                $alertCount++
                $fk = switch ($f.Severity) { 'Critical' { 'Bad' } 'High' { 'Bad' } 'Medium' { 'Warn' } default { 'Dim' } }
                Write-WfxConsole ("[{0:HH:mm:ss}] [{1,-8}] {2}" -f (Get-Date), $f.Severity, $f.Title) -Kind $fk
                try { Add-Content -LiteralPath $alertPath -Value (($f | ConvertTo-Json -Compress -Depth 6)) -Encoding UTF8 } catch { Write-Verbose "alert write failed: $_" }
            }
        }
    } finally {
        $null = Complete-WfxCase
        Write-WfxConsole ''
        Write-WfxConsole ("Monitor stopped. {0} alert(s) at/above {1}. Case: {2}" -f $alertCount, $MinSeverity, $case.Path) -Kind Info
    }
}

function ConnKey {
    param($C)
    "$($C.Protocol)|$($C.LocalAddress):$($C.LocalPort)|$($C.RemoteAddress):$($C.RemotePort)|$($C.State)"
}
