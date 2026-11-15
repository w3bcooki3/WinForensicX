# Event log integrity: signs that the logs themselves were tampered with, beyond the obvious "log cleared"
# events (1102 / 104, handled by the event rules).
#
#  * Time running backwards. Windows numbers records in the order they are written (RecordId), so their
#    timestamps should never go back. When a record written later carries a time well before its
#    predecessor, the system clock was set back while logging, the classic way to make later activity
#    blend into an earlier period or to break timelines.
#  * Silence in a busy log. A log that normally records every few minutes and then has nothing for hours,
#    while other logs on the same machine kept recording, suggests records were removed or logging was
#    stopped. Kept deliberately strict (busy log, long gap, other logs active) so a machine that was simply
#    switched off is not reported.
#  * Sysmon stopped or reconfigured (Sysmon events 4 and 16).
#
# Every check works on the events that were collected, so it only claims what those records show.

function Invoke-WfxLogIntegrityAnalyzer {
    [CmdletBinding()]
    param([object[]]$Event = @(), [string]$HostName = '')
    $out = New-Object System.Collections.Generic.List[object]
    $rows = foreach ($e in $Event) {
        if (-not $e) { continue }
        $t = ConvertTo-WfxDateTime (Get-WfxValue $e 'TimeCreated' (Get-WfxValue $e 'Time' $null))
        if (-not $t) { continue }
        [pscustomobject]@{ Log = [string](Get-WfxValue $e 'Log' ''); Computer = [string](Get-WfxValue $e 'Computer' ''); Id = ConvertTo-WfxInt (Get-WfxValue $e 'Id' 0)
            RecordId = [long](ConvertTo-WfxInt (Get-WfxValue $e 'RecordId' 0)); Time = $t; Fields = (Get-WfxValue $e 'Fields' $null) }
    }
    $rows = @($rows)

    # 1. Time running backwards, per log and machine, in write order.
    foreach ($g in @($rows | Where-Object { $_.RecordId -gt 0 -and $_.Log } | Group-Object Log, Computer)) {
        $seq = @($g.Group | Sort-Object RecordId)
        $hits = New-Object System.Collections.Generic.List[object]
        for ($i = 1; $i -lt $seq.Count; $i++) {
            $a = $seq[$i - 1]; $b = $seq[$i]
            # Close record numbers only: a large jump can be two generations of the log (an archive and the
            # current file), whose numbering restarted, not a clock change.
            if (($b.RecordId - $a.RecordId) -gt 50) { continue }
            $back = ($a.Time - $b.Time).TotalMinutes
            if ($back -gt 2) { $hits.Add([pscustomobject]@{ From = $a; To = $b; Minutes = [Math]::Round($back, 1) }) }
        }
        if (-not $hits.Count) { continue }
        $worst = @($hits | Sort-Object Minutes -Descending)[0]
        $log = $seq[0].Log
        $ev = [ordered]@{
            Log = $log; Computer = $seq[0].Computer; Occurrences = $hits.Count
            Record = "$($worst.From.RecordId) at $(ConvertTo-WfxUtcString $worst.From.Time)"
            NextRecord = "$($worst.To.RecordId) at $(ConvertTo-WfxUtcString $worst.To.Time)"
            WentBack = "$($worst.Minutes) minutes"
            Examples = (@($hits | Select-Object -First 5 | ForEach-Object { "$($_.From.RecordId) -> $($_.To.RecordId): back $($_.Minutes) min" }) -join '; ')
        }
        $out.Add((New-WfxFinding -Id 'LOG-TIME-BACKWARDS' -Title "Clock set back while logging: $log" -Severity 'Medium' -Confidence 'Medium' -Category 'Defense Evasion' `
                    -Technique @('T1070.006') -HostName $HostName -Time $worst.To.Time -Source "evt:$log" -Entity "log:$log" -Evidence $ev `
                    -Description "Records in $log are numbered in the order Windows wrote them, but record $($worst.To.RecordId) carries a time $($worst.Minutes) minutes earlier than record $($worst.From.RecordId) before it. The system clock was set back while the log was recording ($($hits.Count) time$(if ($hits.Count -ne 1) { 's' })). Attackers do this so later activity sorts into an earlier, innocent-looking period." `
                    -Recommendation 'Treat timestamps after the change with care; order this period by record number, not time. Look for who changed the time (Security 4616, System 1) and what ran just before.'))
    }

    # 2. Silence in a busy log while other logs kept recording.
    foreach ($g in @($rows | Where-Object { $_.Log -match '^(?:Security|Microsoft-Windows-Sysmon/Operational)$' } | Group-Object Log, Computer)) {
        $seq = @($g.Group | Sort-Object Time)
        if ($seq.Count -lt 50) { continue }
        $gaps = for ($i = 1; $i -lt $seq.Count; $i++) { ($seq[$i].Time - $seq[$i - 1].Time).TotalMinutes }
        $sorted = @($gaps | Sort-Object); $median = $sorted[[int][Math]::Floor($sorted.Count / 2)]
        if ($median -gt 10) { continue }          # not a busy log: long quiet spells are normal
        $log = $seq[0].Log; $comp = $seq[0].Computer
        $others = @($rows | Where-Object { $_.Log -ne $log -and (-not $comp -or -not $_.Computer -or $_.Computer -eq $comp) })
        for ($i = 1; $i -lt $seq.Count; $i++) {
            $a = $seq[$i - 1].Time; $b = $seq[$i].Time; $hours = ($b - $a).TotalHours
            if ($hours -lt 6) { continue }
            $during = @($others | Where-Object { $_.Time -gt $a -and $_.Time -lt $b })
            $logsDuring = @($during | ForEach-Object Log | Select-Object -Unique)
            if ($during.Count -lt 20 -or $logsDuring.Count -lt 1) { continue }
            $ev = [ordered]@{ Log = $log; Computer = $comp; LastBefore = (ConvertTo-WfxUtcString $a); FirstAfter = (ConvertTo-WfxUtcString $b); Hours = [Math]::Round($hours, 1)
                UsualInterval = "$([Math]::Round($median, 1)) minutes"; OtherLogsDuring = "$($during.Count) records in $($logsDuring -join ', ')" }
            $out.Add((New-WfxFinding -Id 'LOG-SILENT-GAP' -Title "$log recorded nothing for $([Math]::Round($hours, 1)) hours while other logs were active" -Severity 'Low' -Confidence 'Low' -Category 'Defense Evasion' `
                        -Technique @('T1070.001') -HostName $HostName -Time $b -Source "evt:$log" -Entity "log:${log}:$(ConvertTo-WfxUtcString $a)" -Evidence $ev `
                        -Description "$log usually records every $([Math]::Round($median, 1)) minutes, but has no collected records between $(ConvertTo-WfxUtcString $a) and $(ConvertTo-WfxUtcString $b) UTC, while $($during.Count) records were written to other logs. Records may have been deleted selectively, or logging was stopped for that period." `
                        -Recommendation 'Compare with a forwarded copy (SIEM / WEF) for the same period; check for the event log service or audit policy being changed, and for tools that delete single records.'))
        }
    }

    # 3. Sysmon stopped or reconfigured.
    foreach ($r in @($rows | Where-Object { $_.Log -match 'Sysmon' -and $_.Id -in 4, 16 })) {
        $f = $r.Fields; $g = { param($n) [string](Get-WfxValue $f $n '') }
        if ($r.Id -eq 4 -and (& $g 'State') -match '(?i)stopped') {
            $out.Add((New-WfxFinding -Id 'LOG-SYSMON-STOPPED' -Title 'Sysmon service stopped' -Severity 'High' -Confidence 'Medium' -Category 'Defense Evasion' -Technique @('T1562.001') `
                        -HostName $HostName -Time $r.Time -Source "evt:$($r.Log)" -Entity "sysmon:stopped:$(ConvertTo-WfxUtcString $r.Time)" -Evidence ([ordered]@{ EventId = 4; Time = (ConvertTo-WfxUtcString $r.Time); State = (& $g 'State'); Version = (& $g 'Version') }) `
                        -Description 'Sysmon reported that its service stopped. Unless this was an upgrade or a planned change, process, network and file telemetry stopped from this moment.' `
                        -Recommendation 'Check who stopped it (System 7036/7040, Security 4688 for sc.exe or fltmc.exe) and what happened while it was down.'))
        } elseif ($r.Id -eq 16) {
            $out.Add((New-WfxFinding -Id 'LOG-SYSMON-CONFIG' -Title 'Sysmon configuration changed' -Severity 'Medium' -Confidence 'Low' -Category 'Defense Evasion' -Technique @('T1562.001') `
                        -HostName $HostName -Time $r.Time -Source "evt:$($r.Log)" -Entity "sysmon:config:$(ConvertTo-WfxUtcString $r.Time)" -Evidence ([ordered]@{ EventId = 16; Time = (ConvertTo-WfxUtcString $r.Time); Configuration = (& $g 'Configuration'); Hash = (& $g 'ConfigurationFileHash') }) `
                        -Description 'The Sysmon configuration was replaced. An attacker can load a configuration that excludes their tools, keeping Sysmon running but blind.' `
                        -Recommendation 'Compare the configuration hash with the one you deploy; if it differs, recover the file and see what it excludes.'))
        }
    }
    , $out.ToArray()
}
