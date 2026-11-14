# Correlation: groups individual findings into incidents — sets of findings that share an entity (a
# file, program, account or address) and happen close together. An analyst then reads one story
# ("a document spawned PowerShell, which downloaded a tool, which was persisted and ran") instead of
# twenty separate lines. Deterministic and explainable: every link records why two findings were joined.

function Get-WfxFindingEntity {
    <# The things a finding is about, as normalised keys: file:<leaf>, user:<name>, ip:<addr>, host:<name>. #>
    param($Finding)
    $keys = New-Object System.Collections.Generic.HashSet[string]
    $ev = $Finding.Evidence
    $vals = New-Object System.Collections.Generic.List[string]
    $vals.Add([string]$Finding.Entity)
    if ($ev) {
        $pairs = if ($ev -is [System.Collections.IDictionary]) { $ev.GetEnumerator() } else { $ev.PSObject.Properties }
        foreach ($p in $pairs) {
            $n = [string]$p.Name; $v = [string]$p.Value
            if (-not $v) { continue }
            if ($n -match '(?i)^(?:user|users|actor|account|targetusername|subjectusername|accountname)$') { foreach ($u in ($v -split ',\s*')) { $u = ($u -replace '^.*\\', '').Trim().ToLowerInvariant(); if ($u -and $u -notmatch '\.[a-z0-9]{2,4}$' -and $u -notmatch '^(?:system|local service|network service|-|\$|anonymous logon|dwm-\d+|umfd-\d+)$' -and $u -notmatch '\$$') { [void]$keys.Add("user:$u") } } }
            else { $vals.Add($v) }
        }
    }
    foreach ($v in $vals) {
        foreach ($m in [regex]::Matches($v, '(?i)(?:[a-z]:|\\\\[^\\\s]+|\(volume\))?(?:\\[^\\\s"<>|]+)+\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|scr|sys|msi|lnk|iso|zip|7z|rar|txt|docx?|xlsx?)\b')) {
            $leaf = ($m.Value -split '\\')[-1].ToLowerInvariant()
            if ($leaf -notin 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'conhost.exe', 'svchost.exe', 'explorer.exe', 'rundll32.exe', 'wevtutil.exe') { [void]$keys.Add("file:$leaf") }
        }
        foreach ($m in [regex]::Matches($v, '\b(?:\d{1,3}\.){3}\d{1,3}\b')) { if (-not (Test-WfxPrivateIp $m.Value) -and $m.Value -notmatch '^(?:0\.|127\.|255\.)') { [void]$keys.Add("ip:$($m.Value)") } }
    }
    , @($keys)
}

function Get-WfxIncident {
    <#
    .SYNOPSIS Groups findings into incidents. Two findings are linked when they share an entity and are at most
    -Window apart, or are both High/Critical within -Burst of each other. Returns incidents with 2+ findings
    (or a single Critical), most severe first.
    #>
    param([object[]]$Finding, [TimeSpan]$Window = ([TimeSpan]::FromHours(6)), [TimeSpan]$Burst = ([TimeSpan]::FromMinutes(20)))
    $sevRank = @{ Info = 0; Low = 1; Medium = 2; High = 3; Critical = 4 }
    $fs = @($Finding | Where-Object { $_ -and $_.Time -and -not (Test-WfxPostureFinding $_) -and $_.Severity -ne 'Info' })
    $n = $fs.Count
    if ($n -eq 0) { return , @() }
    $t = @($fs | ForEach-Object { ConvertTo-WfxDateTime $_.Time })
    $ent = @($fs | ForEach-Object { , (Get-WfxFindingEntity $_) })
    $parent = [int[]](0..($n - 1))
    $find = { param($i) while ($parent[$i] -ne $i) { $parent[$i] = $parent[$parent[$i]]; $i = $parent[$i] }; $i }
    $why = @{}
    # Entity index → findings that mention it, so linking is not quadratic over all pairs.
    $idx = @{}
    for ($i = 0; $i -lt $n; $i++) { foreach ($k in $ent[$i]) { if (-not $idx.ContainsKey($k)) { $idx[$k] = New-Object System.Collections.Generic.List[int] }; $idx[$k].Add($i) } }
    foreach ($k in $idx.Keys) {
        $list = $idx[$k]; if ($list.Count -lt 2 -or $list.Count -gt 200) { continue }
        for ($a = 0; $a -lt $list.Count; $a++) { for ($b = $a + 1; $b -lt $list.Count; $b++) {
                $i = $list[$a]; $j = $list[$b]
                if ([Math]::Abs(($t[$i] - $t[$j]).TotalSeconds) -le $Window.TotalSeconds) {
                    $ri = & $find $i; $rj = & $find $j; if ($ri -ne $rj) { $parent[$ri] = $rj; $why["$i|$j"] = "shared $k" }
                }
            } }
    }
    $order = @(0..($n - 1) | Sort-Object { $t[$_] })
    for ($a = 1; $a -lt $order.Count; $a++) {
        $i = $order[$a - 1]; $j = $order[$a]
        if ($sevRank[$fs[$i].Severity] -ge 3 -and $sevRank[$fs[$j].Severity] -ge 3 -and ($t[$j] - $t[$i]) -le $Burst) {
            $ri = & $find $i; $rj = & $find $j; if ($ri -ne $rj) { $parent[$ri] = $rj; $why["$i|$j"] = 'high-severity burst' }
        }
    }
    $groups = @{}
    for ($i = 0; $i -lt $n; $i++) { $r = & $find $i; if (-not $groups.ContainsKey($r)) { $groups[$r] = New-Object System.Collections.Generic.List[int] }; $groups[$r].Add($i) }
    $tacticOrder = @('Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact')
    $out = foreach ($g in $groups.Values) {
        $members = @($g | Sort-Object { $t[$_] })
        $maxSev = ($members | ForEach-Object { $sevRank[$fs[$_].Severity] } | Measure-Object -Maximum).Maximum
        if ($members.Count -lt 2 -and $maxSev -lt 4) { continue }
        $tactics = @($members | ForEach-Object { foreach ($tq in @($fs[$_].Technique)) { $x = Get-WfxAttackTechnique $tq; if ($x) { $x.Tactic } } } | Where-Object { $_ } | Select-Object -Unique | Sort-Object { $ix = $tacticOrder.IndexOf([string]$_); if ($ix -lt 0) { 99 } else { $ix } })
        $entCount = @{}; foreach ($m in $members) { foreach ($k in $ent[$m]) { $entCount[$k] = 1 + [int]$entCount[$k] } }
        $topEnt = @($entCount.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 6 | ForEach-Object Key)
        $sevName = @('Info', 'Low', 'Medium', 'High', 'Critical')[$maxSev]
        [pscustomobject]@{
            Severity = $sevName; Start = (ConvertTo-WfxUtcString $t[$members[0]]); End = (ConvertTo-WfxUtcString $t[$members[-1]])
            Tactics = $tactics; Entities = $topEnt; Count = $members.Count
            Score = [Math]::Round(($members | ForEach-Object { [double]$fs[$_].Score } | Measure-Object -Sum).Sum, 1)
            Findings = @($members | ForEach-Object { [pscustomobject]@{ Id = $fs[$_].Id; Title = $fs[$_].Title; Severity = $fs[$_].Severity; Time = $fs[$_].Time; Entity = $fs[$_].Entity } })
            Links = @($why.Keys | Where-Object { $p = $_ -split '\|'; [int]$p[0] -in $members } | ForEach-Object { $why[$_] } | Select-Object -Unique)
        }
    }
    $i = 0
    , @($out | Sort-Object @{ e = { $sevRank[$_.Severity] }; Descending = $true }, @{ e = { $_.Score }; Descending = $true } | ForEach-Object { $i++; $_ | Add-Member -NotePropertyName Id -NotePropertyValue ('INC-{0:D2}' -f $i) -PassThru })
}
