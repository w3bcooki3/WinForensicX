# Event-log analyzer. Operates on normalized events:
#   { Log, Provider, Id, TimeCreated (UTC ISO), Computer, Fields = @{ TargetUserName=…; IpAddress=…; CommandLine=…; … } }
# Works identically on live logs and exported .evtx (the collector normalizes both). Rules are matched on
# BOTH event id and log name, so an unrelated provider's event 104 in Application.evtx is never "log cleared".

function Join-WfxScriptBlock {
    <# Re-assembles PowerShell 4104 script blocks that were split across several events (MessageNumber/
       MessageTotal sharing one ScriptBlockId) so detections see the whole script, not fragments. #>
    param([object[]]$Event)
    $out = [System.Collections.Generic.List[object]]::new()
    $groups = @{}
    foreach ($e in $Event) {
        $fl = Get-WfxValue $e 'Fields' @{}
        $sbid = [string](Get-WfxValue $fl 'ScriptBlockId' '')
        $tot = (ConvertTo-WfxInt (Get-WfxValue $fl 'MessageTotal' 1))
        if ((ConvertTo-WfxInt (Get-WfxValue $e 'Id' 0)) -eq 4104 -and $sbid -and $tot -gt 1) {
            if (-not $groups.ContainsKey($sbid)) { $groups[$sbid] = [System.Collections.Generic.List[object]]::new() }
            $groups[$sbid].Add($e)
        } else { $out.Add($e) }
    }
    foreach ($k in $groups.Keys) {
        $parts = @($groups[$k] | Sort-Object { (ConvertTo-WfxInt (Get-WfxValue (Get-WfxValue $_ 'Fields' @{}) 'MessageNumber' 0)) })
        $text = ($parts | ForEach-Object { [string](Get-WfxValue (Get-WfxValue $_ 'Fields' @{}) 'ScriptBlockText' '') }) -join ''
        $first = $parts[0]
        $fields = @{}
        foreach ($kv in (Get-WfxValue $first 'Fields' @{}).GetEnumerator()) { $fields[$kv.Key] = $kv.Value }
        $fields['ScriptBlockText'] = $text
        $fields['MessageParts'] = "$($parts.Count)/$((Get-WfxValue $fields 'MessageTotal' $parts.Count))"
        $out.Add([pscustomobject]@{ Log = (Get-WfxValue $first 'Log' ''); Provider = (Get-WfxValue $first 'Provider' ''); Id = 4104; TimeCreated = (Get-WfxValue $first 'TimeCreated'); Computer = (Get-WfxValue $first 'Computer' ''); Message = ''; Fields = $fields })
    }
    , $out.ToArray()
}

function Test-WfxRuleLog {
    <# True when the rule's "logs" list is empty or contains the event's log (short or full channel name). #>
    param($Rule, [string]$Log)
    $logs = @(Get-WfxValue $Rule 'logs' @() | Where-Object { $_ })
    if ($logs.Count -eq 0 -or -not $Log) { return $true }
    foreach ($l in $logs) { if ($Log -eq $l) { return $true } }
    return $false
}

function Get-WfxEventField {
    <# One field of a normalized event. 'A|B' returns the first of A, B that has a value ('-' counts as none). Log, Provider and Id are fields too. #>
    param($Event, [string[]]$Names)
    $fs = Get-WfxValue $Event 'Fields' @{}
    foreach ($n in $Names) {
        $v = switch ($n) { 'Log' { Get-WfxValue $Event 'Log' '' } 'Provider' { Get-WfxValue $Event 'Provider' '' } 'Id' { Get-WfxValue $Event 'Id' '' } default { Get-WfxValue $fs $n '' } }
        $s = [string]$v
        if ($s -ne '' -and $s -ne '-') { return $s }
    }
    return ''
}

function Test-WfxEventMatch {
    <# True when every "match" condition of a rule holds for the event and no "matchNot" condition does. #>
    param($Event, $Rule)
    foreach ($m in @($Rule.matchSet)) { if (-not (Test-WfxRegex $m.Rx (Get-WfxEventField $Event $m.Names))) { return $false } }
    foreach ($m in @($Rule.matchNotSet)) { if (Test-WfxRegex $m.Rx (Get-WfxEventField $Event $m.Names)) { return $false } }
    # "differ": [A, B] holds only when the two fields name different files (path and extension ignored), e.g. a renamed binary.
    $df = @(Get-WfxValue $Rule 'differ' @())
    if ($df.Count -eq 2) {
        $a = [IO.Path]::GetFileNameWithoutExtension(((Get-WfxEventField $Event ([string]$df[0] -split '\|')) -replace '.*[\\/]', ''))
        $b = [IO.Path]::GetFileNameWithoutExtension(((Get-WfxEventField $Event ([string]$df[1] -split '\|')) -replace '.*[\\/]', ''))
        if (-not $a -or -not $b -or $a -eq $b) { return $false }
    }
    return $true
}

function New-WfxEventRuleFinding {
    <# Finding for a field-matching event rule. "{Field}" in the title is replaced by the event's value. Evidence lists the rule's fields one by one. #>
    param($Event, $Rule, [string]$HostName)
    $id = ConvertTo-WfxInt (Get-WfxValue $Event 'Id' 0)
    $log = [string](Get-WfxValue $Event 'Log' '')
    $title = [regex]::Replace([string]$Rule.title, '\{([A-Za-z0-9_|]+)\}', {
            param($mm)
            $v = Get-WfxEventField $Event ($mm.Groups[1].Value -split '\|')
            if (-not $v) { return '(unknown)' }
            $v = ($v -replace '\s+', ' ').Trim()
            if ($v.Length -gt 90) { $v = $v.Substring(0, 87) + '...' }
            $v
        })
    $ev = [ordered]@{ EventId = $id; Log = $log; Time = (Get-WfxValue $Event 'TimeCreated') }
    foreach ($fname in @($Rule.fields)) {
        $v = Get-WfxEventField $Event ([string]$fname -split '\|')
        if ($v -eq '') { continue }
        if ($v.Length -gt 2000) { $v = $v.Substring(0, 2000) + ' ...' }
        $ev[(([string]$fname -split '\|')[0])] = Protect-WfxText $v
    }
    if (Get-WfxValue $Event 'Recovered' $false) { $ev['Recovered'] = 'yes (read from unused space in the log file)' }
    $keyFields = @(Get-WfxValue $Rule 'key' @())
    if (-not $keyFields.Count) { $keyFields = @(@($Rule.fields) | Select-Object -First 2) }
    $entity = "event:$($Rule.id):" + ((@($keyFields | ForEach-Object { (Get-WfxEventField $Event ([string]$_ -split '\|')).ToLowerInvariant() })) -join '|')
    New-WfxFinding -Id $Rule.id -Title $title -Severity $Rule.severity -Confidence $Rule.confidence `
        -Category 'EventLog' -Technique $Rule.technique -Description $Rule.description -Recommendation $Rule.recommendation `
        -Entity $entity -HostName $HostName -Time (Get-WfxValue $Event 'TimeCreated') -Source "evt:$log" -Evidence $ev
}

function Invoke-WfxEventAnalyzer {
    param([object[]]$Event, [string]$HostName = '')
    $findings = [System.Collections.Generic.List[object]]::new()
    $joined = Join-WfxScriptBlock -Event @($Event | Where-Object { $_ })
    $events = @($joined)
    if ($events.Count -eq 0) { return , $findings.ToArray() }
    $pack = Get-WfxRulePack -Name 'events'
    $byId = @{}
    foreach ($rule in $pack.rules) { foreach ($i in @($rule.eventIds)) { if (-not $byId.ContainsKey([int]$i)) { $byId[[int]$i] = [System.Collections.Generic.List[object]]::new() }; $byId[[int]$i].Add($rule) } }

    $f = { param($e, $k) [string](Get-WfxValue (Get-WfxValue $e 'Fields' @{}) $k '') }

    # ── Per-event rules (Sigma-lite) ──
    foreach ($e in $events) {
        $id = (ConvertTo-WfxInt (Get-WfxValue $e 'Id' 0))
        if (-not $byId.ContainsKey($id)) { continue }
        $log = [string](Get-WfxValue $e 'Log' '')
        foreach ($rule in $byId[$id]) {
            if ($rule.PSObject.Properties['perEvent'] -and -not $rule.perEvent) { continue }   # aggregate-only rule, handled below
            if (-not (Test-WfxRuleLog $rule $log)) { continue }
            $text = @($rule.fields | ForEach-Object { & $f $e $_ }) -join ' '
            if ($text.Trim() -eq '') { $text = [string](Get-WfxValue $e 'Message' '') }

            if ($rule.pattern -eq '__lotl__') {
                $img = (& $f $e 'NewProcessName'); if (-not $img) { $img = (& $f $e 'Image') }
                $cl = (& $f $e 'CommandLine'); if (-not $cl) { $cl = $text }
                foreach ($r in (Test-WfxCommandLine -CommandLine $cl -Image $img)) {
                    $findings.Add((New-WfxFinding -Id $r.id -Title "$($r.title) (event $id)" -Severity $r.severity -Confidence $r.confidence `
                                -Category 'EventLog' -Technique $r.technique -Description $r.description -Recommendation $r.recommendation `
                                -Entity "event:${id}:$($r.id):$((& $f $e 'ProcessId'), (& $f $e 'NewProcessId'), (& $f $e 'ScriptBlockId') -join '')" -HostName $HostName -Time (Get-WfxValue $e 'TimeCreated') -Source "evt:$log" `
                                -Evidence ([ordered]@{ EventId = $id; Time = (Get-WfxValue $e 'TimeCreated'); Image = $img; Command = (Protect-WfxText $(if ($cl.Length -gt 3000) { $cl.Substring(0, 3000) + ' …' } else { $cl })); Parent = ((& $f $e 'ParentProcessName') + (& $f $e 'ParentImage')); User = ((& $f $e 'SubjectUserName') + (& $f $e 'User')) })))
                }
                if ($id -eq 4104 -or $id -eq 4688 -or $id -eq 1) {
                    $decoded = Get-WfxEncodedCommandPayload $cl
                    if ($decoded) {
                        foreach ($r in (Test-WfxCommandLine -CommandLine $decoded -Image 'powershell.exe')) {
                            if ($r.id -eq 'LOTL-PS-ENCODED') { continue }
                            $findings.Add((New-WfxFinding -Id $r.id -Title "$($r.title) (inside encoded command, event $id)" -Severity $r.severity -Confidence $r.confidence `
                                        -Category 'EventLog' -Technique $r.technique -Description $r.description -Recommendation $r.recommendation `
                                        -Entity "event:${id}:$($r.id):decoded:$(Get-WfxValue $e 'TimeCreated')" -HostName $HostName -Time (Get-WfxValue $e 'TimeCreated') -Source "evt:$log" `
                                        -Evidence ([ordered]@{ EventId = $id; DecodedCommand = (Protect-WfxText $(if ($decoded.Length -gt 2000) { $decoded.Substring(0, 2000) } else { $decoded })) })))
                        }
                    }
                }
                continue
            }
            if (@($rule.matchSet).Count) {
                if (Test-WfxEventMatch $e $rule) { $findings.Add((New-WfxEventRuleFinding -Event $e -Rule $rule -HostName $HostName)) }
                continue
            }
            if ($rule.rx -and -not (Test-WfxRegex $rule.rx $text)) { continue }
            if ($rule.rxExclude -and (Test-WfxRegex $rule.rxExclude $text)) { continue }
            $firstField = if (@($rule.fields).Count) { & $f $e (@($rule.fields)[0]) } else { '' }
            $findings.Add((New-WfxFinding -Id $rule.id -Title $rule.title -Severity $rule.severity -Confidence $rule.confidence `
                        -Category 'EventLog' -Technique $rule.technique -Description $rule.description -Recommendation $rule.recommendation `
                        -Entity "event:$($rule.id):$firstField" -HostName $HostName -Time (Get-WfxValue $e 'TimeCreated') -Source "evt:$log" `
                        -Evidence ([ordered]@{ EventId = $id; Log = $log; Time = (Get-WfxValue $e 'TimeCreated'); Details = (Protect-WfxText $(if ($text.Length -gt 3000) { $text.Substring(0, 3000) + ' …' } else { $text })) })))
        }
    }

    # ── Aggregate rules: failed-logon bursts and spraying (4625) ──
    $fails = @($events | Where-Object { (ConvertTo-WfxInt (Get-WfxValue $_ 'Id' 0)) -eq 4625 })
    if ($fails.Count -ge 10) {
        $bySource = $fails | Group-Object { & $f $_ 'IpAddress' }
        foreach ($g in $bySource) {
            $users = @($g.Group | ForEach-Object { & $f $_ 'TargetUserName' } | Where-Object { $_ } | Sort-Object -Unique)
            $src = if ($g.Name -and $g.Name -ne '-') { $g.Name } else { '(local / unknown source)' }
            $times = @($g.Group | ForEach-Object { ConvertTo-WfxDateTime (Get-WfxValue $_ 'TimeCreated') } | Where-Object { $_ } | Sort-Object)
            $span = if ($times.Count -ge 2) { "$(ConvertTo-WfxUtcString $times[0]) → $(ConvertTo-WfxUtcString $times[-1])" } else { '' }
            if ($g.Count -ge 10 -and $users.Count -ge 5) {
                $findings.Add((New-WfxFinding -Id 'EVT-4625-SPRAY' -Title "Password spraying from $src ($($users.Count) accounts, $($g.Count) failures)" `
                            -Severity 'High' -Confidence 'Medium' -Category 'EventLog' -Technique @('T1110.003') `
                            -Description "Many failed logons for many different accounts from one source — the signature of password spraying." `
                            -Recommendation "Block the source, confirm no logon succeeded, and enforce lockout + MFA." `
                            -Entity "spray:$src" -HostName $HostName -Time $(if ($times.Count) { $times[0] } else { $null }) -Source 'evt:Security' `
                            -Evidence ([ordered]@{ Source = $src; Accounts = $users.Count; Failures = $g.Count; Window = $span; Sample = ($users | Select-Object -First 8) })))
            } elseif ($g.Count -ge 20 -and $users.Count -le 2) {
                $findings.Add((New-WfxFinding -Id 'EVT-4625-BRUTE' -Title "Brute force on $($users -join ',') from $src ($($g.Count) failures)" `
                            -Severity 'High' -Confidence 'Medium' -Category 'EventLog' -Technique @('T1110') `
                            -Description "Many failed logons for one or two accounts from one source — a password-guessing attack." `
                            -Recommendation "Block the source and confirm whether a success (4624) followed." `
                            -Entity "brute:$src" -HostName $HostName -Time $(if ($times.Count) { $times[0] } else { $null }) -Source 'evt:Security' `
                            -Evidence ([ordered]@{ Source = $src; Accounts = $users; Failures = $g.Count; Window = $span })))
            }
        }
    }

    # ── Correlation: repeated failures (in the 24 h BEFORE) then a success, same user + source. O(n) via index. ──
    $failIdx = @{}
    $failBySrc = @{}
    foreach ($x in $fails) {
        $k = "$((& $f $x 'TargetUserName').ToLowerInvariant())|$(& $f $x 'IpAddress')"
        $t = ConvertTo-WfxDateTime (Get-WfxValue $x 'TimeCreated')
        if (-not $t) { continue }
        if (-not $failIdx.ContainsKey($k)) { $failIdx[$k] = New-Object System.Collections.Generic.List[datetime] }
        $failIdx[$k].Add($t)
        $fsrc = & $f $x 'IpAddress'
        if ($fsrc -and $fsrc -ne '-') {
            if (-not $failBySrc.ContainsKey($fsrc)) { $failBySrc[$fsrc] = [System.Collections.Generic.List[object]]::new() }
            $failBySrc[$fsrc].Add([pscustomobject]@{ T = $t; U = (& $f $x 'TargetUserName').ToLowerInvariant() })
        }
    }
    $successes = @($events | Where-Object { (ConvertTo-WfxInt (Get-WfxValue $_ 'Id' 0)) -eq 4624 -and (& $f $_ 'LogonType') -in @('2', '3', '7', '10', '11') })
    $reported = @{}
    foreach ($s in $successes) {
        $src = & $f $s 'IpAddress'; $user = & $f $s 'TargetUserName'; $lt = & $f $s 'LogonType'
        $st = ConvertTo-WfxDateTime (Get-WfxValue $s 'TimeCreated')
        $srcIp = $null
        $isIp = $src -and [System.Net.IPAddress]::TryParse($src.Trim('[', ']'), [ref]$srcIp)   # '-' and host names are not addresses
        if ($isIp -and -not (Test-WfxPrivateIp $src) -and $lt -in @('10', '7')) {
            $findings.Add((New-WfxFinding -Id 'EVT-RDP-EXTERNAL' -Title "Remote logon for $user from external address $src" `
                        -Severity 'Medium' -Confidence 'Medium' -Category 'EventLog' -Technique @('T1021.001', 'T1133') `
                        -Description "An interactive/remote-desktop logon succeeded from a public IP. Internet-facing RDP is a frequent intrusion vector." `
                        -Recommendation "Confirm the source is expected; restrict RDP behind VPN/MFA." `
                        -Entity "rdp:${src}:$user" -HostName $HostName -Time $st -Source 'evt:Security' `
                        -Evidence ([ordered]@{ User = $user; Source = $src; LogonType = $lt; Time = (Get-WfxValue $s 'TimeCreated') })))
        }
        if (-not $user -or -not $st) { continue }
        $k = "$($user.ToLowerInvariant())|$src"
        # A password spray rarely fails against the account that finally works: also correlate by source address.
        if ((-not $failIdx.ContainsKey($k)) -and $isIp -and $failBySrc.ContainsKey($src) -and -not $reported.ContainsKey("src|$src")) {
            $priorSrc = @($failBySrc[$src] | Where-Object { $_.T -lt $st -and $_.T -ge $st.AddHours(-24) })
            $usersTried = @($priorSrc | ForEach-Object { $_.U } | Sort-Object -Unique)
            if ($priorSrc.Count -ge 8) {
                $reported["src|$src"] = $true
                $findings.Add((New-WfxFinding -Id 'EVT-4625-THEN-4624' -Title "Successful logon for $user from $src after $($priorSrc.Count) failed logons from that source ($($usersTried.Count) accounts tried, previous 24 h)" `
                            -Severity 'High' -Confidence 'High' -Category 'EventLog' -Technique @('T1110', 'T1110.003') `
                            -Description 'A source that was failing to log on with many attempts (password guessing or spraying) then logged on successfully. The account that succeeded is likely compromised.' `
                            -Recommendation 'Reset the account''s password, review what it did after the logon, and block the source.' `
                            -Entity "bruteok:${src}:$user" -HostName $HostName -Time $st -Source 'evt:Security' `
                            -Evidence ([ordered]@{ User = $user; Source = $src; LogonType = $lt; Failures = $priorSrc.Count; AccountsTried = $usersTried.Count; Time = (Get-WfxValue $s 'TimeCreated') })))
            }
            continue
        }
        if (-not $failIdx.ContainsKey($k) -or $reported.ContainsKey($k)) { continue }
        $prior = @($failIdx[$k] | Where-Object { $_ -lt $st -and $_ -ge $st.AddHours(-24) })
        if ($prior.Count -ge 8) {
            $reported[$k] = $true
            $findings.Add((New-WfxFinding -Id 'EVT-4625-THEN-4624' -Title "Successful logon for $user after $($prior.Count) failures (same source, previous 24 h)" `
                        -Severity 'High' -Confidence 'High' -Category 'EventLog' -Technique @('T1110') `
                        -Description "An account failed to log on repeatedly, then succeeded, from the same source — consistent with a guessed or sprayed password." `
                        -Recommendation "Reset the password, review the session's activity, and investigate the source host." `
                        -Entity "cracked:${src}:$user" -HostName $HostName -Time $st -Source 'evt:Security' `
                        -Evidence ([ordered]@{ User = $user; Source = $src; PriorFailures = $prior.Count; FirstFailure = (ConvertTo-WfxUtcString ($prior | Sort-Object | Select-Object -First 1)); SuccessTime = (ConvertTo-WfxUtcString $st) })))
        }
    }
    return , (Merge-WfxFinding -Finding $findings.ToArray())
}
