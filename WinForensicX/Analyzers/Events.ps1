# Event-log analyzer. Operates on normalized events:
#   { Log, Id, TimeCreated, Computer, Fields = @{ TargetUserName=…; IpAddress=…; NewProcessName=…; CommandLine=…; … } }
# Works identically on live logs and .evtx ingested from an image (collector normalizes both).

function Invoke-WfxEventAnalyzer {
    param([object[]]$Event, [string]$HostName = '')
    $findings = New-Object System.Collections.Generic.List[object]
    $events = @($Event | Where-Object { $_ })
    if ($events.Count -eq 0) { return , $findings.ToArray() }
    $pack = Get-WfxRulePack -Name 'events'

    $f = { param($e, $k) Get-WfxValue (Get-WfxValue $e 'Fields' @{}) $k '' }

    # ── Per-event rules (Sigma-lite) ──
    foreach ($e in $events) {
        $id = [int](Get-WfxValue $e 'Id' 0)
        foreach ($rule in $pack.rules) {
            if (@($rule.eventIds) -notcontains $id) { continue }
            if ($rule.PSObject.Properties['perEvent'] -and -not $rule.perEvent) { continue }   # aggregate-only rule, handled below
            $text = @($rule.fields | ForEach-Object { [string](& $f $e $_) }) -join ' '
            if ($text.Trim() -eq '' -and $rule.fields) { $text = [string](Get-WfxValue $e 'Message' '') }

            if ($rule.pattern -eq '__lotl__') {
                foreach ($r in (Test-WfxCommandLine -CommandLine $text)) {
                    $findings.Add((New-WfxFinding -Id $r.id -Title "$($r.title) (event $id)" -Severity $r.severity -Confidence $r.confidence `
                                -Category 'EventLog' -Technique $r.technique -Description $r.description -Recommendation $r.recommendation `
                                -Entity "event:${id}:$([string](& $f $e 'NewProcessName'))" -HostName $HostName -Time (Get-WfxValue $e 'TimeCreated') -Source "evt:$($e.Log)" `
                                -Evidence ([ordered]@{ EventId = $id; Command = (Protect-WfxText $text); Parent = (& $f $e 'ParentProcessName') })))
                }
                continue
            }
            if ($rule.pattern) {
                $rx = New-WfxRegex $rule.pattern
                if (-not (Test-WfxRegex $rx $text)) { continue }
            }
            $findings.Add((New-WfxFinding -Id $rule.id -Title $rule.title -Severity $rule.severity -Confidence $rule.confidence `
                        -Category 'EventLog' -Technique $rule.technique -Description $rule.description -Recommendation $rule.recommendation `
                        -Entity "event:$($rule.id):$([string](& $f $e ($rule.fields[0])))" -HostName $HostName -Time (Get-WfxValue $e 'TimeCreated') -Source "evt:$($e.Log)" `
                        -Evidence ([ordered]@{ EventId = $id; Time = (Get-WfxValue $e 'TimeCreated'); Details = (Protect-WfxText $text) })))
        }
    }

    # ── Aggregate rules: failed-logon bursts and spraying (4625) ──
    $fails = @($events | Where-Object { [int](Get-WfxValue $_ 'Id' 0) -eq 4625 })
    if ($fails.Count -ge 10) {
        $bySource = $fails | Group-Object { [string](& $f $_ 'IpAddress') }
        foreach ($g in $bySource) {
            $users = @($g.Group | ForEach-Object { [string](& $f $_ 'TargetUserName') } | Where-Object { $_ } | Sort-Object -Unique)
            $src = if ($g.Name) { $g.Name } else { '(unknown source)' }
            if ($g.Count -ge 10 -and $users.Count -ge 5) {
                $findings.Add((New-WfxFinding -Id 'EVT-4625-SPRAY' -Title "Password spraying from $src ($($users.Count) accounts, $($g.Count) failures)" `
                            -Severity 'High' -Confidence 'Medium' -Category 'EventLog' -Technique @('T1110.003') `
                            -Description "Many failed logons for many different accounts from one source — the signature of password spraying." `
                            -Recommendation "Block the source, confirm no logon succeeded, and enforce lockout + MFA." `
                            -Entity "spray:$src" -HostName $HostName -Source 'evt:Security' `
                            -Evidence ([ordered]@{ Source = $src; Accounts = $users.Count; Failures = $g.Count; Sample = ($users | Select-Object -First 8) })))
            } elseif ($g.Count -ge 20 -and $users.Count -le 2) {
                $findings.Add((New-WfxFinding -Id 'EVT-4625-BRUTE' -Title "Brute force on $($users -join ',') from $src ($($g.Count) failures)" `
                            -Severity 'High' -Confidence 'Medium' -Category 'EventLog' -Technique @('T1110') `
                            -Description "Many failed logons for one or two accounts from one source — a password-guessing attack." `
                            -Recommendation "Block the source and confirm whether a success (4624) followed." `
                            -Entity "brute:$src" -HostName $HostName -Source 'evt:Security' `
                            -Evidence ([ordered]@{ Source = $src; Accounts = $users; Failures = $g.Count })))
            }
        }
    }

    # ── Correlation: repeated failures then a success from the same source ──
    $successes = @($events | Where-Object { [int](Get-WfxValue $_ 'Id' 0) -eq 4624 -and [string](& $f $_ 'LogonType') -in @('2', '3', '7', '10', '11') })
    foreach ($s in $successes) {
        $src = [string](& $f $s 'IpAddress'); $user = [string](& $f $s 'TargetUserName')
        if (-not $src -or (Test-WfxPrivateIp $src) -eq $false) {
            if ($src -and -not (Test-WfxPrivateIp $src) -and [string](& $f $s 'LogonType') -in @('10', '7')) {
                $findings.Add((New-WfxFinding -Id 'EVT-RDP-EXTERNAL' -Title "Remote logon for $user from external address $src" `
                            -Severity 'Medium' -Confidence 'Medium' -Category 'EventLog' -Technique @('T1021.001', 'T1133') `
                            -Description "An interactive/remote-desktop logon succeeded from a public IP. Internet-facing RDP is a frequent intrusion vector." `
                            -Recommendation "Confirm the source is expected; restrict RDP behind VPN/MFA." `
                            -Entity "rdp:${src}:$user" -HostName $HostName -Time (Get-WfxValue $s 'TimeCreated') -Source 'evt:Security' `
                            -Evidence ([ordered]@{ User = $user; Source = $src; LogonType = (& $f $s 'LogonType'); Time = (Get-WfxValue $s 'TimeCreated') })))
            }
        }
        $priorFails = @($fails | Where-Object { [string](& $f $_ 'TargetUserName') -eq $user -and [string](& $f $_ 'IpAddress') -eq $src })
        if ($user -and $priorFails.Count -ge 8) {
            $findings.Add((New-WfxFinding -Id 'EVT-4625-THEN-4624' -Title "Successful logon for $user after $($priorFails.Count) failures (same source)" `
                        -Severity 'High' -Confidence 'High' -Category 'EventLog' -Technique @('T1110') `
                        -Description "An account failed to log on repeatedly, then succeeded, from the same source — consistent with a guessed or sprayed password." `
                        -Recommendation "Reset the password, review the session's activity, and investigate the source host." `
                        -Entity "cracked:${src}:$user" -HostName $HostName -Time (Get-WfxValue $s 'TimeCreated') -Source 'evt:Security' `
                        -Evidence ([ordered]@{ User = $user; Source = $src; PriorFailures = $priorFails.Count; SuccessTime = (Get-WfxValue $s 'TimeCreated') })))
        }
    }
    return , (Merge-WfxFinding -Finding $findings.ToArray())
}
