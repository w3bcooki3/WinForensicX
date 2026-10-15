# Network and DNS analyzers. Pure functions over normalized data.
#   Connection: Protocol, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, Pid, Process
#   DnsEntry:   Name, Type, Data, (optional) Count
#   Beacon samples: { Remote, Times[] } (connection timestamps to one destination)

function Invoke-WfxNetworkAnalyzer {
    param([object[]]$Connection, [string]$HostName = '')
    $findings = New-Object System.Collections.Generic.List[object]
    $conns = @($Connection | Where-Object { $_ })
    if ($conns.Count -eq 0) { return , $findings.ToArray() }

    $dns = Get-WfxRulePack -Name 'dns'
    $ai = Get-WfxRulePack -Name 'ai'
    $tunnelHosts = @($dns.tunnelDomains)
    $aiPorts = @($ai.runtimePorts)

    # Listeners on all interfaces (0.0.0.0 / ::) for non-standard ports.
    $commonListen = @(80, 443, 135, 139, 445, 3389, 5985, 5986, 53, 88, 389, 636, 464, 3268, 3269, 25, 110, 143, 993, 995, 1433, 3306, 5432, 22)
    foreach ($c in $conns) {
        $state = [string](Get-WfxValue $c 'State' '')
        $laddr = [string](Get-WfxValue $c 'LocalAddress' '')
        $lport = [int](Get-WfxValue $c 'LocalPort' 0)
        $proc = [string](Get-WfxValue $c 'Process' '')
        $pid2 = Get-WfxValue $c 'Pid' '?'
        if ($state -match 'Listen' -and ($laddr -eq '0.0.0.0' -or $laddr -eq '::' -or $laddr -eq '[::]' -or $laddr -eq '*')) {
            if ($commonListen -notcontains $lport) {
                $isAi = $aiPorts -contains $lport
                $findings.Add((New-WfxFinding -Id ($(if ($isAi) { 'AI-OLLAMA-EXPOSED' } else { 'NET-LISTENER-EXPOSED' })) `
                            -Title ($(if ($isAi) { "Local AI runtime API exposed on all interfaces (port $lport)" } else { "Process listening on all interfaces on non-standard port $lport" })) `
                            -Severity 'Medium' -Confidence ($(if ($isAi) { 'Medium' } else { 'Low' })) -Category 'Network' `
                            -Technique @('T1133') `
                            -Description ($(if ($isAi) { "A local AI model runtime is listening on 0.0.0.0:$lport. Its API is usually unauthenticated, so anyone who can reach the port can use the model and run it at this host's expense." } else { "A process is listening for connections from any network on an unusual port. Confirm it is an expected service and not a backdoor or exposed dev server." })) `
                            -Recommendation ($(if ($isAi) { "Bind the runtime to 127.0.0.1 and restrict the port with the firewall." } else { "Identify the process and confirm the service is intended to be network-reachable." })) `
                            -Entity "listen:${laddr}:$lport" -HostName $HostName -Source 'network' `
                            -Evidence ([ordered]@{ Pid = $pid2; Process = $proc; Local = "${laddr}:$lport"; Protocol = (Get-WfxValue $c 'Protocol' 'TCP') })))
            }
        }

        # Established connections to public addresses on suspicious / tunneling ports or hosts.
        $raddr = [string](Get-WfxValue $c 'RemoteAddress' '')
        $rport = [int](Get-WfxValue $c 'RemotePort' 0)
        if ($state -match 'Establish' -and $raddr -and -not (Test-WfxPrivateIp $raddr)) {
            $rhost = [string](Get-WfxValue $c 'RemoteHost' '')
            $tun = $tunnelHosts | Where-Object { $rhost -and $rhost.ToLowerInvariant().EndsWith($_) }
            if ($tun) {
                $findings.Add((New-WfxFinding -Id 'NET-TUNNEL-SERVICE' -Title "Connection to a tunneling service ($tun)" `
                            -Severity 'High' -Confidence 'Medium' -Category 'Network' -Technique @('T1572', 'T1090') `
                            -Description "A connection to an ad-hoc tunneling service was found. $($dns.tunnelNote)" `
                            -Recommendation "Identify the process and what it exposes; block the service if unauthorized." `
                            -Entity "conn:${raddr}:$rport" -HostName $HostName -Source 'network' `
                            -Evidence ([ordered]@{ Pid = $pid2; Process = $proc; Remote = "$rhost ($raddr):$rport" })))
            }
            if ($rport -in @(4444, 5555, 1337, 31337, 8081, 6666, 6667, 9001, 9002, 1234, 12345, 50050)) {
                $findings.Add((New-WfxFinding -Id 'NET-SUSPICIOUS-PORT' -Title "Connection to a commonly malicious port ($rport)" `
                            -Severity 'Medium' -Confidence 'Low' -Category 'Network' -Technique @('T1571', 'T1071') `
                            -Description "An outbound connection targets a port frequently used by C2 frameworks and reverse shells (e.g. Metasploit 4444, Cobalt Strike 50050)." `
                            -Recommendation "Identify the process and destination reputation; this is suggestive, not conclusive." `
                            -Entity "conn:${raddr}:$rport" -HostName $HostName -Source 'network' `
                            -Evidence ([ordered]@{ Pid = $pid2; Process = $proc; Remote = "${raddr}:$rport" })))
            }
            # A non-browser process talking to an AI provider API (billable key use / possible agent exfil path).
            $rhostL = $rhost.ToLowerInvariant()
            if ($rhost -and ($ai.apiDomains | Where-Object { $rhostL -like "*$_*" })) {
                $leaf = (Get-WfxLeaf $proc).ToLowerInvariant()
                if ($leaf -and $leaf -notin @('chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe')) {
                    $findings.Add((New-WfxFinding -Id 'AI-API-NONBROWSER' -Title "Non-browser process contacting an AI provider API: $leaf" `
                                -Severity 'Info' -Confidence 'Low' -Category 'AI' -Technique @() `
                                -Description "A process other than a web browser is talking to an AI provider's API. Usually benign (a CLI or app), but worth noting when an API key or data exposure is in scope." `
                                -Recommendation "Confirm the tool and that it uses an authorized API key." `
                                -Entity "conn:${leaf}:$rhostL" -HostName $HostName -Source 'network' `
                                -Evidence ([ordered]@{ Pid = $pid2; Process = $leaf; Remote = $rhost })))
                }
            }
        }
    }
    return , (Merge-WfxFinding -Finding $findings.ToArray())
}

function Invoke-WfxDnsAnalyzer {
    param([object[]]$DnsEntry, [string]$HostName = '')
    $findings = New-Object System.Collections.Generic.List[object]
    $entries = @($DnsEntry | Where-Object { $_ })
    if ($entries.Count -eq 0) { return , $findings.ToArray() }
    $dns = Get-WfxRulePack -Name 'dns'

    foreach ($e in $entries) {
        $fqdn = ([string](Get-WfxValue $e 'Name' '')).Trim('.').ToLowerInvariant()
        if (-not $fqdn -or $fqdn -notmatch '\.') { continue }
        $labels = $fqdn -split '\.'
        $tld = '.' + $labels[-1]
        $reg = if ($labels.Count -ge 2) { $labels[-2] } else { $labels[-1] }

        if ($dns.suspiciousTlds -contains $tld) {
            $findings.Add((New-WfxFinding -Id 'DNS-SUSPICIOUS-TLD' -Title "Lookup of a high-risk TLD domain: $fqdn" `
                        -Severity 'Low' -Confidence 'Low' -Category 'DNS' -Technique @('T1071.004') `
                        -Description "The domain uses a top-level domain disproportionately associated with malware and abuse ($tld)." `
                        -Recommendation "Check the domain's reputation and which process resolved it." `
                        -Entity "dns:$fqdn" -HostName $HostName -Source 'dns' -Evidence ([ordered]@{ Name = $fqdn; TLD = $tld })))
        }
        if ($dns.tunnelDomains | Where-Object { $fqdn.EndsWith($_) }) {
            $findings.Add((New-WfxFinding -Id 'DNS-TUNNEL-SERVICE' -Title "Lookup of a tunneling service: $fqdn" `
                        -Severity 'Medium' -Confidence 'Medium' -Category 'DNS' -Technique @('T1572') `
                        -Description "A tunneling/relay service domain was resolved. $($dns.tunnelNote)" `
                        -Recommendation "Identify the process and whether a tunnel was established." `
                        -Entity "dns:$fqdn" -HostName $HostName -Source 'dns' -Evidence ([ordered]@{ Name = $fqdn })))
        }
        if ($dns.pasteSites | Where-Object { $fqdn -eq $_ -or $fqdn.EndsWith('.' + $_) }) {
            $findings.Add((New-WfxFinding -Id 'DNS-PASTE-SITE' -Title "Lookup of a paste / anonymous-file site: $fqdn" `
                        -Severity 'Low' -Confidence 'Low' -Category 'DNS' -Technique @('T1105', 'T1567') `
                        -Description "A text-paste or anonymous file-sharing site was resolved. $($dns.pasteNote)" `
                        -Recommendation "Check which process accessed it and whether a payload was fetched or data uploaded." `
                        -Entity "dns:$fqdn" -HostName $HostName -Source 'dns' -Evidence ([ordered]@{ Name = $fqdn })))
        }
        # DGA-like: long, high-entropy registrable label, few vowels.
        $entropy = Get-WfxEntropy $reg
        $vowels = ([regex]::Matches($reg, '[aeiou]')).Count
        $digits = ([regex]::Matches($reg, '\d')).Count
        if ($reg.Length -ge 12 -and $entropy -ge 3.6 -and ($vowels / [double]$reg.Length) -lt 0.28 -and $reg -notmatch '^(?:xn--|www\d*$)') {
            $findings.Add((New-WfxFinding -Id 'DNS-DGA-LIKE' -Title "High-entropy domain (possible DGA): $fqdn" `
                        -Severity 'Medium' -Confidence 'Low' -Category 'DNS' -Technique @('T1568.002', 'T1071.004') `
                        -Description "The domain's name looks algorithmically generated (long, random-looking, few vowels). Malware families use domain-generation algorithms for C2 that is hard to block by name." `
                        -Recommendation "Check reputation and resolution history; correlate with connections from the resolving process." `
                        -Entity "dns:$fqdn" -HostName $HostName -Source 'dns' `
                        -Evidence ([ordered]@{ Name = $fqdn; Entropy = $entropy; Length = $reg.Length; Digits = $digits })))
        }
    }
    return , (Merge-WfxFinding -Finding $findings.ToArray())
}

function Invoke-WfxBeaconAnalyzer {
    <#
    .SYNOPSIS Flags regular, low-jitter connections to one destination (C2 beaconing).
    .PARAMETER Beacon  Objects with Remote (string) and Times (datetime[] of connection events).
    #>
    param([object[]]$Beacon, [string]$HostName = '')
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($b in @($Beacon | Where-Object { $_ })) {
        $times = @(Get-WfxValue $b 'Times' @() | ForEach-Object { [datetime]$_ } | Sort-Object)
        if ($times.Count -lt 6) { continue }
        $deltas = for ($i = 1; $i -lt $times.Count; $i++) { ($times[$i] - $times[$i - 1]).TotalSeconds }
        $deltas = @($deltas | Where-Object { $_ -gt 0 })
        if ($deltas.Count -lt 5) { continue }
        $mean = ($deltas | Measure-Object -Average).Average
        if ($mean -lt 1) { continue }
        $var = ($deltas | ForEach-Object { ($_ - $mean) * ($_ - $mean) } | Measure-Object -Average).Average
        $cv = [Math]::Sqrt($var) / $mean      # coefficient of variation: low = very regular
        if ($cv -le 0.18) {
            $sev = if ($mean -ge 30 -and $mean -le 3600) { 'High' } else { 'Medium' }
            $findings.Add((New-WfxFinding -Id 'NET-BEACON' -Title ("Regular beaconing to $([string](Get-WfxValue $b 'Remote' '?')) (~{0:N0}s)" -f $mean) `
                        -Severity $sev -Confidence 'Medium' -Category 'Network' -Technique @('T1071.001', 'T1573') `
                        -Description "Connections to this destination arrive at a near-constant interval with very little variation ($($deltas.Count + 1) connections, jitter $([Math]::Round($cv*100))%). Regular, low-jitter check-ins are a hallmark of C2 beaconing." `
                        -Recommendation "Identify the process and destination; check the destination's reputation. Legitimate software also polls on a schedule, so confirm before acting." `
                        -Entity "beacon:$([string](Get-WfxValue $b 'Remote' '?'))" -HostName $HostName -Source 'network' `
                        -Evidence ([ordered]@{ Remote = (Get-WfxValue $b 'Remote'); Connections = $times.Count; MeanSeconds = [Math]::Round($mean, 1); JitterPct = [Math]::Round($cv * 100, 1) })))
        }
    }
    return , (Merge-WfxFinding -Finding $findings.ToArray())
}
