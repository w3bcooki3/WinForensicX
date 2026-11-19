# Process analyzer: turns a normalized process list into findings. Pure function — no WMI,
# no platform calls — so it runs and is tested anywhere. Each process object is expected to have:
#   Pid, Ppid, Name, Path, CommandLine, User, ParentName, ParentPath, SignatureStatus, Company, CreateTime.

# Legit parents for sensitive system processes (lowercased leaf names).
$script:WfxExpectedParents = @{
    'lsass.exe'    = @('wininit.exe')
    'services.exe' = @('wininit.exe')
    'wininit.exe'  = @('smss.exe', '')
    'csrss.exe'    = @('smss.exe', '')
    'smss.exe'     = @('smss.exe', 'system', '')
    'winlogon.exe' = @('smss.exe', '')
    'lsaiso.exe'   = @('wininit.exe')
    'spoolsv.exe'  = @('services.exe')
    'taskhostw.exe' = @('services.exe', 'svchost.exe')
}
# Processes that should only ever run from System32/SysWOW64.
$script:WfxSystem32Only = @('svchost.exe', 'lsass.exe', 'services.exe', 'wininit.exe', 'csrss.exe',
    'smss.exe', 'winlogon.exe', 'spoolsv.exe', 'conhost.exe', 'dllhost.exe', 'taskhostw.exe',
    'runtimebroker.exe', 'searchindexer.exe', 'sihost.exe', 'fontdrvhost.exe', 'lsaiso.exe')
# Office / browser / mail processes that should not normally spawn script interpreters.
$script:WfxOfficeParents = @('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'onenote.exe',
    'mspub.exe', 'msaccess.exe', 'visio.exe', 'wordpad.exe', 'acrord32.exe', 'acrobat.exe')
$script:WfxBrowserParents = @('chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe', 'iexplore.exe')
$script:WfxScriptChildren = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'mshta.exe', 'wscript.exe',
    'cscript.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'curl.exe',
    'msbuild.exe', 'installutil.exe', 'schtasks.exe')

function Invoke-WfxProcessAnalyzer {
    param([object[]]$Process, [string]$HostName = '')
    $findings = [System.Collections.Generic.List[object]]::new()
    $procs = @($Process | Where-Object { $_ })
    if ($procs.Count -eq 0) { return , $findings.ToArray() }

    $threats = Get-WfxRulePack -Name 'threats'
    $ai = Get-WfxRulePack -Name 'ai'
    $offensive = @($threats.offensiveProcesses | ForEach-Object { $_.ToLowerInvariant() })
    $rmm = @($threats.rmmProcesses | ForEach-Object { $_.ToLowerInvariant() })
    $aiRuntime = @($ai.runtimeProcesses | ForEach-Object { $_.ToLowerInvariant() })
    $aiAssist = @($ai.assistantProcesses | ForEach-Object { $_.ToLowerInvariant() })
    # Assistants installed as npm / pip packages run as node.exe or python.exe: recognise them by package path.
    $aiAssistCmd = @($ai.assistantCommandHints | ForEach-Object { ([string]$_).ToLowerInvariant() } | Where-Object { $_ })
    $agentHints = @($ai.agentHints | ForEach-Object { ([string]$_).ToLowerInvariant() } | Where-Object { $_ })
    $byPid = @{}
    foreach ($p in $procs) { if ($null -ne $p.Pid) { $byPid[[string]$p.Pid] = $p } }

    foreach ($p in $procs) {
        $name = (Get-WfxLeaf (Get-WfxValue $p 'Name' '')).ToLowerInvariant()
        if (-not $name) { $name = (Get-WfxLeaf (Get-WfxValue $p 'Path' '')).ToLowerInvariant() }
        $path = [string](Get-WfxValue $p 'Path' '')
        $cmd = [string](Get-WfxValue $p 'CommandLine' '')
        $parent = (Get-WfxLeaf (Get-WfxValue $p 'ParentName' '')).ToLowerInvariant()
        # PID reuse guard: if the recorded "parent" started AFTER this process, the real parent has exited and
        # its PID was recycled — the name is unrelated and must not drive parent-based detections.
        $ct = ConvertTo-WfxDateTime (Get-WfxValue $p 'CreateTime')
        $pct = ConvertTo-WfxDateTime (Get-WfxValue $p 'ParentCreateTime')
        if ($ct -and $pct -and $pct -gt $ct) { $parent = '' }
        $entity = "process:$(Get-WfxValue $p 'Pid' '?'):$name"
        $sig = [string](Get-WfxValue $p 'SignatureStatus' '')
        $pcmd = [string](Get-WfxValue $p 'ParentCommandLine' '')

        # 1. Command-line rules (the big one — LotL, proxy exec, cred access, recovery inhibition…)
        foreach ($r in (Test-WfxCommandLine -CommandLine $cmd -Image $path)) {
            $findings.Add((New-WfxFinding -Id $r.id -Title $r.title -Severity $r.severity -Confidence $r.confidence `
                        -Category 'Process' -Technique $r.technique -Description $r.description -Recommendation $r.recommendation `
                        -Entity $entity -HostName $HostName -Time (Get-WfxValue $p 'CreateTime') -Source 'process' `
                        -Evidence ([ordered]@{ Pid = $p.Pid; Process = $name; Parent = $parent; CommandLine = (Protect-WfxText $cmd); Path = $path })))
        }

        # 1b. Encoded PowerShell: decode (text only — never executed) and run the rules over the decoded script.
        $isPs = $name -in @('powershell.exe', 'pwsh.exe', 'powershell_ise.exe')
        $canonCmd = ConvertTo-WfxCanonicalCommand $cmd
        if ($isPs -or $canonCmd -match '(?i)\bp(?:ower)?sh' -or $canonCmd -match '(?i)(?:^|\s)-(?:e|ec|en|enc|encodedcommand)\s+["'']?[A-Za-z0-9+/]{20,}') {
            $decoded = Get-WfxEncodedCommandPayload $canonCmd
            if ($decoded -and -not $isPs -and $canonCmd -notmatch '(?i)\bp(?:ower)?sh(?:ell)?(?:_ise)?(?:\.exe)?\b' -and $decoded -match '(?i)[a-z]+-[a-z]+|\biex\b|\$[a-z_]') {
                # A PowerShell payload handed to a program that is not called PowerShell: a copied/renamed interpreter.
                $findings.Add((New-WfxFinding -Id 'PROC-RENAMED-INTERPRETER' -Title "Encoded PowerShell run by a program named $name (renamed PowerShell?)" `
                            -Severity 'High' -Confidence 'Medium' -Category 'Process' -Technique @('T1036.003', 'T1059.001') `
                            -Description 'The process received a Base64 -EncodedCommand that decodes to PowerShell, but its executable is not named PowerShell. Attackers copy powershell.exe under another name to slip past name-based rules.' `
                            -Recommendation 'Hash the executable and compare with System32\WindowsPowerShell\v1.0\powershell.exe; read the decoded script.' `
                            -Entity "$entity`:renamed" -HostName $HostName -Time (Get-WfxValue $p 'CreateTime') -Source 'process' `
                            -Evidence ([ordered]@{ Pid = $p.Pid; Process = $name; Path = $path; DecodedCommand = (Protect-WfxText $(if ($decoded.Length -gt 600) { $decoded.Substring(0, 600) + ' …' } else { $decoded })) })))
            }
            if ($decoded) {
                $dshort = Protect-WfxText $(if ($decoded.Length -gt 2000) { $decoded.Substring(0, 2000) + ' …[truncated]' } else { $decoded })
                foreach ($r in (Test-WfxCommandLine -CommandLine $decoded -Image 'powershell.exe')) {
                    if ($r.id -eq 'LOTL-PS-ENCODED') { continue }
                    $findings.Add((New-WfxFinding -Id $r.id -Title "$($r.title) (inside encoded command)" -Severity $r.severity -Confidence $r.confidence `
                                -Category 'Process' -Technique $r.technique -Description $r.description -Recommendation $r.recommendation `
                                -Entity "$entity`:decoded" -HostName $HostName -Time (Get-WfxValue $p 'CreateTime') -Source 'process' `
                                -Evidence ([ordered]@{ Pid = $p.Pid; Process = $name; Parent = $parent; DecodedCommand = $dshort })))
                }
                $findings.Add((New-WfxFinding -Id 'PROC-ENCODED-DECODED' -Title "Decoded PowerShell payload ($name, pid $(Get-WfxValue $p 'Pid' '?'))" `
                            -Severity 'Info' -Confidence 'High' -Category 'Process' -Technique @('T1027.010') `
                            -Description 'The encoded command was decoded for review (decoding only; nothing was executed).' `
                            -Recommendation 'Read the decoded script; correlate with 4104 script-block logs.' `
                            -Entity "$entity`:payload" -HostName $HostName -Time (Get-WfxValue $p 'CreateTime') -Source 'process' `
                            -Evidence ([ordered]@{ Pid = $p.Pid; DecodedCommand = $dshort })))
            }
        }

        # 2. Masquerading: system-process name running from the wrong place
        if ($script:WfxSystem32Only -contains $name -and $path -and -not (Test-WfxSystemPath $path)) {
            $findings.Add((New-WfxFinding -Id 'PROC-SYSNAME-WRONGPATH' -Title "System process name '$name' running from an unusual path" `
                        -Severity 'High' -Confidence 'High' -Category 'Process' -Technique @('T1036.005') `
                        -Description "A process using the name of a core Windows binary is running from outside System32/SysWOW64. Malware often copies a trusted name to blend in." `
                        -Recommendation "Verify the image path and signature. The real $name runs only from the Windows system folders." `
                        -Entity $entity -HostName $HostName -Time (Get-WfxValue $p 'CreateTime') -Source 'process' `
                        -Evidence ([ordered]@{ Pid = $p.Pid; Process = $name; Path = $path; Parent = $parent })))
        }

        # 3. Parent spoofing of sensitive processes
        if ($script:WfxExpectedParents.ContainsKey($name) -and $parent) {
            if ($script:WfxExpectedParents[$name] -notcontains $parent) {
                $findings.Add((New-WfxFinding -Id 'PROC-PARENT-SPOOF' -Title "$name has an unexpected parent ($parent)" `
                            -Severity 'High' -Confidence 'Medium' -Category 'Process' -Technique @('T1055.012', 'T1036') `
                            -Description "Core Windows processes are started by a fixed parent. A different parent can indicate process hollowing or a masqueraded binary." `
                            -Recommendation "Expected parent for $name is $($script:WfxExpectedParents[$name] -join '/'). Investigate the parent process." `
                            -Entity $entity -HostName $HostName -Time (Get-WfxValue $p 'CreateTime') -Source 'process' `
                            -Evidence ([ordered]@{ Pid = $p.Pid; Process = $name; Parent = $parent; Path = $path })))
            }
        }

        # 4. Office / browser spawning a script interpreter → likely malicious document or exploit
        if (($script:WfxOfficeParents -contains $parent -or $script:WfxBrowserParents -contains $parent) -and $script:WfxScriptChildren -contains $name) {
            $isOffice = $script:WfxOfficeParents -contains $parent
            $findings.Add((New-WfxFinding -Id ($(if ($isOffice) { 'PROC-OFFICE-SPAWN' } else { 'PROC-BROWSER-SPAWN' })) `
                        -Title "$parent spawned $name" -Severity 'High' -Confidence 'Medium' -Category 'Process' `
                        -Technique @('T1204.002', 'T1059.001') `
                        -Description "$(if ($isOffice) {'An Office application'} else {'A web browser'}) started a scripting tool. This is the classic result of a malicious document or a browser exploit/ClickFix lure." `
                        -Recommendation "Review the command line and what $parent opened (recent documents / browser history) just before this ran." `
                        -Entity $entity -HostName $HostName -Time (Get-WfxValue $p 'CreateTime') -Source 'process' `
                        -Evidence ([ordered]@{ Pid = $p.Pid; Process = $name; Parent = $parent; CommandLine = (Protect-WfxText $cmd); ParentCommandLine = (Protect-WfxText $pcmd) })))
        }

        # 5. Unsigned / untrusted binary from a user-writable location
        if ($path -and (Test-WfxUserWritablePath $path) -and $name -notin @('', 'explorer.exe')) {
            $untrusted = $sig -and $sig -notin @('Valid', 'Signed', 'Trusted', '')
            if ($untrusted) {
                $findings.Add((New-WfxFinding -Id 'PROC-UNSIGNED-USERPATH' -Title "Unsigned process running from a user-writable folder: $name" `
                            -Severity 'Medium' -Confidence 'Medium' -Category 'Process' -Technique @('T1036') `
                            -Description "An unsigned or untrusted executable is running from a location any user can write to — a common staging pattern for malware." `
                            -Recommendation "Hash the file and check it against threat intelligence; confirm the publisher." `
                            -Entity $entity -HostName $HostName -Time (Get-WfxValue $p 'CreateTime') -Source 'process' `
                            -Evidence ([ordered]@{ Pid = $p.Pid; Process = $name; Path = $path; Signature = $sig; Parent = $parent })))
            }
        }

        # 6. Known offensive / hacking tools
        if ($offensive | Where-Object { $name -eq $_ -or ($_ -notmatch '\.' -and $name -like "*$_*") }) {
            $findings.Add((New-WfxFinding -Id 'PROC-OFFENSIVE-TOOL' -Title "Offensive security tool running: $name" `
                        -Severity 'High' -Confidence 'Medium' -Category 'Process' -Technique @('T1588.002') `
                        -Description "A process matching a known credential-dumping, C2 or attack tool is running. $($threats.offensiveNote)" `
                        -Recommendation "Confirm whether an authorized test is in progress. If not, treat the host as compromised." `
                        -Entity $entity -HostName $HostName -Time (Get-WfxValue $p 'CreateTime') -Source 'process' `
                        -Evidence ([ordered]@{ Pid = $p.Pid; Process = $name; Path = $path; CommandLine = (Protect-WfxText $cmd) })))
        }

        # 7. Remote-management (RMM) tools — attacker persistence / access on endpoints
        if ($rmm -contains $name) {
            $findings.Add((New-WfxFinding -Id 'PROC-RMM-TOOL' -Title "Remote-management tool running: $name" `
                        -Severity 'Low' -Confidence 'Low' -Category 'Process' -Technique @('T1219') `
                        -Description "A remote access / RMM tool is running. These are legitimate, but intruders frequently install one for durable access, especially if it is not your standard tool." `
                        -Recommendation "Confirm this RMM tool is sanctioned on this host and tied to a known administrator." `
                        -Entity $entity -HostName $HostName -Time (Get-WfxValue $p 'CreateTime') -Source 'process' `
                        -Evidence ([ordered]@{ Pid = $p.Pid; Process = $name; Path = $path })))
        }

        # 8. AI-era context (informational): local LLM runtime + AI assistant with shell access
        if ($aiRuntime -contains $name) {
            $findings.Add((New-WfxFinding -Id 'AI-RUNTIME-PRESENT' -Title "Local AI model runtime running: $name" `
                        -Severity 'Info' -Confidence 'High' -Category 'AI' -Technique @() `
                        -Description "A local large-language-model runtime is running. Noted for context: these often expose an unauthenticated API on localhost (see network findings)." `
                        -Recommendation "Confirm it is bound to localhost and not reachable from the network." `
                        -Entity $entity -HostName $HostName -Time (Get-WfxValue $p 'CreateTime') -Source 'process' `
                        -Evidence ([ordered]@{ Pid = $p.Pid; Process = $name; Path = $path })))
        }
        $cmdL = $cmd.ToLowerInvariant()
        $agent = @($agentHints | Where-Object { $cmdL.Contains($_) }) | Select-Object -First 1
        if ($agent) {
            $findings.Add((New-WfxFinding -Id 'AI-AGENT-SHELL' -Title "Autonomous AI agent framework running ($agent)" `
                        -Severity 'Low' -Confidence 'Low' -Category 'AI' -Technique @('T1059.001', 'T1204.004') `
                        -Description "An AI agent framework able to run shell commands is active. Some commands on this host may have been generated and run by it rather than typed by a person." `
                        -Recommendation "When reconstructing a timeline, consider the agent as a possible actor and review its logs." `
                        -Entity "$entity`:agent" -HostName $HostName -Time (Get-WfxValue $p 'CreateTime') -Source 'process' `
                        -Evidence ([ordered]@{ Pid = $p.Pid; Process = $name; Hint = $agent; CommandLine = (Protect-WfxText $cmd) })))
        }
        $assistHint = if ($aiAssist -contains $name) { $name } else { @($aiAssistCmd | Where-Object { $cmdL.Replace('\', '/').Contains($_) }) | Select-Object -First 1 }
        if ($assistHint) {
            $findings.Add((New-WfxFinding -Id 'AI-ASSISTANT-PRESENT' -Title "AI assistant / agent running: $(if ($assistHint -ne $name) { "$assistHint (in $name)" } else { $name })" `
                        -Severity 'Info' -Confidence 'Low' -Category 'AI' -Technique @('T1204.004') `
                        -Description "An AI coding assistant or agent capable of running commands is present. Relevant when attributing activity: some commands may have been generated and run by this tool." `
                        -Recommendation "If reconstructing a timeline, consider this tool as a possible actor for shell activity." `
                        -Entity $entity -HostName $HostName -Time (Get-WfxValue $p 'CreateTime') -Source 'process' `
                        -Evidence ([ordered]@{ Pid = $p.Pid; Process = $name; Hint = $assistHint })))
        }
    }
    return , (Merge-WfxFinding -Finding $findings.ToArray())
}
