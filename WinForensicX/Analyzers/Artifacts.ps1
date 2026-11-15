# Artifact analyzer — turns execution and user-activity artifacts (ShimCache, Amcache, Prefetch, BAM,
# UserAssist, PCA, ShellBags, Jump Lists, shortcuts, RunMRU, browser downloads, Defender logs) into findings.
#
# One program usually appears in several artifacts (Amcache + ShimCache + Prefetch + BAM). Findings about a
# file are therefore made once per file, listing every artifact that saw it and the earliest/latest times.

function Join-WfxDict {
    <# Copy of an ordered dictionary with extra keys appended (works the same on PowerShell 5.1 and 7). #>
    param($A, $B)
    $o = [ordered]@{}; foreach ($k in $A.Keys) { $o[$k] = $A[$k] }; foreach ($k in $B.Keys) { $o[$k] = $B[$k] }; $o
}

function Invoke-WfxArtifactAnalyzer {
    param([object[]]$Artifacts, [string]$HostName = '')
    $findings = New-Object System.Collections.Generic.List[object]
    $arts = @($Artifacts | Where-Object { $_ })
    if (-not $arts.Count) { return , $findings.ToArray() }
    $threats = $null; try { $threats = Get-WfxRulePack -Name 'threats' } catch { }
    $dnsPack = $null; try { $dnsPack = Get-WfxRulePack -Name 'dns' } catch { }
    $offensive = @($threats.offensiveProcesses | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $rmm = @($threats.rmmProcesses | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $vulnDrv = @($threats.vulnerableDrivers | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $exfil = @($threats.exfilTools | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $paste = @($dnsPack.pasteSites | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $tunnel = @($dnsPack.tunnelDomains | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $tlds = @($dnsPack.suspiciousTlds | ForEach-Object { ([string]$_).ToLowerInvariant().TrimStart('.') })
    $exeRx = '(?i)\.(?:exe|scr|com|pif|cpl|msi|dll|sys)$'
    $riskyDl = '(?i)\.(?:exe|scr|com|pif|cpl|msi|msix|appx|dll|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|lnk|url|iso|img|vhd|vhdx|one|jar|xll|reg|chm|appref-ms|library-ms|search-ms|svg|html?)$'
    $sysNames = @('svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe', 'services.exe', 'smss.exe', 'wininit.exe', 'spoolsv.exe', 'taskhostw.exe', 'dllhost.exe', 'conhost.exe', 'rundll32.exe', 'lsm.exe', 'sihost.exe', 'ctfmon.exe', 'msmpeng.exe', 'searchindexer.exe', 'runtimebroker.exe', 'explorer.exe', 'taskmgr.exe', 'regsvr32.exe', 'wmiprvse.exe')
    $staging = '(?i)^(?:[a-z]:|\(volume\))?\\(?:users\\public\\|users\\[^\\]+\\appdata\\local\\temp\\|windows\\temp\\|perflogs\\|\$recycle\.bin\\|programdata\\[^\\]+\.(?:exe|scr|dll|com)$|users\\[^\\]+\\appdata\\roaming\\[^\\]+\.(?:exe|scr|dll|com)$|windows\\tasks\\|windows\\debug\\|windows\\fonts\\[^\\]+\.exe$|intel\\|temp\\)'
    $isFull = { param($p) $p -match '^(?:[a-z]:\\|\\\\|\(volume\)\\|%[a-z]+%\\)' }
    $add = {
        param($Id, $Title, $Sev, $Conf, [string[]]$Tech, $Desc, $Rec, $Entity, $Time, $Ev, [string]$Cat = 'Execution', [string]$Src = 'artifacts')
        $findings.Add((New-WfxFinding -Id $Id -Title $Title -Severity $Sev -Confidence $Conf -Category $Cat -Technique $Tech -Description $Desc -Recommendation $Rec `
                    -Entity $Entity -HostName $HostName -Time $Time -Source $Src -Evidence $Ev))
    }

    # ── group per file: execution / presence evidence for the same path from several artifacts ──
    $byFile = @{}
    foreach ($a in $arts) {
        if ($a.Evidence -notin 'Execution', 'Presence', 'Install') { continue }
        $p = ConvertFrom-WfxEnvPath ([string]$a.Path); if (-not $p) { continue }
        $key = $p.ToLowerInvariant() -replace '^\(volume\)', '' -replace '^[a-z]:', ''
        if (-not $byFile.ContainsKey($key)) { $byFile[$key] = New-Object System.Collections.Generic.List[object] }
        $byFile[$key].Add($a)
    }
    foreach ($key in $byFile.Keys) {
        $rows = $byFile[$key].ToArray()
        $first = $rows[0]; $path = ConvertFrom-WfxEnvPath ([string]$first.Path)
        $full = @($rows | Where-Object { & $isFull (ConvertFrom-WfxEnvPath $_.Path) } | Select-Object -First 1); if ($full) { $path = ConvertFrom-WfxEnvPath ([string]$full[0].Path) }
        $leaf = (Get-WfxLeaf $path).ToLowerInvariant()
        $kinds = @($rows | ForEach-Object Artifact | Select-Object -Unique)
        $ran = [bool]@($rows | Where-Object Evidence -eq 'Execution').Count
        $times = @($rows | ForEach-Object Time | Where-Object { $_ } | Sort-Object)
        $sha = @($rows | ForEach-Object Sha1 | Where-Object { $_ } | Select-Object -First 1)
        $pub = @($rows | ForEach-Object { if ($_.Extra -and $_.Extra.PSObject.Properties['Publisher']) { [string]$_.Extra.Publisher } } | Where-Object { $_ } | Select-Object -First 1)
        $users = @($rows | ForEach-Object User | Where-Object { $_ } | Select-Object -Unique)
        $ev = [ordered]@{ Path = $path; SeenIn = ($kinds -join ', '); FirstSeen = $(if ($times) { $times[0] }); LastSeen = $(if ($times) { $times[-1] }); Sha1 = $(if ($sha) { $sha[0] }); Publisher = $(if ($pub) { $pub[0] }); Users = ($users -join ', ') }
        $what = if ($ran) { 'ran' } else { 'was present' }
        $when = if ($times) { $times[-1] } else { $null }
        $entity = "file:$path"

        $offHit = @($offensive | Where-Object { $leaf -eq $_ -or ($_ -notmatch '\.' -and $leaf.Contains($_)) } | Select-Object -First 1)
        if ($offHit) {
            & $add 'ART-OFFENSIVE-TOOL' "Offensive / remote-execution tool ${what}: $leaf" $(if ($ran) { 'High' } else { 'Medium' }) 'Medium' @('T1588.002') `
                "Execution artifacts ($($kinds -join ', ')) show $leaf, a tool used for credential theft, discovery or lateral movement. These artifacts survive deletion of the file, so this holds even if the tool is gone." `
                'Establish who ran it and when (see Seen in / times), hash-match it if the file still exists, and scope the accounts and hosts it could have touched.' $entity $when $ev
            continue
        }
        $exfHit = @($exfil | Where-Object { $leaf -eq $_ } | Select-Object -First 1)
        if ($exfHit -and ($ran -or $first.Artifact -eq 'DefenderLog')) {
            & $add 'ART-EXFIL-TOOL' "Data-transfer tool ran: $leaf" 'High' 'Medium' @('T1567.002', 'T1048') `
                "$leaf copies files to cloud storage or remote servers and is the most common exfiltration tool in ransomware intrusions. Seen in: $($kinds -join ', ')." `
                'Find its configuration file (e.g. rclone.conf) and command lines, establish what was copied and where to, and preserve proxy / firewall logs.' $entity $when $ev 'Exfiltration'
            continue
        }
        $rmmHit = @($rmm | Where-Object { $leaf -eq $_ } | Select-Object -First 1)
        if ($rmmHit -and $ran) {
            & $add 'ART-RMM-TOOL' "Remote-access tool ran: $leaf" 'Medium' 'Medium' @('T1219') `
                'A remote monitoring / remote desktop tool ran on this host. Intruders install these for persistent hands-on access that blends in with IT tooling.' `
                'Confirm IT uses this tool here; if not, remove it and review its connection logs.' $entity $when $ev
        }
        $okDir = '(?i)\\windows\\(?:system32|syswow64|winsxs|servicing|softwaredistribution)\\|^(?:[a-z]:|\(volume\))\\windows\\(?:explorer|regedit|notepad|hh|write)\.exe$'
        if ($leaf -eq 'msmpeng.exe') { $okDir = '(?i)\\(?:program files\\windows defender|programdata\\microsoft\\windows defender\\platform\\[^\\]+)\\msmpeng\.exe$' }
        if ($leaf -in $sysNames -and (& $isFull $path) -and $path -notmatch $okDir) {
            & $add 'ART-MASQUERADE' "System program name in the wrong folder: $path" 'High' 'Medium' @('T1036.005') `
                "$leaf is a Windows system program, but this copy $what outside the Windows system folders. Malware uses system names so it looks normal in a process list." `
                'Hash and inspect the file; check its parent process and persistence.' $entity $when $ev 'Defense Evasion'
            continue
        }
        # Installer bootstrappers unpack into Temp\{GUID}\ all the time; they are not interesting on their own.
        $installer = $path -match '(?i)\\temp\\\{[0-9a-f-]{36}\}(?:~setup)?\\|\\temp\\(?:vmware-[^\\]+|msi[0-9a-f]+\.tmp|is-[a-z0-9]+\.tmp|ckz_[a-z0-9]+|nsu[0-9a-z]+\.tmp|[0-9a-f]{8}-[0-9a-f-]{27})\\' -or
            $leaf -match '(?i)^(?:setup\d*|install(?:er)?|unins\d*|dismhost|mpsigstub|am_delta.*|mpam-.*|onedrivesetup|msedgeupdate.*|googleupdate.*|vc_?redist.*|dotnet.*|ndp\d+.*|windows\d+\.\d-kb\d+.*)\.exe$'
        if ($leaf -match $exeRx -and $path -match $staging -and -not $installer) {
            $sev = if ($pub) { 'Low' } elseif ($ran) { 'Medium' } else { 'Low' }
            & $add 'ART-EXEC-STAGING-PATH' "Program $what from a staging folder: $path" $sev 'Medium' @('T1204.002', 'T1074.001') `
                "Executables in Temp, Public, PerfLogs, the Recycle Bin or the root of ProgramData are where droppers and hands-on intruders stage tools. Seen in: $($kinds -join ', ')." `
                'Check the file hash and signer; find how it arrived (downloads, mail, archives) and what it started.' $entity $when $ev
        }
        if ($first.Artifact -eq 'AmcacheDriver' -or ($leaf -match '\.sys$')) {
            if ($leaf -in $vulnDrv) {
                & $add 'ART-VULNERABLE-DRIVER' "Known-vulnerable driver recorded: $leaf" 'High' 'Medium' @('T1068', 'T1562.001') `
                    "$leaf is a signed but vulnerable driver abused to kill security tools or gain kernel access (bring-your-own-vulnerable-driver)." `
                    'Find the service that loaded it and when; enable the Microsoft vulnerable driver blocklist.' $entity $when $ev 'Defense Evasion'
            }
        }
    }

    # Risky / attack-tool downloads, for browser history and for $MFT Zone.Identifier streams alike.
    $dlCheck = {
        param($p, $x, $time, $ev)
            $url = if ($x) { [string]$x.Url } else { '' }
            $host_ = ''; try { if ($url) { $host_ = ([uri]$url).Host.ToLowerInvariant() } } catch { }
            $rawIp = $host_ -match '^\d{1,3}(?:\.\d{1,3}){3}$|^\[?[0-9a-f:]+\]?$'
            $why = @()
            if ($rawIp -and -not (Test-WfxPrivateIp $host_)) { $why += 'served from a bare IP address' }
            if ($host_ -and @($paste | Where-Object { $host_ -eq $_ -or $host_.EndsWith(".$_") }).Count) { $why += 'from a paste / file-sharing site' }
            if ($host_ -and @($tunnel | Where-Object { $host_ -eq $_ -or $host_.EndsWith(".$_") }).Count) { $why += 'from a tunnelling service' }
            $tld = ($host_ -split '\.')[-1]; if ($host_ -and -not $rawIp -and $tld -in $tlds) { $why += "from a .$tld domain" }
            if ($x -and $x.Danger -and $x.Danger -notmatch 'safe|allowlisted') { $why += "the browser warned: $($x.Danger)" }
            if ($p -match $riskyDl -and $why.Count) {
                $sev = if (($x -and $x.Opened) -or $why.Count -ge 2) { 'High' } else { 'Medium' }
                & $add 'ART-RISKY-DOWNLOAD' "Risky download: $(Get-WfxLeaf $p)" $sev 'Medium' @('T1105', 'T1204.002') `
                    "An executable, script or disk-image file was downloaded ($($why -join '; ')). This is how loaders and phishing payloads arrive." `
                    'Check whether it was opened or run (Amcache / Prefetch / ShimCache for the same name), hash it, and review the referrer and the source site.' "download:$p" $time (Join-WfxDict $ev ([ordered]@{ Url = $url; Referrer = $(if ($x) { $x.Referrer }); Opened = $(if ($x) { $x.Opened }) })) 'Initial Access'
            }
            $leaf = (Get-WfxLeaf $p).ToLowerInvariant()
            if (@($offensive | Where-Object { $leaf -eq $_ -or ($_ -notmatch '\.' -and $leaf.Contains($_)) }).Count) {
                & $add 'ART-OFFENSIVE-DOWNLOAD' "Attack tool downloaded: $leaf" 'High' 'Medium' @('T1105', 'T1588.002') `
                    'A browser download saved a file named like a known attack tool.' 'Check whether it ran (execution artifacts for the same name) and who downloaded it.' "download:$p" $time (Join-WfxDict $ev ([ordered]@{ Url = $url })) 'Initial Access'
            }
    }

    foreach ($a in $arts) {
        $p = [string]$a.Path; $x = $a.Extra; $time = $a.Time
        $ev = [ordered]@{ Artifact = $a.Artifact; Time = $a.Time; TimeKind = $a.TimeKind; Path = $p; Detail = $a.Detail; User = $a.User; Source = $a.Source }
        switch ($a.Artifact) {
            'DefenderLog' {
                if ($a.Evidence -ne 'Detection') { break }
                $threat = [string]$a.Name
                $sev = if ($threat -match '(?i)^(?:PUA|PUADlMgr|Adware|BrowserModifier|SoftwareBundler|App):') { 'Low' } elseif ($threat -match '(?i)^(?:Ransom|Backdoor|HackTool|Exploit|Trojan|Behavior|VirTool):') { 'High' } else { 'Medium' }
                & $add 'ART-DEFENDER-DETECTION' "Defender detection in its own log: $threat" $sev 'High' @() `
                    "Microsoft Defender's support log records a detection of $threat on $p. This log is separate from the event log, so it can survive when event logs were cleared." `
                    'Confirm the remediation succeeded, find how the file arrived, and check for related detections on other hosts.' "defender:${threat}:$p" $time $ev 'Malware'
            }
            'Download' { & $dlCheck $p $x $time $ev }
            'SRUM' {
                if (-not $x -or -not $x.PSObject.Properties['BytesSent']) { break }
                $sent = [double]$x.BytesSent; $recv = [double]$x.BytesReceived
                $leaf = (Get-WfxLeaf $p).ToLowerInvariant()
                $isExfil = [bool]@($exfil | Where-Object { $leaf -eq $_ }).Count
                # Programs that upload by design: sync clients, browsers, mail, Windows itself.
                $expected = $p -match '(?i)(?:^System$|^\(unnamed app|\\(?:onedrive|dropbox|googledrivefs|box|boxsync|teams|ms-teams|outlook|thunderbird|chrome|msedge|firefox|brave|opera|iexplore|svchost|backgroundtransferhost|backgroundtaskhost|lsass|searchapp|msmpeng|mpdefendercoreservice|wuauclt|usoclient|code|zoom)\.exe$)'
                $big = $sent -ge 500MB -or ($sent -ge 100MB -and $sent -ge 4 * $recv)
                $sz = if ($sent -ge 1GB) { '{0:n1} GB' -f ($sent / 1GB) } else { '{0:n0} MB' -f ($sent / 1MB) }
                if (($isExfil -and $sent -ge 10MB) -or ($big -and -not $expected)) {
                    $sev = if ($isExfil -or ($p -match $staging)) { 'High' } else { 'Medium' }
                    & $add 'ART-SRUM-UPLOAD' "Large upload by $(Get-WfxLeaf $p): $sz sent" $sev 'Medium' @('T1048', 'T1567') `
                        "Windows' resource usage database (SRUM) records that $(Get-WfxLeaf $p) sent $sz over the network ($('{0:n0}' -f ($recv / 1MB)) MB received) in $($x.Hours) hourly records. Sending far more than receiving is the shape of an upload; SRUM keeps this for weeks, even after the program is deleted." `
                        'Find what the program is and who ran it; check proxy and firewall logs for the destination in the same hours, and what data it could reach.' "srum:$p|$($a.User)" $time (Join-WfxDict $ev ([ordered]@{ BytesSent = $x.BytesSent; BytesReceived = $x.BytesReceived; FirstSeen = $x.FirstSeen; Hours = $x.Hours })) 'Exfiltration'
                }
            }
            'MFT' {
                if ($x -and $x.PSObject.Properties['Url'] -and $x.Url) { & $dlCheck $p $x $time $ev }
                if ($x -and $x.PSObject.Properties['Timestomp'] -and $x.Timestomp) {
                    $sev = if ([int]$x.TimestompScore -ge 3) { 'High' } else { 'Medium' }
                    & $add 'ART-TIMESTOMP' "File timestamps rewritten: $(Get-WfxLeaf $p)" $sev 'Medium' @('T1070.006') `
                        "The `$MFT shows signs that this file's timestamps were changed after it was written: $($x.Timestomp). Attackers backdate their tools so they hide among old system files and fall outside a timeline." `
                        'Trust the $FILE_NAME times for this file; hash and inspect it, and check what ran around the $FILE_NAME creation time.' "timestomp:$p" $(if ($x.FNCreated) { $x.FNCreated } else { $time }) (Join-WfxDict $ev ([ordered]@{ FNCreated = $x.FNCreated; Reasons = $x.Timestomp })) 'Defense Evasion'
                }
            }
            { $_ -in 'ShellBag', 'JumpList', 'Shortcut', 'TypedPath' } {
                if ($p -match '^\\\\([^\\]+)\\(?:[a-z]\$|admin\$)(?:\\|$)') {
                    & $add 'ART-ADMIN-SHARE-ACCESS' "Administrative share opened: $p" 'Medium' 'Medium' @('T1021.002') `
                        "A user browsed the hidden administrative share of $($Matches[1]) ($($a.Artifact)). Attackers use C$ / ADMIN$ to copy tools to other machines and to collect data." `
                        'Confirm the user had a reason to open admin shares on that host; check that host for the same time window.' "share:$p" $time $ev 'Lateral Movement'
                }
                $args_ = if ($x -and $x.PSObject.Properties['Arguments']) { [string]$x.Arguments } else { '' }
                if ($args_) {
                    foreach ($r in @(Test-WfxCommandLine -CommandLine ("`"$p`" $args_") -Image $p)) {
                        & $add $r.id "$($r.title) (in a shortcut)" $r.severity $r.confidence $r.technique "$($r.description) The command is stored in a shortcut / Jump List entry ($($a.Source))." $r.recommendation "shortcut:$($a.Source)" $time (Join-WfxDict $ev ([ordered]@{ Arguments = $args_ }))
                    }
                }
                if ($x -and $x.PSObject.Properties['DriveType'] -and $x.DriveType -eq 'Removable') {
                    $isExe = $p -match $exeRx -or $p -match '(?i)\.(?:ps1|bat|cmd|vbs|js|hta|lnk)$'
                    & $add $(if ($isExe) { 'ART-REMOVABLE-EXEC' } else { 'ART-REMOVABLE-ACCESS' }) "$(if ($isExe) { 'Program run from a removable drive' } else { 'File opened from a removable drive' }): $(Get-WfxLeaf $p)" $(if ($isExe) { 'Medium' } else { 'Low' }) 'Medium' $(if ($isExe) { @('T1091') } else { @() }) `
                        "$($a.Artifact) records $p on a removable drive$(if ($x.VolumeLabel) { " labelled '$($x.VolumeLabel)'" })$(if ($x.VolumeSerial) { " (volume serial $($x.VolumeSerial))" }). Useful for data-theft and USB-malware questions." `
                        'Match the volume serial with USB device history (Explore → USB history) to identify the device.' "usb:$p" $time $ev 'Collection'
                }
            }
            'RunMRU' {
                foreach ($r in @(Test-WfxCommandLine -CommandLine $p)) {
                    & $add $r.id "$($r.title) (typed into the Run dialog)" $r.severity $r.confidence (@($r.technique) + 'T1204.004') `
                        "$($r.description) It was typed or pasted into Win+R — the 'ClickFix' / fake-CAPTCHA lure tells users to do exactly this." $r.recommendation "runmru:$p" $time $ev
                }
            }
            'Search' {
                if ($p -match '(?i)passw|credential|\bcreds?\b|secret|\.kdbx|keepass|vpn|wallet|seed|private key|id_rsa|\.pem|\.pfx|unattend|sysprep|ntds|\bsam\b') {
                    & $add 'ART-SENSITIVE-SEARCH' "Explorer search for credentials: '$p'" 'Medium' 'Low' @('T1083', 'T1552.001') `
                        'Someone searched the file system for password or key material from Explorer. Intruders with desktop access do this to find stored credentials.' `
                        'Confirm with the user; check what files matching that search were opened next (Jump Lists, shortcuts).' "search:$($a.User):$p" $time $ev 'Credential Access'
                }
            }
        }
    }
    , $findings.ToArray()
}
