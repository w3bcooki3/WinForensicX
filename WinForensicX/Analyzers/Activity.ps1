# Activity analyzer — turns "what changed recently" records into findings for the changes attackers make.
# Input: normalized activity records { Time, Category, Action, Target, Detail, Actor, Source }.

function Invoke-WfxActivityAnalyzer {
    param([object[]]$Activity, [string]$HostName = '')
    $findings = New-Object System.Collections.Generic.List[object]
    $acts = @($Activity | Where-Object { $_ })
    if (-not $acts.Count) { return , $findings.ToArray() }
    $threats = $null; try { $threats = Get-WfxRulePack -Name 'threats' } catch {}
    $rmm = @($threats.rmmProcesses | ForEach-Object { ([string]$_ -replace '\.exe$', '').ToLowerInvariant() } | Where-Object { $_.Length -ge 4 })
    $offensive = @($threats.offensiveProcesses)
    $rmmExe = @($threats.rmmProcesses)
    $c2Ports = @(4444, 5555, 1337, 31337, 6666, 6667, 9001, 9002, 12345, 50050)
    $execExt = '(?i)\.(?:exe|dll|scr|com|pif|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|msi|lnk|cpl|jar)$'
    $ev = { param($a) [ordered]@{ Time = $a.Time; Action = $a.Action; Target = $a.Target; Detail = $a.Detail; Actor = $a.Actor; Source = $a.Source } }
    $add = {
        param($Id, $Title, $Sev, $Conf, $Tech, $Desc, $Rec, $A, [string]$Cat = 'Activity')
        $findings.Add((New-WfxFinding -Id $Id -Title $Title -Severity $Sev -Confidence $Conf -Category $Cat -Technique $Tech -Description $Desc -Recommendation $Rec `
                    -Entity "activity:${Id}:$($A.Target)" -HostName $HostName -Time $A.Time -Source "activity:$($A.Source)" -Evidence (& $ev $A)))
    }

    foreach ($a in $acts) {
        $act = [string]$a.Action; $tgt = [string]$a.Target; $det = [string]$a.Detail; $actor = [string]$a.Actor
        switch -Regex ($act) {
            '^Hijack key written' {
                & $add 'ACT-HIJACK-KEY-CHANGED' "Execution-hijack registry key changed: $(Get-WfxLeaf $tgt)" 'High' 'Medium' @('T1546.012', 'T1548.002') `
                    'An Image File Execution Options, SilentProcessExit or shell-handler key was written in the look-back window. These keys let an attacker run code whenever a program starts or bypass UAC.' `
                    'Inspect the key values (Detail) and remove any Debugger / command values you did not set.' $a
            }
            '^Autostart key written' {
                & $add 'ACT-AUTOSTART-KEY-CHANGED' "Autostart registry location changed recently: $tgt" 'Medium' 'Low' @('T1547.001') `
                    'A Run/RunOnce/Winlogon/AppInit autostart key was modified in the look-back window. Installers do this too; check what was added.' `
                    'Compare the values with the Autostart list and confirm each entry is expected.' $a
            }
            '^Defence key written' {
                $sev = if ($tgt -match '(?i)\\Exclusions\\') { 'High' } else { 'Medium' }
                & $add 'ACT-DEFENCE-KEY-CHANGED' "Security-control setting changed: $tgt" $sev 'Medium' @('T1562.001') `
                    'A Defender exclusion, Defender policy, PowerShell logging policy or firewall-rule key was modified in the look-back window — attackers change these right before dropping tools.' `
                    'Confirm the change was approved; review what the exclusion / policy now allows.' $a
            }
            '^Credentials key written' {
                if ($tgt -match '(?i)WDigest' -or $det -match '(?i)UseLogonCredential=1|RunAsPPL=0') {
                    & $add 'ACT-CRED-KEY-CHANGED' "Credential-protection setting changed: $tgt" 'High' 'Medium' @('T1112', 'T1003.001') `
                        'The WDigest or LSA configuration key was written. Attackers enable WDigest clear-text credentials or weaken LSA protection before dumping passwords.' `
                        'Check UseLogonCredential (should be 0 / absent) and RunAsPPL; reset credentials if weakened.' $a
                }
            }
            '^Software installed' {
                $hit = @($rmm | Where-Object { $tgt.ToLowerInvariant().Contains($_) }) | Select-Object -First 1
                if ($hit) {
                    & $add 'ACT-RMM-INSTALLED' "Remote-access software installed: $hit" 'Medium' 'Medium' @('T1219') `
                        'A remote monitoring/management tool was installed in the look-back window. Intruders install these for persistent hands-on access.' `
                        'Confirm IT installed it; if not, remove it and investigate how it arrived.' $a
                }
            }
            '^Service installed' {
                if ($tgt -match '(?i)^(?:PSEXESVC|PAExec\S*|RemComSvc|csexecsvc|winexesvc|BTOBTO|SMBExec\S*)$' -or $det -match '(?i)\\(?:users|programdata|windows\\temp|temp|appdata)\\|cmd(?:\.exe)?\s+/c|powershell|\\\\[^\\]+\\(?:admin|c)\$|(?:%SystemRoot%|[a-z]:\\windows)\\[^\\]+\.exe') {
                    & $add 'ACT-SERVICE-SUSPICIOUS' "Service installed from an unusual location: $tgt" 'High' 'Medium' @('T1543.003', 'T1569.002') `
                        'A new service runs a shell command or a binary from a user-writable folder or admin share — the pattern of PsExec-style remote execution and service persistence.' `
                        'Inspect the service binary and the account that created it.' $a
                }
            }
            '^(?:All firewall rules deleted|Firewall rule added|Firewall profile setting changed)' {
                if ($act -match 'All firewall' -or ($actor -and $actor -notmatch '(?i)\\(?:svchost|mpssvc|msmpeng|system32\\(?:netsh|dllhost)|wbem\\wmiprvse)\.exe$|^System$')) {
                    & $add 'ACT-FIREWALL-CHANGED' "Firewall changed by $(if ($actor) { Get-WfxLeaf $actor } else { 'unknown' }): $tgt" 'Medium' 'Medium' @('T1562.004') `
                        'A firewall rule was added or settings changed by a program that is not the usual Windows management path.' `
                        'Review the rule (program, ports, direction) and remove it if not expected.' $a
                }
            }
            '^Audit policy changed' { & $add 'ACT-AUDIT-POLICY-CHANGED' 'Audit policy was changed' 'Medium' 'Medium' @('T1562.002') 'The audit policy was modified — attackers turn auditing off to avoid leaving events.' 'Check the current audit policy (auditpol /get /category:*) and who changed it.' $a }
            '^(?:Event logging shut down|Security log cleared|Event log cleared)' { & $add 'ACT-LOGGING-TAMPER' "$act" 'High' 'High' @('T1070.001') 'Event logging was cleared or stopped, destroying evidence.' 'Recover logs from forwarding/SIEM and review what happened just before.' $a }
            '^System time changed' {
                if ($det -notmatch '(?i)svchost|w32time|^$' -and $actor -notmatch '(?i)LOCAL SERVICE|NETWORK SERVICE') {
                    & $add 'ACT-TIME-CHANGED' 'System time changed manually' 'Low' 'Low' @('T1070.006') 'The system clock was changed by something other than time synchronisation, which can be used to confuse timelines.' 'Account for the shift when reading timestamps; identify who changed it.' $a
                }
            }
            'timestomp' { & $add 'ACT-TIMESTOMP' "File timestamp altered: $(Get-WfxLeaf $tgt)" 'Medium' 'Medium' @('T1070.006') 'A file''s creation time was changed (Sysmon 2) — used to hide new files among old ones. Some installers and browsers also do this.' 'Check the process that changed it (Actor) and the file.' $a }
            '^BITS transfer' {
                if ($tgt -notmatch '(?i)\.(?:microsoft|windowsupdate|windows|office|msedge|live|bing|skype|azureedge|msftconnecttest|xboxlive|onedrive|sharepoint|adobe|google|gvt1|mozilla|dropbox)\.(?:com|net)') {
                    & $add 'ACT-BITS-DOWNLOAD' "BITS download from an unusual source: $(Get-WfxShortText $tgt 80)" 'Medium' 'Medium' @('T1197', 'T1105') 'A BITS job transferred a file from a non-vendor URL. BITS is a quiet way to download payloads and survive reboots.' 'List BITS jobs (bitsadmin /list /allusers /verbose) and retrieve the file for analysis.' $a
                }
            }
            '^Permanent WMI subscription' { & $add 'ACT-WMI-SUBSCRIPTION' 'Permanent WMI event subscription registered' 'High' 'Medium' @('T1546.003') 'A permanent WMI event consumer was registered — a stealthy persistence mechanism.' 'Inspect root\subscription filters, consumers and bindings; remove unknown ones.' $a }
            '^(?:Real-time protection disabled|Virus scanning disabled|Spyware scanning disabled)' { & $add 'ACT-DEFENDER-DISABLED' "$act" 'High' 'High' @('T1562.001') 'Microsoft Defender protection was turned off.' 'Re-enable protection and find who disabled it.' $a }
            '^Program ran \(BAM\)' {
                if ((Test-WfxUserWritablePath $tgt) -and $tgt -match '(?i)\.(?:exe|scr|com)$') {
                    & $add 'ACT-EXEC-USERPATH' "Program ran from a user folder: $(Get-WfxLeaf $tgt)" 'Low' 'Low' @('T1204.002') 'A program in a user-writable folder (Downloads, Temp, AppData, ProgramData…) was executed in the look-back window. Common for installers; also how most malware first runs.' 'Hash and check the file (Hunt & analyze → file triage) if you do not recognise it.' $a
                }
            }
            '^Outbound RDP' { & $add 'ACT-RDP-OUTBOUND' "Outbound RDP to $tgt" 'Info' 'Medium' @('T1021.001') 'This host was used to connect to another machine over RDP — context for lateral movement.' 'Confirm the connection was expected.' $a }
            '^(?:Created|Executable/script created)' {
                if ($a.Category -eq 'File' -and $tgt -match '(?i)\\Start Menu\\Programs\\Startup\\[^\\]+$' -and $tgt -notmatch '(?i)\\desktop\.ini$') {
                    & $add 'ACT-STARTUP-DROP' "File placed in a Startup folder: $(Get-WfxLeaf $tgt)" 'High' 'Medium' @('T1547.001') 'A file was created in a Startup folder; it will run at every logon of that user (or all users).' 'Inspect the file and remove it if it was not installed by known software.' $a
                }
                if ($a.Category -eq 'File' -and $tgt -match '(?i)\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|zip|rar|mp4|mp3)\.(?:exe|scr|com|pif|js|jse|vbs|vbe|wsf|hta|bat|cmd|lnk|ps1)$') {
                    & $add 'ACT-DOUBLE-EXTENSION' "File with a disguised double extension: $(Get-WfxLeaf $tgt)" 'High' 'Medium' @('T1036.007') 'A file name ends in a document/media extension followed by an executable one (e.g. invoice.pdf.exe). Explorer hides known extensions by default, so the user sees "invoice.pdf". This is a classic phishing lure.' 'Do not open it; hash it and check its origin (Zone.Identifier, browser history, mail).' $a
                }
                if ($a.Category -eq 'File' -and $tgt -match '(?i)\\[^\\]*(?:decrypt|ransom|recover[_ -]?(?:your|my|all)?[_ -]?(?:files|data)|restore[_ -]?(?:your|my|all)?[_ -]?files|how[_ -]?to[_ -]?(?:decrypt|recover|restore|back))[^\\]*\.(?:txt|html?|hta|url|rtf)$') {
                    & $add 'ACT-RANSOM-NOTE' "Possible ransom note created: $(Get-WfxLeaf $tgt)" 'High' 'Low' @('T1486') 'A file was created whose name matches the naming used by ransomware notes (decrypt / recover files / how to restore …).' 'Open the file with a text viewer (do not run it); if it is a ransom note, isolate the host immediately.' $a
                }
                if ((Test-WfxNameInList $tgt $offensive)) {
                    & $add 'ACT-OFFENSIVE-TOOL-DROPPED' "Known offensive tool written to disk: $(Get-WfxLeaf $tgt)" 'High' 'Medium' @('T1588.002') "A file with the name of a known attack / credential-theft tool was created. $($threats.offensiveNote)" 'Hash the file and check it; determine who placed it and whether it ran (Prefetch, BAM).' $a
                }
                if ($act -match '^Created and deleted' -and $a.Category -eq 'File' -and $tgt -match $execExt -and $tgt -notmatch '(?i)\\(?:windows\\(?:softwaredistribution|winsxs|servicing)|program files|programdata\\(?:microsoft|package cache))\\') {
                    & $add 'ACT-SHORTLIVED-EXEC' "Executable created and deleted again: $(Get-WfxLeaf $tgt)" 'Medium' 'Low' @('T1070.004') 'An executable or script existed only briefly — the pattern of a dropper that runs a payload and removes it. Installers and updaters also do this.' 'Check execution artefacts (Prefetch, BAM, Sysmon) around this time for the same name.' $a
                }
                if ($a.Category -eq 'File' -and $tgt -match '(?i)\\(?:windows\\(?:temp|tasks|tracing)|programdata|users\\public|perflogs|\$recycle\.bin)\\[^\\]*\.(?:exe|dll|scr|ps1|bat|vbs|hta)$') {
                    & $add 'ACT-DROP-EXECUTABLE' "Executable written to a staging folder: $(Get-WfxLeaf $tgt)" 'Medium' 'Low' @('T1105') 'A program or script was created in a folder commonly used to stage malware.' 'Hash and check the file.' $a
                }
            }
            '^(?:Deleted|File deleted|Permanently deleted|Deleted to Recycle Bin)' {
                if ($tgt -match '(?i)\\winevt\\Logs\\[^\\]+\.evtx$') {
                    & $add 'ACT-EVTX-DELETED' "Event log file deleted: $(Get-WfxLeaf $tgt)" 'High' 'Medium' @('T1070.001') 'A Windows event log file was deleted from the log folder — evidence destruction.' 'Recover the log from forwarding/SIEM or backups; review what happened just before.' $a
                }
                if ($tgt -match '(?i)\\PSReadLine\\ConsoleHost_history\.txt$') {
                    & $add 'ACT-PSHISTORY-DELETED' 'PowerShell command history deleted' 'Medium' 'Medium' @('T1070.003') 'The PSReadLine history file (record of typed PowerShell commands) was deleted.' 'Check other execution evidence (4104 script blocks, Prefetch) for the same period.' $a
                }
            }
            '^Program (?:ran|launched)' {
                if (Test-WfxNameInList $tgt $offensive) {
                    & $add 'ACT-OFFENSIVE-TOOL-RAN' "Known offensive tool executed: $(Get-WfxLeaf $tgt)" 'High' 'Medium' @('T1588.002') "A program with the name of a known attack / credential-theft tool ran on this host. $($threats.offensiveNote)" 'Confirm whether this was an authorised test; if not, treat the host as compromised.' $a
                } elseif (Test-WfxNameInList $tgt $rmmExe) {
                    & $add 'ACT-RMM-RAN' "Remote-access tool executed: $(Get-WfxLeaf $tgt)" 'Medium' 'Low' @('T1219') 'A remote monitoring / remote desktop tool ran. Legitimate for IT support, and a common intruder access method.' 'Confirm the tool is sanctioned and who used it.' $a
                }
            }
            '^Defender configuration changed' {
                if ($tgt -match '(?i)\\Exclusions\\') {
                    & $add 'ACT-DEFENDER-EXCLUSION' "Defender exclusion changed: $(Get-WfxShortText $tgt 120)" 'High' 'Medium' @('T1562.001') 'A Microsoft Defender exclusion (path, process or extension) was added or changed. Attackers exclude their tools from scanning.' 'Review the exclusion list (Get-MpPreference) and remove anything not approved.' $a
                }
            }
            '^Malware detected' { & $add 'ACT-MALWARE-DETECTED' "Defender detected malware: $(Get-WfxShortText $tgt 120)" 'High' 'High' @() 'Microsoft Defender reported a detection. Check whether it was remediated and how the file arrived.' 'Review Defender history (Explore → Events → Defender) and the file''s origin.' $a }
            '^User created' { & $add 'ACT-USER-CREATED' "Local account created: $tgt" 'Medium' 'Medium' @('T1136.001') 'A new account was created. Intruders create accounts for persistent access.' 'Confirm the account is expected and who created it (Actor).' $a }
            '^Added to group' {
                if ($tgt -match '(?i)→\s*(?:Administrators|Domain Admins|Enterprise Admins|Remote Desktop Users|Remote Management Users|Backup Operators)\s*$') {
                    $sev = if ($tgt -match '(?i)Admin') { 'High' } else { 'Medium' }
                    & $add 'ACT-PRIV-GROUP-ADD' "Account added to a privileged group: $tgt" $sev 'Medium' @('T1098') 'An account was added to a group that grants administrative or remote access.' 'Confirm the change was approved; remove the membership if not.' $a
                }
            }
            '^Scheduled task (?:created|changed|registered|updated)' {
                if ($det) {
                    foreach ($r in (Test-WfxCommandLine -CommandLine $det)) { & $add $r.id "$($r.title) (scheduled task $tgt)" $r.severity $r.confidence @(Get-WfxValue $r 'technique' @()) 'A scheduled task was created or changed with a command matching a known attack technique.' 'Inspect the task (schtasks /query /tn <name> /xml) and remove it if not expected.' $a }
                    $img = Get-WfxImagePath $det
                    if ($img -and (Test-WfxUserWritablePath $img)) { & $add 'ACT-TASK-USERPATH' "Scheduled task runs a program from a user-writable folder: $tgt" 'Medium' 'Medium' @('T1053.005') 'A scheduled task created or changed in the look-back window launches a program from Temp, AppData, ProgramData, Public or Downloads.' 'Inspect the task and the program it runs.' $a }
                }
            }
            '^Outbound connection' {
                if ($tgt -match '^(.+):(\d+)$' -and -not (Test-WfxPrivateIp $Matches[1]) -and [int]$Matches[2] -in $c2Ports) {
                    & $add 'ACT-C2-PORT' "Outbound connection to a port typical of C2 / reverse shells: $tgt" 'Medium' 'Low' @('T1571') 'An outbound connection used a port commonly used by attack frameworks and reverse shells (e.g. 4444, 50050). Suggestive, not conclusive.' 'Identify the process (Actor) and the destination''s reputation.' $a
                }
            }
            'Alternate (?:data )?stream' {
                if ($a.Category -eq 'File' -and $tgt -match '(?i)\.(?:exe|dll|txt|log|ini|jpg|png)$' -and $tgt -notmatch '(?i)\\(?:Downloads|INetCache)\\') {
                    & $add 'ACT-ADS-WRITTEN' "Alternate data stream written: $(Get-WfxLeaf $tgt)" 'Low' 'Low' @('T1564.004') 'An NTFS alternate data stream was added to a file outside download folders. ADS can hide payloads.' 'List streams with Get-Item -Stream * and inspect unexpected ones.' $a
                }
            }
        }
    }

    # Bursts: mass deletion / mass content change in user data (ransomware / wiper behaviour).
    $files = @($acts | Where-Object { $_.Category -eq 'File' -and [string]$_.Target -match '(?i)\\users\\' -and [string]$_.Target -notmatch '(?i)\\appdata\\|\\\.git\\|\\node_modules\\' })
    foreach ($kind in @(@{ Rx = 'Deleted'; Id = 'ACT-MASS-DELETE'; T = 'Mass file deletion in user folders'; Tech = @('T1485', 'T1070.004') }, @{ Rx = 'Content overwritten|^Renamed|^Moved'; Id = 'ACT-MASS-MODIFY'; T = 'Mass file modification/renaming in user folders'; Tech = @('T1486') })) {
        $set = @($files | Where-Object { $_.Action -match $kind.Rx } | ForEach-Object { [pscustomobject]@{ T = ConvertTo-WfxDateTime $_.Time; A = $_ } } | Where-Object { $_.T } | Sort-Object T)
        if ($set.Count -lt 300) { continue }
        $best = 0; $bi = 0; $j = 0
        for ($i = 0; $i -lt $set.Count; $i++) { while ($set[$i].T - $set[$j].T -gt [TimeSpan]::FromMinutes(10)) { $j++ }; if (($i - $j + 1) -gt $best) { $best = $i - $j + 1; $bi = $i } }
        if ($best -ge 300) {
            $first = $set[$bi - $best + 1].A
            $findings.Add((New-WfxFinding -Id $kind.Id -Title "$($kind.T): $best files within 10 minutes" -Severity 'High' -Confidence 'Medium' -Category 'Activity' -Technique $kind.Tech `
                        -Description 'Hundreds of user files were deleted or rewritten within minutes — consistent with ransomware, a wiper, or a large legitimate clean-up/sync. Check which process was active at that time.' `
                        -Recommendation 'Isolate the host if unexpected; check shadow copies/backups; correlate with process execution at that time.' `
                        -Entity "activity:$($kind.Id)" -HostName $HostName -Time $first.Time -Source 'activity:burst' `
                        -Evidence ([ordered]@{ Files = $best; From = $first.Time; To = $set[$bi].A.Time; Sample = @($set[($bi - [Math]::Min(9, $best - 1))..$bi] | ForEach-Object { $_.A.Target }) })))
        }
    }
    return , (Merge-WfxFinding -Finding $findings.ToArray())
}
