# Security-posture analyzer. Turns the posture object from Get-WfxSecurityData into findings about
# defensive gaps: disabled/evaded AV, suspicious Defender exclusions (a common tamper IOC), missing
# audit logging (a visibility gap, so "no findings" is interpreted correctly), weak RDP, and LSASS
# protection. These are hardening/visibility findings, not proof of compromise — severities reflect that.

function Invoke-WfxPostureAnalyzer {
    param($Posture, [string]$HostName = '')
    $findings = New-Object System.Collections.Generic.List[object]
    if (-not $Posture) { return , $findings.ToArray() }

    $def = Get-WfxValue $Posture 'Defender' $null
    $thirdParty = @(Get-WfxValue $Posture 'ThirdPartyAV' @())
    $hasThirdParty = $thirdParty.Count -gt 0

    # ── Defender: real-time protection / AV off with no third-party engine ──
    if ($def -and (Get-WfxValue $def 'Installed' $false)) {
        $rtp = Get-WfxValue $def 'RealTimeProtectionEnabled' $null
        $av = Get-WfxValue $def 'AntivirusEnabled' $null
        if (($rtp -eq $false -or $av -eq $false) -and -not $hasThirdParty) {
            $findings.Add((New-WfxFinding -Id 'POSTURE-AV-DISABLED' -Title 'Antivirus real-time protection is OFF (no other AV present)' `
                        -Severity 'High' -Confidence 'High' -Category 'Posture' -Technique @('T1562.001') `
                        -Description "Microsoft Defender real-time/antivirus protection is disabled and no third-party AV is registered. The host is running without active malware protection — this is often the first thing an intruder disables." `
                        -Recommendation "Re-enable real-time protection, confirm it was not disabled by malware or GPO, and review when and by what it was turned off." `
                        -Entity 'posture:defender:rtp' -HostName $HostName -Source 'posture' `
                        -Evidence ([ordered]@{ RealTimeProtection = $rtp; AntivirusEnabled = $av; ThirdPartyAV = $thirdParty })))
        }
        # Tamper protection off
        if ((Get-WfxValue $def 'TamperProtectionEnabled' $null) -eq $false) {
            $findings.Add((New-WfxFinding -Id 'POSTURE-TAMPER-OFF' -Title 'Defender Tamper Protection is off' `
                        -Severity 'Low' -Confidence 'Medium' -Category 'Posture' -Technique @('T1562.001') `
                        -Description "Tamper Protection is disabled, so Defender settings can be changed by local admin tools or malware without resistance." `
                        -Recommendation "Enable Tamper Protection (Windows Security > Virus & threat protection settings)." `
                        -Entity 'posture:defender:tamper' -HostName $HostName -Source 'posture' -Evidence ([ordered]@{ TamperProtection = $false })))
        }
        # Stale signatures
        $sigAge = Get-WfxValue $def 'SignatureAgeDays' $null
        if ($null -ne $sigAge -and [int]$sigAge -ge 7) {
            $findings.Add((New-WfxFinding -Id 'POSTURE-SIG-STALE' -Title "Antivirus signatures are $sigAge days old" `
                        -Severity 'Medium' -Confidence 'High' -Category 'Posture' -Technique @('T1562.001') `
                        -Description "Defender definitions have not updated in $sigAge days. Detection of recent threats is degraded; updates may be blocked (no connectivity, disabled service, or deliberate tampering)." `
                        -Recommendation "Force a signature update and investigate why updates stopped." `
                        -Entity 'posture:defender:sigage' -HostName $HostName -Source 'posture' -Evidence ([ordered]@{ SignatureAgeDays = $sigAge })))
        }
        # Suspicious exclusions — attackers add these to carve out a safe folder for their tools.
        $exPaths = @(Get-WfxValue $def 'ExclusionPath' @())
        foreach ($ex in $exPaths) {
            $broadOrWritable = ($ex -match '(?i)^[a-z]:\\?$' -or $ex -match '(?i)\\$' -and $ex.Length -le 4) -or (Test-WfxUserWritablePath $ex) -or ($ex -match '(?i)\\(users|temp|tmp|downloads|appdata|programdata|public)\b')
            if ($broadOrWritable) {
                $findings.Add((New-WfxFinding -Id 'POSTURE-DEFENDER-EXCLUSION' -Title "Suspicious Defender exclusion: $ex" `
                            -Severity 'Medium' -Confidence 'Medium' -Category 'Posture' -Technique @('T1562.001') `
                            -Description "Defender is configured to ignore '$ex'. Broad or user-writable exclusions are a classic way for an attacker to make a folder where their tools won't be scanned. Verify it was set intentionally." `
                            -Recommendation "Confirm the business reason for this exclusion; remove it if unexplained and scan the excluded location." `
                            -Entity "posture:defender:exclusion:$ex" -HostName $HostName -Source 'posture' -Evidence ([ordered]@{ Exclusion = $ex })))
            }
        }
        $exProc = @(Get-WfxValue $def 'ExclusionProcess' @())
        foreach ($ep in $exProc) {
            if ($ep -match '(?i)(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|python|node)\b') {
                $findings.Add((New-WfxFinding -Id 'POSTURE-DEFENDER-PROC-EXCLUSION' -Title "Defender process exclusion for an interpreter: $ep" `
                            -Severity 'Medium' -Confidence 'Medium' -Category 'Posture' -Technique @('T1562.001') `
                            -Description "Defender is told not to scan activity by '$ep'. Excluding a scripting interpreter effectively blinds AV to script-based attacks." `
                            -Recommendation "Remove the exclusion unless there is a strong, documented reason." `
                            -Entity "posture:defender:procexcl:$ep" -HostName $HostName -Source 'posture' -Evidence ([ordered]@{ Process = $ep })))
            }
        }
    } elseif ($def -and -not (Get-WfxValue $def 'Installed' $false) -and -not $hasThirdParty) {
        $findings.Add((New-WfxFinding -Id 'POSTURE-NO-AV' -Title 'No antivirus engine detected' `
                    -Severity 'Medium' -Confidence 'Low' -Category 'Posture' -Technique @('T1562.001') `
                    -Description "Neither Microsoft Defender status nor a third-party AV could be read. The host may have no active AV, or status collection was blocked." `
                    -Recommendation "Confirm an AV product is installed, running and updating." `
                    -Entity 'posture:av:none' -HostName $HostName -Source 'posture' -Evidence ([ordered]@{ ThirdPartyAV = $thirdParty })))
    }

    # ── Logging visibility ──
    $audit = Get-WfxValue $Posture 'Audit' $null
    if ($audit) {
        $sysmon = Get-WfxValue $audit 'SysmonInstalled' $false
        if ((Get-WfxValue $audit 'ProcessCreation' $false) -eq $false -and -not $sysmon) {
            $findings.Add((New-WfxFinding -Id 'POSTURE-NO-PROCESS-AUDIT' -Title 'Process-creation auditing is off (4688 / Sysmon absent)' `
                        -Severity 'Medium' -Confidence 'High' -Category 'Visibility' -Technique @('T1562.002') `
                        -Description "Neither Security 4688 process-creation auditing nor Sysmon is active. Most process-based detections in this tool and in any SIEM are blind on this host — absence of findings here does not mean absence of activity." `
                        -Recommendation "Enable 'Audit Process Creation' (Success) via GPO, or deploy Sysmon. Also enable command-line auditing." `
                        -Entity 'posture:audit:proc' -HostName $HostName -Source 'posture' -Evidence ([ordered]@{ ProcessCreationAudit = $false; Sysmon = $sysmon })))
        }
        if ((Get-WfxValue $audit 'CommandLineInProcessCreation' $false) -eq $false -and -not $sysmon) {
            $findings.Add((New-WfxFinding -Id 'POSTURE-NO-CMDLINE-AUDIT' -Title 'Command-line logging in 4688 is disabled' `
                        -Severity 'Low' -Confidence 'High' -Category 'Visibility' -Technique @('T1562.002') `
                        -Description "Process-creation events will not include command lines, so encoded/abusive command lines cannot be reviewed after the fact." `
                        -Recommendation "Enable 'Include command line in process creation events' via GPO." `
                        -Entity 'posture:audit:cmdline' -HostName $HostName -Source 'posture' -Evidence ([ordered]@{ CommandLineAudit = $false })))
        }
        if ((Get-WfxValue $audit 'ScriptBlockLogging' $false) -eq $false) {
            $findings.Add((New-WfxFinding -Id 'POSTURE-NO-SCRIPTBLOCK-LOG' -Title 'PowerShell script-block logging is off' `
                        -Severity 'Medium' -Confidence 'High' -Category 'Visibility' -Technique @('T1562.002') `
                        -Description "PowerShell Script Block Logging (4104) is disabled, so malicious/obfuscated PowerShell leaves little forensic trace. PowerShell is one of the most abused tools in intrusions." `
                        -Recommendation "Enable Script Block Logging via GPO (Administrative Templates > Windows Components > Windows PowerShell)." `
                        -Entity 'posture:audit:sbl' -HostName $HostName -Source 'posture' -Evidence ([ordered]@{ ScriptBlockLogging = $false })))
        }
    }

    # ── Firewall ──
    $fw = Get-WfxValue $Posture 'Firewall' $null
    if ($fw) {
        $off = @()
        foreach ($p in @('Domain', 'Private', 'Public')) { if ((Get-WfxValue $fw $p $true) -eq $false) { $off += $p } }
        if ($off.Count -gt 0) {
            $findings.Add((New-WfxFinding -Id 'POSTURE-FIREWALL-OFF' -Title "Windows Firewall disabled on profile(s): $($off -join ', ')" `
                        -Severity 'Medium' -Confidence 'High' -Category 'Posture' -Technique @('T1562.004') `
                        -Description "One or more firewall profiles are turned off, widening the host's network exposure. Attackers disable the firewall to enable lateral movement and inbound tooling." `
                        -Recommendation "Re-enable the firewall on all profiles and confirm it was not disabled by malware or an overly broad policy." `
                        -Entity 'posture:firewall' -HostName $HostName -Source 'posture' -Evidence ([ordered]@{ Disabled = $off })))
        }
    }

    # ── RDP without NLA ──
    $rdp = Get-WfxValue $Posture 'Rdp' $null
    if ($rdp -and (Get-WfxValue $rdp 'Enabled' $false) -and (Get-WfxValue $rdp 'NlaEnabled' $true) -eq $false) {
        $findings.Add((New-WfxFinding -Id 'POSTURE-RDP-NO-NLA' -Title 'RDP is enabled without Network Level Authentication' `
                    -Severity 'Medium' -Confidence 'High' -Category 'Posture' -Technique @('T1021.001') `
                    -Description "Remote Desktop is accepting connections without NLA, which weakens protection against unauthenticated and brute-force attacks on the RDP service." `
                    -Recommendation "Require NLA for RDP, restrict it to a VPN/jump host, and enforce account lockout + MFA where possible." `
                    -Entity 'posture:rdp:nla' -HostName $HostName -Source 'posture' -Evidence ([ordered]@{ RdpEnabled = $true; NLA = $false })))
    }

    # ── LSASS not protected (informational hardening) ──
    $lsa = Get-WfxValue $Posture 'Lsa' $null
    if ($lsa -and (Get-WfxValue $lsa 'RunAsPPL' $false) -eq $false -and (Get-WfxValue $lsa 'CredentialGuard' $false) -ne $true) {
        $findings.Add((New-WfxFinding -Id 'POSTURE-LSASS-UNPROTECTED' -Title 'LSASS is not running as a protected process (no PPL / Credential Guard)' `
                    -Severity 'Low' -Confidence 'Medium' -Category 'Posture' -Technique @('T1003.001') `
                    -Description "LSASS has neither RunAsPPL nor Credential Guard enabled, so credential material in memory is easier for an admin-level attacker to access. This is a hardening gap, not evidence of compromise." `
                    -Recommendation "Enable LSA Protection (RunAsPPL) and, where supported, Credential Guard." `
                    -Entity 'posture:lsa:ppl' -HostName $HostName -Source 'posture' -Evidence ([ordered]@{ RunAsPPL = $false; CredentialGuard = (Get-WfxValue $lsa 'CredentialGuard' $null) })))
    }

    return , (Merge-WfxFinding -Finding $findings.ToArray())
}
