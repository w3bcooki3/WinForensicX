# Secrets-exposure & security-hygiene analyzer.
#
# This is a DEFENSIVE audit: it reports WHERE sensitive material or a misconfiguration exists and
# WHY it is a risk, so it can be remediated. It never emits secret values — matches are redacted to a
# type + length via Find-WfxSecret / Format-WfxSecret — and it does not read, copy, decrypt or parse
# credential stores (SAM/NTDS, browser login DBs, DPAPI, LSASS). Detecting exposure needs none of that.
#
# Input: normalized exposure records the collector builds:
#   { Kind, Path, Detail, Accessible, WorldReadable, Content (small text only, for secret scanning) }
# Kind ∈ GppCpassword, UnattendPassword, SensitiveHive, ShadowCopy, CredFileWorldReadable,
#        SecretInFile, SecretInEnv, SecretInHistory, AiKey, SshKeyUnprotected, AutoLogon.

function Invoke-WfxExposureAnalyzer {
    param([object[]]$Exposure, [string]$HostName = '')
    $findings = New-Object System.Collections.Generic.List[object]
    $items = @($Exposure | Where-Object { $_ })
    if ($items.Count -eq 0) { return , $findings.ToArray() }

    foreach ($x in $items) {
        $kind = [string](Get-WfxValue $x 'Kind' '')
        $path = [string](Get-WfxValue $x 'Path' '')
        $detail = [string](Get-WfxValue $x 'Detail' '')
        $content = [string](Get-WfxValue $x 'Content' '')
        $entity = "exposure:$kind`:$path"

        switch ($kind) {
            'GppCpassword' {
                $findings.Add((New-WfxFinding -Id 'EXPO-GPP-CPASSWORD' -Title "Group Policy Preferences password (MS14-025): $(Get-WfxLeaf $path)" `
                            -Severity 'Critical' -Confidence 'High' -Category 'Exposure' -Technique @('T1552.006') `
                            -Description "A GPP XML file contains a cPassword. Microsoft published the decryption key in 2014, so any domain user can recover this password. It is one of the most reliable privilege-escalation findings in a Windows domain." `
                            -Recommendation "Remove the GPP that sets the password, change the affected account's password, and apply KB2962486. Use Windows LAPS to manage local admin passwords instead." `
                            -Entity $entity -HostName $HostName -Source 'exposure' -Evidence ([ordered]@{ Path = $path })))
            }
            'UnattendPassword' {
                $findings.Add((New-WfxFinding -Id 'EXPO-UNATTEND-PASSWORD' -Title "Credential in an unattended-install file: $(Get-WfxLeaf $path)" `
                            -Severity 'High' -Confidence 'High' -Category 'Exposure' -Technique @('T1552.001') `
                            -Description "A Windows unattended-setup file contains a password (sometimes only Base64-wrapped, not encrypted). These are readable by anyone who can reach the file." `
                            -Recommendation "Remove the file or the password element, and rotate the account's password." `
                            -Entity $entity -HostName $HostName -Source 'exposure' -Evidence ([ordered]@{ Path = $path })))
            }
            'SensitiveHive' {
                $acc = [bool](Get-WfxValue $x 'Accessible' $false)
                $findings.Add((New-WfxFinding -Id 'EXPO-HIVE-ACCESS' -Title "$detail readable by non-administrators" `
                            -Severity 'High' -Confidence 'Medium' -Category 'Exposure' -Technique @('T1003.002') `
                            -Description "A registry hive or database that stores password material ($detail) is accessible to accounts that should not be able to read it. An attacker could copy it and recover hashes offline." `
                            -Recommendation "Restore correct ACLs (only SYSTEM/Administrators). If the file is a stray backup, remove it. Review how it became readable." `
                            -Entity $entity -HostName $HostName -Source 'exposure' -Evidence ([ordered]@{ Path = $path; Accessible = $acc })))
            }
            'ShadowCopy' {
                $findings.Add((New-WfxFinding -Id 'EXPO-SHADOW-COPY' -Title "Volume shadow copies present ($detail)" `
                            -Severity 'Low' -Confidence 'Low' -Category 'Exposure' -Technique @('T1003.002') `
                            -Description "Volume Shadow Copies exist. They are useful for recovery, but also let an attacker with admin rights read otherwise-locked files such as the SAM hive. Reported for awareness, not as a compromise." `
                            -Recommendation "This is informational. Ensure admin access to the host is tightly controlled." `
                            -Entity $entity -HostName $HostName -Source 'exposure' -Evidence ([ordered]@{ Detail = $detail })))
            }
            'CredFileWorldReadable' {
                $findings.Add((New-WfxFinding -Id 'EXPO-CREDFILE-READABLE' -Title "Credential file readable by other users: $(Get-WfxLeaf $path)" `
                            -Severity 'High' -Confidence 'Medium' -Category 'Exposure' -Technique @('T1552.001') `
                            -Description "A file that normally holds credentials ($detail) can be read by users other than its owner. On a shared machine this exposes those credentials." `
                            -Recommendation "Restrict the file's permissions to its owner, and rotate any credentials it contains." `
                            -Entity $entity -HostName $HostName -Source 'exposure' -Evidence ([ordered]@{ Path = $path; Detail = $detail })))
            }
            'AutoLogon' {
                $findings.Add((New-WfxFinding -Id 'EXPO-AUTOLOGON' -Title "Automatic logon password stored in the registry" `
                            -Severity 'High' -Confidence 'High' -Category 'Exposure' -Technique @('T1552.001') `
                            -Description "A DefaultPassword is stored in clear text under Winlogon for automatic logon. Any local user can read it." `
                            -Recommendation "Disable auto-logon, or use the LSA-secrets method; rotate the password." `
                            -Entity $entity -HostName $HostName -Source 'exposure' -Evidence ([ordered]@{ Account = $detail })))
            }
            'SshKeyUnprotected' {
                $findings.Add((New-WfxFinding -Id 'EXPO-SSH-KEY' -Title "Unencrypted SSH private key: $(Get-WfxLeaf $path)" `
                            -Severity 'Medium' -Confidence 'Medium' -Category 'Exposure' -Technique @('T1552.004') `
                            -Description "An SSH private key is stored without a passphrase. If this host or file is compromised, the key can be used directly to reach whatever it unlocks." `
                            -Recommendation "Add a passphrase (ssh-keygen -p), restrict the file's permissions, and rotate the key if exposure is suspected." `
                            -Entity $entity -HostName $HostName -Source 'exposure' -Evidence ([ordered]@{ Path = $path })))
            }
            'AiKey' {
                $findings.Add((New-WfxFinding -Id 'AI-KEY-EXPOSED' -Title "AI provider API key in clear text: $detail" `
                            -Severity 'High' -Confidence 'High' -Category 'Exposure' -Technique @('T1552.001') `
                            -Description "An API key for an AI provider was found in clear text ($detail). These keys are billable and often broadly scoped; a leaked key can be abused immediately and run up cost." `
                            -Recommendation "Revoke and rotate the key with the provider, remove it from the file/variable, and store it in a secret manager." `
                            -Entity $entity -HostName $HostName -Source 'exposure' `
                            -Evidence ([ordered]@{ Where = $path; Type = $detail; Redacted = (Get-WfxValue $x 'Redacted' '') })))
            }
            { $_ -in @('SecretInFile', 'SecretInEnv', 'SecretInHistory') } {
                $where = switch ($kind) { 'SecretInFile' { "file $path" } 'SecretInEnv' { "environment variable $detail" } 'SecretInHistory' { "command history ($path)" } }
                # Prefer a redaction the collector already computed (so the raw value never enters a record
                # that might be persisted). Fall back to scanning Content when a caller supplied it directly.
                $preRedacted = @(Get-WfxValue $x 'Redacted' @() | Where-Object { $_ })
                $secrets = if ($content) { Find-WfxSecret $content } else { @() }
                $redactedList = if ($preRedacted.Count) { $preRedacted } else { @($secrets | ForEach-Object { "$($_.Type) (line $($_.Line)): $($_.Redacted)" }) }
                $label = if ($detail) { $detail } elseif ($secrets) { ($secrets | Select-Object -First 1).Type } elseif ($preRedacted.Count) { (($preRedacted[0] -split ' \(line| \(env')[0]) } else { 'credential-like string' }
                $sev = if ($kind -eq 'SecretInHistory') { 'Medium' } else { 'High' }
                $findings.Add((New-WfxFinding -Id "EXPO-$($kind.ToUpper())" -Title "Possible secret in $where" `
                            -Severity $sev -Confidence 'Low' -Category 'Exposure' -Technique @('T1552.001') `
                            -Description "Text that looks like a credential ($label) was found in $where. Clear-text secrets can be read by anyone (or any malware) with access to this location." `
                            -Recommendation "Confirm whether it is a live secret; if so, rotate it and move it to a secret store. Avoid passing secrets on the command line (they land in history and logs)." `
                            -Entity $entity -HostName $HostName -Source 'exposure' `
                            -Evidence ([ordered]@{ Where = $where; Type = $label; Redacted = $redactedList })))
            }
        }
    }
    return , (Merge-WfxFinding -Finding $findings.ToArray())
}
