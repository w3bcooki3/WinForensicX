# Persistence analyzer. Operates on normalized autostart entries:
#   { Kind, Name, Command, Path, Location, User, Enabled, SignatureStatus }
# Kind ∈ RunKey, Startup, Service, ScheduledTask, WmiSubscription, Winlogon, AppInit, ImageFileExecution,
#         ComHijack, LsaProvider, BootExecute, Driver, OfficeAddin, BrowserExtension.

function Invoke-WfxPersistenceAnalyzer {
    param([object[]]$Autostart, [string]$HostName = '')
    $findings = New-Object System.Collections.Generic.List[object]
    $items = @($Autostart | Where-Object { $_ })
    if ($items.Count -eq 0) { return , $findings.ToArray() }

    $threats = Get-WfxRulePack -Name 'threats'
    $drivers = @($threats.vulnerableDrivers | ForEach-Object { $_.ToLowerInvariant() })

    foreach ($a in $items) {
        $kind = [string](Get-WfxValue $a 'Kind' '')
        $name = [string](Get-WfxValue $a 'Name' '')
        $cmd = [string](Get-WfxValue $a 'Command' '')
        $path = [string](Get-WfxValue $a 'Path' '')
        if (-not $path -and $cmd) { $path = Get-WfxImagePath $cmd }
        $loc = [string](Get-WfxValue $a 'Location' '')
        $sig = [string](Get-WfxValue $a 'SignatureStatus' '')
        $entity = "autostart:$kind`:$name"
        $userWritable = (Test-WfxUserWritablePath $path) -or (Test-WfxUserWritablePath $cmd)

        # Command-line rules apply to the autostart command too (encoded PS, proxy exec, etc.)
        foreach ($r in (Test-WfxCommandLine -CommandLine $cmd -Image $path)) {
            $findings.Add((New-WfxFinding -Id $r.id -Title "$($r.title) (in $kind persistence)" -Severity $r.severity -Confidence $r.confidence `
                        -Category 'Persistence' -Technique $r.technique -Description $r.description -Recommendation $r.recommendation `
                        -Entity $entity -HostName $HostName -Source 'persistence' `
                        -Evidence ([ordered]@{ Kind = $kind; Name = $name; Location = $loc; Command = (Protect-WfxText $cmd) })))
        }

        # High-signal persistence locations are suspicious on their own.
        $highSignal = @{
            'WmiSubscription'     = @('T1546.003', 'A WMI event subscription runs code when a system event fires. Rarely legitimate and a favourite stealthy persistence mechanism.')
            'AppInit'             = @('T1546.010', 'AppInit_DLLs loads a DLL into almost every process. Legacy and heavily abused.')
            'ImageFileExecution'  = @('T1546.012', 'An Image File Execution Options debugger hijacks a program so an attacker binary runs in its place (also used to disable security tools).')
            'ComHijack'           = @('T1546.015', 'A COM object was redirected to a user-controlled DLL/command — a quiet persistence and defense-evasion trick.')
            'LsaProvider'         = @('T1547.004', 'A security/authentication package was registered with LSA, which can capture credentials and persist.')
            'Winlogon'            = @('T1547.004', 'A Winlogon helper (Shell/Userinit/Notify) was modified to run extra code at logon.')
            'BootExecute'         = @('T1547.001', 'A BootExecute entry runs before the user logs on and is very rarely changed legitimately.')
        }
        if ($highSignal.ContainsKey($kind)) {
            $info = $highSignal[$kind]
            $sev = if ($userWritable -or ($sig -and $sig -notin @('Valid', 'Signed', 'Trusted', ''))) { 'High' } else { 'Medium' }
            $findings.Add((New-WfxFinding -Id "PERSIST-$($kind.ToUpper())" -Title "$kind persistence: $name" -Severity $sev -Confidence 'Medium' `
                        -Category 'Persistence' -Technique @($info[0]) -Description $info[1] `
                        -Recommendation "Confirm this entry is expected; capture and analyze the referenced code before removing it." `
                        -Entity $entity -HostName $HostName -Source 'persistence' `
                        -Evidence ([ordered]@{ Kind = $kind; Name = $name; Location = $loc; Command = (Protect-WfxText $cmd); Path = $path; Signature = $sig })))
        }

        # Run keys / startup / services / tasks pointing at user-writable or unsigned binaries.
        if ($kind -in @('RunKey', 'Startup', 'Service', 'ScheduledTask') -and ($userWritable -or ($sig -and $sig -notin @('Valid', 'Signed', 'Trusted', '')))) {
            $tech = switch ($kind) { 'RunKey' { 'T1547.001' } 'Startup' { 'T1547.001' } 'Service' { 'T1543.003' } 'ScheduledTask' { 'T1053.005' } }
            $findings.Add((New-WfxFinding -Id "PERSIST-$($kind.ToUpper())-SUSPECT" -Title "$kind autostart from an untrusted location: $name" `
                        -Severity 'Medium' -Confidence 'Medium' -Category 'Persistence' -Technique @($tech) `
                        -Description "A $kind autostart entry runs a program that is unsigned or located in a user-writable folder — a common way malware survives reboot." `
                        -Recommendation "Verify the program's publisher and purpose; remove if not legitimate." `
                        -Entity $entity -HostName $HostName -Source 'persistence' `
                        -Evidence ([ordered]@{ Kind = $kind; Name = $name; Location = $loc; Path = $path; Signature = $sig; Command = (Protect-WfxText $cmd) })))
        }

        # Known-vulnerable driver used for BYOVD.
        if ($kind -eq 'Driver') {
            $leaf = (Get-WfxLeaf $path).ToLowerInvariant()
            if ($drivers -contains $leaf) {
                $findings.Add((New-WfxFinding -Id 'PERSIST-VULN-DRIVER' -Title "Known-vulnerable driver installed: $leaf" `
                            -Severity 'High' -Confidence 'Medium' -Category 'Persistence' -Technique @('T1068', 'T1562.001') `
                            -Description "A driver known to be abused in bring-your-own-vulnerable-driver attacks is present. $($threats.vulnerableDriverNote)" `
                            -Recommendation "Confirm the driver is required. If not, remove it; attackers use these to disable EDR and gain kernel access." `
                            -Entity $entity -HostName $HostName -Source 'persistence' `
                            -Evidence ([ordered]@{ Driver = $leaf; Path = $path; Signature = $sig })))
            } elseif ($userWritable) {
                $findings.Add((New-WfxFinding -Id 'PERSIST-DRIVER-USERPATH' -Title "Driver loaded from a user-writable path: $(Get-WfxLeaf $path)" `
                            -Severity 'High' -Confidence 'Medium' -Category 'Persistence' -Technique @('T1014') `
                            -Description "A kernel driver is loaded from an unusual, user-writable location. Legitimate drivers live under System32\drivers." `
                            -Recommendation "Verify the driver's signature and origin." `
                            -Entity $entity -HostName $HostName -Source 'persistence' -Evidence ([ordered]@{ Path = $path; Signature = $sig })))
            }
        }
    }
    return , (Merge-WfxFinding -Finding $findings.ToArray())
}
