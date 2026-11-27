# Network isolation with an automatic way back, and a Microsoft Defender second opinion.
#
# Isolation adds two Windows Firewall rules that block every address except the ones you allow. Block rules
# win over allow rules in Windows Firewall, so other software's allow rules cannot punch through. Allowed
# automatically: the address of the session you are connected from (RDP, WinRM, SSH), so you are not cut
# off, and the DHCP server, so the computer keeps its address. Loopback is never blocked.
# By default the isolation ends by itself after 30 minutes: a one-time scheduled task (running as SYSTEM)
# removes the two rules. That is the safety net if the block cuts off more than intended. End it earlier with
# Stop-WfxIsolation; make it last with -Minutes 0 (asks twice).

$script:WfxIsolationRules = @('WFX-Isolation-In', 'WFX-Isolation-Out')
$script:WfxIsolationTask = @{ Path = '\WinForensicX\'; Name = 'Isolation revert' }

function Initialize-WfxNumerics { if (-not ('System.Numerics.BigInteger' -as [type])) { Add-Type -AssemblyName System.Numerics } }

function ConvertTo-WfxIpNumber {
    <# An IP address as an unsigned number (BigInteger). Pure. #>
    param([Parameter(Mandatory)][System.Net.IPAddress]$Ip)
    Initialize-WfxNumerics
    $b = $Ip.GetAddressBytes(); [array]::Reverse($b)
    New-Object System.Numerics.BigInteger (, [byte[]]($b + [byte]0))
}

function ConvertFrom-WfxIpNumber {
    param([Parameter(Mandatory)]$Number, [ValidateSet(4, 6)][int]$Family)
    $len = if ($Family -eq 4) { 4 } else { 16 }
    $raw = $Number.ToByteArray()
    $b = New-Object byte[] $len
    [Array]::Copy($raw, $b, [Math]::Min($len, $raw.Length))
    [array]::Reverse($b)
    ([System.Net.IPAddress]::new($b)).ToString()
}

function Get-WfxComplementRange {
    <#
    .SYNOPSIS Address ranges covering everything EXCEPT the given addresses, for one address family, in the
    "a-b" form firewall rules accept. Loopback is always left out. Pure.
    #>
    param([string[]]$Allow = @(), [ValidateSet(4, 6)][int]$Family = 4)
    Initialize-WfxNumerics
    $af = if ($Family -eq 4) { 'InterNetwork' } else { 'InterNetworkV6' }
    $iv = [System.Collections.Generic.List[object]]::new()
    foreach ($a in @($Allow | Where-Object { $_ })) {
        $ip = $null
        if ([System.Net.IPAddress]::TryParse(([string]$a -replace '%\d+$', ''), [ref]$ip) -and [string]$ip.AddressFamily -eq $af) { $n = ConvertTo-WfxIpNumber $ip; $iv.Add(@($n, $n)) }
    }
    if ($Family -eq 4) { $iv.Add(@((ConvertTo-WfxIpNumber ([System.Net.IPAddress]::Parse('127.0.0.0'))), (ConvertTo-WfxIpNumber ([System.Net.IPAddress]::Parse('127.255.255.255'))))) }
    else { $one = ConvertTo-WfxIpNumber ([System.Net.IPAddress]::IPv6Loopback); $iv.Add(@($one, $one)) }
    $max = [System.Numerics.BigInteger]::Pow(2, $(if ($Family -eq 4) { 32 } else { 128 })) - 1
    $sorted = @($iv | Sort-Object { $_[0] })
    $out = [System.Collections.Generic.List[string]]::new()
    $start = [System.Numerics.BigInteger]::Zero
    foreach ($r in $sorted) {
        if ($r[0] -gt $start) {
            $end = $r[0] - 1
            $s = ConvertFrom-WfxIpNumber $start $Family; $e = ConvertFrom-WfxIpNumber $end $Family
            $out.Add($(if ($s -eq $e) { $s } else { "$s-$e" }))
        }
        if ($r[1] + 1 -gt $start) { $start = $r[1] + 1 }
    }
    if ($start -le $max) { $out.Add(("{0}-{1}" -f (ConvertFrom-WfxIpNumber $start $Family), (ConvertFrom-WfxIpNumber $max $Family))) }
    , $out.ToArray()
}

function Get-WfxSessionAddress {
    <# Remote addresses of the sessions this computer is being managed through right now (RDP, WinRM, SSH). #>
    @(try {
            Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object { $_.LocalPort -in 3389, 5985, 5986, 22 -and $_.RemoteAddress -notmatch '^(?:127\.|::1$|0\.0\.0\.0)' } | ForEach-Object { [string]$_.RemoteAddress }
        } catch { }) | Sort-Object -Unique
}

function Stop-WfxIsolationCore {
    <# Removes the isolation rules and the revert task, and turns back off any firewall profile isolation turned on. #>
    param($Undo = $null)
    Remove-NetFirewallRule -Name $script:WfxIsolationRules -Confirm:$false -ErrorAction SilentlyContinue
    $on = @(Get-WfxValue $Undo 'ProfilesEnabled' @() | Where-Object { $_ })
    if ($on.Count) { Set-NetFirewallProfile -Profile $on -Enabled False -Confirm:$false -ErrorAction SilentlyContinue }
    Unregister-ScheduledTask -TaskPath $script:WfxIsolationTask.Path -TaskName $script:WfxIsolationTask.Name -Confirm:$false -ErrorAction SilentlyContinue
}

function Start-WfxIsolation {
    <#
    .SYNOPSIS
        Cuts this computer off the network except for the addresses you allow, and puts it back by itself after
        -Minutes (default 30). Needs administrator rights.
    .DESCRIPTION
        Allowed automatically: the session you are connected from (RDP / WinRM / SSH) and the DHCP server(s).
        -AllowDns also allows the configured DNS servers. Add a management server, EDR console or file server
        with -Allow. Stop-WfxIsolation (or Undo-WfxAction) ends it early; -Minutes 0 keeps it until you do.
    .EXAMPLE
        Start-WfxIsolation -Minutes 30 -Allow 10.0.0.15
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([ValidateRange(0, 10080)][int]$Minutes = 30, [string[]]$Allow = @(), [switch]$AllowDns, [string]$QuarantinePath = '', [switch]$Force)
    if (-not (Test-WfxWindows)) { throw 'Isolation needs Windows.' }
    if (-not (Test-WfxAdmin) -and -not $WhatIfPreference) { throw 'Isolation needs administrator rights.' }
    if (Get-NetFirewallRule -Name $script:WfxIsolationRules[0] -ErrorAction SilentlyContinue) { throw 'This computer is already isolated by WinForensicX. Stop-WfxIsolation ends it.' }
    foreach ($a in $Allow) { $ip = $null; if (-not [System.Net.IPAddress]::TryParse($a, [ref]$ip)) { throw "-Allow takes IP addresses; '$a' is not one." } }
    $sessions = @(Get-WfxSessionAddress)
    $cfg = @(try { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop } catch { })
    $dhcp = @($cfg | ForEach-Object { [string]$_.DHCPServer } | Where-Object { $_ -and $_ -ne '255.255.255.255' } | Sort-Object -Unique)
    $dns = if ($AllowDns) { @($cfg | ForEach-Object { $_.DNSServerSearchOrder } | Where-Object { $_ } | Sort-Object -Unique) } else { @() }
    $allowed = @(@($Allow) + $sessions + $dhcp + $dns | Where-Object { $_ } | Sort-Object -Unique)
    $ranges = @(Get-WfxComplementRange -Allow $allowed -Family 4) + @(Get-WfxComplementRange -Allow $allowed -Family 6)
    $profilesOff = @(try { Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled } | ForEach-Object { [string]$_.Name } } catch { })

    Write-WfxConsole ''
    Write-WfxConsole ('  Allowed through: {0}' -f $(if ($allowed.Count) { $allowed -join ', ' } else { 'nothing (no remote session, no DHCP server found)' })) -Kind Info
    if ($sessions.Count) { Write-WfxConsole ('  (your session from {0} stays connected)' -f ($sessions -join ', ')) -Kind Dim }
    if ($profilesOff.Count) { Write-WfxConsole ("  The firewall is off for: {0}. It will be turned on for the isolation and off again after." -f ($profilesOff -join ', ')) -Kind Warn }
    Write-WfxConsole $(if ($Minutes) { "  The isolation ends by itself in $Minutes minute(s)." } else { '  No automatic end: it lasts until Stop-WfxIsolation.' }) -Kind $(if ($Minutes) { 'Dim' } else { 'Warn' })
    if (-not $Minutes -and -not $Force -and -not $WhatIfPreference) {
        if (-not $PSCmdlet.ShouldContinue('Isolation with no automatic end: if it also blocks your way in, only someone at the console can end it. Continue?', 'WinForensicX: are you sure?')) { return }
    }
    if (-not $PSCmdlet.ShouldProcess([Environment]::MachineName, "Block all network traffic except $($allowed.Count) allowed address(es)")) { return }

    $root = Initialize-WfxQuarantineRoot -Path $QuarantinePath
    $rec = [ordered]@{
        Id = ('{0}-{1}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'), [guid]::NewGuid().ToString('N').Substring(0, 6))
        Type = 'Isolate'; Target = [Environment]::MachineName; Reason = 'Network isolation'; Findings = @(); Status = ''; Message = ''; Time = (Get-WfxUtcNow)
        Operator = [Environment]::UserName; Host = [Environment]::MachineName; Reversible = $true
        Evidence = [ordered]@{ Allowed = $allowed; Sessions = $sessions; Dhcp = $dhcp; Dns = $dns; Minutes = $Minutes; Until = $(if ($Minutes) { ConvertTo-WfxUtcString (Get-Date).AddMinutes($Minutes) } else { '' }) }
        Undo = [ordered]@{ Rules = $script:WfxIsolationRules; ProfilesEnabled = $profilesOff; Task = ($script:WfxIsolationTask.Path + $script:WfxIsolationTask.Name) }; Undone = ''
    }
    try {
        if ($profilesOff.Count) { Set-NetFirewallProfile -Profile $profilesOff -Enabled True -Confirm:$false -ErrorAction Stop }
        foreach ($d in 'Inbound', 'Outbound') {
            $n = if ($d -eq 'Inbound') { $script:WfxIsolationRules[0] } else { $script:WfxIsolationRules[1] }
            New-NetFirewallRule -Name $n -DisplayName "WinForensicX isolation ($d)" -Group 'WinForensicX isolation' -Direction $d -RemoteAddress $ranges -Action Block -Profile Any -ErrorAction Stop | Out-Null
        }
        if ($Minutes) {
            # Plain, readable command (no encoding); it only removes the two rules, restores profiles and deletes itself.
            $cmd = "Remove-NetFirewallRule -Name '$($script:WfxIsolationRules[0])','$($script:WfxIsolationRules[1])' -ErrorAction SilentlyContinue"
            if ($profilesOff.Count) { $cmd += "; Set-NetFirewallProfile -Profile $($profilesOff -join ',') -Enabled False" }
            $cmd += "; Unregister-ScheduledTask -TaskPath '$($script:WfxIsolationTask.Path)' -TaskName '$($script:WfxIsolationTask.Name)' -Confirm:`$false"
            $act = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument "-NoProfile -NonInteractive -Command `"$cmd`""
            $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($Minutes)
            $pri = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
            $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
            Register-ScheduledTask -TaskPath $script:WfxIsolationTask.Path -TaskName $script:WfxIsolationTask.Name -Action $act -Trigger $trg -Principal $pri -Settings $set -Description 'Ends the network isolation started by WinForensicX.' -ErrorAction Stop | Out-Null
        }
        $rec.Status = 'Done'; $rec.Message = $(if ($Minutes) { "Isolated until $($rec.Evidence.Until) UTC." } else { 'Isolated until Stop-WfxIsolation.' })
    } catch {
        # Never leave the computer isolated without the way back that was asked for.
        Stop-WfxIsolationCore -Undo $rec.Undo
        $rec.Status = 'Failed'; $rec.Message = "Not isolated: $($_.Exception.Message) (everything was put back)."
    }
    Save-WfxActionRecord -Record $rec -Root $root
    [pscustomobject]$rec
}

function Stop-WfxIsolation {
    <# Ends a WinForensicX network isolation now: removes its firewall rules and its revert task. #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$QuarantinePath = '')
    if (-not (Test-WfxAdmin) -and -not $WhatIfPreference) { throw 'Needs administrator rights.' }
    $open = @(Get-WfxActionRecord -Root (Get-WfxQuarantineRoot -Path $QuarantinePath) | Where-Object { $_.Type -eq 'Isolate' -and $_.Status -eq 'Done' -and -not $_.Undone }) | Select-Object -First 1
    if ($open) { Undo-WfxAction -Id $open.Id -QuarantinePath $QuarantinePath -Confirm:$false -WhatIf:$WhatIfPreference; return }
    if (Get-NetFirewallRule -Name $script:WfxIsolationRules[0] -ErrorAction SilentlyContinue) {
        if ($PSCmdlet.ShouldProcess([Environment]::MachineName, 'Remove the WinForensicX isolation rules')) { Stop-WfxIsolationCore }
    } else { Write-WfxConsole '  This computer is not isolated by WinForensicX.' -Kind Dim }
}

function Invoke-WfxDefenderScan {
    <#
    .SYNOPSIS A second opinion from Microsoft Defender: scans the given files or folders (or a quick scan) and
    returns what it detected during this scan.
    .DESCRIPTION Defender acts on what it finds according to its own settings (it may quarantine or remove
    files), so this asks for confirmation. Quarantine suspects with Invoke-WfxRespond first if you want to keep
    them as evidence.
    .EXAMPLE
        Invoke-WfxDefenderScan -Path C:\Users\ana\AppData\Roaming\upd
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string[]]$Path = @(), [switch]$Quick)
    if (-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)) { throw 'Microsoft Defender is not available on this computer.' }
    if (-not $Path.Count -and -not $Quick) { throw 'Give -Path, or -Quick for a quick scan.' }
    $what = if ($Quick) { 'a Defender quick scan' } else { "a Defender scan of $($Path -join ', ')" }
    if (-not $PSCmdlet.ShouldProcess([Environment]::MachineName, "Run $what (Defender may quarantine or remove what it finds)")) { return }
    $start = (Get-Date).AddSeconds(-5)
    if ($Quick) { Start-MpScan -ScanType QuickScan -ErrorAction Stop }
    foreach ($p in $Path) { Start-MpScan -ScanType CustomScan -ScanPath $p -ErrorAction Stop }
    $names = @{}; foreach ($t in @(Get-MpThreat -ErrorAction SilentlyContinue)) { $names[[string]$t.ThreatID] = [string]$t.ThreatName }
    $hits = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge $start })
    if (-not $hits.Count) { Write-WfxConsole "  Defender found nothing in $what. (Absence of a detection is not proof that a file is safe.)" -Kind Dim; return }
    foreach ($h in $hits) {
        [pscustomobject]@{ Threat = $names[[string]$h.ThreatID]; ThreatId = $h.ThreatID; Detected = (ConvertTo-WfxUtcString $h.InitialDetectionTime); Resources = @($h.Resources); ActionSuccess = $h.ActionSuccess; Process = [string]$h.ProcessName }
    }
}
