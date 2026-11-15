# Per-host summaries saved in result.json so many cases can be compared without reloading raw evidence:
#  * Programs  - every program path seen (processes, autostarts, execution artifacts, process-start events),
#                for "seen on one host only" (rarity) across a fleet.
#  * Logons    - remote logons into the host and connections / credential use out of it, for drawing
#                movement between hosts.
#  * Addresses - the host's own IP addresses, so other hosts' logon records can be matched to it.

function ConvertTo-WfxProgramKey {
    <# Path key that is stable across machines: no drive, user name or version folders, lower case. #>
    param([string]$Path)
    $p = ([string]$Path).Trim().Trim('"').ToLowerInvariant()
    if (-not $p) { return '' }
    $p = $p -replace '^\\\\\?\\', '' -replace '^\\device\\harddiskvolume\d+', '' -replace '^\(volume\)', '' -replace '^[a-z]:', '' -replace '/', '\'
    $p = $p -replace '^%systemroot%', '\windows' -replace '^%windir%', '\windows' -replace '^%programfiles%', '\program files' -replace '^\\systemroot\\', '\windows\'
    $p = $p -replace '\\users\\[^\\]+\\', '\users\*\' -replace '\\(?:\d+\.){1,3}\d+(?:[-_.][^\\]*)?\\', '\*\' -replace '\\\{[0-9a-f-]{36}\}\\', '\{guid}\'
    $p
}

function Get-WfxProgramSummary {
    <# Distinct programs seen on the host: { Key; Path; Sources; Last }. #>
    param($Bundle, [object[]]$Event = @(), [object[]]$Artifact = @(), [int]$Max = 20000)
    $map = @{}
    $add = {
        param([string]$Path, [string]$Source, $Time)
        if (-not $Path -or $Path -notmatch '(?i)\.(?:exe|dll|sys|scr|com|ps1|bat|cmd|vbs|js|hta|msi)$') { return }
        $k = ConvertTo-WfxProgramKey $Path; if (-not $k) { return }
        if (-not $map.ContainsKey($k)) { if ($map.Count -ge $Max) { return }; $map[$k] = [pscustomobject]@{ Key = $k; Path = $Path; Sources = New-Object System.Collections.Generic.List[string]; Last = '' } }
        $m = $map[$k]
        if (-not $m.Sources.Contains($Source)) { $m.Sources.Add($Source) }
        $t = if ($Time) { ConvertTo-WfxUtcString $Time } else { '' }
        if ($t -and $t -gt $m.Last) { $m.Last = $t }
    }
    foreach ($p in @(Get-WfxValue $Bundle 'Process' @())) { & $add ([string](Get-WfxValue $p 'Path' '')) 'Process' (Get-WfxValue $p 'CreateTime' $null) }
    foreach ($p in @(Get-WfxValue $Bundle 'Persistence' @())) { $pp = [string](Get-WfxValue $p 'Path' ''); if (-not $pp) { $pp = Get-WfxImagePath ([string](Get-WfxValue $p 'Command' '')) }; & $add $pp 'Autostart' $null }
    foreach ($a in $Artifact) { if ($a -and $a.Evidence -in 'Execution', 'Install', 'Presence') { & $add ([string]$a.Path) ([string]$a.Artifact) $a.Time } }
    foreach ($e in $Event) {
        $id = ConvertTo-WfxInt (Get-WfxValue $e 'Id' 0); $fl = Get-WfxValue $e 'Fields' $null; if (-not $fl -or $fl -is [string]) { continue }
        if ($id -eq 1 -and [string](Get-WfxValue $e 'Log' '') -match 'Sysmon') { & $add ([string](Get-WfxValue $fl 'Image' '')) 'Sysmon 1' (Get-WfxValue $e 'TimeCreated' $null) }
        elseif ($id -eq 4688) { & $add ([string](Get-WfxValue $fl 'NewProcessName' '')) 'Security 4688' (Get-WfxValue $e 'TimeCreated' $null) }
    }
    , @($map.Values | Sort-Object Key | ForEach-Object { [pscustomobject]@{ Key = $_.Key; Path = $_.Path; Sources = ($_.Sources -join ', '); Last = $_.Last } })
}

function Get-WfxLogonSummary {
    <#
    Remote access into and out of the host, aggregated: { Direction (In/Out); Kind; Peer; PeerName; Account;
    Detail; Count; First; Last }. In: 4624 network (3) and remote-desktop (10) logons from another machine.
    Out: 4648 logons with explicit credentials to another server, Sysmon 3 connections to SMB, RDP, WinRM, RPC.
    #>
    param([object[]]$Event = @(), [int]$Max = 2000)
    $agg = @{}
    $add = {
        param($Dir, $Kind, $Peer, $PeerName, $Account, $Detail, $Time)
        $Peer = ([string]$Peer).Trim(); $PeerName = ([string]$PeerName).Trim()
        if ((-not $Peer -or $Peer -in '-', '::1', '127.0.0.1', '0.0.0.0', 'localhost') -and (-not $PeerName -or $PeerName -eq '-')) { return }
        if ($Peer -in '-', '::1', '127.0.0.1', '0.0.0.0') { $Peer = '' }
        $k = "$Dir|$Kind|$($Peer.ToLowerInvariant())|$($PeerName.ToLowerInvariant())|$(([string]$Account).ToLowerInvariant())|$Detail"
        if (-not $agg.ContainsKey($k)) { if ($agg.Count -ge $Max) { return }; $agg[$k] = [pscustomobject]@{ Direction = $Dir; Kind = $Kind; Peer = $Peer; PeerName = $PeerName; Account = [string]$Account; Detail = $Detail; Count = 0; First = ''; Last = '' } }
        $g = $agg[$k]; $g.Count++
        $t = ConvertTo-WfxUtcString $Time
        if ($t) { if (-not $g.First -or $t -lt $g.First) { $g.First = $t }; if ($t -gt $g.Last) { $g.Last = $t } }
    }
    foreach ($e in $Event) {
        if (-not $e) { continue }
        $id = ConvertTo-WfxInt (Get-WfxValue $e 'Id' 0); $log = [string](Get-WfxValue $e 'Log' ''); $fl = Get-WfxValue $e 'Fields' $null
        if (-not $fl -or $fl -is [string]) { continue }
        $g = { param($n) [string](Get-WfxValue $fl $n '') }
        $t = Get-WfxValue $e 'TimeCreated' $null
        if ($log -eq 'Security' -and $id -eq 4624) {
            $lt = & $g 'LogonType'
            if ($lt -notin '3', '10') { continue }
            $user = & $g 'TargetUserName'
            if (-not $user -or $user -match '\$$' -or $user -match '^(?:ANONYMOUS LOGON|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d+|UMFD-\d+)$') { continue }
            $dom = & $g 'TargetDomainName'; $acct = if ($dom -and $dom -ne '-') { "$dom\$user" } else { $user }
            & $add 'In' $(if ($lt -eq '10') { 'Remote desktop logon' } else { 'Network logon' }) (& $g 'IpAddress') (& $g 'WorkstationName') $acct "type $lt" $t
        } elseif ($log -eq 'Security' -and $id -eq 4648) {
            $srv = & $g 'TargetServerName'
            if (-not $srv -or $srv -in 'localhost', '-') { continue }
            $acct = & $g 'TargetUserName'; $dom = & $g 'TargetDomainName'; if ($dom -and $dom -ne '-') { $acct = "$dom\$acct" }
            & $add 'Out' 'Explicit credentials' '' $srv $acct (& $g 'ProcessName') $t
        } elseif ($log -match 'Sysmon' -and $id -eq 3) {
            $port = & $g 'DestinationPort'
            $svc = @{ '445' = 'SMB'; '3389' = 'Remote desktop'; '5985' = 'WinRM'; '5986' = 'WinRM'; '135' = 'RPC'; '22' = 'SSH' }[$port]
            if (-not $svc -or (& $g 'Initiated') -match '(?i)^false$') { continue }
            & $add 'Out' "$svc connection" (& $g 'DestinationIp') (& $g 'DestinationHostname') (& $g 'User') ((& $g 'Image') -replace '^.*\\', '') $t
        }
    }
    , @($agg.Values | Sort-Object First)
}

function Get-WfxHostAddress {
    <# The host's own addresses: from host info, else the local side of its connections. #>
    param($Bundle)
    $set = New-Object System.Collections.Generic.HashSet[string]
    $h = Get-WfxValue $Bundle 'Host' $null
    foreach ($a in @(Get-WfxValue $h 'Addresses' @())) { if ($a) { [void]$set.Add([string]$a) } }
    foreach ($c in @(Get-WfxValue $Bundle 'Network' @())) {
        $la = [string](Get-WfxValue $c 'LocalAddress' '')
        if ($la -and $la -notmatch '^(?:0\.0\.0\.0|127\.|::|::1|fe80:|0:0:)' -and $la -ne '::') { [void]$set.Add($la) }
    }
    , @($set | Sort-Object)
}
