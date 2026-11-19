# Windows collectors — gather live data into the normalized shapes the analyzers consume.
# Every collector: returns [] on non-Windows or on error (recorded as a gap), never throws, never makes
# network requests, and degrades gracefully without administrator rights. Timestamps are stored as UTC.

$script:WfxSigCache = @{}

function Get-WfxUserProfilePath {
    <# Real user-profile folders from the registry ProfileList (works when profiles are not on C:\Users). #>
    $paths = New-Object System.Collections.Generic.List[string]
    if (-not (Test-WfxWindows)) { return , $paths.ToArray() }
    try {
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop | ForEach-Object {
            if ($_.PSChildName -match '^S-1-5-21-|^S-1-12-1-') {
                $p = [Environment]::ExpandEnvironmentVariables([string]$_.GetValue('ProfileImagePath'))
                if ($p -and (Test-Path -LiteralPath $p) -and -not $paths.Contains($p)) { $paths.Add($p) }
            }
        }
    } catch {}
    if ($paths.Count -eq 0) {
        $root = Join-Path $env:SystemDrive 'Users'
        Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') } | ForEach-Object { $paths.Add($_.FullName) }
    }
    $paths.ToArray()
}

function Get-WfxHostInfo {
    if (-not (Test-WfxWindows)) {
        return [pscustomobject]@{ HostName = [Environment]::MachineName; Os = 'Non-Windows (collectors limited)'; Collected = (Get-WfxUtcNow); Admin = $false }
    }
    $os = Invoke-WfxStep 'hostinfo:os' { Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } $null
    $cs = Invoke-WfxStep 'hostinfo:cs' { Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } $null
    $tz = $null; try { $tz = Get-TimeZone -ErrorAction Stop } catch {}
    [pscustomobject]@{
        HostName     = [Environment]::MachineName
        Domain       = if ($cs) { $cs.Domain } else { '' }
        Os           = if ($os) { "$($os.Caption) $($os.Version) (build $($os.BuildNumber))" } else { '' }
        Architecture = if ($os) { [string]$os.OSArchitecture } else { '' }
        Is64BitProcess = [Environment]::Is64BitProcess
        BootUtc      = if ($os) { ConvertTo-WfxUtcString $os.LastBootUpTime } else { '' }
        InstallUtc   = if ($os) { ConvertTo-WfxUtcString $os.InstallDate } else { '' }
        Manufacturer = if ($cs) { "$($cs.Manufacturer) $($cs.Model)" } else { '' }
        Collected    = (Get-WfxUtcNow)
        TimeZone     = if ($tz) { $tz.Id } else { '' }
        UtcOffsetMinutes = if ($tz) { [int]$tz.GetUtcOffset((Get-Date)).TotalMinutes } else { $null }
        Admin        = (Test-WfxAdmin)
        Operator     = [Environment]::UserName
        PSVersion    = $PSVersionTable.PSVersion.ToString()
        # Own unicast addresses (read from the network stack; nothing is sent), so other hosts' logon
        # records can be matched to this one in a fleet report.
        Addresses    = @(try {
                [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' } |
                    ForEach-Object { $_.GetIPProperties().UnicastAddresses } | ForEach-Object { $_.Address } | Where-Object { -not $_.IsIPv6LinkLocal -and -not [System.Net.IPAddress]::IsLoopback($_) } | ForEach-Object { $_.ToString() }
            } catch { })
    }
}

function Get-WfxSignature {
    <# Authenticode status, cached per path for the duration of a collection (services share binaries). #>
    param([string]$Path)
    if (-not $Path -or -not (Test-WfxWindows)) { return '' }
    $k = $Path.ToLowerInvariant()
    if ($script:WfxSigCache.ContainsKey($k)) { return $script:WfxSigCache[$k] }
    $s = ''
    if (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue) {
        try { $s = [string](Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop).Status } catch { $s = 'Unknown' }
    }
    $script:WfxSigCache[$k] = $s
    return $s
}

function Get-WfxProcessData {
    <# Normalized process list with parent linkage, signature status and owner.
       -Skip: hashtable of "pid:name" keys to leave out (used by the live monitor to enrich only new processes). #>
    param([hashtable]$Skip = @{})
    if (-not (Test-WfxWindows)) { return @() }
    $raw = Invoke-WfxStep 'process:list' { Get-CimInstance Win32_Process -ErrorAction Stop } @()
    if (-not $raw) { return @() }
    $byPid = @{}
    foreach ($p in $raw) { $byPid[[string]$p.ProcessId] = $p }
    # Owners: one bulk call when elevated (fast); per-process CIM GetOwner otherwise (only own processes resolve).
    $owners = @{}
    if (Test-WfxAdmin) { try { Get-Process -IncludeUserName -ErrorAction Stop | ForEach-Object { if ($_.UserName) { $owners[[string]$_.Id] = $_.UserName } } } catch {} }
    $companyCache = @{}
    $out = foreach ($p in $raw) {
        if ($Skip.Count -and $Skip.ContainsKey("$($p.ProcessId):$($p.Name)")) { continue }
        $path = $p.ExecutablePath
        if (-not $path) { $path = Get-WfxImagePath $p.CommandLine }
        $sig = Get-WfxSignature $path
        $company = ''
        if ($path -and $sig) {
            if (-not $companyCache.ContainsKey($path)) { try { $companyCache[$path] = (Get-Item -LiteralPath $path -ErrorAction Stop).VersionInfo.CompanyName } catch { $companyCache[$path] = '' } }
            $company = $companyCache[$path]
        }
        $parent = $byPid[[string]$p.ParentProcessId]
        $owner = [string]$owners[[string]$p.ProcessId]
        if (-not $owner -and $owners.Count -eq 0 -and [int]$p.SessionId -ne 0) {
            try { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue; if ($o.User) { $owner = if ($o.Domain) { "$($o.Domain)\$($o.User)" } else { $o.User } } } catch { $owner = '' }
        }
        [pscustomobject]@{
            Pid               = [int]$p.ProcessId
            Ppid              = [int]$p.ParentProcessId
            Name              = $p.Name
            Path              = $path
            # Scrub secrets out of command lines at collection time, so the raw bundle is safe to persist
            # and ship. Tool/command structure is preserved; only embedded secret values are redacted.
            CommandLine       = (Protect-WfxText $p.CommandLine)
            ParentName        = if ($parent) { $parent.Name } else { '' }
            ParentPath        = if ($parent) { $parent.ExecutablePath } else { '' }
            ParentCommandLine = if ($parent) { Protect-WfxText $parent.CommandLine } else { '' }
            ParentCreateTime  = if ($parent) { ConvertTo-WfxUtcString $parent.CreationDate } else { '' }
            SignatureStatus   = $sig
            Company           = $company
            CreateTime        = ConvertTo-WfxUtcString $p.CreationDate
            User              = $owner
            SessionId         = [int]$p.SessionId
        }
    }
    $out
}

function Get-WfxNetworkData {
    <# TCP connections/listeners and UDP endpoints. No name resolution is performed here — endpoints are
       named later from the DNS cache, so the tool sends no packets from the host under investigation. #>
    if (-not (Test-WfxWindows)) { return @() }
    $procNames = @{}
    try { Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procNames[[string]$_.Id] = $_.ProcessName } } catch {}
    $out = [System.Collections.Generic.List[object]]::new()
    $tcp = Invoke-WfxStep 'network:tcp' { Get-NetTCPConnection -ErrorAction Stop } $null
    if ($tcp) {
        foreach ($c in $tcp) {
            $out.Add([pscustomobject]@{
                    Protocol = 'TCP'; LocalAddress = $c.LocalAddress; LocalPort = [int]$c.LocalPort
                    RemoteAddress = $c.RemoteAddress; RemotePort = [int]$c.RemotePort; State = [string]$c.State
                    Pid = [int]$c.OwningProcess; Process = $procNames[[string]$c.OwningProcess]; RemoteHost = ''
                    CreatedUtc = ConvertTo-WfxUtcString $c.CreationTime
                })
        }
        $udp = Invoke-WfxStep 'network:udp' { Get-NetUDPEndpoint -ErrorAction Stop } $null
        foreach ($u in @($udp | Where-Object { $_ })) {
            $out.Add([pscustomobject]@{ Protocol = 'UDP'; LocalAddress = $u.LocalAddress; LocalPort = [int]$u.LocalPort; RemoteAddress = ''; RemotePort = 0
                    State = 'Bound'; Pid = [int]$u.OwningProcess; Process = $procNames[[string]$u.OwningProcess]; RemoteHost = ''; CreatedUtc = ConvertTo-WfxUtcString $u.CreationTime })
        }
    } else {
        # Fallback for very old hosts: parse netstat (state names may be localized; recorded as a gap).
        Add-WfxGap -Source 'network' -Reason 'Get-NetTCPConnection unavailable; used netstat fallback (state names may be localized).'
        $ns = Invoke-WfxStep 'network:netstat' { netstat -ano } @()
        foreach ($line in $ns) {
            if ($line -match '^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)\s+(\d+)\s*$') {
                $out.Add([pscustomobject]@{ Protocol = 'TCP'; LocalAddress = $Matches[1].Trim('[', ']'); LocalPort = [int]$Matches[2]
                        RemoteAddress = $Matches[3].Trim('[', ']'); RemotePort = [int]$Matches[4]; State = ($Matches[5] -replace '^LISTENING$', 'Listen' -replace '^ESTABLISHED$', 'Established')
                        Pid = [int]$Matches[6]; Process = $procNames[$Matches[6]]; RemoteHost = ''; CreatedUtc = '' })
            } elseif ($line -match '^\s*UDP\s+(\S+):(\d+)\s+\S+\s+(\d+)\s*$') {
                $out.Add([pscustomobject]@{ Protocol = 'UDP'; LocalAddress = $Matches[1].Trim('[', ']'); LocalPort = [int]$Matches[2]; RemoteAddress = ''; RemotePort = 0
                        State = 'Bound'; Pid = [int]$Matches[3]; Process = $procNames[$Matches[3]]; RemoteHost = ''; CreatedUtc = '' })
            }
        }
    }
    $out.ToArray()
}

function Get-WfxDnsData {
    if (-not (Test-WfxWindows)) { return @() }
    $raw = Invoke-WfxStep 'dns:cache' { Get-DnsClientCache -ErrorAction Stop } $null
    if ($null -eq $raw) {
        # Fallback: ipconfig /displaydns parsing (English output only; recorded as a gap).
        Add-WfxGap -Source 'dns' -Reason 'Get-DnsClientCache unavailable; used ipconfig /displaydns fallback (English output only).'
        $out = [System.Collections.Generic.List[object]]::new()
        $dns = Invoke-WfxStep 'dns:ipconfig' { ipconfig /displaydns } @()
        $cur = ''
        foreach ($line in $dns) {
            if ($line -match 'Record Name[.\s]*:\s*(\S+)') { $cur = $Matches[1] }
            elseif ($line -match '(?:A \(Host\)|AAAA) Record[.\s]*:\s*(\S+)' -and $cur) { $out.Add([pscustomobject]@{ Name = $cur; Type = 'A'; Data = $Matches[1] }) }
        }
        return $out.ToArray()
    }
    $raw | ForEach-Object { [pscustomobject]@{ Name = $_.Entry; RecordName = $_.Name; Type = [string]$_.Type; Data = [string]$_.Data; TTL = $_.TimeToLive } } | Where-Object { $_.Name }
}

function Get-WfxServiceAndDriver {
    <# Services and kernel drivers → autostart records (Kind Service / Driver). #>
    if (-not (Test-WfxWindows)) { return @() }
    $out = [System.Collections.Generic.List[object]]::new()
    $svc = Invoke-WfxStep 'persist:services' { Get-CimInstance Win32_Service -ErrorAction Stop } @()
    foreach ($s in $svc) {
        $img = Get-WfxImagePath $s.PathName
        $out.Add([pscustomobject]@{ Kind = 'Service'; Name = $s.Name; DisplayName = $s.DisplayName; Command = (Protect-WfxText $s.PathName); Path = $img
                Location = "Service:$($s.StartMode)"; State = [string]$s.State; User = $s.StartName; Enabled = ($s.StartMode -ne 'Disabled'); SignatureStatus = (Get-WfxSignature $img) })
    }
    $drv = Invoke-WfxStep 'persist:drivers' { Get-CimInstance Win32_SystemDriver -ErrorAction Stop } @()
    foreach ($d in $drv) {
        if ($d.State -ne 'Running' -and $d.StartMode -eq 'Disabled') { continue }
        $img = Get-WfxImagePath $d.PathName
        $out.Add([pscustomobject]@{ Kind = 'Driver'; Name = $d.Name; DisplayName = $d.DisplayName; Command = (Protect-WfxText $d.PathName); Path = $img
                Location = "Driver:$($d.StartMode)"; State = [string]$d.State; Enabled = ($d.StartMode -ne 'Disabled'); SignatureStatus = (Get-WfxSignature $img) })
    }
    $out.ToArray()
}
