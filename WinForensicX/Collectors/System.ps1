# Windows collectors — gather live data into the normalized shapes the analyzers consume.
# Every collector: returns [] on non-Windows or on error (recorded as a gap), never throws,
# and degrades gracefully without administrator rights.

function Get-WfxHostInfo {
    if (-not (Test-WfxWindows)) {
        return [pscustomobject]@{ HostName = [Environment]::MachineName; Os = 'Non-Windows (collectors limited)'; Collected = (Get-Date).ToUniversalTime().ToString('o'); Admin = $false }
    }
    $os = Invoke-WfxStep 'hostinfo:os' { Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } $null
    $cs = Invoke-WfxStep 'hostinfo:cs' { Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } $null
    [pscustomobject]@{
        HostName   = [Environment]::MachineName
        Domain     = if ($cs) { $cs.Domain } else { '' }
        Os         = if ($os) { "$($os.Caption) $($os.Version) (build $($os.BuildNumber))" } else { '' }
        Boot       = if ($os) { $os.LastBootUpTime } else { $null }
        Manufacturer = if ($cs) { "$($cs.Manufacturer) $($cs.Model)" } else { '' }
        Collected  = (Get-Date).ToUniversalTime().ToString('o')
        TimeZone   = (Get-TimeZone -ErrorAction SilentlyContinue).Id
        Admin      = (Test-WfxAdmin)
        Operator   = [Environment]::UserName
        PSVersion  = $PSVersionTable.PSVersion.ToString()
    }
}

function Get-WfxProcessData {
    <# Normalized process list with parent linkage, signature status and hashes (admin gets command lines reliably). #>
    if (-not (Test-WfxWindows)) { return @() }
    $raw = Invoke-WfxStep 'process:list' { Get-CimInstance Win32_Process -ErrorAction Stop } @()
    if (-not $raw) { return @() }
    $byPid = @{}
    foreach ($p in $raw) { $byPid[[string]$p.ProcessId] = $p }
    # Signatures/paths are relatively expensive; cache by path.
    $sigCache = @{}
    $out = foreach ($p in $raw) {
        $path = $p.ExecutablePath
        if (-not $path) { $path = Get-WfxImagePath $p.CommandLine }
        $sig = ''
        $company = ''
        if ($path -and (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) {
            if ($sigCache.ContainsKey($path)) { $sig = $sigCache[$path].Sig; $company = $sigCache[$path].Co }
            else {
                try {
                    $s = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
                    $sig = [string]$s.Status
                    try { $company = (Get-Item -LiteralPath $path).VersionInfo.CompanyName } catch { $company = '' }
                } catch { $sig = 'Unknown' }
                $sigCache[$path] = @{ Sig = $sig; Co = $company }
            }
        }
        $parent = $byPid[[string]$p.ParentProcessId]
        $owner = ''
        try { $owner = (Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue).User } catch { $owner = '' }
        [pscustomobject]@{
            Pid             = [int]$p.ProcessId
            Ppid            = [int]$p.ParentProcessId
            Name            = $p.Name
            Path            = $path
            # Scrub secrets out of command lines at collection time, so the raw bundle is safe to persist
            # and ship. Tool/command structure is preserved; only embedded secret values are redacted.
            CommandLine     = (Protect-WfxText $p.CommandLine)
            ParentName      = if ($parent) { $parent.Name } else { '' }
            ParentPath      = if ($parent) { $parent.ExecutablePath } else { '' }
            ParentCommandLine = if ($parent) { Protect-WfxText $parent.CommandLine } else { '' }
            SignatureStatus = $sig
            Company         = $company
            CreateTime      = $p.CreationDate
            User            = $owner
        }
    }
    , @($out)
}

function Get-WfxNetworkData {
    if (-not (Test-WfxWindows)) { return @() }
    $procNames = @{}
    try { Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procNames[[string]$_.Id] = $_.ProcessName } } catch {}
    $out = New-Object System.Collections.Generic.List[object]
    $tcp = Invoke-WfxStep 'network:tcp' { Get-NetTCPConnection -ErrorAction Stop } $null
    if ($tcp) {
        foreach ($c in $tcp) {
            $out.Add([pscustomobject]@{
                    Protocol = 'TCP'; LocalAddress = $c.LocalAddress; LocalPort = $c.LocalPort
                    RemoteAddress = $c.RemoteAddress; RemotePort = $c.RemotePort; State = [string]$c.State
                    Pid = $c.OwningProcess; Process = $procNames[[string]$c.OwningProcess]
                    RemoteHost = ''
                })
        }
    } else {
        # Fallback for very old hosts: parse netstat.
        $ns = Invoke-WfxStep 'network:netstat' { netstat -ano } @()
        foreach ($line in $ns) {
            if ($line -match '^\s*(TCP|UDP)\s+(\S+):(\d+)\s+(\S+):(\d+|\*)\s+(\S*)\s*(\d*)\s*$') {
                $out.Add([pscustomobject]@{ Protocol = $Matches[1]; LocalAddress = $Matches[2]; LocalPort = [int]$Matches[3]
                        RemoteAddress = $Matches[4]; RemotePort = ($Matches[5] -replace '\*', '0'); State = $Matches[6]
                        Pid = $Matches[7]; Process = $procNames[$Matches[7]]; RemoteHost = '' })
            }
        }
    }
    # Resolve a handful of public remote addresses to names for the DNS/beacon context (best-effort, bounded).
    $resolved = @{}
    foreach ($c in $out) {
        if ($c.State -match 'Establish' -and $c.RemoteAddress -and -not (Test-WfxPrivateIp $c.RemoteAddress) -and -not $resolved.ContainsKey($c.RemoteAddress)) {
            if ($resolved.Count -ge 40) { break }
            try { $resolved[$c.RemoteAddress] = ([System.Net.Dns]::GetHostEntry($c.RemoteAddress)).HostName } catch { $resolved[$c.RemoteAddress] = '' }
        }
    }
    foreach ($c in $out) { if ($resolved.ContainsKey($c.RemoteAddress)) { $c.RemoteHost = $resolved[$c.RemoteAddress] } }
    , @($out.ToArray())
}

function Get-WfxDnsData {
    if (-not (Test-WfxWindows)) { return @() }
    $raw = Invoke-WfxStep 'dns:cache' { Get-DnsClientCache -ErrorAction Stop } $null
    if ($null -eq $raw) {
        # Fallback: ipconfig /displaydns parsing.
        $out = New-Object System.Collections.Generic.List[object]
        $dns = Invoke-WfxStep 'dns:ipconfig' { ipconfig /displaydns } @()
        $cur = ''
        foreach ($line in $dns) {
            if ($line -match 'Record Name[.\s]*:\s*(\S+)') { $cur = $Matches[1] }
            elseif ($line -match 'CNAME Record|A \(Host\) Record|AAAA Record' -and $cur) { $out.Add([pscustomobject]@{ Name = $cur; Type = 'A'; Data = '' }) }
        }
        return , @($out.ToArray())
    }
    , @($raw | ForEach-Object { [pscustomobject]@{ Name = $_.Entry; Type = [string]$_.Type; Data = $_.Data; TTL = $_.TimeToLive } } | Where-Object { $_.Name })
}

function Get-WfxServiceAndDriver {
    <# Services and kernel drivers → autostart records (Kind Service / Driver). #>
    if (-not (Test-WfxWindows)) { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    $svc = Invoke-WfxStep 'persist:services' { Get-CimInstance Win32_Service -ErrorAction Stop } @()
    foreach ($s in $svc) {
        $out.Add([pscustomobject]@{ Kind = 'Service'; Name = $s.Name; Command = (Protect-WfxText $s.PathName); Path = (Get-WfxImagePath $s.PathName)
                Location = "Service:$($s.StartMode)"; User = $s.StartName; Enabled = ($s.StartMode -ne 'Disabled'); SignatureStatus = (Get-WfxSignature (Get-WfxImagePath $s.PathName)) })
    }
    $drv = Invoke-WfxStep 'persist:drivers' { Get-CimInstance Win32_SystemDriver -ErrorAction Stop } @()
    foreach ($d in $drv) {
        if ($d.State -ne 'Running' -and $d.StartMode -eq 'Disabled') { continue }
        $out.Add([pscustomobject]@{ Kind = 'Driver'; Name = $d.Name; Command = (Protect-WfxText $d.PathName); Path = ($d.PathName -replace '^\\\?\?\\', '' -replace '^System32', "$env:SystemRoot\System32")
                Location = "Driver:$($d.StartMode)"; Enabled = ($d.StartMode -ne 'Disabled'); SignatureStatus = (Get-WfxSignature ($d.PathName -replace '^\\\?\?\\', '')) })
    }
    , @($out.ToArray())
}

function Get-WfxSignature {
    param([string]$Path)
    if (-not $Path -or -not (Test-WfxWindows)) { return '' }
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) { return '' }
    try { return [string](Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop).Status } catch { return 'Unknown' }
}
