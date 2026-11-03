# Collection aggregator — runs the collectors and returns ONE normalized bundle object.
# This is the single unit of data that: (a) the analyzers consume, (b) gets saved as raw evidence,
# and (c) is shipped back from a remote WinRM session. Every field is already OS-neutral, timestamps are
# UTC ISO-8601 strings, and text is secret-scrubbed, so the bundle is safe to serialize and move off-box.

function Get-WfxCollectionBundle {
    <#
    .SYNOPSIS Collects all live triage data into one bundle. Each section degrades to [] on error (recorded as a gap).
    .PARAMETER Hours        Event look-back window.
    .PARAMETER FileScan     Include the web-root / drop-folder / ransomware file scan (slower).
    .PARAMETER ExposureScan Include the deeper config-file and domain-SYSVOL secret scan.
    .PARAMETER Sections     Limit collection to these sections (default: all).
    #>
    param(
        [int]$Hours = 72,
        [switch]$FileScan,
        [switch]$ExposureScan,
        [ValidateSet('Host', 'Process', 'Network', 'Dns', 'Persistence', 'Events', 'Files', 'Exposure', 'Security')]
        [string[]]$Sections = @('Host', 'Process', 'Network', 'Dns', 'Persistence', 'Events', 'Files', 'Exposure', 'Security')
    )
    $want = @{}; foreach ($s in $Sections) { $want[$s] = $true }
    Clear-WfxGap
    $script:WfxSigCache = @{}
    $started = Get-WfxUtcNow

    # Volatile, fast-changing state first (DNS cache, connections, processes), then the rest.
    $hostInfo = if ($want.Host) { Get-WfxHostInfo } else { $null }
    $dns = if ($want.Dns) { @(Get-WfxDnsData) } else { @() }
    $net = if ($want.Network) { @(Get-WfxNetworkData) } else { @() }
    $procs = if ($want.Process) { @(Get-WfxProcessData) } else { @() }

    $persist = @()
    if ($want.Persistence) { $persist = @(Get-WfxPersistenceData) + @(Get-WfxServiceAndDriver) }

    $events = @()
    if ($want.Events) { $events = @(Get-WfxEventData -Hours $Hours) }

    $files = @(); $ransom = [pscustomobject]@{ Note = @(); RecentFile = @() }
    if ($want.Files -and $FileScan) {
        $files = @(Get-WfxFileData)
        $ransom = Get-WfxRansomwareData
    }

    $exposure = @()
    if ($want.Exposure) { $exposure = @(Get-WfxExposureData -IncludeFileScan:$ExposureScan) }

    $security = if ($want.Security) { Get-WfxSecurityData } else { $null }

    [pscustomobject]@{
        Schema      = 'winforensicx.bundle/2'
        ToolVersion = $script:WfxVersion
        Started     = $started
        Collected   = (Get-WfxUtcNow)
        HostName    = if ($hostInfo) { $hostInfo.HostName } else { [Environment]::MachineName }
        Host        = $hostInfo
        Process     = $procs
        Network     = $net
        Dns         = $dns
        Persistence = $persist
        Events      = $events
        Files       = $files
        Ransom      = $ransom
        Exposure    = $exposure
        Security    = $security
        Gaps        = @(Get-WfxGap)
        Meta        = [pscustomobject]@{ Mode = 'live'; Hours = $Hours; FileScan = [bool]$FileScan; ExposureScan = [bool]$ExposureScan; Sections = @($Sections) }
    }
}

function Get-WfxOfflineBundle {
    <#
    .SYNOPSIS Builds a bundle from exported .evtx files ONLY (no live data from the analysis machine).
    The host name is taken from the events' Computer field (the most common value).
    #>
    param([Parameter(Mandatory)][string]$EvtxPath, [int]$MaxPerLog = 50000)
    Clear-WfxGap
    $files = if (Test-Path -LiteralPath $EvtxPath -PathType Container) { @(Get-ChildItem -LiteralPath $EvtxPath -Filter *.evtx -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object FullName) } else { @((Resolve-Path -LiteralPath $EvtxPath).Path) }
    if (-not $files.Count) { Add-WfxGap -Source 'offline' -Reason "No .evtx files found under $EvtxPath" }
    $events = @(Get-WfxEventData -EvtxFile $files -MaxPerLog $MaxPerLog)
    $hn = @($events | ForEach-Object { [string]$_.Computer } | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending | Select-Object -First 1).Name
    if (-not $hn) { $hn = 'unknown-offline-host' }
    $hostName = ($hn -split '\.')[0]
    [pscustomobject]@{
        Schema      = 'winforensicx.bundle/2'
        ToolVersion = $script:WfxVersion
        Started     = (Get-WfxUtcNow)
        Collected   = (Get-WfxUtcNow)
        HostName    = $hostName
        Host        = [pscustomobject]@{ HostName = $hostName; Fqdn = $hn; Os = '(offline event logs)'; Collected = (Get-WfxUtcNow); Admin = $null; Operator = [Environment]::UserName }
        Process     = @(); Network = @(); Dns = @(); Persistence = @(); Files = @(); Exposure = @(); Security = $null
        Ransom      = [pscustomobject]@{ Note = @(); RecentFile = @() }
        Events      = $events
        Gaps        = @(Get-WfxGap)
        Meta        = [pscustomobject]@{ Mode = 'offline'; EvtxPath = $EvtxPath; EvtxFiles = @($files) }
    }
}
