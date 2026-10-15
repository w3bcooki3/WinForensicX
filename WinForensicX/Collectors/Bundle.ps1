# Collection aggregator — runs the collectors and returns ONE normalized bundle object.
# This is the single unit of data that: (a) the analyzers consume, (b) gets saved as raw evidence,
# and (c) is shipped back from a remote WinRM session. Every field is already OS-neutral and (for
# exposure) pre-redacted, so the bundle is safe to serialize and move off-box.

function Get-WfxCollectionBundle {
    <#
    .SYNOPSIS Collects all triage data into one bundle. Each section degrades to [] on error (recorded as a gap).
    .PARAMETER Hours        Event look-back window (live mode).
    .PARAMETER EvtxPath     Analyze events from exported .evtx instead of the live log.
    .PARAMETER FileScan     Include the web-root / drop-folder file scan (can be slower).
    .PARAMETER ExposureScan Include the deeper config-file secret scan.
    .PARAMETER Sections     Limit collection to these sections (default: all).
    #>
    param(
        [int]$Hours = 72,
        [string]$EvtxPath = '',
        [switch]$FileScan,
        [switch]$ExposureScan,
        [ValidateSet('Host', 'Process', 'Network', 'Dns', 'Persistence', 'Events', 'Files', 'Exposure', 'Security')]
        [string[]]$Sections = @('Host', 'Process', 'Network', 'Dns', 'Persistence', 'Events', 'Files', 'Exposure', 'Security')
    )
    $want = @{}; foreach ($s in $Sections) { $want[$s] = $true }
    Clear-WfxGap

    $hostInfo = if ($want.Host) { Get-WfxHostInfo } else { $null }
    $procs = if ($want.Process) { @(Get-WfxProcessData) } else { @() }
    $net = if ($want.Network) { @(Get-WfxNetworkData) } else { @() }
    $dns = if ($want.Dns) { @(Get-WfxDnsData) } else { @() }

    $persist = @()
    if ($want.Persistence) { $persist = @(Get-WfxPersistenceData) + @(Get-WfxServiceAndDriver) }

    $events = @()
    if ($want.Events) { $events = @(Get-WfxEventData -Hours $Hours -EvtxPath $EvtxPath) }

    $files = @(); $ransom = [pscustomobject]@{ Note = @(); RecentFile = @() }
    if ($want.Files -and $FileScan) {
        $files = @(Get-WfxFileData)
        $ransom = Get-WfxRansomwareData
    }

    $exposure = @()
    if ($want.Exposure) { $exposure = @(Get-WfxExposureData -IncludeFileScan:$ExposureScan) }

    $security = if ($want.Security) { Get-WfxSecurityData } else { $null }

    [pscustomobject]@{
        Schema      = 'winforensicx.bundle/1'
        ToolVersion = $script:WfxVersion
        Collected   = (Get-Date).ToUniversalTime().ToString('o')
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
        Meta        = [pscustomobject]@{ Hours = $Hours; EvtxPath = $EvtxPath; FileScan = [bool]$FileScan; ExposureScan = [bool]$ExposureScan; Sections = @($Sections) }
    }
}
