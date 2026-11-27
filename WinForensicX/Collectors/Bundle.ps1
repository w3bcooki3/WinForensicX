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
        [switch]$DeepScan,
        [ValidateSet('Host', 'Process', 'Network', 'Dns', 'Volatile', 'Persistence', 'Events', 'Activity', 'Artifacts', 'Files', 'Exposure', 'Security')]
        [string[]]$Sections = @('Host', 'Process', 'Network', 'Dns', 'Volatile', 'Persistence', 'Events', 'Activity', 'Artifacts', 'Files', 'Exposure', 'Security')
    )
    $want = @{}; foreach ($s in $Sections) { $want[$s] = $true }
    Clear-WfxGap
    $script:WfxSigCache = @{}
    $script:WfxHashCache = @{}
    $started = Get-WfxUtcNow
    $steps = @('Host', 'Dns', 'Network', 'Process', 'Volatile', 'Persistence', 'Events', 'Activity', 'Artifacts', 'Files', 'Exposure', 'Security') | Where-Object { $want[$_] -and ($_ -ne 'Files' -or $FileScan) }
    $script:WfxProgress = @{ N = 0; Total = @($steps).Count }
    $stage = {
        param([string]$Label, [scriptblock]$Body)
        $script:WfxProgress.N++
        $sw = [Diagnostics.Stopwatch]::StartNew()
        Write-WfxConsole ("  [{0}/{1}] {2,-34}" -f $script:WfxProgress.N, $script:WfxProgress.Total, $Label) -Kind Plain -NoNewline
        if (-not $script:WfxQuiet) { Write-Progress -Activity 'WinForensicX collection' -Status $Label -PercentComplete ([int](100 * ($script:WfxProgress.N - 1) / [Math]::Max(1, $script:WfxProgress.Total))) }
        $r = & $Body
        $count = if ($null -eq $r) { 0 } elseif ($r -is [System.Collections.IEnumerable] -and $r -isnot [string]) { @($r).Count } else { 1 }
        Write-WfxConsole ("{0,7:N1}s  {1}" -f $sw.Elapsed.TotalSeconds, $(if ($count -gt 1) { "$count items" } else { '' })) -Kind Dim
        $r
    }

    # Volatile, fast-changing state first (DNS cache, connections, processes), then the rest.
    $hostInfo = if ($want.Host) { & $stage 'System information' { Get-WfxHostInfo } } else { $null }
    $dns = if ($want.Dns) { @(& $stage 'DNS cache' { Get-WfxDnsData }) } else { @() }
    $net = if ($want.Network) { @(& $stage 'Network connections' { Get-WfxNetworkData }) } else { @() }
    $procs = if ($want.Process) { @(& $stage 'Processes (+ signatures, hashes)' { Get-WfxProcessData }) } else { @() }
    $volatile = if ($want.Volatile) { & $stage $(if ($DeepScan) { 'Pipes, sessions, ARP, DLLs, injected code' } else { 'Pipes, sessions, ARP, loaded DLLs' }) { Get-WfxVolatileData -DeepScan:$DeepScan } } else { $null }

    $persist = @()
    if ($want.Persistence) { $persist = @(& $stage 'Autostarts, services, drivers' { @(Get-WfxPersistenceData) + @(Get-WfxServiceAndDriver) }) }

    $events = @()
    if ($want.Events) { $events = @(& $stage "Event logs (last $Hours h)" { Get-WfxEventData -Hours $Hours }) }

    $activity = @()
    $days = [int][Math]::Max(1, [Math]::Ceiling($Hours / 24.0))
    if ($want.Activity) { $activity = @(& $stage "Recent changes (last $days d$(if ($FileScan) { ', incl. NTFS journal' }))" { Get-WfxActivityData -Days $days -Journal:$FileScan }) }

    $artifacts = @()
    if ($want.Artifacts) { $artifacts = @(& $stage 'Execution & user-activity artifacts' { Get-WfxArtifactData }) }

    $files = @(); $ransom = [pscustomobject]@{ Note = @(); RecentFile = @() }
    if ($want.Files -and $FileScan) {
        $files = @(& $stage 'File scan (web roots, drops, ransomware)' { $script:WfxRansomTmp = Get-WfxRansomwareData; Get-WfxFileData })
        $ransom = $script:WfxRansomTmp
    }

    $exposure = @()
    if ($want.Exposure) { $exposure = @(& $stage 'Credential exposure audit (redacted)' { Get-WfxExposureData -IncludeFileScan:$ExposureScan }) }

    $security = if ($want.Security) { & $stage 'Security posture' { Get-WfxSecurityData } } else { $null }
    # Containment already done here by WinForensicX (Respond mode), so the report shows it next to the findings.
    $responses = @(Invoke-WfxStep 'respond:history' { @(Get-WfxActionRecord -Days 90 | Select-Object Id, Time, Type, Target, Status, Message, Undone, Operator) } @())
    if (-not $script:WfxQuiet) { Write-Progress -Activity 'WinForensicX collection' -Completed }

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
        Volatile    = $volatile
        Persistence = $persist
        Events      = $events
        Activity    = $activity
        Artifacts   = $artifacts
        Files       = $files
        Ransom      = $ransom
        Exposure    = $exposure
        Security    = $security
        Responses   = $responses
        Gaps        = @(Get-WfxGap | Expand-WfxRecord)
        Meta        = [pscustomobject]@{ Mode = 'live'; Hours = $Hours; FileScan = [bool]$FileScan; ExposureScan = [bool]$ExposureScan; DeepScan = [bool]$DeepScan; Sections = @($Sections) }
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
        Process     = @(); Network = @(); Dns = @(); Persistence = @(); Activity = @(); Artifacts = @(); Files = @(); Exposure = @(); Security = $null
        Ransom      = [pscustomobject]@{ Note = @(); RecentFile = @() }
        Events      = $events
        Gaps        = @(Get-WfxGap | Expand-WfxRecord)
        Meta        = [pscustomobject]@{ Mode = 'offline'; EvtxPath = $EvtxPath; EvtxFiles = @($files) }
    }
}

function Get-WfxArtifactBundle {
    <#
    .SYNOPSIS Builds a bundle from a folder of collected evidence (KAPE / Velociraptor output, a mounted image,
    CTF files): registry hives, Jump Lists, shortcuts, browser databases, PCA / Defender logs, Prefetch and any
    .evtx files found. Nothing is collected from the machine running the tool.
    #>
    param([Parameter(Mandatory)][string]$Path, [int]$MaxPerLog = 50000)
    Clear-WfxGap
    $script:WfxImportHost = $null; $script:WfxImportOs = $null
    $arts = @(Import-WfxArtifact -Path $Path)
    $evtx = @($script:WfxImportEvtx)
    $events = if ($evtx.Count) { @(Get-WfxEventData -EvtxFile $evtx -MaxPerLog $MaxPerLog) } else { @() }
    $hn = $script:WfxImportHost
    if (-not $hn) { $hn = @($events | ForEach-Object { [string]$_.Computer } | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending | Select-Object -First 1).Name; if ($hn) { $hn = ($hn -split '\.')[0] } }
    if (-not $hn) { $hn = 'unknown-offline-host' }
    [pscustomobject]@{
        Schema      = 'winforensicx.bundle/2'
        ToolVersion = $script:WfxVersion
        Started     = (Get-WfxUtcNow)
        Collected   = (Get-WfxUtcNow)
        HostName    = $hn
        Host        = [pscustomobject]@{ HostName = $hn; Os = $(if ($script:WfxImportOs) { $script:WfxImportOs } else { '(collected artifacts)' }); Collected = (Get-WfxUtcNow); Admin = $null; Operator = [Environment]::UserName }
        Process     = @(); Network = @(); Dns = @(); Persistence = @(); Activity = @(); Files = @(); Exposure = @(); Security = $null
        Ransom      = [pscustomobject]@{ Note = @(); RecentFile = @() }
        Events      = $events
        Artifacts   = $arts
        Gaps        = @(Get-WfxGap | Expand-WfxRecord)
        Meta        = [pscustomobject]@{ Mode = 'artifacts'; ArtifactPath = $Path; EvtxFiles = $evtx; ArtifactCount = $arts.Count }
    }
}
