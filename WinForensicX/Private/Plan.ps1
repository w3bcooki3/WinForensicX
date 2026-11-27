# What a triage will read, before it reads anything: Invoke-WfxTriage -Plan.
#
# One row per collection stage: what it reads, which built-in Windows programs it runs (all read-only),
# what needs administrator rights, and whether it is included with the options given. Nothing is collected
# and no case folder is created. The rows name the collector steps they cover (Steps), and a test checks
# that every step the collectors run is covered here, so the plan cannot quietly fall behind the code.

$script:WfxPlanStage = @(
    [ordered]@{ Stage = 'System information'; Steps = @('hostinfo:*')
        Reads = 'Windows version, computer and domain name, time zone, last boot and install time, this computer''s own IP addresses (WMI, network stack).'
        Runs = ''; Admin = 'No'; Option = '' }
    [ordered]@{ Stage = 'DNS cache'; Steps = @('dns:*')
        Reads = 'Names this computer looked up recently (DNS client cache). Nothing is resolved or sent.'
        Runs = 'ipconfig /displaydns, only if the DNS cmdlets are missing'; Admin = 'No'; Option = '' }
    [ordered]@{ Stage = 'Network connections'; Steps = @('network:*')
        Reads = 'Open TCP connections, listening ports and UDP endpoints, with the program that owns each.'
        Runs = 'netstat -ano, only if the network cmdlets are missing'; Admin = 'Better: names the owners of system processes'; Option = '' }
    [ordered]@{ Stage = 'Processes'; Steps = @('process:*')
        Reads = 'Every running program: path, command line (secrets masked), parent, owner, digital signature, SHA-256 of the program file (files over 256 MB skipped).'
        Runs = ''; Admin = 'Better: other users'' processes and their owners'; Option = '' }
    [ordered]@{ Stage = 'Pipes, sessions, neighbours, loaded DLLs'; Steps = @('volatile:*')
        Reads = 'Names of open named pipes (none is opened), signed-in and disconnected sessions, the ARP neighbour cache, and DLLs loaded from user-writable folders with their signatures. LSASS, other critical system processes and security products are never opened.'
        Runs = 'quser (list sessions)'; Admin = 'Better: modules of other users'' and system processes'; Option = '' }
    [ordered]@{ Stage = 'Injected-code scan'; Steps = @('memory:*')
        Reads = 'Which memory regions of each process are executable without coming from a file on disk, and the first 1 KB of those regions (to see a program header). No other memory is read or kept. LSASS, critical system processes and security products are never opened.'
        Runs = ''; Admin = 'Yes for other users'' and system processes'; Option = 'DeepScan' }
    [ordered]@{ Stage = 'Autostarts, services, drivers'; Steps = @('persist:*')
        Reads = 'Run and RunOnce keys (machine and signed-in users), Startup folders, scheduled tasks, WMI subscriptions, Winlogon, AppInit, IFEO debuggers, LSA packages, BootExecute, Run-box history, services and drivers.'
        Runs = ''; Admin = 'Better: some task and service details'; Option = '' }
    [ordered]@{ Stage = 'Event logs'; Steps = @('events:*')
        Reads = '__EVENTLOGS__'
        Runs = ''; Admin = 'Yes for the Security log'; Option = '' }
    [ordered]@{ Stage = 'Recent changes'; Steps = @('activity:*')
        Reads = 'Last-write times of persistence and security registry keys, the Recycle Bin, installs, program runs (Prefetch, BAM, UserAssist) and connection history from the event logs. With -FileScan, also the NTFS change journal.'
        Runs = 'fsutil usn (read the change journal), with -FileScan'; Admin = 'Yes for the change journal'; Option = '' }
    [ordered]@{ Stage = 'Execution and user-activity artifacts'; Steps = @()
        Reads = 'ShimCache, BAM, Prefetch, PCA, Defender support logs; per user: UserAssist, ShellBags, Jump Lists, Recent shortcuts, Run box, typed paths, searches, browser download history. Amcache and SRUM are tried; Windows usually keeps them locked.'
        Runs = ''; Admin = 'Yes for Prefetch, Defender logs and other users'' profiles'; Option = '' }
    [ordered]@{ Stage = 'File scan'; Steps = @('files:*')
        Reads = 'Web server folders (web shells), recently written programs and scripts in Downloads, Desktop, Documents, Temp, AppData, Public and ProgramData, ransom notes, files that look encrypted. Bounded in count and size.'
        Runs = ''; Admin = 'Better: other users'' folders'; Option = 'FileScan' }
    [ordered]@{ Stage = 'Credential exposure audit'; Steps = @('expo:*')
        Reads = 'Whether secrets are exposed, never their values: Group Policy passwords, unattend files, access to SAM/SYSTEM/NTDS (permissions only), auto-logon, unencrypted SSH keys, keys in environment variables and PowerShell history. With -ExposureScan, also common config files and the domain SYSVOL share (network).'
        Runs = ''; Admin = 'Better'; Option = '' }
    [ordered]@{ Stage = 'Earlier containment'; Steps = @('respond:*')
        Reads = 'The record of actions WinForensicX Respond mode took on this computer in the last 90 days (Downloads\WinForensicX-Quarantine\actions), to show them in the report.'
        Runs = ''; Admin = 'Yes (the folder is locked to administrators)'; Option = '' }
    [ordered]@{ Stage = 'Security posture and memory-capture readiness'; Steps = @('posture:*', 'ready:*')
        Reads = 'Defender status and exclusions, registered antivirus, firewall profiles, audit and PowerShell logging policy, Sysmon, LSA protection and Credential Guard, RDP settings, BitLocker status (never the recovery key), installed AI tools; crash-dump, page-file, hibernation and Fast Startup settings, virtual machine, uptime.'
        Runs = 'auditpol /get (read the audit policy)'; Admin = 'Yes for exclusions, audit policy and BitLocker'; Option = '' }
)

function Get-WfxTriagePlan {
    <#
    .SYNOPSIS What a triage with these options will read. Pure: reads nothing from the system.
    .PARAMETER Mode   Local, Remote, Offline, Reanalyze or Artifacts (the parameter set of Invoke-WfxTriage).
    .PARAMETER Admin  Whether the session has administrator rights (sets the Without admin column).
    .PARAMETER Source The path given for Offline / Reanalyze / Artifacts.
    #>
    param(
        [string]$Mode = 'Local',
        [int]$Hours = 72,
        [switch]$FileScan,
        [switch]$ExposureScan,
        [switch]$DeepScan,
        [bool]$Admin = $true,
        [string[]]$YaraRules = @(),
        [string[]]$SigmaPath = @(),
        [string]$Source = ''
    )
    $rows = [System.Collections.Generic.List[object]]::new()
    if ($Mode -in 'Offline', 'Reanalyze', 'Artifacts') {
        $what = switch ($Mode) {
            'Offline' { 'The exported event-log files (.evtx) under this path.' }
            'Reanalyze' { 'The saved bundle.json of that case. The evidence is analyzed again; nothing new is collected.' }
            'Artifacts' { 'Registry hives, Amcache, Jump Lists, shortcuts, browser databases, Prefetch, PCA and Defender logs, SRUM, $MFT and .evtx files found under this path.' }
        }
        $rows.Add([pscustomobject]@{ Stage = 'Evidence you supplied'; Reads = "$what $Source".Trim(); Runs = ''; Included = 'Yes'; Admin = 'No'; WithoutAdmin = '' })
        $rows.Add([pscustomobject]@{ Stage = 'This computer'; Reads = 'Nothing. No data is collected from the computer running the tool.'; Runs = ''; Included = 'Yes'; Admin = 'No'; WithoutAdmin = '' })
    } else {
        $logs = @($script:WfxEventQuery | ForEach-Object { $_.Log -replace '^Microsoft-Windows-', '' -replace '/Operational$', '' } | Select-Object -Unique)
        foreach ($s in $script:WfxPlanStage) {
            $opt = [string]$s.Option
            $inc = if ($opt -eq 'FileScan' -and -not $FileScan) { 'No (add -FileScan)' } elseif ($opt -eq 'DeepScan' -and -not $DeepScan) { 'No (add -DeepScan)' } else { 'Yes' }
            $reads = ([string]$s.Reads).Replace('__EVENTLOGS__', ("Last {0} hours of selected event IDs from: {1}." -f $Hours, ($logs -join ', ')))
            if (@($SigmaPath).Count -and $s.Stage -eq 'Event logs') { $reads += ' Your Sigma rules may add Security and System event IDs.' }
            if ($ExposureScan -and $s.Stage -eq 'Credential exposure audit') { $reads += ' (-ExposureScan is on.)' }
            $need = [string]$s.Admin
            # "Yes for the Security log" -> "Missing: the Security log"; "Better: <detail>" -> "Less complete (<detail>)"
            $without = if ($Admin -or $need -eq 'No') { '' } elseif ($need -like 'Yes*') { 'Missing: ' + ($need -replace '^Yes(?: for)? ?', '') } elseif ($need -match '^Better: (.+)$') { "Less complete ($($Matches[1]))" } else { 'Less complete' }
            $rows.Add([pscustomobject]@{ Stage = $s.Stage; Reads = $reads; Runs = [string]$s.Runs; Included = $inc; Admin = $need; WithoutAdmin = $without })
        }
        if (@($YaraRules).Count) {
            $rows.Add([pscustomobject]@{ Stage = 'YARA scan'; Reads = 'Running programs, autostarts, recently run and downloaded programs and (-FileScan) scanned files, with your rules.'; Runs = 'the yara executable you provided'; Included = 'Yes'; Admin = 'Better'; WithoutAdmin = $(if ($Admin) { '' } else { 'Less complete' }) })
        }
        if ($Mode -eq 'Remote') {
            $rows.Add([pscustomobject]@{ Stage = 'Remote collection'; Reads = 'The stages above run on each remote computer over the WinRM session you start; only the collection code is sent, and the results come back here for analysis.'; Runs = ''; Included = 'Yes'; Admin = 'Rights of the account you use'; WithoutAdmin = '' })
        }
    }
    $rows.ToArray()
}

function Write-WfxTriagePlan {
    <# Prints a plan to the console. #>
    param([object[]]$Plan, [string]$Mode = 'Local', [bool]$Admin = $true)
    Write-WfxSection 'What this triage will read (nothing has been read yet)'
    foreach ($r in $Plan) {
        $off = $r.Included -ne 'Yes'
        Write-WfxConsole ("  {0}" -f $r.Stage) -Kind $(if ($off) { 'Dim' } else { 'Head' }) -NoNewline
        if ($off) { Write-WfxConsole ("  [{0}]" -f $r.Included) -Kind Dim } else { Write-WfxConsole '' }
        Write-WfxConsole ("    {0}" -f $r.Reads) -Kind Dim
        if ($r.Runs) { Write-WfxConsole ("    Runs: {0}" -f $r.Runs) -Kind Dim }
        if ($r.WithoutAdmin) { Write-WfxConsole ("    Without administrator rights: {0}" -f $r.WithoutAdmin) -Kind Warn }
    }
    Write-WfxConsole ''
    if ($Mode -in 'Local', 'Remote') {
        Write-WfxConsole '  It changes nothing, executes nothing it finds and sends nothing over the network of its own' -Kind Dim
        Write-WfxConsole '  (except the domain SYSVOL share with -ExposureScan and the WinRM session in remote mode).' -Kind Dim
    }
    Write-WfxConsole '  It writes only its case folder. Run the same command without -Plan to start.' -Kind Dim
}
