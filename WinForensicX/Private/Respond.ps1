# Respond mode: the rules that keep containment from hurting the computer, and the response plan.
#
# Everything here is decided before anything is changed, and most of it is pure so it can be tested on
# any OS. Invoke-WfxRespond (Public) does the changing, one confirmed action at a time.
#
# Never touched, whatever the plan or the operator says:
#   * processes Windows cannot run without (killing them crashes the computer), security products,
#     svchost.exe as a whole (stop the one service instead) and WinForensicX itself;
#   * files under the Windows folder that Microsoft signed, and anything inside the quarantine;
#   * firewall blocks for loopback, "everything", or this computer's own addresses;
#   * the account in use, built-in system accounts, and the last enabled local administrator;
#   * services Windows needs to start, log on, network or protect itself;
#   * registry values outside the Run / RunOnce keys.

$script:WfxCriticalProcess = @('system', 'idle', 'registry', 'memory compression', 'secure system', 'smss', 'csrss', 'wininit', 'winlogon',
    'services', 'lsass', 'lsaiso', 'svchost', 'fontdrvhost', 'dwm', 'sihost', 'ctfmon', 'conhost', 'audiodg', 'spoolsv', 'wudfhost', 'searchindexer',
    'msmpeng', 'mpdefendercoreservice', 'nissrv', 'mssense', 'senseir', 'sensecncproxy', 'securityhealthservice', 'securityhealthsystray', 'smartscreen',
    'csfalconservice', 'csfalconcontainer', 'sentinelagent', 'sentinelservicehost', 'cb', 'repmgr', 'elastic-agent', 'elastic-endpoint', 'xagt',
    'cylancesvc', 'taniumclient', 'cyserver', 'cytray', 'ekrn', 'avp', 'bdagent', 'vsserv', 'savservice', 'sophoshealth', 'mbamservice')

$script:WfxCriticalService = @('rpcss', 'dcomlaunch', 'rpceptmapper', 'lsm', 'samss', 'eventlog', 'eventsystem', 'plugplay', 'power', 'profsvc', 'usermanager',
    'gpsvc', 'schedule', 'winmgmt', 'cryptsvc', 'brokerinfrastructure', 'systemeventsbroker', 'coremessagingregistrar', 'staterepository', 'bfe', 'mpssvc',
    'dhcp', 'dnscache', 'nsi', 'netprofm', 'nlasvc', 'lanmanworkstation', 'lanmanserver', 'tcpip', 'afd', 'netbt', 'windefend', 'wdnissvc', 'sense',
    'securityhealthservice', 'wscsvc', 'keyiso', 'vaultsvc', 'netlogon', 'kdc', 'ntds', 'dns', 'w32time', 'appinfo', 'trustedinstaller', 'wuauserv',
    'bits', 'termservice', 'winrm', 'audiosrv', 'themes', 'wdiservicehost', 'sysmain', 'fontcache', 'camsvc', 'msiserver', 'vss', 'swprv', 'sysmon', 'sysmon64', 'sysmondrv')

$script:WfxProtectedAccount = @('system', 'local service', 'network service', 'defaultaccount', 'wdagutilityaccount', 'trustedinstaller')

$script:WfxResponseTypes = @('Kill', 'Quarantine', 'DisableRunKey', 'DisableTask', 'DisableService', 'DisableWmi', 'BlockAddress', 'BlockProgram', 'DisableAccount', 'Isolate')

function Test-WfxRefusedProcess {
    <# '' when a process may be stopped; otherwise the reason it never is. Pure. #>
    param([string]$Name, [int]$ProcessId = -1, [int]$Self = -1)
    $n = ([string]$Name).ToLowerInvariant() -replace '\.exe$', ''
    if ($ProcessId -in 0, 4) { return 'Windows itself (System / Idle).' }
    if ($Self -ge 0 -and $ProcessId -eq $Self) { return 'This is the PowerShell running WinForensicX.' }
    if ($n -eq 'svchost') { return 'svchost.exe hosts many Windows services; stopping it can crash the computer. Disable the one suspicious service instead (-DisableService).' }
    if ($script:WfxCriticalProcess -contains $n) { return "$Name is a critical Windows process or a security product. Stopping it can crash the computer or blind your defences." }
    return ''
}

function Test-WfxRefusedService {
    param([string]$Name)
    if ($script:WfxCriticalService -contains ([string]$Name).ToLowerInvariant()) { return "$Name is a service Windows or its security depends on; disabling it can stop the computer from starting, logging on or networking." }
    return ''
}

function Test-WfxRunKeyPath {
    <# $true only for the Run / RunOnce keys Respond may remove values from. Pure. #>
    param([string]$Path)
    return [bool]($Path -match '(?i)^(?:HKLM:|HKCU:|Registry::HKEY_(?:LOCAL_MACHINE|CURRENT_USER|USERS\\[^\\]+))\\Software\\(?:Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|Policies\\Explorer\\Run)$')
}

function Test-WfxRefusedFile {
    <# '' when a file may be quarantined. $Signer: Authenticode signer subject, if known. Pure apart from no I/O. #>
    param([string]$Path, [string]$SystemRoot = $env:SystemRoot, [string]$QuarantineRoot = '', [string]$Signature = '', [string]$Signer = '')
    if (-not $Path) { return 'No path.' }
    $p = $Path.TrimEnd('\')
    if ($QuarantineRoot -and ($p + '\').StartsWith($QuarantineRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { return 'It is already in the quarantine.' }
    if ($p -match '^(?i)[a-z]:$' -or $p -match '(?i)^[a-z]:\\(?:pagefile|hiberfil|swapfile)\.sys$') { return 'A drive root or a Windows system file.' }
    if ($SystemRoot -and ($p + '\').StartsWith($SystemRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        if ($Signature -eq 'Valid' -and $Signer -match '(?i)O=Microsoft (?:Corporation|Windows)') { return 'A Microsoft-signed file in the Windows folder: removing it can break Windows.' }
    }
    return ''
}

function Test-WfxRefusedAddress {
    <# '' when an address may be blocked; otherwise why not. $Own: this computer's addresses. Pure. #>
    param([string]$Address, [string[]]$Own = @())
    $a = ([string]$Address).Trim()
    if (-not $a) { return 'No address.' }
    $ip = $null; $hostPart = ($a -split '/')[0]
    if (-not [System.Net.IPAddress]::TryParse($hostPart, [ref]$ip)) { return "'$a' is not an IP address or range." }
    if ($a -match '/(\d+)$' -and [int]$Matches[1] -lt 8) { return 'That range is too wide (most of the internet).' }
    if ([System.Net.IPAddress]::IsLoopback($ip) -or $hostPart -in '0.0.0.0', '::', '255.255.255.255') { return 'Loopback, "any" or broadcast.' }
    if ($Own -contains $hostPart) { return 'That is this computer''s own address.' }
    return ''
}

function Test-WfxRefusedAccount {
    param([string]$Name, [string]$Current = [Environment]::UserName, [bool]$IsLastAdmin = $false)
    $n = ([string]$Name).ToLowerInvariant()
    if ($n -match '\\') { $n = ($n -split '\\')[-1] }
    if ($n -eq ([string]$Current).ToLowerInvariant()) { return 'That is the account you are using now.' }
    if ($script:WfxProtectedAccount -contains $n) { return 'A built-in system account.' }
    if ($IsLastAdmin) { return 'It is the last enabled local administrator; you could lock yourself out.' }
    return ''
}

function Get-WfxQuarantineRoot {
    <# Downloads\WinForensicX-Quarantine of the account running the tool (or -Path). #>
    param([string]$Path = '')
    if ($Path) { return [IO.Path]::GetFullPath($Path) }
    $dl = ''
    try { $dl = [string](Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name '{374DE290-123F-4565-9164-39C4925E467B}' -ErrorAction Stop).'{374DE290-123F-4565-9164-39C4925E467B}' } catch {}
    if ($dl) { $dl = [Environment]::ExpandEnvironmentVariables($dl) } else { $dl = Join-Path $env:USERPROFILE 'Downloads' }
    Join-Path $dl 'WinForensicX-Quarantine'
}

function Get-WfxActionRecord {
    <# The saved action records (newest first). Read-only; used by Get-WfxAction and by triage. #>
    param([string]$Root = '', [int]$Days = 0)
    if (-not $Root) { $Root = Get-WfxQuarantineRoot }
    $dir = Join-Path $Root 'actions'
    if (-not (Test-Path -LiteralPath $dir)) { return }
    $since = if ($Days -gt 0) { (Get-Date).ToUniversalTime().AddDays(-$Days) } else { [datetime]::MinValue }
    Get-ChildItem -LiteralPath $dir -Filter '*.json' -File -ErrorAction SilentlyContinue | ForEach-Object {
        try { Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
    } | Where-Object { $_ -and (ConvertTo-WfxDateTime $_.Time) -ge $since } | Sort-Object { [string]$_.Time } -Descending
}

function Test-WfxQuarantineFolder {
    <# '' when a folder may become the quarantine (it is about to be locked to administrators): a new or empty
       folder, or one this tool already made (it holds the .wfx-quarantine marker). Never a drive root, a
       system folder or a folder with other content, whose permissions it would otherwise take away. #>
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    if ($full -eq '' -or $full -match '^[A-Za-z]:$' -or $full -eq '/') { return 'A drive root cannot be the quarantine.' }
    $eq = { param($x) $x -and $full -eq ([string]$x).TrimEnd('\', '/') }
    $under = { param($x) $x -and ($full + '\').StartsWith(([string]$x).TrimEnd('\', '/') + '\', [StringComparison]::OrdinalIgnoreCase) }
    foreach ($sys in @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)})) { if (& $under $sys) { return "The quarantine cannot be inside $sys." } }
    $usersDir = if ($env:USERPROFILE) { Split-Path -Parent $env:USERPROFILE } else { '' }
    foreach ($top in @($env:ProgramData, $env:USERPROFILE, $usersDir, $env:PUBLIC)) { if (& $eq $top) { return "The quarantine cannot be $full itself (a system or profile folder)." } }
    if (Test-Path -LiteralPath $full -PathType Leaf) { return "$full is a file." }
    if (Test-Path -LiteralPath $full -PathType Container) {
        if (Test-Path -LiteralPath (Join-Path $full '.wfx-quarantine')) { return '' }
        if (@(Get-ChildItem -LiteralPath $full -Force -ErrorAction SilentlyContinue | Select-Object -First 1).Count) { return "$full already holds other files; its permissions would be replaced. Choose a new or empty folder." }
    }
    return ''
}

function Test-WfxCloudPath {
    <# '' when the folder is local; otherwise the sync service that would copy quarantined files off the computer. Pure. #>
    param([string]$Path, [string[]]$CloudRoots = @($env:OneDrive, $env:OneDriveCommercial, $env:OneDriveConsumer))
    if ($Path -match '^\\\\') { return 'a network share' }
    foreach ($r in @($CloudRoots | Where-Object { $_ })) { if (($Path + '\').StartsWith($r.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { return 'OneDrive' } }
    if ($Path -match '(?i)\\(?:OneDrive(?: - [^\\]+)?|Dropbox|Google Drive|My Drive|iCloudDrive|Box)\\') { return ($Matches[0].Trim('\')) }
    return ''
}

# ── quarantine file format ──
# "WFXQ" + version 2 + AES-256 key (32 bytes) + IV (16 bytes) + the content encrypted with AES-CBC. The key
# travels in the file: this is not secrecy, it makes the file unrunnable and invisible to scanner
# signatures, and it is restored byte for byte. AES is built into .NET, so nothing is compiled.
$script:WfxQuarantineMagic = [byte[]](0x57, 0x46, 0x58, 0x51, 2)

function Write-WfxQuarantineFile {
    <# Encrypts $Source into $Target (which must not exist). Returns the SHA-256 of the original content. #>
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Target)
    $aes = [Security.Cryptography.Aes]::Create(); $aes.KeySize = 256; $aes.GenerateKey(); $aes.GenerateIV()
    $sha = [Security.Cryptography.SHA256]::Create()
    $in = [IO.File]::Open($Source, 'Open', 'Read', 'Read')
    try {
        $out = [IO.File]::Open($Target, 'CreateNew', 'Write', 'None')
        try {
            $out.Write($script:WfxQuarantineMagic, 0, 5); $out.Write($aes.Key, 0, 32); $out.Write($aes.IV, 0, 16)
            $cs = New-Object Security.Cryptography.CryptoStream($out, $aes.CreateEncryptor(), 'Write')
            $buf = New-Object byte[] 1048576
            while (($n = $in.Read($buf, 0, $buf.Length)) -gt 0) { [void]$sha.TransformBlock($buf, 0, $n, $null, 0); $cs.Write($buf, 0, $n) }
            $cs.FlushFinalBlock(); $cs.Dispose()
            [void]$sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
        } finally { $out.Dispose() }
    } finally { $in.Dispose(); $aes.Dispose() }
    -join ($sha.Hash | ForEach-Object { $_.ToString('x2') })
}

function Read-WfxQuarantineFile {
    <# Decrypts a .wfxq file to $Target (or, with no $Target, only hashes it). Returns the SHA-256 of the content. #>
    param([Parameter(Mandatory)][string]$Source, [string]$Target = '')
    $sha = [Security.Cryptography.SHA256]::Create()
    $in = [IO.File]::Open($Source, 'Open', 'Read', 'Read')
    $out = $null; $aes = $null
    try {
        $hdr = New-Object byte[] 53
        if ($in.Read($hdr, 0, 53) -ne 53 -or (Compare-Object $hdr[0..4] $script:WfxQuarantineMagic -SyncWindow 0)) { throw "Not a WinForensicX quarantine file: $Source" }
        $aes = [Security.Cryptography.Aes]::Create(); $aes.KeySize = 256; $aes.Key = $hdr[5..36]; $aes.IV = $hdr[37..52]
        $cs = New-Object Security.Cryptography.CryptoStream($in, $aes.CreateDecryptor(), 'Read')
        if ($Target) { $out = [IO.File]::Open($Target, 'CreateNew', 'Write', 'None') }
        $buf = New-Object byte[] 1048576
        while (($n = $cs.Read($buf, 0, $buf.Length)) -gt 0) { [void]$sha.TransformBlock($buf, 0, $n, $null, 0); if ($out) { $out.Write($buf, 0, $n) } }
        [void]$sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
    } finally { if ($out) { $out.Dispose() }; $in.Dispose(); if ($aes) { $aes.Dispose() } }
    -join ($sha.Hash | ForEach-Object { $_.ToString('x2') })
}

# ── response plan ──
function Get-WfxRemoteIp {
    <# The IP in "host (1.2.3.4):443", "1.2.3.4:443" or "[2001:db8::1]:443". '' if none. Pure. #>
    param([string]$Remote)
    $c = @()
    if ($Remote -match '\(([^)]+)\):\d+$') { $c += $Matches[1] }
    if ($Remote -match '^\[([^\]]+)\]:\d+$') { $c += $Matches[1] }
    if ($Remote -match '^([^\s()\[\]]+):\d+$') { $c += $Matches[1] }
    $c += $Remote
    foreach ($x in $c) { $ip = $null; if ([System.Net.IPAddress]::TryParse([string]$x, [ref]$ip)) { return $ip.ToString() } }
    ''
}

function ConvertTo-WfxResponsePlan {
    <#
    .SYNOPSIS Suggests containment actions from a triage result: stop the processes, quarantine the files,
    disable the autostarts and block the public addresses that findings point at. Pure: nothing is done.
    Critical and High findings are selected; the rest are listed unselected. Every action is checked again,
    and confirmed one by one, when Invoke-WfxRespond runs it.
    #>
    param($Result, $Bundle = $null)
    $actions = [ordered]@{}
    $procs = @{}; foreach ($p in @(Get-WfxValue $Bundle 'Process' @())) { $procs[[string](Get-WfxValue $p 'Pid' '')] = $p }
    $add = {
        param($Type, $Target, [hashtable]$Params, $F)
        $k = "$Type|$([string]$Target)".ToLowerInvariant()
        $sel = [string]$F.Severity -in 'Critical', 'High'
        if ($actions.Contains($k)) { if ($sel) { $actions[$k].Selected = $true }; $actions[$k].Findings += [string]$F.Id; return }
        $actions[$k] = [pscustomobject]@{ Type = $Type; Target = [string]$Target; Params = $Params; Reason = [string]$F.Title; Severity = [string]$F.Severity; Findings = @([string]$F.Id); Selected = $sel }
    }
    foreach ($f in @(Get-WfxValue $Result 'Findings' @())) {
        if (Test-WfxPostureFinding $f) { continue }
        $e = Get-WfxValue $f 'Evidence' $null
        $src = [string](Get-WfxValue $f 'Source' '')
        $path = [string](Get-WfxValue $e 'Path' '')
        $procId = [string](Get-WfxValue $e 'Pid' '')
        if ($procId -match '^\d+$' -and [int]$procId -gt 4 -and $src -in 'process', 'volatile', 'network') {
            $p = $procs[$procId]
            $name = if ($p) { [string](Get-WfxValue $p 'Name' '') } else { [string](Get-WfxValue $e 'Process' '') }
            if (-not (Test-WfxRefusedProcess -Name $name -ProcessId ([int]$procId))) {
                & $add 'Kill' "$name ($procId)" @{ Pid = [int]$procId; Name = $name; Path = [string](Get-WfxValue $p 'Path' $path); StartTime = [string](Get-WfxValue $p 'CreateTime' ''); Sha256 = [string](Get-WfxValue $p 'Sha256' '') } $f
            }
        }
        if ($src -eq 'persistence') {
            $kind = [string](Get-WfxValue $e 'Kind' ''); $nm = [string](Get-WfxValue $e 'Name' ''); $loc = [string](Get-WfxValue $e 'Location' '')
            switch ($kind) {
                'RunKey' { if (Test-WfxRunKeyPath $loc) { & $add 'DisableRunKey' "$loc\$nm" @{ Key = $loc; Name = $nm } $f } }
                'ScheduledTask' { & $add 'DisableTask' $nm @{ Task = $nm } $f }
                'Service' { if (-not (Test-WfxRefusedService $nm)) { & $add 'DisableService' $nm @{ Name = $nm } $f } }
                'WmiSubscription' { & $add 'DisableWmi' $nm @{ Consumer = $nm } $f }
                'Startup' { if ($loc -and $nm) { & $add 'Quarantine' (Join-Path $loc $nm) @{ Path = (Join-Path $loc $nm) } $f } }
            }
            if ($path -and (Test-WfxUserWritablePath $path)) { & $add 'Quarantine' $path @{ Path = $path } $f }
        }
        if ($src -eq 'files' -and $path) { & $add 'Quarantine' $path @{ Path = $path } $f }
        if ($src -eq 'volatile') {
            $m = [string](Get-WfxValue $e 'Module' '')
            if ($m) { & $add 'Quarantine' $m @{ Path = $m } $f }
        }
        $remote = [string](Get-WfxValue $e 'Remote' '')
        if ($remote -and $src -eq 'network') {
            $ip = Get-WfxRemoteIp $remote
            if ($ip -and -not (Test-WfxPrivateIp $ip) -and -not (Test-WfxRefusedAddress $ip)) { & $add 'BlockAddress' $ip @{ Address = $ip } $f }
        }
    }
    $i = 0
    $list = foreach ($a in $actions.Values) { $i++; $a | Add-Member -NotePropertyName Id -NotePropertyValue ('A{0:D3}' -f $i) -PassThru }
    [pscustomobject]@{
        Schema    = 'winforensicx.respond-plan/1'
        Host      = [string](Get-WfxValue $Result 'HostName' '')
        Case      = [string](Get-WfxValue (Get-WfxValue $Result 'Case' $null) 'Id' '')
        Created   = (Get-WfxUtcNow)
        Note      = 'Suggestions only. Nothing has been done. Run: Invoke-WfxRespond -PlanPath <this file>. Each action is checked again and confirmed one by one.'
        Actions   = @($list)
    }
}
