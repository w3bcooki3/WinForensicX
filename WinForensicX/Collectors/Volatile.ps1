# Volatile state that is gone after a restart and that the other collectors do not keep: open named pipes,
# who is signed in, the neighbour (ARP) cache, and DLLs loaded from user-writable folders. Read-only.
#
# Named pipes: only the NAMES are listed (\\.\pipe\). No pipe is opened: connecting to one would talk to
# whatever program serves it.
# Loaded modules: the module list of each process the account can open, read through the normal Windows
# process API (as Task Manager and Process Explorer do). These processes are never opened: LSASS, the other
# critical system processes and the security products (touching LSASS memory is what credential theft looks
# like, and an EDR would rightly raise an alert). Only modules in user-writable folders are kept, so the
# bundle stays small; those are the ones DLL side-loading and planted DLLs come from.

# Process names whose modules are never read.
$script:WfxModuleSkip = @('System', 'Idle', 'Registry', 'Memory Compression', 'Secure System', 'smss', 'csrss', 'wininit', 'services',
    'lsass', 'lsaiso', 'winlogon', 'MsMpEng', 'MpDefenderCoreService', 'NisSrv', 'MsSense', 'SenseIR', 'SenseCncProxy', 'SecurityHealthService',
    'MsMpEngCP', 'vmmem', 'vmcompute', 'audiodg', 'WinForensicX')

function ConvertFrom-WfxQuser {
    <# Parses "quser" output (one header line, then one line per session) into rows. Pure. The session-name
       column is empty for disconnected sessions, which shifts the columns; both shapes are handled. #>
    param([string[]]$Line)
    foreach ($l in @($Line | Select-Object -Skip 1)) {
        if ([string]::IsNullOrWhiteSpace($l) -or $l.Length -lt 2) { continue }
        $t = @($l.Substring(1).Trim() -split '\s{2,}')
        if ($t.Count -ge 6) { [pscustomobject]@{ User = $t[0]; Session = $t[1]; Id = $t[2]; State = $t[3]; Idle = $t[4]; LogonTime = ($t[5..($t.Count - 1)] -join ' '); Current = $l.StartsWith('>') } }
        elseif ($t.Count -eq 5) { [pscustomobject]@{ User = $t[0]; Session = ''; Id = $t[1]; State = $t[2]; Idle = $t[3]; LogonTime = $t[4]; Current = $l.StartsWith('>') } }
    }
}

function Get-WfxPipeName {
    <# Names of the named pipes open now, without the \\.\pipe\ prefix. #>
    $names = $null
    try { $names = [IO.Directory]::GetFiles('\\.\pipe\') } catch {}
    if ($null -eq $names) {
        # .NET Framework refuses the whole list if one pipe name holds a character it considers illegal.
        $names = @(Get-ChildItem -LiteralPath '\\.\pipe\' -ErrorAction Stop | ForEach-Object { $_.FullName })
    }
    @($names | ForEach-Object { ([string]$_) -replace '^\\\\\.\\pipe\\', '' } | Where-Object { $_ } | Sort-Object -Unique)
}

function Get-WfxModuleData {
    <# DLLs loaded from user-writable folders, per process, with signature status. Bounded. #>
    param([int]$MaxModules = 2000, [int]$MaxSignatureChecks = 400)
    $out = [System.Collections.Generic.List[object]]::new()
    $skip = @{}; foreach ($n in $script:WfxModuleSkip) { $skip[$n.ToLowerInvariant()] = $true }
    $sigChecks = 0; $denied = 0; $self = $PID
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue | Sort-Object Id)) {
        if ($out.Count -ge $MaxModules) { Add-WfxGap -Source 'volatile:modules' -Reason "Stopped after $MaxModules modules from user-writable folders." ; break }
        if ($p.Id -le 4 -or $p.Id -eq $self -or $skip.ContainsKey(([string]$p.ProcessName).ToLowerInvariant())) { continue }
        $mods = $null
        try { $mods = @($p.Modules) } catch { $denied++; continue }
        $exe = ''
        try { $exe = [string]$p.MainModule.FileName } catch {}
        foreach ($m in $mods) {
            $f = [string]$m.FileName
            if (-not $f -or $f -eq $exe -or -not (Test-WfxUserWritablePath $f)) { continue }
            $sig = 'NotChecked'
            if ($sigChecks -lt $MaxSignatureChecks -or $script:WfxSigCache.ContainsKey($f.ToLowerInvariant())) {
                if (-not $script:WfxSigCache.ContainsKey($f.ToLowerInvariant())) { $sigChecks++ }
                $sig = Get-WfxSignature $f
            }
            $out.Add([pscustomobject]@{ Pid = [int]$p.Id; Process = [string]$p.ProcessName; ProcessPath = $exe; Module = $f; Signature = $sig })
            if ($out.Count -ge $MaxModules) { break }
        }
    }
    if ($denied) { Add-WfxGap -Source 'volatile:modules' -Reason "$denied process(es) could not be opened to list their modules$(if (-not (Test-WfxAdmin)) { ' (other users'' and system processes need administrator rights)' })." }
    if ($sigChecks -ge $MaxSignatureChecks) { Add-WfxGap -Source 'volatile:modules' -Reason "Signatures were checked for the first $MaxSignatureChecks modules only; the rest are marked NotChecked." }
    , $out.ToArray()
}

function Get-WfxVolatileData {
    if (-not (Test-WfxWindows)) { return $null }
    $pipes = Invoke-WfxStep 'volatile:pipes' { Get-WfxPipeName } @()
    $sessions = Invoke-WfxStep 'volatile:sessions' {
        $q = @(quser 2>$null)
        if ($q.Count -ge 2) { @(ConvertFrom-WfxQuser -Line $q) }
        else { @([pscustomobject]@{ User = [string](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName; Session = 'console'; Id = ''; State = 'Active'; Idle = ''; LogonTime = ''; Current = $false }) }
    } @()
    $arp = Invoke-WfxStep 'volatile:arp' {
        @(Get-NetNeighbor -ErrorAction Stop | Where-Object { $_.State -notin 'Unreachable', 'Incomplete' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^(?:00-00-00-00-00-00|FF-FF-FF-FF-FF-FF|)$' -and $_.IPAddress -notmatch '^(?:22[4-9]|23\d|255)\.|^ff' } |
            ForEach-Object { [pscustomobject]@{ IPAddress = [string]$_.IPAddress; LinkLayerAddress = [string]$_.LinkLayerAddress; State = [string]$_.State; Interface = [string]$_.InterfaceAlias } })
    } @()
    $modules = Invoke-WfxStep 'volatile:modules' { Get-WfxModuleData } @()
    [pscustomobject]@{
        Pipes    = @($pipes)
        Sessions = @($sessions)
        Arp      = @($arp)
        Modules  = @($modules)
    }
}
