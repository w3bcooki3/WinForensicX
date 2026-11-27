# Volatile-state analyzer: open named pipes and DLLs loaded from user-writable folders.
#
# Pipes: the default pipe names of C2 frameworks (threats.json suspiciousPipes: Cobalt Strike, Meterpreter,
# Covenant ...) and the pipe names of privilege-escalation and remote-execution tools (the same pattern the
# Sysmon 17/18 rule in events.json uses, so both stay one list).
# Modules: an unsigned DLL from a user-writable folder loaded by a Windows program, or by a program installed
# somewhere else, is how DLL side-loading and planted DLLs look. A program that lives in AppData loading its
# own unsigned DLLs from its own folder is normal (Teams, Slack, Discord, VS Code ...) and is not reported.

function Test-WfxSuspiciousPipe {
    <# Returns $null, or @{ Kind; Severity; Why; Technique; Rule } for one pipe name (without \\.\pipe\). #>
    param([AllowEmptyString()][string]$Name)
    if (-not $Name) { return $null }
    $n = '\' + $Name.TrimStart('\')
    foreach ($p in @(Get-WfxPipeList)) {
        if ($n.IndexOf([string]$p, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return @{ Kind = 'c2'; Severity = 'High'; Why = "Pipe name used by default by C2 frameworks (contains '$p')"; Technique = @('T1055', 'T1570'); Rule = 'VOL-PIPE-C2' }
        }
    }
    $rx = Get-WfxPipeEscalationPattern
    if ($rx -and (Test-WfxRxMatch $rx $n)) {
        return @{ Kind = 'escalation'; Severity = 'High'; Why = 'Pipe name used by privilege-escalation or remote-execution tools (potato exploits, PsExec-style services)'; Technique = @('T1134.001', 'T1569.002'); Rule = 'VOL-PIPE-ESCALATION' }
    }
    return $null
}

function Get-WfxPipeList {
    if ($null -eq $script:WfxPipeList) { $script:WfxPipeList = @(try { @((Get-WfxRulePack -Name 'threats').suspiciousPipes | Where-Object { $_ }) } catch { }) }
    $script:WfxPipeList
}

function Get-WfxPipeEscalationPattern {
    if ($null -eq $script:WfxPipeRx) {
        $script:WfxPipeRx = ''
        try {
            $r = @((Get-WfxRulePack -Name 'events').rules | Where-Object { $_.id -eq 'EVT-SYSMON-17-PIPE-IMPERSONATION' }) | Select-Object -First 1
            if ($r) { $script:WfxPipeRx = [string](Get-WfxValue (Get-WfxValue $r 'match' $null) 'PipeName' '') }
        } catch {}
    }
    $script:WfxPipeRx
}

function Test-WfxModuleLoad {
    <# Returns $null, or @{ Severity; Why; Technique; Rule } for one loaded-module record. #>
    param($Module)
    $mod = [string](Get-WfxValue $Module 'Module' '')
    $exe = [string](Get-WfxValue $Module 'ProcessPath' '')
    $sig = [string](Get-WfxValue $Module 'Signature' '')
    if (-not $mod -or -not (Test-WfxUserWritablePath $mod)) { return $null }
    if ($sig -eq 'NotChecked' -or $sig -eq '' -or (Test-WfxTrustedSignature $sig)) { return $null }
    $modDir = (Split-Path -Parent $mod).ToLowerInvariant().TrimEnd('\')
    $exeDir = if ($exe) { (Split-Path -Parent $exe).ToLowerInvariant().TrimEnd('\') } else { '' }
    $leaf = Split-Path -Leaf $mod
    if ($exe -and $exe -match '(?i)^[a-z]:\\windows\\') {
        return @{ Severity = 'High'; Why = "Windows program loads an unsigned DLL from a user-writable folder: $leaf ($sig)"; Technique = @('T1574.002', 'T1574.001'); Rule = 'VOL-MODULE-SIDELOAD-WINDOWS' }
    }
    # The program's own folder (or a sub-folder of it) is its install; anything else is foreign to it.
    if ($exeDir -and ($modDir -eq $exeDir -or $modDir.StartsWith($exeDir + '\'))) { return $null }
    # Squirrel-installed apps (Teams classic, Slack, Discord) run from ...\<App>\app-1.2.3\: the whole <App> folder is theirs.
    if ($exeDir -and (Split-Path -Leaf $exeDir) -match '^app-\d') {
        $appRoot = (Split-Path -Parent $exeDir).ToLowerInvariant().TrimEnd('\')
        if ($modDir -eq $appRoot -or $modDir.StartsWith($appRoot + '\')) { return $null }
    }
    return @{ Severity = 'Medium'; Why = "Unsigned DLL from a user-writable folder outside the program's own folder: $leaf ($sig)"; Technique = @('T1574.002', 'T1055.001'); Rule = 'VOL-MODULE-FOREIGN-UNSIGNED' }
}

function Invoke-WfxVolatileAnalyzer {
    param($Volatile, [string]$HostName = '')
    $findings = [System.Collections.Generic.List[object]]::new()
    if (-not $Volatile) { return , $findings.ToArray() }
    foreach ($name in @(Get-WfxValue $Volatile 'Pipes' @() | Where-Object { $_ })) {
        $v = Test-WfxSuspiciousPipe -Name ([string]$name)
        if (-not $v) { continue }
        $desc = if ($v.Kind -eq 'c2') { 'A named pipe with a name that Cobalt Strike, Meterpreter, Covenant or a similar command-and-control framework uses by default is open right now. These frameworks use pipes to talk between implants and to inject into other processes. Renamed pipes are common, so the absence of this finding proves nothing.' }
                else { 'A named pipe used by potato-style privilege escalation (PrintSpoofer, EfsPotato, RoguePotato), Kekeo, or PsExec-style remote execution is open right now. PsExec is also an admin tool: confirm whether someone ran it on purpose.' }
        $findings.Add((New-WfxFinding -Id $v.Rule -Title "Suspicious named pipe open: \\.\pipe\$name" -Severity $v.Severity -Confidence 'Medium' -Category 'Process' -Technique $v.Technique `
                    -Description $desc -Recommendation 'Find the process that serves the pipe (Process Explorer: Find Handle or DLL, search the pipe name; or Sysinternals handle.exe), capture memory before stopping it, and check how it started.' `
                    -Entity "pipe:$name" -HostName $HostName -Source 'volatile' -Evidence ([ordered]@{ Pipe = "\\.\pipe\$name"; Why = $v.Why })))
    }
    foreach ($m in @(Get-WfxValue $Volatile 'Modules' @() | Where-Object { $_ })) {
        $v = Test-WfxModuleLoad -Module $m
        if (-not $v) { continue }
        $proc = [string](Get-WfxValue $m 'Process' '')
        $mod = [string](Get-WfxValue $m 'Module' '')
        $findings.Add((New-WfxFinding -Id $v.Rule -Title ("{0} loaded {1}" -f $proc, (Split-Path -Leaf $mod)) -Severity $v.Severity -Confidence 'Medium' -Category 'Process' -Technique $v.Technique `
                    -Description ("{0}. DLL side-loading places a malicious DLL where a trusted program will load it, so the code runs inside that program. Some legitimate software does load unsigned DLLs from user folders: check the publisher and when the file appeared." -f $v.Why) `
                    -Recommendation 'Hash the DLL and check it (Get-WfxFileTriage), find when it was written (Explore, Recent changes), and capture memory before stopping the process.' `
                    -Entity "module:$($proc.ToLowerInvariant()):$($mod.ToLowerInvariant())" -HostName $HostName -Source 'volatile' `
                    -Evidence ([ordered]@{ Pid = (Get-WfxValue $m 'Pid' ''); Process = $proc; ProcessPath = (Get-WfxValue $m 'ProcessPath' ''); Module = $mod; Signature = (Get-WfxValue $m 'Signature' '') })))
    }
    , $findings.ToArray()
}
