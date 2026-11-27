# Memory-capture readiness and the incident card. Pure: works on the facts from Get-WfxReadinessData (live or
# from a saved bundle), so it runs and is tested on any OS.
#
# Status of each check:
#   Ready      this way of keeping memory (or evidence) works now
#   Not ready  it does not; Fix says what to set up BEFORE an incident (changing it now usually needs a restart,
#              and a restart is what destroys the memory you want)
#   Note       something a responder must know before capturing memory or switching the computer off
#   Unknown    the setting could not be read (usually: no administrator rights)
# None of this is a finding: it does not change the compromise or posture scores.

function New-WfxReadinessRow {
    param([string]$Check, [ValidateSet('Ready', 'Not ready', 'Note', 'Unknown')][string]$Status, [string]$Value = '', [string]$Why = '', [string]$Fix = '', [string]$Key = '')
    [pscustomobject]@{ Key = $Key; Check = $Check; Status = $Status; Value = $Value; Why = $Why; Fix = $Fix }
}

function Format-WfxBytes {
    param($Bytes)
    if ($null -eq $Bytes) { return '?' }
    $b = [double]$Bytes
    if ($b -ge 1TB) { return ('{0:N1} TB' -f ($b / 1TB)) }
    if ($b -ge 1GB) { return ('{0:N1} GB' -f ($b / 1GB)) }
    return ('{0:N0} MB' -f ($b / 1MB))
}

function Get-WfxReadinessCheck {
    <#
    .SYNOPSIS Turns readiness facts into checks: can memory be kept if this computer has to go off, and what a
    responder must know first. Returns rows { Key, Check, Status, Value, Why, Fix }.
    .PARAMETER Data  The object from Get-WfxReadinessData (or the same from a saved bundle).
    .PARAMETER Now   The time "uptime" is measured to (default: when the data was collected).
    #>
    param($Data, $Now = $null)
    $rows = [System.Collections.Generic.List[object]]::new()
    if (-not $Data) { return , $rows.ToArray() }
    $dump = Get-WfxValue $Data 'Dump' $null
    $mem = Get-WfxValue $Data 'Memory' $null
    $pow = Get-WfxValue $Data 'Power' $null
    $pro = Get-WfxValue $Data 'Protection' $null
    $bl = Get-WfxValue $Data 'BitLocker' $null
    $ram = if ($mem) { ConvertTo-WfxLong (Get-WfxValue $mem 'RamBytes' 0) } else { 0L }

    # ── Virtual machine: the hypervisor can copy memory with nothing running inside ──
    $vm = if ($mem) { [string](Get-WfxValue $mem 'VmVendor' '') } else { '' }
    if ($vm) {
        $rows.Add((New-WfxReadinessRow -Key 'vm' -Check 'Virtual machine' -Status 'Ready' -Value $vm -Why 'A snapshot or suspend from the hypervisor saves all memory with nothing running inside the guest: the cleanest capture there is.' -Fix ''))
    } elseif ($mem) {
        $rows.Add((New-WfxReadinessRow -Key 'vm' -Check 'Virtual machine' -Status 'Note' -Value ("No ({0} {1})" -f (Get-WfxValue $mem 'Manufacturer' ''), (Get-WfxValue $mem 'Model' '')).Trim() -Why 'A physical computer: memory can only be kept by a memory-capture tool run on it, a crash dump or the hibernation file.'))
    }

    # ── Crash dump: what a stop (or a forced crash) would write ──
    if ($dump) {
        $t = Get-WfxValue $dump 'CrashDumpEnabled' $null
        $filter = (Get-WfxValue $dump 'FilterPages' $null) -eq 1
        $fix = 'Before an incident: System Properties, Advanced, Startup and Recovery, "Complete memory dump" (or set CrashDumpEnabled to 1 under HKLM\SYSTEM\CurrentControlSet\Control\CrashControl). Takes effect after a restart.'
        switch ([string]$t) {
            '1' { $rows.Add((New-WfxReadinessRow -Key 'dump' -Check 'Crash dump keeps all memory' -Status 'Ready' -Value $(if ($filter) { 'Active memory dump' } else { 'Complete memory dump' }) -Why 'If Windows stops (or you force a crash), all memory in use is written to the dump file, including running programs.')) }
            { $_ -in '2', '7' } { $rows.Add((New-WfxReadinessRow -Key 'dump' -Check 'Crash dump keeps all memory' -Status 'Not ready' -Value $(if ($_ -eq '7') { 'Automatic (kernel memory only)' } else { 'Kernel memory only' }) -Why 'A dump would hold the kernel but not the memory of running programs, where most attacker activity is.' -Fix $fix)) }
            '3' { $rows.Add((New-WfxReadinessRow -Key 'dump' -Check 'Crash dump keeps all memory' -Status 'Not ready' -Value 'Small memory dump' -Why 'A small dump holds only a few hundred kilobytes of crash details, not memory.' -Fix $fix)) }
            '0' { $rows.Add((New-WfxReadinessRow -Key 'dump' -Check 'Crash dump keeps all memory' -Status 'Not ready' -Value 'None' -Why 'Crash dumps are turned off.' -Fix $fix)) }
            default { $rows.Add((New-WfxReadinessRow -Key 'dump' -Check 'Crash dump keeps all memory' -Status 'Unknown' -Value '' -Why 'The crash-dump setting could not be read.')) }
        }
        # Space for the dump on the volume it is written to.
        $free = Get-WfxValue $dump 'DumpVolumeFree' $null
        if ($null -ne $free -and $ram -gt 0) {
            $ok = [long]$free -ge $ram
            $rows.Add((New-WfxReadinessRow -Key 'dumpspace' -Check 'Free space for a full dump' -Status $(if ($ok) { 'Ready' } else { 'Not ready' }) -Value ("{0} free for {1} of memory ({2})" -f (Format-WfxBytes $free), (Format-WfxBytes $ram), (Get-WfxValue $dump 'DumpFile' '')) -Why 'A complete dump needs about as much free space as there is memory.' -Fix $(if ($ok) { '' } else { 'Free space on that drive, or point the dump file to a larger volume.' })))
        }
    }

    # ── Page file: a complete dump is staged in it unless a dedicated dump file is set ──
    if ($mem -and $ram -gt 0) {
        $dedicated = if ($dump) { [string](Get-WfxValue $dump 'DedicatedDumpFile' '') } else { '' }
        $pfs = @(Get-WfxValue $mem 'PageFiles' @() | Where-Object { $_ })
        $sysDrive = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
        $sysMb = 0; foreach ($p in $pfs) { if ([string](Get-WfxValue $p 'Path' '') -like "$sysDrive*") { $sysMb += [int](Get-WfxValue $p 'AllocatedMB' 0) } }
        $needMb = [long][Math]::Ceiling($ram / 1MB) + 257
        if ($dedicated) {
            $rows.Add((New-WfxReadinessRow -Key 'pagefile' -Check 'Page file large enough for a full dump' -Status 'Ready' -Value "Dedicated dump file: $dedicated" -Why 'A dedicated dump file is used instead of the page file.'))
        } elseif ((Get-WfxValue $mem 'AutoPageFile' $false) -eq $true) {
            $rows.Add((New-WfxReadinessRow -Key 'pagefile' -Check 'Page file large enough for a full dump' -Status 'Note' -Value ("System-managed, now {0} MB; a full dump needs {1} MB" -f $sysMb, $needMb) -Why 'Windows sizes a system-managed page file itself and may not make it large enough for a complete dump.' -Fix "Before an incident: set a fixed page file of at least $needMb MB on $sysDrive, or a dedicated dump file."))
        } else {
            $ok = $sysMb -ge $needMb
            $rows.Add((New-WfxReadinessRow -Key 'pagefile' -Check 'Page file large enough for a full dump' -Status $(if ($ok) { 'Ready' } else { 'Not ready' }) -Value ("{0} MB on {1}; a full dump needs {2} MB" -f $sysMb, $sysDrive, $needMb) -Why 'A complete dump is first written into the page file on the system drive.' -Fix $(if ($ok) { '' } else { "Before an incident: make the page file on $sysDrive at least $needMb MB, or set a dedicated dump file." })))
        }
        $clear = Get-WfxValue $mem 'ClearPageFileAtShutdown' $null
        if ($clear -eq 1) {
            $rows.Add((New-WfxReadinessRow -Key 'pfclear' -Check 'Page file kept after shutdown' -Status 'Note' -Value 'Wiped at shutdown' -Why 'Pieces of memory written to the page file are erased when the computer is shut down.'))
        } else {
            $rows.Add((New-WfxReadinessRow -Key 'pfclear' -Check 'Page file kept after shutdown' -Status 'Ready' -Value 'Kept' -Why 'pagefile.sys survives power-off and can hold pieces of memory; collect it with a raw-copy tool.'))
        }
    }

    # ── Forced crash from the keyboard ──
    if ($pow) {
        $usb = (Get-WfxValue $pow 'CrashOnCtrlScrollUsb' $null) -eq 1
        $ps2 = (Get-WfxValue $pow 'CrashOnCtrlScrollPs2' $null) -eq 1
        if ($usb -or $ps2) {
            $rows.Add((New-WfxReadinessRow -Key 'ctrlscroll' -Check 'Crash dump on demand (Ctrl+Scroll Lock)' -Status 'Ready' -Value $(if ($usb -and $ps2) { 'USB and PS/2 keyboards' } elseif ($usb) { 'USB keyboards' } else { 'PS/2 keyboards' }) -Why 'Hold the right Ctrl key and press Scroll Lock twice: Windows stops and writes a dump, then restarts. Only useful with a complete dump set.'))
        } else {
            $rows.Add((New-WfxReadinessRow -Key 'ctrlscroll' -Check 'Crash dump on demand (Ctrl+Scroll Lock)' -Status 'Note' -Value 'Not set up' -Why 'Lets a responder force a full memory dump without any tool. It needs a restart to take effect, so it must be set up before an incident.' -Fix 'Before an incident: set CrashOnCtrlScroll = 1 (DWORD) under HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters (USB keyboards) and i8042prt\Parameters (PS/2), then restart.'))
        }

        # ── Hibernation: memory written to disk on purpose ──
        $he = Get-WfxValue $pow 'HibernateEnabled' $null
        $hf = [bool](Get-WfxValue $pow 'HiberFileExists' $false)
        if ($he -eq 1 -or $hf) {
            $rows.Add((New-WfxReadinessRow -Key 'hibernate' -Check 'Hibernation available' -Status 'Ready' -Value $(if ($hf) { 'On (hiberfil.sys present)' } else { 'On' }) -Why 'If it must be switched off, hibernate it (shutdown /h): memory is written to hiberfil.sys and survives power-off.'))
        } elseif ($he -eq 0) {
            $rows.Add((New-WfxReadinessRow -Key 'hibernate' -Check 'Hibernation available' -Status 'Not ready' -Value 'Off' -Why 'Switching off loses memory: there is no hibernation file to write it to.' -Fix 'Before an incident (administrator): powercfg /hibernate on'))
        } else {
            $rows.Add((New-WfxReadinessRow -Key 'hibernate' -Check 'Hibernation available' -Status 'Unknown' -Value '' -Why 'The hibernation setting could not be read.'))
        }
        if ((Get-WfxValue $pow 'FastStartup' $null) -eq 1) {
            $rows.Add((New-WfxReadinessRow -Key 'faststartup' -Check 'Fast Startup' -Status 'Note' -Value 'On' -Why '"Shut down" from the Start menu signs users out and overwrites hiberfil.sys: programs'' memory is lost. To keep memory use shutdown /h, never Shut down or Restart.'))
        }
    }

    # ── BitLocker: the disk can only be imaged after power-off with the recovery key ──
    if ($bl) {
        $prot = [string](Get-WfxValue $bl 'Protection' '')
        $types = @(Get-WfxValue $bl 'ProtectorTypes' @() | ForEach-Object { [string]$_ })
        if ($prot -match '(?i)^On$|^1$') {
            if ($types -contains 'RecoveryPassword') {
                $rows.Add((New-WfxReadinessRow -Key 'bitlocker' -Check 'BitLocker recovery key' -Status 'Note' -Value ("Protected; protectors: {0}" -f ($types -join ', ')) -Why 'Once it is off, the disk can only be read with the recovery key. Make sure you can get it (Active Directory, Entra ID, Microsoft account or a printout) before anything is switched off. The key itself is not read by this tool.'))
            } else {
                $rows.Add((New-WfxReadinessRow -Key 'bitlocker' -Check 'BitLocker recovery key' -Status 'Not ready' -Value ("Protected; protectors: {0}" -f $(if ($types.Count) { $types -join ', ' } else { 'unknown' })) -Why 'No recovery password protector: if the computer is switched off, investigators may not be able to read the disk at all.' -Fix 'Before an incident: add a recovery password (manage-bde -protectors -add C: -RecoveryPassword) and store it in Active Directory or Entra ID.'))
            }
        } elseif ($prot) {
            $rows.Add((New-WfxReadinessRow -Key 'bitlocker' -Check 'BitLocker recovery key' -Status 'Ready' -Value "Not protected ($([string](Get-WfxValue $bl 'Status' '')))" -Why 'The system drive is not locked by BitLocker: it can be imaged after power-off without a key.'))
        }
    } else {
        $rows.Add((New-WfxReadinessRow -Key 'bitlocker' -Check 'BitLocker recovery key' -Status 'Unknown' -Value '' -Why 'BitLocker status could not be read (needs administrator rights). Find out whether the disk is encrypted before switching anything off.'))
    }

    # ── Protections that change how memory can be captured ──
    if ($pro) {
        if ((Get-WfxValue $pro 'MemoryIntegrity' $null) -eq $true) { $rows.Add((New-WfxReadinessRow -Key 'hvci' -Check 'Memory Integrity (HVCI)' -Status 'Note' -Value 'On' -Why 'Some memory-capture drivers will not load. Choose a capture tool that supports Memory Integrity, or use a crash dump or hibernation. Do not turn it off on a suspect machine.')) }
        if ((Get-WfxValue $pro 'RunAsPPL' $null) -eq $true) { $rows.Add((New-WfxReadinessRow -Key 'ppl' -Check 'LSA protection (RunAsPPL)' -Status 'Note' -Value 'On' -Why 'Tools cannot open LSASS on the running system. A full memory capture still contains it.')) }
        if ((Get-WfxValue $pro 'CredentialGuard' $null) -eq $true) { $rows.Add((New-WfxReadinessRow -Key 'credguard' -Check 'Credential Guard' -Status 'Note' -Value 'On' -Why 'Credentials are kept in an isolated area that a memory capture does not include.')) }
    }

    # ── Uptime and power ──
    $boot = ConvertTo-WfxDateTime (Get-WfxValue $Data 'BootUtc' '')
    if ($boot) {
        $ref = ConvertTo-WfxDateTime $(if ($Now) { $Now } else { Get-WfxValue $Data 'Collected' '' })
        if (-not $ref) { $ref = (Get-Date).ToUniversalTime() }
        $days = [Math]::Max(0, ($ref - $boot).TotalDays)
        $rows.Add((New-WfxReadinessRow -Key 'uptime' -Check 'Running since' -Status 'Note' -Value ("{0} UTC ({1})" -f $boot.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture), $(if ($days -ge 1) { '{0:N0} day(s)' -f [Math]::Floor($days) } else { '{0:N0} hour(s)' -f [Math]::Floor($days * 24) })) -Why 'Memory only holds what happened since the last start. Activity before it is gone from memory.'))
    }
    if ($mem -and (Get-WfxValue $mem 'HasBattery' $false) -eq $true) {
        $rows.Add((New-WfxReadinessRow -Key 'battery' -Check 'Battery' -Status 'Note' -Value 'Laptop or tablet' -Why 'Keep it on mains power and do not close the lid: an empty battery or sleep can end what is running.'))
    }
    , $rows.ToArray()
}

function Get-WfxReadinessSummary {
    <# One sentence: the ways memory could be kept right now, best first. #>
    param([object[]]$Check)
    $ready = @{}; foreach ($c in @($Check)) { if ($c.Status -eq 'Ready') { $ready[$c.Key] = $true } }
    $ways = [System.Collections.Generic.List[string]]::new()
    if ($ready['vm']) { $ways.Add('a snapshot from the hypervisor') }
    $ways.Add('a memory-capture tool run now')
    if ($ready['hibernate']) { $ways.Add('hibernating it (shutdown /h)') }
    if ($ready['dump'] -and $ready['ctrlscroll']) { $ways.Add('a forced crash dump (right Ctrl + Scroll Lock twice)') }
    if ($ways.Count -eq 1) { return 'If this computer is switched off or restarted, its memory is lost: the only way to keep it is a memory-capture tool run before anything else. Leave it running.' }
    $list = (@($ways | Select-Object -First ($ways.Count - 1)) -join ', ') + ' or ' + $ways[$ways.Count - 1]
    return ('Memory can be kept by {0}. Switching it off or restarting it any other way loses it.' -f $list)
}

function Get-WfxIncidentCard {
    <#
    .SYNOPSIS The first steps for this computer, in order: what to do and what not to do, adapted to its
    readiness. Returns rows { Kind = 'Do' | 'Avoid'; Text }.
    #>
    param([object[]]$Check)
    $ready = @{}; $state = @{}
    foreach ($c in @($Check)) { $state[$c.Key] = $c; if ($c.Status -eq 'Ready') { $ready[$c.Key] = $true } }
    $card = [System.Collections.Generic.List[object]]::new()
    $do = { param($t) $card.Add([pscustomobject]@{ Kind = 'Do'; Text = $t }) }
    $avoid = { param($t) $card.Add([pscustomobject]@{ Kind = 'Avoid'; Text = $t }) }
    & $do 'Leave it running. Write down the time, who is signed in and what is on the screen; photograph the screen.'
    & $do 'Cut it off the network without switching it off: unplug the cable and turn off Wi-Fi, or isolate it from your EDR console.'
    if ($ready['vm']) { & $do 'Take a snapshot (or suspend) from the hypervisor before anything else: it saves all memory.' }
    else { & $do 'If memory matters, capture it now with your memory-capture tool, saving to external media, before anything else.' }
    if ($ready['hibernate']) { & $do 'If it really must go off, hibernate it with shutdown /h: memory is kept in hiberfil.sys.' }
    $bl = $state['bitlocker']
    if ($bl -and $bl.Status -ne 'Ready') { & $do 'Get the BitLocker recovery key before anything is switched off; without it the disk may be unreadable.' }
    & $do 'Keep this report and the manifest SHA-256 printed at the end of the run with your case notes.'
    & $avoid $(if ($state['faststartup']) { 'Shutting it down or restarting it: memory is lost, and with Fast Startup on, hiberfil.sys is overwritten.' } else { 'Shutting it down or restarting it: memory is lost.' })
    & $avoid 'Running antivirus clean-up, deleting files or installing software on it before evidence is collected.'
    & $avoid 'Signing in to it with a domain administrator account: an attacker on it could take those credentials.'
    , $card.ToArray()
}
