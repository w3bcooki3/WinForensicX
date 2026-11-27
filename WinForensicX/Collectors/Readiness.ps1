# Memory-capture readiness collector: the settings that decide whether this computer's memory can still be
# preserved if it has to be switched off or restarted during an incident. Read-only: registry values, WMI and
# file existence. It changes nothing (the report gives the fix as text, to apply before an incident).
#
# BitLocker: only the protection status and the TYPES of key protectors are kept. The recovery password is
# never read into the result, printed or stored.
#
# Facts only; Get-WfxReadinessCheck (Analyzers/Readiness.ps1) turns them into verdicts, so the judgement can
# be tested on any OS with made-up facts.

function Get-WfxVmVendor {
    <# The hypervisor named by the computer's manufacturer and model, or '' for a physical machine. Pure. #>
    param([string]$Manufacturer = '', [string]$Model = '')
    $s = "$Manufacturer $Model"
    if ($s -match '(?i)\bVMware\b') { return 'VMware' }
    if ($s -match '(?i)VirtualBox|innotek') { return 'VirtualBox' }
    if ($s -match '(?i)Microsoft Corporation' -and $s -match '(?i)Virtual Machine') { return 'Hyper-V' }
    if ($s -match '(?i)\bQEMU\b|\bKVM\b|Standard PC \((?:i440FX|Q35)') { return 'QEMU/KVM' }
    if ($s -match '(?i)\bXen\b') { return 'Xen' }
    if ($s -match '(?i)Parallels') { return 'Parallels' }
    if ($s -match '(?i)Amazon EC2') { return 'Amazon EC2' }
    if ($s -match '(?i)Google Compute Engine') { return 'Google Compute Engine' }
    return ''
}

function Get-WfxReadinessData {
    if (-not (Test-WfxWindows)) { return $null }
    $cc = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'

    $dump = Invoke-WfxStep 'ready:crashdump' {
        $file = [string](Get-WfxRegValue $cc 'DumpFile')
        if (-not $file) { $file = '%SystemRoot%\MEMORY.DMP' }
        $expanded = [Environment]::ExpandEnvironmentVariables($file)
        $free = $null
        try { $free = [long]([IO.DriveInfo]::new([IO.Path]::GetPathRoot($expanded))).AvailableFreeSpace } catch {}
        [pscustomobject]@{
            CrashDumpEnabled  = Get-WfxRegValue $cc 'CrashDumpEnabled'
            FilterPages       = Get-WfxRegValue $cc 'FilterPages'
            DedicatedDumpFile = [string](Get-WfxRegValue $cc 'DedicatedDumpFile')
            DumpFile          = $expanded
            DumpVolumeFree    = $free
        }
    } $null

    $mem = Invoke-WfxStep 'ready:memory' {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $pf = @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Path = [string]$_.Name; AllocatedMB = [int]$_.AllocatedBaseSize } })
        $battery = $false
        try { $battery = [bool]@(Get-CimInstance Win32_Battery -ErrorAction Stop).Count } catch {}
        [pscustomobject]@{
            RamBytes        = [long]$cs.TotalPhysicalMemory
            AutoPageFile    = [bool]$cs.AutomaticManagedPagefile
            PageFiles       = $pf
            ClearPageFileAtShutdown = Get-WfxRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'ClearPageFileAtShutdown'
            Manufacturer    = [string]$cs.Manufacturer
            Model           = [string]$cs.Model
            VmVendor        = (Get-WfxVmVendor -Manufacturer ([string]$cs.Manufacturer) -Model ([string]$cs.Model))
            HasBattery      = $battery
        }
    } $null

    $power = Invoke-WfxStep 'ready:power' {
        $hiber = Join-Path $env:SystemDrive 'hiberfil.sys'
        [pscustomobject]@{
            HibernateEnabled   = Get-WfxRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled'
            HiberFileExists    = [bool](Test-Path -LiteralPath $hiber)
            FastStartup        = Get-WfxRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled'
            CrashOnCtrlScrollUsb  = Get-WfxRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters' 'CrashOnCtrlScroll'
            CrashOnCtrlScrollPs2  = Get-WfxRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters' 'CrashOnCtrlScroll'
        }
    } $null

    $protect = Invoke-WfxStep 'ready:protection' {
        $hvci = $null; $cg = $null
        try {
            $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
            $running = @($dg.SecurityServicesRunning)
            $cg = $running -contains 1
            $hvci = $running -contains 2
        } catch {}
        [pscustomobject]@{
            MemoryIntegrity = $hvci
            CredentialGuard = $cg
            RunAsPPL        = ((Get-WfxRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL') -in @(1, 2))
        }
    } $null

    $bitlocker = Invoke-WfxStep 'ready:bitlocker' {
        $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        # Protector TYPES only. $v.KeyProtector also carries the recovery password itself: never copied out.
        $types = @($v.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType } | Sort-Object -Unique)
        [pscustomobject]@{ Protection = [string]$v.ProtectionStatus; Status = [string]$v.VolumeStatus; ProtectorTypes = $types }
    } $null

    $boot = Invoke-WfxStep 'ready:uptime' {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        ConvertTo-WfxUtcString $os.LastBootUpTime
    } ''

    [pscustomobject]@{
        Collected  = (Get-WfxUtcNow)
        Admin      = (Test-WfxAdmin)
        BootUtc    = $boot
        Dump       = $dump
        Memory     = $mem
        Power      = $power
        Protection = $protect
        BitLocker  = $bitlocker
    }
}
