# Security-posture collector — gathers the host's defensive configuration so the triage can tell the
# difference between "nothing found" and "nothing could be seen". Read-only. Produces one posture
# object the Posture analyzer turns into visibility/hardening findings, plus an AI-tooling inventory.

function Get-WfxRegValue {
    param([string]$Path, [string]$Name)
    try { $p = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop; return $p.$Name } catch { return $null }
}

function Get-WfxSecurityData {
    if (-not (Test-WfxWindows)) {
        return [pscustomobject]@{ Defender = $null; ThirdPartyAV = @(); Firewall = $null; Audit = $null; BitLocker = $null; Lsa = $null; Rdp = $null; AiTools = @() }
    }

    # ── Microsoft Defender ──
    $defender = Invoke-WfxStep 'posture:defender' {
        $st = $null; $pf = $null
        try { $st = Get-MpComputerStatus -ErrorAction Stop } catch {}
        try { $pf = Get-MpPreference -ErrorAction Stop } catch {}
        if (-not $st -and -not $pf) { throw 'Defender cmdlets unavailable' }
        $sigAge = $null
        if ($st -and $st.AntivirusSignatureLastUpdated) { try { $sigAge = [int]((Get-Date) - $st.AntivirusSignatureLastUpdated).TotalDays } catch {} }
        [pscustomobject]@{
            Installed                 = $true
            AntivirusEnabled          = if ($st) { [bool]$st.AntivirusEnabled } else { $null }
            RealTimeProtectionEnabled = if ($st) { [bool]$st.RealTimeProtectionEnabled } else { $null }
            TamperProtectionEnabled   = if ($st) { [bool]$st.IsTamperProtected } else { $null }
            BehaviorMonitorEnabled    = if ($st) { [bool]$st.BehaviorMonitorEnabled } else { $null }
            SignatureAgeDays          = $sigAge
            EngineVersion             = if ($st) { [string]$st.AMEngineVersion } else { '' }
            ExclusionPath             = if ($pf) { @($pf.ExclusionPath | Where-Object { $_ }) } else { @() }
            ExclusionProcess          = if ($pf) { @($pf.ExclusionProcess | Where-Object { $_ }) } else { @() }
            ExclusionExtension        = if ($pf) { @($pf.ExclusionExtension | Where-Object { $_ }) } else { @() }
            DisableRealtimeMonitoring = if ($pf) { [bool]$pf.DisableRealtimeMonitoring } else { $null }
        }
    } $null

    # ── Registered AV products (SecurityCenter2) — tells us if a 3rd-party AV is the active engine ──
    $thirdParty = Invoke-WfxStep 'posture:securitycenter' {
        @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
            Where-Object { $_.displayName -and $_.displayName -notmatch '(?i)windows defender|microsoft defender' } |
            ForEach-Object { $_.displayName })
    } @()

    # ── Firewall profiles ──
    $firewall = Invoke-WfxStep 'posture:firewall' {
        $fw = @{}
        Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { $fw[[string]$_.Name] = [bool]$_.Enabled }
        [pscustomobject]$fw
    } $null

    # ── Audit / logging visibility ──
    $audit = Invoke-WfxStep 'posture:audit' {
        $procAudit = $false
        try {
            $ap = auditpol /get /subcategory:"Process Creation" 2>$null
            if ($ap -match '(?i)Process Creation\s+(Success|Success and Failure)') { $procAudit = $true }
        } catch {}
        [pscustomobject]@{
            ProcessCreation             = $procAudit
            CommandLineInProcessCreation = ((Get-WfxRegValue 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled') -eq 1)
            ScriptBlockLogging          = ((Get-WfxRegValue 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq 1)
            ModuleLogging               = ((Get-WfxRegValue 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging') -eq 1)
            Transcription               = ((Get-WfxRegValue 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting') -eq 1)
            SysmonInstalled             = [bool]((Get-Service -Name 'Sysmon', 'Sysmon64' -ErrorAction SilentlyContinue) | Where-Object { $_.Status -eq 'Running' })
        }
    } $null

    # ── LSASS protection / Credential Guard ──
    $lsa = Invoke-WfxStep 'posture:lsa' {
        $cg = $null
        try { $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop; $cg = (@($dg.SecurityServicesRunning) -contains 1) } catch {}
        [pscustomobject]@{
            RunAsPPL        = ((Get-WfxRegValue 'HKLM:\System\CurrentControlSet\Control\Lsa' 'RunAsPPL') -in @(1, 2))
            CredentialGuard = $cg
        }
    } $null

    # ── RDP exposure ──
    $rdp = Invoke-WfxStep 'posture:rdp' {
        $deny = Get-WfxRegValue 'HKLM:\System\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
        $nla = Get-WfxRegValue 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
        [pscustomobject]@{ Enabled = ($deny -eq 0); NlaEnabled = ($nla -eq 1) }
    } $null

    # ── BitLocker (system drive) ──
    $bitlocker = Invoke-WfxStep 'posture:bitlocker' {
        $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        [pscustomobject]@{ SystemDriveProtection = [string]$v.ProtectionStatus; Encryption = [string]$v.VolumeStatus }
    } $null

    # ── AI tooling inventory (installed runtimes / assistant CLIs) — context, not a finding by itself ──
    $aiTools = Invoke-WfxStep 'posture:aitools' {
        $found = New-Object System.Collections.Generic.List[object]
        $dirs = @(
            @{ N = 'Ollama'; P = "$env:LOCALAPPDATA\Programs\Ollama" }
            @{ N = 'LM Studio'; P = "$env:LOCALAPPDATA\LM-Studio" }
            @{ N = 'Jan'; P = "$env:LOCALAPPDATA\Programs\Jan" }
            @{ N = 'GPT4All'; P = "$env:LOCALAPPDATA\nomic.ai\GPT4All" }
            @{ N = 'Open WebUI'; P = "$env:LOCALAPPDATA\open-webui" }
        )
        foreach ($d in $dirs) { if (Test-Path -LiteralPath $d.P) { $found.Add([pscustomobject]@{ Name = $d.N; Path = $d.P; Kind = 'runtime' }) } }
        foreach ($cli in @('ollama', 'llm', 'claude', 'openai', 'aider', 'gh-copilot')) {
            $c = Get-Command $cli -ErrorAction SilentlyContinue
            if ($c) { $found.Add([pscustomobject]@{ Name = $cli; Path = $c.Source; Kind = 'cli' }) }
        }
        @($found.ToArray())
    } @()

    [pscustomobject]@{
        Defender     = $defender
        ThirdPartyAV = @($thirdParty)
        Firewall     = $firewall
        Audit        = $audit
        Lsa          = $lsa
        Rdp          = $rdp
        BitLocker    = $bitlocker
        AiTools      = @($aiTools)
    }
}
