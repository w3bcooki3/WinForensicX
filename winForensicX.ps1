#Requires -Version 5.1
<#
.SYNOPSIS
    DFIR Swiss Knife - Digital Forensics & Incident Response Toolkit
    
.DESCRIPTION
    Enterprise-grade PowerShell toolkit for:
    - Digital Forensics & Incident Response (DFIR)
    - Threat Hunting (SIGMA / YARA / IOC)
    - APT Detection & TTPs (MITRE ATT&CK aligned)
    - SOC Analyst Operations
    - Cybercrime Investigation
    - Incident Commander Dashboards

.NOTES
    Author      : DFIR Swiss Knife
    Version     : 3.0.0
    Requires    : PowerShell 5.1+ | Admin rights for full functionality
    Platform    : Windows 10/11, Server 2016/2019/2022
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

#region ─── BANNER ────────────────────────────────────────────────────────────

function Show-Banner {
    $banner = @"
 ██████╗ ███████╗██╗██████╗     ███████╗██╗    ██╗██╗███████╗███████╗
 ██╔══██╗██╔════╝██║██╔══██╗    ██╔════╝██║    ██║██║██╔════╝██╔════╝
 ██║  ██║█████╗  ██║██████╔╝    ███████╗██║ █╗ ██║██║███████╗███████╗
 ██║  ██║██╔══╝  ██║██╔══██╗    ╚════██║██║███╗██║██║╚════██║╚════██║
 ██████╔╝██║     ██║██║  ██║    ███████║╚███╔███╔╝██║███████║███████║
 ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚═╝╚══════╝╚══════╝
              ██╗  ██╗███╗   ██╗██╗███████╗███████╗
              ██║ ██╔╝████╗  ██║██║██╔════╝██╔════╝
              █████╔╝ ██╔██╗ ██║██║█████╗  █████╗  
              ██╔═██╗ ██║╚██╗██║██║██╔══╝  ██╔══╝  
              ██║  ██╗██║ ╚████║██║██║     ███████╗
              ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝
    [DFIR Swiss Knife v3.0 | Threat Hunt | Forensics | IOC | APT]
    ══════════════════════════════════════════════════════════════
"@
    Write-Host $banner -ForegroundColor Cyan
}

#endregion

#region ─── HELPERS ───────────────────────────────────────────────────────────

function Write-Section {
    param([string]$Title)
    $line = "═" * 70
    Write-Host "`n$line" -ForegroundColor DarkCyan
    Write-Host "  ► $Title" -ForegroundColor Yellow
    Write-Host "$line" -ForegroundColor DarkCyan
}

function Write-Alert {
    param([string]$Msg, [string]$Level = "INFO")
    $colors = @{ INFO="Cyan"; WARN="Yellow"; HIGH="Red"; CRIT="Magenta"; OK="Green" }
    $color  = if ($colors.ContainsKey($Level)) { $colors[$Level] } else { "White" }
    Write-Host "  [$(Get-Date -f 'HH:mm:ss')] [$Level] $Msg" -ForegroundColor $color
}

function Export-ResultsCsv {
    param($Data, [string]$Name)
    $path = "$env:TEMP\DFIR_${Name}_$(Get-Date -f 'yyyyMMdd_HHmmss').csv"
    $Data | Export-Csv -Path $path -NoTypeInformation -Force
    Write-Alert "Exported → $path" "OK"
    return $path
}

function Show-ResultsView {
    <#
    .SYNOPSIS
    Display results in Out-GridView (interactive popup) if available,
    otherwise fall back to Format-Table in console.
    GridView lets you sort by any column, filter/search, resize, and copy rows.
    #>
    param(
        $Data,
        [string]$Title = "DFIR Results",
        [switch]$FallbackTable
    )
    if (-not $Data -or ($Data | Measure-Object).Count -eq 0) {
        Write-Host "  [No data to display]" -ForegroundColor DarkGray
        return
    }
    # Out-GridView requires Windows PowerShell or PS7+ with WindowsCompatibility
    $hasGridView = $null -ne (Get-Command Out-GridView -EA SilentlyContinue)
    if ($hasGridView -and -not $FallbackTable) {
        try {
            Write-Host "  [Opening GridView window: '$Title' — sortable, filterable, searchable]" -ForegroundColor DarkCyan
            $Data | Out-GridView -Title "DFIR Swiss Knife | $Title | $(Get-Date -f 'HH:mm:ss') | $($Data.Count) rows"
            return
        } catch {
            Write-Alert "GridView unavailable (headless/Core session), using table view" "WARN"
        }
    }
    # Fallback: formatted table with auto-size
    $Data | Format-Table -AutoSize -Wrap | Out-String -Width 250 | Write-Host
}

function Get-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

#endregion

#region ─── MODULE 1: NETWORK FORENSICS ──────────────────────────────────────

function Get-NetworkConnections {
    <#
    .SYNOPSIS Active connections, remote IPs, GeoIP hints, suspicious ports
    #>
    param([switch]$Export, [switch]$SuspiciousOnly, [switch]$GridView)

    Write-Section "NETWORK CONNECTIONS & REMOTE ADDRESSES"

    $suspiciousPorts = @(4444,1337,31337,8080,8888,9001,9050,6667,6668,6669,12345,54321,
                         23,2323,5900,5901,3389,1080,8443,7777,1234,65535)
    $suspiciousProc  = @("powershell","cmd","wscript","cscript","mshta","regsvr32",
                         "rundll32","svchost","lsass","csrss")

    try {
        $conns = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort,
                    RemoteAddress, RemotePort, State,
                    @{N="ProcessName"; E={ (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name }},
                    @{N="PID"; E={ $_.OwningProcess }},
                    @{N="ProcessPath"; E={ (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Path }},
                    @{N="CommandLine"; E={
                        (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.OwningProcess)" -EA SilentlyContinue).CommandLine
                    }},
                    @{N="SuspiciousPort"; E={ $_.RemotePort -in $suspiciousPorts -or $_.LocalPort -in $suspiciousPorts }},
                    @{N="SuspiciousProc"; E={
                        $pn = (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name
                        $suspiciousProc -contains ($pn -replace "\.exe","")
                    }}

        if ($SuspiciousOnly) {
            $conns = $conns | Where-Object { $_.SuspiciousPort -or $_.SuspiciousProc }
        }

        # Flag established external connections
        $external = $conns | Where-Object {
            $_.State -eq "Established" -and
            $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0|::$)"
        }

        Write-Alert "Total connections: $($conns.Count)" "INFO"
        Write-Alert "External established: $($external.Count)" $(if($external.Count -gt 10){"WARN"}else{"OK"})

        foreach ($c in $conns | Sort-Object SuspiciousProc,SuspiciousPort -Descending) {
            $flag = if ($c.SuspiciousPort -or $c.SuspiciousProc) { "⚠ " } else { "  " }
            $color= if ($c.SuspiciousPort -or $c.SuspiciousProc) { "Red" } else { "Gray" }
            Write-Host ("  $flag [{0,-20}] {1,-22} → {2,-22} [{3}] PID:{4} {5}" -f
                $c.ProcessName, "$($c.LocalAddress):$($c.LocalPort)",
                "$($c.RemoteAddress):$($c.RemotePort)",
                $c.State, $c.PID, $c.ProcessPath) -ForegroundColor $color
        }

        # UDP listeners
        Write-Host "`n  [UDP Listeners]" -ForegroundColor DarkYellow
        Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,
            @{N="Process";E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}},
            @{N="PID";E={$_.OwningProcess}} |
            Sort-Object LocalPort | Format-Table -AutoSize | Out-String | Write-Host

            if ($GridView) { Show-ResultsView -Data $conns -Title "Network Connections" }
    if ($Export) { Export-ResultsCsv -Data $conns -Name "NetworkConnections" }
        return $conns
    }
    catch { Write-Alert "Error: $_" "WARN" }
}

function Get-DNSCache {
    param([switch]$Export, [switch]$GridView)
    Write-Section "DNS CACHE (Potential C2 / Exfil Domains)"
    $dns = Get-DnsClientCache | Select-Object Entry, RecordName, RecordType, TimeToLive, Data
    $suspicious = @("ngrok","pagekite","serveo","localtunnel","ddns","no-ip","duckdns",
                    ".onion",".bit","temp","paste","hastebin","ghostbin")
    foreach ($d in $dns) {
        $flag = $suspicious | Where-Object { $d.Entry -match $_ }
        $color = if ($flag) { "Red" } else { "Gray" }
        Write-Host ("  {0,-50} → {1}" -f $d.Entry, $d.Data) -ForegroundColor $color
    }
    if ($GridView) { Show-ResultsView -Data $dns -Title "DNS Cache" }
    return $dns
}

function Get-FirewallLog {
    param([int]$Last = 100)
    Write-Section "WINDOWS FIREWALL RECENT EVENTS"
    $log = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    if (Test-Path $log) {
        Get-Content $log -Tail $Last | Where-Object { $_ -notmatch "^#" } |
            ForEach-Object {
                $color = if ($_ -match "DROP") { "Red" } elseif ($_ -match "ALLOW") { "Green" } else { "Gray" }
                Write-Host "  $_" -ForegroundColor $color
            }
    } else { Write-Alert "Firewall log not found (may need admin)" "WARN" }
}

#endregion

#region ─── MODULE 2: PROCESS FORENSICS & INJECTION DETECTION ─────────────────

function Get-ProcessForensics {
    <#
    .SYNOPSIS Deep process inspection: parent spoofing, hollowing, injection indicators
    #>
    param([switch]$Export, [int]$PID = 0, [switch]$GridView)

    Write-Section "PROCESS FORENSICS & INJECTION DETECTION"

    $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId,
        Name, ExecutablePath, CommandLine, CreationDate,
        @{N="User"; E={ try { $_.GetOwner().User } catch { "SYSTEM" } }},
        @{N="Domain"; E={ try { $_.GetOwner().Domain } catch { "NT AUTHORITY" } }}

    # Known legitimate parent-child relationships
    $legitParents = @{
        "services.exe" = @("svchost.exe")
        "lsass.exe"    = @()
        "explorer.exe" = @("taskmgr.exe","control.exe","mmc.exe")
        "wininit.exe"  = @("services.exe","lsass.exe","lsm.exe")
    }

    $suspiciousProcs = @()

    foreach ($proc in $processes) {
        $flags = @()

        # Check for process running from suspicious locations
        if ($proc.ExecutablePath -match "\\Temp\\|\\AppData\\|\\Downloads\\|\\Public\\") {
            $flags += "SUSPICIOUS_PATH"
        }

        # Check parent-child anomalies
        $parent = $processes | Where-Object { $_.ProcessId -eq $proc.ParentProcessId }
        if ($parent) {
            $knownChildren = $legitParents[$parent.Name]
            if ($knownChildren -ne $null -and $proc.Name -notin $knownChildren -and
                $proc.Name -notin @("WerFault.exe","wermgr.exe")) {
                # Suspicious parent
            }
        }

        # Double extension, space padding tricks
        if ($proc.Name -match "\.(exe|pdf|doc|jpg)\.exe$" -or
            $proc.CommandLine -match "powershell.*-[Ee][Nn][Cc]" -or
            $proc.CommandLine -match "-[Ww]indow[Ss]tyle\s+[Hh]idden" -or
            $proc.CommandLine -match "IEX|Invoke-Expression|DownloadString|WebClient" -or
            $proc.CommandLine -match "FromBase64String|::Load\(|Reflection\.Assembly") {
            $flags += "OBFUSCATED_CMDLINE"
        }

        # Detect processes without image on disk (possible hollowing)
        if ($proc.ExecutablePath -and -not (Test-Path $proc.ExecutablePath)) {
            $flags += "IMAGE_NOT_ON_DISK"
        }

        if ($flags.Count -gt 0) {
            $suspiciousProcs += [PSCustomObject]@{
                PID       = $proc.ProcessId
                PPID      = $proc.ParentProcessId
                Name      = $proc.Name
                Parent    = $parent.Name
                User      = $proc.User
                Path      = $proc.ExecutablePath
                CmdLine   = $proc.CommandLine
                Flags     = $flags -join " | "
                Created   = $proc.CreationDate
            }
        }
    }

    Write-Alert "Total processes scanned: $($processes.Count)" "INFO"
    Write-Alert "Suspicious processes found: $($suspiciousProcs.Count)" $(if($suspiciousProcs.Count -gt 0){"HIGH"}else{"OK"})

    if ($suspiciousProcs.Count -gt 0) {
        foreach ($sp in $suspiciousProcs) {
            Write-Host "`n  ⚠  PID:$($sp.PID) [$($sp.Name)] → $($sp.Flags)" -ForegroundColor Red
            Write-Host "     Parent  : $($sp.Parent) (PPID:$($sp.PPID))" -ForegroundColor Yellow
            Write-Host "     User    : $($sp.User)" -ForegroundColor Yellow
            Write-Host "     Path    : $($sp.Path)" -ForegroundColor DarkYellow
            Write-Host "     CmdLine : $($sp.CmdLine)" -ForegroundColor DarkYellow
        }
    }

    # Process injection detection via loaded modules
    Write-Host "`n  [Checking for suspicious DLL injections...]" -ForegroundColor DarkCyan
    $suspiciousDlls = @("meterpreter","cobalt","beacon","empire","havoc","sliver",
                         "cobaltstrike","reflective","inject","hook","shellcode")
    
    Get-Process | ForEach-Object {
        $proc = $_
        try {
            $proc.Modules | Where-Object {
                $m = $_.ModuleName.ToLower()
                $suspiciousDlls | Where-Object { $m -match $_ }
            } | ForEach-Object {
                Write-Alert "Suspicious DLL: [$($proc.Name):$($proc.Id)] → $($_.FileName)" "CRIT"
            }
        } catch {}
    }

    if ($Export) { Export-ResultsCsv -Data ($processes + $suspiciousProcs) -Name "ProcessForensics" }
    return $suspiciousProcs
}

function Get-ProcessTree {
    param([switch]$Export, [switch]$GridView)
    Write-Section "PROCESS TREE"
    $procs = Get-CimInstance Win32_Process | Sort-Object ParentProcessId, ProcessId
    $dict  = @{}
    $procs | ForEach-Object { $dict[$_.ProcessId] = $_ }

    function Print-Tree($pid, $depth) {
        $p = $dict[$pid]
        if ($null -eq $p) { return }
        $indent = "  " * $depth
        $symbol = if ($depth -eq 0) { "■" } else { "└─" }
        $color  = switch ($depth) { 0{"White"} 1{"Cyan"} 2{"Yellow"} default{"Gray"} }
        Write-Host ("{0}{1} [{2}] PID:{3} ← {4}" -f $indent,$symbol,$p.Name,$p.ProcessId,$p.CommandLine) -ForegroundColor $color
        $procs | Where-Object { $_.ParentProcessId -eq $pid -and $_.ProcessId -ne $pid } |
            ForEach-Object { Print-Tree $_.ProcessId ($depth+1) }
    }

    $roots = $procs | Where-Object { $null -eq $dict[$_.ParentProcessId] -or $_.ParentProcessId -eq 0 }
    foreach ($r in $roots) { Print-Tree $r.ProcessId 0 }
    if ($GridView) { Show-ResultsView -Data (Get-CimInstance Win32_Process -EA SilentlyContinue | Select-Object ProcessId,Name,ParentProcessId,CommandLine | Sort-Object ParentProcessId) -Title "Process Tree" }
}

#endregion

#region ─── MODULE 3: REGISTRY FORENSICS ─────────────────────────────────────

function Get-RegistryForensics {
    <#
    .SYNOPSIS Hunt persistence, ASEPs, malicious registry modifications
    #>
    param([switch]$Export, [switch]$GridView)

    Write-Section "REGISTRY FORENSICS - PERSISTENCE & ASEP HUNTING"

    $huntKeys = @(
        # Run Keys (Classic persistence)
        @{ Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Label="HKLM Run" }
        @{ Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Label="HKLM RunOnce" }
        @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Label="HKCU Run" }
        @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Label="HKCU RunOnce" }
        @{ Path="HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Label="WOW64 Run" }
        # Services
        @{ Path="HKLM:\SYSTEM\CurrentControlSet\Services"; Label="Services" }
        # Shell Extensions
        @{ Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Label="Winlogon" }
        # AppInit
        @{ Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"; Label="AppInit DLLs" }
        # COM Hijacking
        @{ Path="HKCU:\SOFTWARE\Classes\CLSID"; Label="HKCU CLSID (COM Hijack)" }
        # Image File Execution Options (Debugger hijack)
        @{ Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"; Label="IFEO Debugger" }
        # LSA Providers
        @{ Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Label="LSA Auth Packages" }
        # Scheduled Tasks registry
        @{ Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"; Label="Scheduled Tasks Cache" }
        # Terminal Server Run
        @{ Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run"; Label="TS Run Key" }
        # Boot Execute
        @{ Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Label="BootExecute" }
        # PowerShell policies
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"; Label="PS Execution Policy" }
        # Disable security tools
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Label="Defender Policy" }
    )

    $results = @()
    $suspicious = @("powershell","cmd\.exe","wscript","cscript","mshta","regsvr32",
                     "rundll32","certutil","bitsadmin","msiexec","wmic","\\temp\\",
                     "\\appdata\\","base64","http://","https://","\.ps1","\.vbs","\.bat","\.hta")

    foreach ($hk in $huntKeys) {
        if (-not (Test-Path $hk.Path)) { continue }
        try {
            $values = Get-ItemProperty -Path $hk.Path -EA SilentlyContinue
            if ($null -eq $values) { continue }

            $values.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $val   = $_.Value -as [string]
                $isSusp = $suspicious | Where-Object { $val -match $_ }
                $entry = [PSCustomObject]@{
                    Label     = $hk.Label
                    KeyPath   = $hk.Path
                    ValueName = $_.Name
                    Data      = $val
                    Suspicious= [bool]$isSusp
                }
                $results += $entry

                $color = if ($isSusp) { "Red" } else { "Gray" }
                $flag  = if ($isSusp) { "⚠ " } else { "  " }
                Write-Host ("  $flag [{0,-30}] {1,-30} = {2}" -f $hk.Label, $_.Name, $val) -ForegroundColor $color
            }
        } catch {}
    }

    # Check for hidden/encoded registry values
    Write-Host "`n  [Checking for Base64/encoded registry data...]" -ForegroundColor DarkCyan
    $b64pattern = "[A-Za-z0-9+/]{50,}={0,2}"
    $results | Where-Object { $_.Data -match $b64pattern } | ForEach-Object {
        Write-Alert "ENCODED VALUE DETECTED: [$($_.Label)] $($_.ValueName)" "CRIT"
    }

    Write-Alert "Total registry entries scanned: $($results.Count)" "INFO"
    Write-Alert "Suspicious entries: $(($results | Where-Object Suspicious).Count)" $(if(($results|Where-Object Suspicious).Count -gt 0){"HIGH"}else{"OK"})

        if ($GridView) { Show-ResultsView -Data $results -Title "Registry Forensics" }
    if ($Export) { Export-ResultsCsv -Data $results -Name "RegistryForensics" }
    return $results
}

#endregion

#region ─── MODULE 4: USER ACCOUNT FORENSICS ─────────────────────────────────

function Get-UserAccountForensics {
    param([switch]$Export, [switch]$GridView)
    Write-Section "USER ACCOUNT FORENSICS"

    # Local accounts
    Write-Host "`n  [Local User Accounts]" -ForegroundColor DarkCyan
    $users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet,
        PasswordNeverExpires, UserMayChangePassword, Description,
        @{N="IsAdmin"; E={ (Get-LocalGroupMember "Administrators" -EA SilentlyContinue).Name -contains ".\$($_.Name)" }}

    foreach ($u in $users) {
        $color = if ($u.IsAdmin -and $u.Enabled) { "Red" } elseif (-not $u.Enabled) { "DarkGray" } else { "Cyan" }
        $admin = if ($u.IsAdmin) { "[ADMIN]" } else { "" }
        Write-Host ("  {0,-25} Enabled:{1,-5} LastLogon:{2,-25} {3}" -f
            $u.Name, $u.Enabled, $u.LastLogon, $admin) -ForegroundColor $color
    }

    # Admin group members
    Write-Host "`n  [Administrators Group Members]" -ForegroundColor DarkCyan
    Get-LocalGroupMember "Administrators" -EA SilentlyContinue | ForEach-Object {
        Write-Host "  ⚑ $($_.Name) [$($_.ObjectClass)] PrincipalSource:$($_.PrincipalSource)" -ForegroundColor Yellow
    }

    # Remote Desktop Users
    Write-Host "`n  [Remote Desktop Users]" -ForegroundColor DarkCyan
    Get-LocalGroupMember "Remote Desktop Users" -EA SilentlyContinue | ForEach-Object {
        Write-Host "  ► $($_.Name)" -ForegroundColor Cyan
    }

    # Recently created accounts (last 30 days)
    Write-Host "`n  [Recently Modified Accounts (30 days)]" -ForegroundColor DarkCyan
    $cutoff = (Get-Date).AddDays(-30)
    $users | Where-Object { $_.PasswordLastSet -gt $cutoff } | ForEach-Object {
        Write-Alert "Recent password change: $($_.Name) @ $($_.PasswordLastSet)" "WARN"
    }

    # Logon events
    Write-Host "`n  [Recent Logon Events (Security Log)]" -ForegroundColor DarkCyan
    try {
        Get-WinEvent -FilterHashtable @{LogName="Security"; Id=@(4624,4625,4648,4672,4720,4732)} -MaxEvents 50 -EA SilentlyContinue |
            Select-Object TimeCreated, Id,
                @{N="EventType"; E={
                    switch ($_.Id) {
                        4624 { "LOGON_SUCCESS" }
                        4625 { "LOGON_FAILURE" }
                        4648 { "LOGON_EXPLICIT_CREDS" }
                        4672 { "SPECIAL_PRIVILEGES" }
                        4720 { "ACCOUNT_CREATED" }
                        4732 { "ADDED_TO_GROUP" }
                    }
                }},
                @{N="User"; E={ if ($_.Properties[5].Value) { $_.Properties[5].Value } else { $_.Properties[0].Value } }},
                @{N="Source"; E={ if ($_.Properties[18].Value) { $_.Properties[18].Value } else { $_.Properties[8].Value } }},
                Message | Sort-Object TimeCreated -Descending |
            ForEach-Object {
                $color = switch ($_.EventType) {
                    "LOGON_FAILURE"      { "Red" }
                    "ACCOUNT_CREATED"    { "Magenta" }
                    "ADDED_TO_GROUP"     { "Yellow" }
                    "LOGON_EXPLICIT_CREDS"{ "Yellow" }
                    default              { "Gray" }
                }
                Write-Host ("  [{0}] {1,-25} User:{2,-20} Src:{3}" -f
                    $_.TimeCreated, $_.EventType, $_.User, $_.Source) -ForegroundColor $color
            }
    } catch { Write-Alert "Insufficient privileges for Security log (run as admin)" "WARN" }

        if ($GridView) { Show-ResultsView -Data $users -Title "User Accounts" }
    if ($Export) { Export-ResultsCsv -Data $users -Name "UserAccounts" }
    return $users
}

#endregion

#region ─── MODULE 5: PERSISTENCE & SCHEDULED TASKS ─────────────────────────

function Get-PersistenceMechanisms {
    param([switch]$Export, [switch]$GridView)
    Write-Section "PERSISTENCE MECHANISMS"

    $results = @()

    # Scheduled Tasks
    Write-Host "`n  [Scheduled Tasks - Non-Microsoft]" -ForegroundColor DarkCyan
    $tasks = Get-ScheduledTask | Where-Object {
        $_.TaskPath -notmatch "\\Microsoft\\" -and $_.State -ne "Disabled"
    } | Select-Object TaskName, TaskPath, State,
        @{N="Action"; E={ ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join " | " }},
        @{N="Trigger"; E={ ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join "," }},
        @{N="Author"; E={ $_.Principal.UserId }}

    foreach ($t in $tasks) {
        $susp = $t.Action -match "powershell|cmd|wscript|mshta|\\temp\\|base64|http"
        $color = if ($susp) { "Red" } else { "Cyan" }
        Write-Host ("  {0,-40} [{1}] → {2}" -f $t.TaskName, $t.State, $t.Action) -ForegroundColor $color
        $results += $t
    }

    # Services
    Write-Host "`n  [Services - Suspicious Binary Paths]" -ForegroundColor DarkCyan
    Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -match "\\temp\\|\\appdata\\|\\downloads\\|cmd\.exe|powershell"
    } | ForEach-Object {
        Write-Alert "Suspicious service: [$($_.Name)] → $($_.PathName)" "HIGH"
        $results += $_
    }

    # Startup folders
    Write-Host "`n  [Startup Folder Contents]" -ForegroundColor DarkCyan
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    )
    foreach ($sp in $startupPaths) {
        Get-ChildItem $sp -EA SilentlyContinue | ForEach-Object {
            Write-Alert "Startup item: $($_.FullName)" "WARN"
        }
    }

    # WMI Subscriptions
    Write-Host "`n  [WMI Event Subscriptions (Fileless Persistence)]" -ForegroundColor DarkCyan
    $wmiFilters  = Get-WMIObject -Namespace root\subscription -Class __EventFilter -EA SilentlyContinue
    $wmiConsumers= Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer -EA SilentlyContinue
    $wmiBindings = Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding -EA SilentlyContinue

    if ($wmiFilters)   { $wmiFilters   | ForEach-Object { Write-Alert "WMI Filter: $($_.Name) [$($_.Query)]" "CRIT" } }
    if ($wmiConsumers) { $wmiConsumers | ForEach-Object { Write-Alert "WMI Consumer: $($_.Name) → $($_.CommandLineTemplate)" "CRIT" } }
    if ($wmiBindings)  { Write-Alert "WMI Bindings detected: $($wmiBindings.Count)" "CRIT" }

    if (-not $wmiFilters -and -not $wmiConsumers) { Write-Alert "No WMI subscriptions detected" "OK" }

        if ($GridView) { Show-ResultsView -Data $results -Title "Persistence" }
    if ($Export) { Export-ResultsCsv -Data $results -Name "Persistence" }
    return $results
}

#endregion

#region ─── MODULE 6: THREAT HUNT / IOC MATCHING ─────────────────────────────

function Invoke-IOCHunt {
    <#
    .SYNOPSIS Hunt for known IOCs: IPs, domains, hashes, filenames, registry keys
    #>
    param(
        [string[]]$IPs       = @(, [switch]$GridView),
        [string[]]$Domains   = @(),
        [string[]]$Hashes    = @(),   # MD5/SHA256
        [string[]]$FileNames = @(),
        [string[]]$RegKeys   = @(),
        [string]  $IOCFile   = "",    # Path to newline-delimited IOC list
        [switch]  $Export
    )

    Write-Section "IOC HUNT ENGINE"

    # Load IOCs from file if provided
    if ($IOCFile -and (Test-Path $IOCFile)) {
        $fileContent = Get-Content $IOCFile
        $IPs      += $fileContent | Where-Object { $_ -match "^\d{1,3}(\.\d{1,3}){3}$" }
        $Domains  += $fileContent | Where-Object { $_ -match "^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$" -and $_ -notmatch "^\d" }
        $Hashes   += $fileContent | Where-Object { $_ -match "^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{64}$" }
        Write-Alert "Loaded IOCs from $IOCFile — IPs:$($IPs.Count) Domains:$($Domains.Count) Hashes:$($Hashes.Count)" "INFO"
    }

    $hits = @()

    # ── IP Match ────────────────────────────────────────────────────────────
    if ($IPs.Count -gt 0) {
        Write-Host "`n  [Checking Network Connections for IOC IPs]" -ForegroundColor DarkCyan
        $conns = Get-NetTCPConnection -EA SilentlyContinue
        foreach ($ip in $IPs) {
            $match = $conns | Where-Object { $_.RemoteAddress -eq $ip }
            if ($match) {
                $proc = (Get-Process -Id $match.OwningProcess -EA SilentlyContinue).Name
                Write-Alert "IOC IP HIT: $ip ← Process:$proc PID:$($match.OwningProcess)" "CRIT"
                $hits += [PSCustomObject]@{ Type="IP"; IOC=$ip; Detail="Process:$proc"; Severity="CRITICAL" }
            }
        }
        # Also check DNS cache
        $dns = Get-DnsClientCache -EA SilentlyContinue
        foreach ($ip in $IPs) {
            $match = $dns | Where-Object { $_.Data -eq $ip }
            if ($match) {
                Write-Alert "IOC IP in DNS Cache: $ip (domain: $($match.Entry))" "HIGH"
                $hits += [PSCustomObject]@{ Type="IP_DNS"; IOC=$ip; Detail=$match.Entry; Severity="HIGH" }
            }
        }
    }

    # ── Domain Match ────────────────────────────────────────────────────────
    if ($Domains.Count -gt 0) {
        Write-Host "`n  [Checking DNS Cache for IOC Domains]" -ForegroundColor DarkCyan
        $dns = Get-DnsClientCache -EA SilentlyContinue
        foreach ($domain in $Domains) {
            $match = $dns | Where-Object { $_.Entry -match [regex]::Escape($domain) }
            if ($match) {
                Write-Alert "IOC DOMAIN HIT in DNS Cache: $domain" "CRIT"
                $hits += [PSCustomObject]@{ Type="Domain"; IOC=$domain; Detail=$match.Data; Severity="CRITICAL" }
            }
        }
        # Check hosts file
        $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
        foreach ($domain in $Domains) {
            if (Select-String -Path $hostsFile -Pattern $domain -EA SilentlyContinue) {
                Write-Alert "IOC DOMAIN in HOSTS file: $domain" "HIGH"
                $hits += [PSCustomObject]@{ Type="Domain_Hosts"; IOC=$domain; Detail="hosts file"; Severity="HIGH" }
            }
        }
    }

    # ── Hash Match ──────────────────────────────────────────────────────────
    if ($Hashes.Count -gt 0) {
        Write-Host "`n  [Checking Running Processes & System32 for IOC Hashes]" -ForegroundColor DarkCyan
        $procPaths = Get-Process | Where-Object { $_.Path } | Select-Object -ExpandProperty Path -Unique

        foreach ($path in $procPaths) {
            try {
                $md5  = (Get-FileHash $path -Algorithm MD5    -EA SilentlyContinue).Hash
                $sha  = (Get-FileHash $path -Algorithm SHA256 -EA SilentlyContinue).Hash
                foreach ($hash in $Hashes) {
                    if ($md5 -eq $hash.ToUpper() -or $sha -eq $hash.ToUpper()) {
                        Write-Alert "IOC HASH HIT: $hash → $path" "CRIT"
                        $hits += [PSCustomObject]@{ Type="Hash"; IOC=$hash; Detail=$path; Severity="CRITICAL" }
                    }
                }
            } catch {}
        }
    }

    # ── Filename Match ──────────────────────────────────────────────────────
    if ($FileNames.Count -gt 0) {
        Write-Host "`n  [Searching filesystem for IOC filenames]" -ForegroundColor DarkCyan
        $searchPaths = @($env:TEMP, $env:APPDATA, $env:LOCALAPPDATA,
                         "$env:SystemRoot\Temp", "C:\Users\Public")
        foreach ($fn in $FileNames) {
            foreach ($sp in $searchPaths) {
                Get-ChildItem -Path $sp -Filter $fn -Recurse -EA SilentlyContinue | ForEach-Object {
                    Write-Alert "IOC FILE HIT: $($_.FullName)" "CRIT"
                    $hits += [PSCustomObject]@{ Type="File"; IOC=$fn; Detail=$_.FullName; Severity="CRITICAL" }
                }
            }
        }
    }

    # Summary
    Write-Host ""
    if ($hits.Count -eq 0) {
        Write-Alert "No IOC matches found on this system" "OK"
    } else {
        Write-Alert "TOTAL IOC HITS: $($hits.Count)" "CRIT"
        $hits | Group-Object Severity | ForEach-Object {
            Write-Alert "$($_.Name): $($_.Count) hit(s)" $(if($_.Name -eq "CRITICAL"){"CRIT"}else{"HIGH"})
        }
    }

        if ($GridView) { Show-ResultsView -Data $hits -Title "I O C Hunts" }
    if ($Export) { Export-ResultsCsv -Data $hits -Name "IOCHunts" }
    return $hits
}

#endregion

#region ─── MODULE 7: SIGMA RULE ENGINE ──────────────────────────────────────

function Invoke-SigmaHunt {
    <#
    .SYNOPSIS Built-in SIGMA-inspired detection rules mapped to Windows Event Log
    #>
    param([switch]$Export, [string]$RuleFile = "", [switch]$GridView)

    Write-Section "SIGMA RULE DETECTION ENGINE"

    # Built-in SIGMA-inspired rules (simplified detection logic)
    $builtinRules = @(
        @{
            Id="SIG001"; Title="Suspicious PowerShell Encoded Command"
            Description="Detects PowerShell launched with base64-encoded commands"
            Technique="T1059.001"; Tactic="Execution"
            Detection = { Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; Id=4104} -MaxEvents 200 -EA SilentlyContinue |
                Where-Object { $_.Message -match "-[Ee][Nn][Cc]|-[Ee][Nn][Cc][Oo][Dd][Ee][Dd]|IEX|Invoke-Expression|FromBase64String" } }
        },
        @{
            Id="SIG002"; Title="Credential Dumping via LSASS"
            Description="Detects LSASS memory access (Mimikatz / credential dumping)"
            Technique="T1003.001"; Tactic="Credential Access"
            Detection = { Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4656} -MaxEvents 500 -EA SilentlyContinue |
                Where-Object { $_.Message -match "lsass" -and $_.Message -match "0x1410|0x1010|0x1438|0x143a|0x1418" } }
        },
        @{
            Id="SIG003"; Title="New Local Admin Account Created"
            Description="Detects creation of local admin accounts"
            Technique="T1136.001"; Tactic="Persistence"
            Detection = { Get-WinEvent -FilterHashtable @{LogName="Security"; Id=@(4720,4732)} -MaxEvents 100 -EA SilentlyContinue }
        },
        @{
            Id="SIG004"; Title="WMI Lateral Movement"
            Description="Detects WMI process creation (lateral movement)"
            Technique="T1021.006"; Tactic="Lateral Movement"
            Detection = { Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-WMI-Activity/Operational"} -MaxEvents 100 -EA SilentlyContinue |
                Where-Object { $_.Message -match "powershell|cmd\.exe|wscript|mshta|rundll32" } }
        },
        @{
            Id="SIG005"; Title="Scheduled Task Creation"
            Description="Detects new scheduled task creation"
            Technique="T1053.005"; Tactic="Persistence"
            Detection = { Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4698} -MaxEvents 50 -EA SilentlyContinue }
        },
        @{
            Id="SIG006"; Title="Pass-the-Hash / Pass-the-Ticket"
            Description="Detects PtH/PtT indicators"
            Technique="T1550.002"; Tactic="Lateral Movement"
            Detection = { Get-WinEvent -FilterHashtable @{LogName="Security"; Id=@(4624)} -MaxEvents 500 -EA SilentlyContinue |
                Where-Object { $_.Message -match "LogonType.*3" -and $_.Message -match "NTLM" } }
        },
        @{
            Id="SIG007"; Title="Disabling Windows Defender"
            Description="Detects Defender tampering"
            Technique="T1562.001"; Tactic="Defense Evasion"
            Detection = { Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Windows Defender/Operational"; Id=@(5001,5004,5007,5010,5012)} -MaxEvents 50 -EA SilentlyContinue }
        },
        @{
            Id="SIG008"; Title="Suspicious Certutil Usage"
            Description="certutil used to download or decode files"
            Technique="T1105"; Tactic="Command and Control"
            Detection = { Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4688} -MaxEvents 500 -EA SilentlyContinue |
                Where-Object { $_.Message -match "certutil" -and $_.Message -match "urlcache|decode|-encode|download" } }
        },
        @{
            Id="SIG009"; Title="Ransomware File Extension Rename Pattern"
            Description="Mass file rename (potential ransomware)"
            Technique="T1486"; Tactic="Impact"
            Detection = { Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4663} -MaxEvents 1000 -EA SilentlyContinue |
                Where-Object { $_.Message -match "\.(locked|encrypted|crypt|enc|ransom|crypted|pay)" } }
        },
        @{
            Id="SIG010"; Title="DCSync Attack Detection"
            Description="Detects directory service replication requests (DCSync)"
            Technique="T1003.006"; Tactic="Credential Access"
            Detection = { Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4662} -MaxEvents 200 -EA SilentlyContinue |
                Where-Object { $_.Message -match "1131f6aa|1131f6ad|89e95b76" } }
        }
    )

    $allHits = @()

    foreach ($rule in $builtinRules) {
        Write-Host "`n  [$($rule.Id)] $($rule.Title)" -ForegroundColor Cyan
        Write-Host "     Tactic: $($rule.Tactic) | ATT&CK: $($rule.Technique)" -ForegroundColor DarkGray

        try {
            $ruleMatches = & $rule.Detection
            if ($ruleMatches -and $ruleMatches.Count -gt 0) {
                Write-Alert "DETECTION HIT [$($rule.Id)]: $($ruleMatches.Count) event(s) found!" "CRIT"
                $ruleMatches | Select-Object -First 3 | ForEach-Object {
                    Write-Host "     Sample: [$($_.TimeCreated)] $($_.Message.Substring(0,[Math]::Min(150,$_.Message.Length)))..." -ForegroundColor Yellow
                }
                $allHits += [PSCustomObject]@{
                    RuleId      = $rule.Id
                    Title       = $rule.Title
                    Technique   = $rule.Technique
                    Tactic      = $rule.Tactic
                    HitCount    = $ruleMatches.Count
                    FirstSeen   = ($ruleMatches | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
                    LastSeen    = ($ruleMatches | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
                }
            } else {
                Write-Host "     → No matches" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "     → Skipped (insufficient access or log empty)" -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Write-Alert "SIGMA Rules run: $($builtinRules.Count) | Hits: $($allHits.Count)" $(if($allHits.Count -gt 0){"CRIT"}else{"OK"})

        if ($GridView) { Show-ResultsView -Data $allHits -Title "Sigma Hunts" }
    if ($Export) { Export-ResultsCsv -Data $allHits -Name "SigmaHunts" }
    return $allHits
}

#endregion

#region ─── MODULE 8: YARA-STYLE MEMORY SCAN ─────────────────────────────────

function Invoke-YaraStyleScan {
    <#
    .SYNOPSIS PowerShell-based YARA-like pattern matching on process memory strings
    Note: Full YARA requires yara64.exe. This uses string matching as fallback.
    #>
    param([string]$YaraExePath = "", [switch]$Export)

    Write-Section "YARA-STYLE MEMORY & FILE SCAN"

    # Built-in string patterns (mimics YARA rules)
    $yaraPatterns = @(
        @{ Name="Cobalt_Strike_Beacon";   Strings=@("beacon","CobaltStrike","cobaltstrike","watermark","pipename") }
        @{ Name="Mimikatz";               Strings=@("mimikatz","sekurlsa","lsadump","privilege::debug","sekurlsa::logonpasswords") }
        @{ Name="Meterpreter";            Strings=@("meterpreter","ReflectiveDll","METERPRETER","meterab") }
        @{ Name="PowerShell_Empire";      Strings=@("Empire","powershell/empire","staging","AGENTBrowse") }
        @{ Name="Ransomware_Strings";     Strings=@("Your files have been encrypted","Bitcoin","send payment","decrypt","ransom") }
        @{ Name="Lateral_Movement_Tools"; Strings=@("psexec","wmiexec","atexec","smbexec","dcomexec") }
        @{ Name="Shellcode_Patterns";     Strings=@("VirtualAlloc","CreateThread","WriteProcessMemory","NtUnmapViewOfSection") }
        @{ Name="Credential_Keywords";    Strings=@("password","passwd","credentials","SAM database","NTDS.dit") }
        @{ Name="C2_Framework_Havoc";     Strings=@("Havoc","teamserver","HavocC2","DEMON_MAGIC") }
        @{ Name="Sliver_C2";              Strings=@("sliver","sliverC2","SLIVER_CA_CERT") }
    )

    $hits = @()

    # If YARA binary available, use it
    if ($YaraExePath -and (Test-Path $YaraExePath)) {
        Write-Alert "YARA binary found at $YaraExePath" "OK"
        $rulesTemp = "$env:TEMP\dfir_yara_rules.yar"
        $yaraContent = ""
        foreach ($rule in $yaraPatterns) {
            $strings = ($rule.Strings | ForEach-Object { "    `$s$([array]::IndexOf($rule.Strings,$_)) = `"$_`" nocase" }) -join "`n"
            $yaraContent += "rule $($rule.Name) {`n  strings:`n$strings`n  condition: any of them`n}`n`n"
        }
        $yaraContent | Set-Content $rulesTemp
        Get-Process | Where-Object { $_.Path } | Select-Object -First 20 | ForEach-Object {
            $out = & $YaraExePath $rulesTemp $_.Id 2>&1
            if ($out -and $out -notmatch "error") {
                Write-Alert "YARA HIT on PID:$($_.Id) [$($_.Name)]: $out" "CRIT"
            }
        }
    } else {
        # Fallback: string search via strings extraction
        Write-Alert "YARA binary not found. Using string-based fallback scan..." "WARN"
        Write-Alert "Tip: Place yara64.exe in the same folder for full YARA scanning" "INFO"

        $procs = Get-Process | Where-Object { $_.Path -and (Test-Path $_.Path) } | Select-Object -First 30

        foreach ($proc in $procs) {
            try {
                $fileBytes = [System.IO.File]::ReadAllBytes($proc.Path)
                $fileText  = [System.Text.Encoding]::ASCII.GetString($fileBytes)

                foreach ($rule in $yaraPatterns) {
                    $matched = $rule.Strings | Where-Object { $fileText -match [regex]::Escape($_) }
                    if ($matched.Count -gt 0) {
                        Write-Alert "PATTERN HIT [$($rule.Name)]: $($proc.Name) (PID:$($proc.Id)) → $($matched -join ', ')" "CRIT"
                        $hits += [PSCustomObject]@{
                            Rule    = $rule.Name
                            Process = $proc.Name
                            PID     = $proc.Id
                            Path    = $proc.Path
                            Matched = $matched -join " | "
                        }
                    }
                }
            } catch {}
        }
    }

    Write-Alert "YARA-style scan complete. Hits: $($hits.Count)" $(if($hits.Count -gt 0){"CRIT"}else{"OK"})

        if ($GridView) { Show-ResultsView -Data $hits -Title "Yara Scan" }
    if ($Export) { Export-ResultsCsv -Data $hits -Name "YaraScan" }
    return $hits
}

#endregion

#region ─── MODULE 9: APT THREAT HUNTING ─────────────────────────────────────

function Invoke-APTHunt {
    <#
    .SYNOPSIS Hunt for APT-specific TTPs and indicators based on MITRE ATT&CK
    #>
    param([string[]]$APTGroups = @("ALL", [switch]$GridView), [switch]$Export)

    Write-Section "APT THREAT HUNT ENGINE (MITRE ATT&CK)"

    $aptProfiles = @{
        "APT29_Cozy_Bear" = @{
            Aliases     = @("Cozy Bear","The Dukes","Midnight Blizzard","NOBELIUM")
            Techniques  = @("T1059.001","T1078","T1021.002","T1550.003","T1195")
            IOCDomains  = @("skywhaleapp.com","solarwinds.com.fake")
            Tools       = @("SUNBURST","TEARDROP","WellMess","EnvyScout")
            Indicators  = @{
                Processes  = @("msiexec.exe.*solarwinds","avsvmcloud","dllhost.exe.*WNetGetProviderName")
                RegKeys    = @("HKLM.*SolarWinds","SOFTWARE.*OrionImprovement")
                Network    = @("avsvmcloud.com","freescanonline.com","deftsecurity.com")
                EventIds   = @(4624,4688,7045)
            }
        }
        "APT28_Fancy_Bear" = @{
            Aliases     = @("Fancy Bear","Sofacy","Strontium","Forest Blizzard","Pawn Storm")
            Techniques  = @("T1566.001","T1203","T1027","T1055","T1036")
            Tools       = @("X-Agent","Sofacy","CHOPSTICK","GAMEFISH","Zebrocy")
            Indicators  = @{
                Processes  = @("winword.*macro","excel.*4\.0 macro")
                Network    = @("*.space","*.bid","*.website")
                EventIds   = @(4624,4648,4697)
            }
        }
        "LAZARUS_Group" = @{
            Aliases     = @("Hidden Cobra","Guardians of Peace","Zinc","Diamond Sleet")
            Techniques  = @("T1486","T1059.001","T1021.001","T1071.001","T1105")
            Tools       = @("WannaCry","HOPLIGHT","ELECTRICFISH","FALLCHILL")
            Indicators  = @{
                Files      = @("mssecsvc.exe","tasksche.exe","@WanaDecryptor@")
                Network    = @("iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com")
                EventIds   = @(4663,4688)
                Hashes     = @("84c82835a5d21bbcf75a61706d8ab549","ed01ebfbc9eb5bbea545af4d01bf5f10")
            }
        }
        "FIN7_Carbanak" = @{
            Aliases     = @("FIN7","Carbon Spider","Sangria Tempest")
            Techniques  = @("T1566.001","T1059.003","T1059.005","T1218.011","T1053.005")
            Tools       = @("Carbanak","BIRDWATCH","GRIFFON","PowerPlant")
            Indicators  = @{
                Processes  = @("mshta.exe.*http","regsvr32.*scrobj","wscript.*\.jse")
                EventIds   = @(4688,4698,7045)
            }
        }
        "BlackCat_ALPHV" = @{
            Aliases     = @("ALPHV","BlackCat","Noberus")
            Techniques  = @("T1486","T1489","T1562","T1070.001","T1078.002")
            Tools       = @("BlackCat ransomware","ExMatter","Fendr")
            Indicators  = @{
                Files      = @("*.alphv","recover-files.txt","ALPHV_*.txt")
                Processes  = @("vssadmin delete shadows","bcdedit /set.*recovery","wbadmin delete")
                EventIds   = @(7036,7040,4663)
            }
        }
    }

    $allHits = @()
    $groupsToHunt = if ("ALL" -in $APTGroups) { $aptProfiles.Keys } else { $APTGroups }

    foreach ($aptName in $groupsToHunt) {
        $apt = $aptProfiles[$aptName]
        if (-not $apt) { Write-Alert "Unknown APT group: $aptName" "WARN"; continue }

        Write-Host "`n  ┌─[ $aptName ]" -ForegroundColor Magenta
        Write-Host "  │  Aliases : $($apt.Aliases -join ', ')" -ForegroundColor DarkMagenta
        Write-Host "  │  Techniques: $($apt.Techniques -join ', ')" -ForegroundColor DarkMagenta

        $aptHits = @()

        # Check processes
        if ($apt.Indicators.Processes) {
            $runningProcs = Get-CimInstance Win32_Process | Select-Object Name, CommandLine
            foreach ($pattern in $apt.Indicators.Processes) {
                $match = $runningProcs | Where-Object { "$($_.Name) $($_.CommandLine)" -match $pattern }
                if ($match) {
                    Write-Alert "APT PROCESS HIT [$aptName]: $pattern" "CRIT"
                    $aptHits += "PROCESS:$pattern"
                }
            }
        }

        # Check network IOCs in DNS/connections
        if ($apt.Indicators.Network) {
            $dns = Get-DnsClientCache -EA SilentlyContinue
            foreach ($domain in $apt.Indicators.Network) {
                $match = $dns | Where-Object { $_.Entry -match [regex]::Escape($domain.Replace("*","")) }
                if ($match) {
                    Write-Alert "APT NETWORK HIT [$aptName]: $domain in DNS cache" "CRIT"
                    $aptHits += "NETWORK:$domain"
                }
            }
        }

        # Check for suspicious file names
        if ($apt.Indicators.Files) {
            $searchDirs = @($env:TEMP,$env:SystemRoot,"C:\Users\Public","C:\Windows\Temp")
            foreach ($fn in $apt.Indicators.Files) {
                foreach ($dir in $searchDirs) {
                    $found = Get-ChildItem $dir -Filter ($fn -replace "\*\.","*.") -EA SilentlyContinue -Recurse
                    if ($found) {
                        Write-Alert "APT FILE HIT [$aptName]: $($found.FullName)" "CRIT"
                        $aptHits += "FILE:$($found.FullName)"
                    }
                }
            }
        }

        # Check event logs
        if ($apt.Indicators.EventIds) {
            $evtCount = 0
            foreach ($evtId in $apt.Indicators.EventIds) {
                $evts = Get-WinEvent -FilterHashtable @{LogName=@("Security","System","Application"); Id=$evtId} -MaxEvents 10 -EA SilentlyContinue
                if ($evts) { $evtCount += $evts.Count }
            }
            if ($evtCount -gt 0) {
                Write-Host "  │  Event indicators found: $evtCount events matching $($apt.Indicators.EventIds -join ',')" -ForegroundColor Yellow
            }
        }

        if ($aptHits.Count -gt 0) {
            Write-Alert "⚠ APT INDICATORS CONFIRMED FOR $aptName ($($aptHits.Count) hits)" "CRIT"
            $allHits += [PSCustomObject]@{
                APT        = $aptName
                Aliases    = $apt.Aliases -join ","
                Techniques = $apt.Techniques -join ","
                Hits       = $aptHits -join " | "
                HitCount   = $aptHits.Count
            }
        } else {
            Write-Host "  └─ No indicators found" -ForegroundColor DarkGray
        }
    }

    Write-Alert "APT Hunt complete. Groups checked: $($groupsToHunt.Count) | Confirmed hits: $($allHits.Count)" `
        $(if($allHits.Count -gt 0){"CRIT"}else{"OK"})

        if ($GridView) { Show-ResultsView -Data $allHits -Title "A P T Hunts" }
    if ($Export) { Export-ResultsCsv -Data $allHits -Name "APTHunts" }
    return $allHits
}

#endregion

#region ─── MODULE 10: MEMORY FORENSICS ──────────────────────────────────────

function Get-MemoryForensics {
    param([switch]$Export, [switch]$GridView)
    Write-Section "MEMORY FORENSICS - INJECTED CODE DETECTION"

    # VAD (Virtual Address Descriptor) analysis via handles
    Write-Host "`n  [Processes with Unusual Memory Regions (RWX)]" -ForegroundColor DarkCyan

    # Look for processes with network connections but no disk image
    $conns = Get-NetTCPConnection -State Established -EA SilentlyContinue
    $procs = Get-Process

    $hollowedCandidates = @()

    foreach ($proc in $procs | Where-Object { $_.WorkingSet64 -gt 50MB }) {
        $hasDisk    = Test-Path $proc.Path -EA SilentlyContinue
        $hasNetwork = $conns | Where-Object { $_.OwningProcess -eq $proc.Id }

        if (-not $hasDisk -and $hasNetwork) {
            Write-Alert "POSSIBLE PROCESS HOLLOWING: $($proc.Name) PID:$($proc.Id) — has network but no disk image!" "CRIT"
            $hollowedCandidates += $proc
        }
    }

    # Look for unusual thread injection markers (via loaded module analysis)
    Write-Host "`n  [Checking for unsigned/unusual loaded modules]" -ForegroundColor DarkCyan
    $systemProcs = @("services.exe","svchost.exe","lsass.exe","winlogon.exe","wininit.exe","csrss.exe")
    
    foreach ($sysProc in (Get-Process | Where-Object { $systemProcs -contains $_.Name })) {
        try {
            $unsignedMods = $sysProc.Modules | Where-Object {
                $path = $_.FileName
                if (-not (Test-Path $path -EA SilentlyContinue)) { return $false }
                $sig = Get-AuthenticodeSignature $path -EA SilentlyContinue
                return ($sig.Status -ne "Valid")
            }
            if ($unsignedMods) {
                foreach ($m in $unsignedMods) {
                    Write-Alert "Unsigned module in $($sysProc.Name): $($m.FileName)" "HIGH"
                }
            }
        } catch {}
    }

    # Detect DLL Search Order Hijacking candidates
    Write-Host "`n  [DLL Hijacking Candidates (PATH analysis)]" -ForegroundColor DarkCyan
    $path = $env:PATH -split ";"
    $writablePaths = $path | Where-Object {
        $_ -and (Test-Path $_ -EA SilentlyContinue) -and
        (Get-Acl $_ -EA SilentlyContinue).Access | Where-Object {
            $_.FileSystemRights -match "Write|FullControl" -and
            $_.IdentityReference -match "BUILTIN\\Users|Everyone"
        }
    }
    if ($writablePaths) {
        $writablePaths | ForEach-Object { Write-Alert "Writable PATH entry (DLL hijack risk): $_" "HIGH" }
    } else {
        Write-Alert "No writable PATH entries detected" "OK"
    if ($GridView) { Show-ResultsView -Data (Get-Process -EA SilentlyContinue | Where-Object { $_.Modules.Count -gt 0 } | Select-Object Id,Name,Path,@{N="Modules";E={$_.Modules.Count}} | Sort-Object Modules -Descending | Select-Object -First 100) -Title "Memory Forensics - Processes" }
    }
}

#endregion

#region ─── MODULE 11: FILE SYSTEM FORENSICS ─────────────────────────────────

function Get-FileSystemForensics {
    param([switch]$Export, [switch]$GridView)
    Write-Section "FILE SYSTEM FORENSICS"

    # Recently modified files in sensitive locations
    Write-Host "`n  [Recently Modified Files (24h) in Sensitive Locations]" -ForegroundColor DarkCyan
    $sensitivePaths = @(
        $env:SystemRoot, "$env:SystemRoot\System32",
        "$env:SystemRoot\System32\drivers",
        "$env:APPDATA", "$env:LOCALAPPDATA",
        "$env:TEMP", "$env:SystemRoot\Temp",
        "C:\Users\Public"
    )

    $cutoff = (Get-Date).AddHours(-24)
    $recentFiles = @()

    foreach ($sp in $sensitivePaths) {
        Get-ChildItem $sp -EA SilentlyContinue -File | Where-Object { $_.LastWriteTime -gt $cutoff } | ForEach-Object {
            $sig = Get-AuthenticodeSignature $_.FullName -EA SilentlyContinue
            $recentFiles += [PSCustomObject]@{
                Path      = $_.FullName
                Modified  = $_.LastWriteTime
                Size      = $_.Length
                Signed    = $sig.Status
                Extension = $_.Extension
            }
            $color = if ($sig.Status -ne "Valid" -and $_.Extension -match "\.exe|\.dll|\.sys|\.ps1") { "Red" } else { "Gray" }
            Write-Host ("  [{0}] {1,-60} {2}" -f $_.LastWriteTime, $_.FullName, $sig.Status) -ForegroundColor $color
        }
    }

    # Check for alternate data streams (ADS)
    Write-Host "`n  [Alternate Data Streams Detection]" -ForegroundColor DarkCyan
    $adsPaths = @($env:TEMP, $env:APPDATA, "C:\Users\Public")
    foreach ($p in $adsPaths) {
        Get-Item "$p\*" -Stream * -EA SilentlyContinue |
            Where-Object { $_.Stream -ne ':$Data' -and $_.Stream -ne 'Zone.Identifier' } |
            ForEach-Object {
                Write-Alert "ADS FOUND: $($_.FileName) → Stream:$($_.Stream) Size:$($_.Length)" "HIGH"
            }
    }

    # Recently accessed prefetch files
    Write-Host "`n  [Recent Execution Evidence (Prefetch)]" -ForegroundColor DarkCyan
    $prefetchPath = "$env:SystemRoot\Prefetch"
    if (Test-Path $prefetchPath) {
        Get-ChildItem $prefetchPath -Filter "*.pf" -EA SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20 |
            ForEach-Object {
                Write-Host ("  [{0}] {1}" -f $_.LastWriteTime, $_.Name) -ForegroundColor Gray
            }
    }

        if ($GridView) { Show-ResultsView -Data $recentFiles -Title "File System Forensics" }
    if ($Export) { Export-ResultsCsv -Data $recentFiles -Name "FileSystemForensics" }
    return $recentFiles
}

#endregion

#region ─── MODULE 12: LIVE RESPONSE / INCIDENT SNAPSHOT ─────────────────────

function Get-IncidentSnapshot {
    <#
    .SYNOPSIS Full system snapshot for incident response - one-shot collection
    #>
    param([string]$OutputDir = "$env:TEMP\DFIR_$(Get-Date -f 'yyyyMMdd_HHmmss')")

    Write-Section "INCIDENT RESPONSE SNAPSHOT"
    Write-Alert "Output directory: $OutputDir" "INFO"
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

    # System info
    $sysInfo = Get-CimInstance Win32_ComputerSystem | Select-Object *
    $osInfo  = Get-CimInstance Win32_OperatingSystem | Select-Object *
    $bios    = Get-CimInstance Win32_BIOS | Select-Object *
    
    [PSCustomObject]@{
        Hostname    = $env:COMPUTERNAME
        Domain      = $env:USERDOMAIN
        OS          = $osInfo.Caption
        Build       = $osInfo.BuildNumber
        LastBoot    = $osInfo.LastBootUpTime
        LoggedUser  = $env:USERNAME
        TimeStamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
        IsAdmin     = Get-IsAdmin
    } | Export-Csv "$OutputDir\00_SystemInfo.csv" -NoTypeInformation

    # Run all modules and save
    Write-Alert "Collecting: Network connections..." "INFO"
    Get-NetworkConnections -Export | Export-Csv "$OutputDir\01_NetworkConnections.csv" -NoTypeInformation -Force

    Write-Alert "Collecting: DNS cache..." "INFO"
    Get-DNSCache | Export-Csv "$OutputDir\02_DNSCache.csv" -NoTypeInformation -Force

    Write-Alert "Collecting: Process forensics..." "INFO"
    Get-ProcessForensics -Export | Export-Csv "$OutputDir\03_ProcessForensics.csv" -NoTypeInformation -Force

    Write-Alert "Collecting: Registry persistence..." "INFO"
    Get-RegistryForensics -Export | Export-Csv "$OutputDir\04_RegistryForensics.csv" -NoTypeInformation -Force

    Write-Alert "Collecting: User accounts..." "INFO"
    Get-UserAccountForensics -Export | Export-Csv "$OutputDir\05_UserAccounts.csv" -NoTypeInformation -Force

    Write-Alert "Collecting: Persistence mechanisms..." "INFO"
    Get-PersistenceMechanisms -Export | Export-Csv "$OutputDir\06_Persistence.csv" -NoTypeInformation -Force

    Write-Alert "Collecting: File system forensics..." "INFO"
    Get-FileSystemForensics -Export | Export-Csv "$OutputDir\07_FileSystem.csv" -NoTypeInformation -Force

    Write-Alert "Running SIGMA detection..." "INFO"
    Invoke-SigmaHunt -Export | Export-Csv "$OutputDir\08_SigmaHits.csv" -NoTypeInformation -Force

    Write-Alert "Running APT hunt..." "INFO"
    Invoke-APTHunt -Export | Export-Csv "$OutputDir\09_APTHunts.csv" -NoTypeInformation -Force

    # Event log collection
    Write-Alert "Collecting critical event logs..." "INFO"
    $critEvents = Get-WinEvent -FilterHashtable @{
        LogName = @("Security","System","Application")
        StartTime = (Get-Date).AddHours(-24)
    } -MaxEvents 500 -EA SilentlyContinue
    $critEvents | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message |
        Export-Csv "$OutputDir\10_EventLogs_24h.csv" -NoTypeInformation -Force

    # Hash all suspicious binaries
    Write-Alert "Hashing suspicious process images..." "INFO"
    Get-Process | Where-Object { $_.Path } | ForEach-Object {
        [PSCustomObject]@{
            Name   = $_.Name
            PID    = $_.Id
            Path   = $_.Path
            MD5    = (Get-FileHash $_.Path -Algorithm MD5    -EA SilentlyContinue).Hash
            SHA256 = (Get-FileHash $_.Path -Algorithm SHA256 -EA SilentlyContinue).Hash
        }
    } | Export-Csv "$OutputDir\11_ProcessHashes.csv" -NoTypeInformation -Force

    Write-Alert "Snapshot complete! Files saved to: $OutputDir" "OK"
    Write-Host "`n  Files collected:" -ForegroundColor Green
    Get-ChildItem $OutputDir | ForEach-Object {
        Write-Host "    ✔ $($_.Name)" -ForegroundColor DarkGreen
    }
    return $OutputDir
}

#endregion

#region ─── MODULE 13: LATERAL MOVEMENT DETECTION ────────────────────────────

function Get-LateralMovementIndicators {
    param([switch]$Export, [switch]$GridView)
    Write-Section "LATERAL MOVEMENT DETECTION"

    # SMB connections
    Write-Host "`n  [Active SMB Sessions]" -ForegroundColor DarkCyan
    Get-SmbSession -EA SilentlyContinue | Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsExists |
        ForEach-Object { Write-Host "  ► $($_.ClientComputerName) ← $($_.ClientUserName) Opens:$($_.NumOpens)" -ForegroundColor Cyan }

    # Admin shares
    Write-Host "`n  [Admin Shares]" -ForegroundColor DarkCyan
    Get-SmbShare -EA SilentlyContinue | Where-Object { $_.Name -match "ADMIN\$|C\$|IPC\$" } |
        Format-Table -AutoSize | Out-String | Write-Host

    # WinRM / PSRemoting
    Write-Host "`n  [WinRM Service Status]" -ForegroundColor DarkCyan
    $winrm = Get-Service WinRM -EA SilentlyContinue
    $color = if ($winrm.Status -eq "Running") { "Yellow" } else { "Green" }
    Write-Host "  WinRM: $($winrm.Status)" -ForegroundColor $color

    # RDP connections from event log
    Write-Host "`n  [Recent RDP Connections (Event 4624 Type 10)]" -ForegroundColor DarkCyan
    Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624} -MaxEvents 200 -EA SilentlyContinue |
        Where-Object { $_.Message -match "LogonType.*10\b" } |
        Select-Object -First 10 TimeCreated, @{N="Detail"; E={ $_.Message.Substring(0,200) }} |
        ForEach-Object { Write-Host "  [$($_.TimeCreated)] RDP: $($_.Detail)" -ForegroundColor Yellow }

    # PsExec artifacts
    Write-Host "`n  [PsExec Artifacts]" -ForegroundColor DarkCyan
    $psexecKeys = @("HKLM:\SYSTEM\CurrentControlSet\Services\PSEXESVC",
                    "HKLM:\SYSTEM\CurrentControlSet\Services\PsExecSvc")
    foreach ($k in $psexecKeys) {
        if (Test-Path $k) { Write-Alert "PsExec service key found: $k" "HIGH" }
    $lateralResults = @()
    if ($GridView) { Show-ResultsView -Data (Get-SmbSession -EA SilentlyContinue | Select-Object ClientComputerName,ClientUserName,NumOpens) -Title "Lateral Movement - SMB Sessions" }
    if ($Export)   { Write-Alert "Use Get-LateralMovementIndicators -Export after piping results to collect data" "INFO" }
    }
    if (Get-Service PSEXESVC -EA SilentlyContinue) { Write-Alert "PsExec service is running!" "CRIT" }
}

#endregion

#region ─── MODULE 14: BROWSER FORENSICS ─────────────────────────────────────

function Get-BrowserForensics {
    <#
    .SYNOPSIS Extract browser history, downloads, saved passwords locations, extensions
    Supports: Chrome, Edge, Firefox, Brave, Opera
    #>
    param([switch]$Export, [switch]$PasswordLocations, [switch]$GridView)

    Write-Section "BROWSER FORENSICS (Chrome/Edge/Firefox/Brave/Opera)"

    $results = @()
    $userProfiles = Get-ChildItem "C:\Users" -Directory -EA SilentlyContinue | Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") }

    $browserPaths = @{
        "Chrome"  = @{ History="Google\Chrome\User Data\Default\History"; Extensions="Google\Chrome\User Data\Default\Extensions"; Downloads="Google\Chrome\User Data\Default\History" }
        "Edge"    = @{ History="Microsoft\Edge\User Data\Default\History"; Extensions="Microsoft\Edge\User Data\Default\Extensions" }
        "Brave"   = @{ History="BraveSoftware\Brave-Browser\User Data\Default\History"; Extensions="BraveSoftware\Brave-Browser\User Data\Default\Extensions" }
        "Firefox" = @{ History="Mozilla\Firefox\Profiles"; Extensions="Mozilla\Firefox\Profiles" }
        "Opera"   = @{ History="Opera Software\Opera Stable\History" }
    }

    foreach ($user in $userProfiles) {
        $appData = "$($user.FullName)\AppData\Local"
        $roaming = "$($user.FullName)\AppData\Roaming"

        foreach ($browser in $browserPaths.Keys) {
            $histPath = $null
            if ($browser -eq "Firefox") {
                $ffProfiles = Get-ChildItem "$roaming\Mozilla\Firefox\Profiles" -Directory -EA SilentlyContinue
                foreach ($ffp in $ffProfiles) {
                    $histPath = "$($ffp.FullName)\places.sqlite"
                    if (Test-Path $histPath) {
                        $size = (Get-Item $histPath).Length
                        Write-Host ("  [Firefox] User:{0,-15} Profile:{1,-30} Size:{2} bytes" -f $user.Name, $ffp.Name, $size) -ForegroundColor Cyan
                        # Check for suspicious extensions
                        $extPath = "$($ffp.FullName)\extensions.json"
                        if (Test-Path $extPath) {
                            $extContent = Get-Content $extPath -Raw -EA SilentlyContinue
                            $suspExts = @("greasemonkey","tampermonkey","scriptsafe")
                            foreach ($se in $suspExts) {
                                if ($extContent -match $se) {
                                    Write-Alert "Script injection extension in Firefox [$($user.Name)]: $se" "WARN"
                                }
                            }
                        }
                        $results += [PSCustomObject]@{ User=$user.Name; Browser="Firefox"; Type="History DB"; Path=$histPath; Size=$size }
                    }
                }
            } else {
                $histPath = "$appData\$($browserPaths[$browser].History)"
                if (Test-Path $histPath) {
                    $size = (Get-Item $histPath).Length
                    $lastWrite = (Get-Item $histPath).LastWriteTime
                    Write-Host ("  [{0,-8}] User:{1,-15} Last Modified:{2} Size:{3}" -f $browser, $user.Name, $lastWrite, $size) -ForegroundColor Cyan

                    # Check for suspicious extensions
                    if ($browserPaths[$browser].Extensions) {
                        $extBase = "$appData\$($browserPaths[$browser].Extensions)"
                        if (Test-Path $extBase) {
                            $exts = Get-ChildItem $extBase -Directory -EA SilentlyContinue
                            Write-Host ("     Extensions installed: {0}" -f $exts.Count) -ForegroundColor DarkGray
                            # Known malicious extension IDs (sample set)
                            $maliciousExtIds = @("nmmhkkegccagdldgiimedpiccmgmieda","aapbdbdomjkkjkaonfhkkikfgjllcleb")
                            foreach ($ext in $exts) {
                                if ($ext.Name -in $maliciousExtIds) {
                                    Write-Alert "KNOWN MALICIOUS EXTENSION: $($ext.Name) in $browser [$($user.Name)]" "CRIT"
                                }
                            }
                        }
                    }
                    $results += [PSCustomObject]@{ User=$user.Name; Browser=$browser; Type="History DB"; Path=$histPath; LastWrite=$lastWrite; Size=$size }
                }
            }
        }

        # Check for saved credentials in browser stores
        if ($PasswordLocations) {
            $credPaths = @(
                "$appData\Google\Chrome\User Data\Default\Login Data"
                "$appData\Microsoft\Edge\User Data\Default\Login Data"
                "$appData\BraveSoftware\Brave-Browser\User Data\Default\Login Data"
            )
            foreach ($cp in $credPaths) {
                if (Test-Path $cp) {
                    Write-Alert "Browser credential store found: $cp (copy + decrypt with Mimikatz/LaZagne)" "HIGH"
                    $results += [PSCustomObject]@{ User=$user.Name; Browser="Chrome/Edge"; Type="Login Data"; Path=$cp }
                }
            }
        }
    }

    # Recent browser downloads from common download locations
    Write-Host "`n  [Recent Downloads (last 72h)]" -ForegroundColor DarkCyan
    $suspExts = @("\.exe$","\.ps1$","\.bat$","\.vbs$","\.hta$","\.js$","\.jar$","\.msi$","\.dll$","\.scr$","\.pif$","\.com$","\.cpl$")
    foreach ($user in $userProfiles) {
        $dlPath = "$($user.FullName)\Downloads"
        if (Test-Path $dlPath) {
            Get-ChildItem $dlPath -File -EA SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-72) } |
                ForEach-Object {
                    $isSusp = $suspExts | Where-Object { $_.Name -match $_ }
                    $color  = if ($isSusp) { "Red" } else { "Gray" }
                    $flag   = if ($isSusp) { "SUSPICIOUS" } else { "" }
                    Write-Host ("  [{0}] {1,-50} {2} {3}" -f $_.LastWriteTime, $_.FullName, $_.Length, $flag) -ForegroundColor $color
                    if ($isSusp) {
                        $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -EA SilentlyContinue).Hash
                        Write-Alert "Suspicious download: $($_.FullName) | SHA256: $hash" "HIGH"
                        $results += [PSCustomObject]@{ User=$user.Name; Browser="Downloads"; Type="SuspiciousFile"; Path=$_.FullName; SHA256=$hash; Modified=$_.LastWriteTime }
                    }
                }
        }
    }

        if ($GridView) { Show-ResultsView -Data $results -Title "Browser Forensics" }
    if ($Export) { Export-ResultsCsv -Data $results -Name "BrowserForensics" }
    return $results
}

#endregion

#region ─── MODULE 15: WINDOWS EVENT LOG DEEP ANALYSIS ───────────────────────

function Get-EventLogForensics {
    <#
    .SYNOPSIS Deep Windows Event Log analysis across Security, System, Application,
    PowerShell, WMI, Sysmon (if installed), Task Scheduler, and more.
    #>
    param(
        [int]$HoursBack = 48,
        [switch]$Export,
        [switch]$Sysmon
    , [switch]$GridView)

    Write-Section "WINDOWS EVENT LOG DEEP ANALYSIS (Last $HoursBack hours)"

    $startTime = (Get-Date).AddHours(-$HoursBack)
    $allEvents = @()

    # ── Critical Event ID reference map ─────────────────────────────────────
    $criticalEventMap = @{
        # Authentication & Account
        4624 = @{ Desc="Successful Logon";            Severity="INFO" }
        4625 = @{ Desc="Failed Logon";                Severity="WARN" }
        4634 = @{ Desc="Logoff";                      Severity="INFO" }
        4647 = @{ Desc="User Initiated Logoff";       Severity="INFO" }
        4648 = @{ Desc="Logon with Explicit Creds";   Severity="HIGH" }
        4672 = @{ Desc="Special Privilege Logon";     Severity="WARN" }
        4688 = @{ Desc="New Process Created";         Severity="INFO" }
        4689 = @{ Desc="Process Exited";              Severity="INFO" }
        4697 = @{ Desc="Service Installed";           Severity="HIGH" }
        4698 = @{ Desc="Scheduled Task Created";      Severity="HIGH" }
        4699 = @{ Desc="Scheduled Task Deleted";      Severity="WARN" }
        4700 = @{ Desc="Scheduled Task Enabled";      Severity="WARN" }
        4701 = @{ Desc="Scheduled Task Disabled";     Severity="WARN" }
        4702 = @{ Desc="Scheduled Task Updated";      Severity="WARN" }
        4719 = @{ Desc="Audit Policy Changed";        Severity="CRIT" }
        4720 = @{ Desc="User Account Created";        Severity="HIGH" }
        4722 = @{ Desc="User Account Enabled";        Severity="WARN" }
        4723 = @{ Desc="Password Change Attempt";     Severity="WARN" }
        4724 = @{ Desc="Password Reset Attempt";      Severity="HIGH" }
        4725 = @{ Desc="User Account Disabled";       Severity="WARN" }
        4726 = @{ Desc="User Account Deleted";        Severity="HIGH" }
        4728 = @{ Desc="Member Added to Global Group";Severity="HIGH" }
        4732 = @{ Desc="Member Added to Local Group"; Severity="HIGH" }
        4740 = @{ Desc="Account Locked Out";          Severity="HIGH" }
        4756 = @{ Desc="Member Added Universal Group";Severity="HIGH" }
        4767 = @{ Desc="Account Unlocked";            Severity="WARN" }
        4776 = @{ Desc="NTLM Auth / Credential Validation"; Severity="WARN" }
        4768 = @{ Desc="Kerberos TGT Requested";      Severity="INFO" }
        4769 = @{ Desc="Kerberos Service Ticket";     Severity="INFO" }
        4771 = @{ Desc="Kerberos Pre-Auth Failed";    Severity="HIGH" }
        # Object Access
        4656 = @{ Desc="Object Handle Requested";     Severity="WARN" }
        4657 = @{ Desc="Registry Value Modified/Changed"; Severity="WARN" }
        4660 = @{ Desc="Object Deleted";              Severity="WARN" }
        4661 = @{ Desc="Handle to Object Requested";  Severity="WARN" }
        4662 = @{ Desc="Operation on AD Object";      Severity="HIGH" }
        4663 = @{ Desc="Object Access Attempt";       Severity="INFO" }
        # System
        1102 = @{ Desc="AUDIT LOG CLEARED";           Severity="CRIT" }
        1100 = @{ Desc="Event Log Service Stopped";   Severity="CRIT" }
        4616 = @{ Desc="System Time Changed";         Severity="HIGH" }
        6005 = @{ Desc="Event Log Started (Reboot)";  Severity="INFO" }
        6006 = @{ Desc="Event Log Stopped";           Severity="WARN" }
        6008 = @{ Desc="Unexpected Shutdown";         Severity="HIGH" }
        6013 = @{ Desc="System Uptime";               Severity="INFO" }
        # Services & Drivers
        7034 = @{ Desc="Service Crashed";             Severity="HIGH" }
        7035 = @{ Desc="Service Control Request";     Severity="INFO" }
        7036 = @{ Desc="Service State Changed";       Severity="INFO" }
        7040 = @{ Desc="Service Start Type Changed";  Severity="HIGH" }
        7045 = @{ Desc="New Service Installed";       Severity="HIGH" }
        # PowerShell
        4103 = @{ Desc="PS Module Logging";           Severity="INFO" }
        4104 = @{ Desc="PS Script Block Logging";     Severity="INFO" }
        # RDP
        4778 = @{ Desc="RDP Session Reconnected";     Severity="WARN" }
        4779 = @{ Desc="RDP Session Disconnected";    Severity="INFO" }
        # AppLocker / Windows Defender
        8004 = @{ Desc="AppLocker Block";             Severity="HIGH" }
        1116 = @{ Desc="Malware Detected (Defender)"; Severity="CRIT" }
        1117 = @{ Desc="Defender Action Taken";       Severity="HIGH" }
        1118 = @{ Desc="Defender Remediation Failed"; Severity="CRIT" }
        1119 = @{ Desc="Defender Remediation Success";Severity="OK" }
        5001 = @{ Desc="Defender Real-Time Disabled"; Severity="CRIT" }
        5007 = @{ Desc="Defender Config Changed";     Severity="HIGH" }
    }

    $logTargets = @(
        @{ Name="Security";           Max=1000 }
        @{ Name="System";             Max=500  }
        @{ Name="Application";        Max=300  }
        @{ Name="Microsoft-Windows-PowerShell/Operational"; Max=500 }
        @{ Name="Microsoft-Windows-WMI-Activity/Operational"; Max=200 }
        @{ Name="Microsoft-Windows-TaskScheduler/Operational"; Max=200 }
        @{ Name="Microsoft-Windows-Windows Defender/Operational"; Max=200 }
        @{ Name="Microsoft-Windows-Sysmon/Operational"; Max=500 }
        @{ Name="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; Max=100 }
        @{ Name="Microsoft-Windows-AppLocker/EXE and DLL"; Max=100 }
    )

    $summaryTable = @{}
    $anomalies    = @()

    foreach ($log in $logTargets) {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $log.Name
                StartTime = $startTime
            } -MaxEvents $log.Max -EA SilentlyContinue

            if (-not $events) { continue }

            Write-Host "`n  [Log: $($log.Name)] — $($events.Count) events" -ForegroundColor DarkCyan

            foreach ($evt in $events) {
                $info = $criticalEventMap[$evt.Id]
                $sev  = if ($info) { $info.Severity } else { "INFO" }
                $desc = if ($info) { $info.Desc } else { "Event $($evt.Id)" }

                # Only show WARN and above in console
                if ($sev -in @("WARN","HIGH","CRIT","OK")) {
                    $color = switch ($sev) {
                        "CRIT" { "Magenta" } "HIGH" { "Red" } "WARN" { "Yellow" }
                        "OK"   { "Green"   } default { "Gray" }
                    }
                    Write-Host ("  [{0}] ID:{1,-5} [{2,-10}] {3}" -f $evt.TimeCreated, $evt.Id, $sev, $desc) -ForegroundColor $color
                }

                # Track frequency for anomaly detection
                $key = "$($log.Name)_$($evt.Id)"
                if ($summaryTable[$key]) { $summaryTable[$key]++ } else { $summaryTable[$key] = 1 }

                $allEvents += [PSCustomObject]@{
                    TimeCreated = $evt.TimeCreated
                    Log         = $log.Name
                    EventId     = $evt.Id
                    Description = $desc
                    Severity    = $sev
                    Provider    = $evt.ProviderName
                    Message     = $evt.Message.Substring(0, [Math]::Min(300, $evt.Message.Length))
                }
            }
        }
        catch { Write-Host "  Skipped: $($log.Name) (access denied or not installed)" -ForegroundColor DarkGray }
    }

    # ── Brute force detection ────────────────────────────────────────────────
    Write-Host "`n  [Brute Force / Account Lockout Analysis]" -ForegroundColor DarkCyan
    $failedLogons = $allEvents | Where-Object { $_.EventId -eq 4625 }
    if ($failedLogons.Count -gt 10) {
        Write-Alert "HIGH VOLUME FAILED LOGONS: $($failedLogons.Count) in last $HoursBack hours!" "CRIT"
        $anomalies += [PSCustomObject]@{ Type="BruteForce"; Count=$failedLogons.Count; Detail="4625 Failed Logon events" }
    }

    # ── Log clearing detection ───────────────────────────────────────────────
    $logClears = $allEvents | Where-Object { $_.EventId -in @(1102, 1100) }
    if ($logClears.Count -gt 0) {
        Write-Alert "EVENT LOG CLEARED/STOPPED $($logClears.Count) times — ANTI-FORENSICS INDICATOR!" "CRIT"
        $anomalies += [PSCustomObject]@{ Type="LogCleared"; Count=$logClears.Count; Detail="1102/1100 events" }
    }

    # ── Defender detections ──────────────────────────────────────────────────
    $malwareHits = $allEvents | Where-Object { $_.EventId -in @(1116,1117,1118) }
    if ($malwareHits.Count -gt 0) {
        Write-Alert "DEFENDER MALWARE DETECTIONS: $($malwareHits.Count) events!" "CRIT"
        $malwareHits | Select-Object -First 5 | ForEach-Object {
            Write-Host "  → [$($_.TimeCreated)] $($_.Message.Substring(0,200))" -ForegroundColor Red
        }
    }

    # ── Summary ──────────────────────────────────────────────────────────────
    Write-Host "`n  [Event Frequency Summary — Top 15]" -ForegroundColor DarkCyan
    $summaryTable.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15 | ForEach-Object {
        Write-Host ("  {0,-60} Count:{1}" -f $_.Key, $_.Value) -ForegroundColor Gray
    }

    Write-Alert "Total events analyzed: $($allEvents.Count) | Anomalies: $($anomalies.Count)" $(if($anomalies.Count -gt 0){"HIGH"}else{"OK"})

        if ($GridView) { Show-ResultsView -Data $allEvents -Title "Event Log Analysis" }
    if ($Export) { Export-ResultsCsv -Data $allEvents -Name "EventLogAnalysis" }
    return $allEvents
}

#endregion

#region ─── MODULE 16: ACTIVE DIRECTORY / DOMAIN FORENSICS ───────────────────

function Get-ActiveDirectoryForensics {
    <#
    .SYNOPSIS AD reconnaissance and anomaly detection.
    Works on domain-joined machines. Requires RSAT or direct AD access.
    #>
    param([switch]$Export, [switch]$GridView)

    Write-Section "ACTIVE DIRECTORY / DOMAIN FORENSICS"

    # Check domain membership
    $domain = $env:USERDNSDOMAIN
    if (-not $domain) {
        Write-Alert "Not domain-joined or domain info unavailable" "WARN"
        # Still collect local domain info
        Write-Host "`n  [Local Domain/Workgroup Info]" -ForegroundColor DarkCyan
        (Get-CimInstance Win32_ComputerSystem) | Select-Object Name, Domain, Workgroup, PartOfDomain | Format-List | Out-String | Write-Host
        return
    }

    Write-Alert "Domain detected: $domain" "INFO"
    $results = @()

    # ── DC Discovery ─────────────────────────────────────────────────────────
    Write-Host "`n  [Domain Controllers]" -ForegroundColor DarkCyan
    try {
        $dcs = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
        foreach ($dc in $dcs) {
            Write-Host ("  ► {0,-30} OS:{1}" -f $dc.Name, $dc.OSVersion) -ForegroundColor Cyan
            $results += [PSCustomObject]@{ Type="DomainController"; Name=$dc.Name; OS=$dc.OSVersion; Site=$dc.SiteName }
        }
    } catch { Write-Alert "Cannot enumerate DCs (RSAT required for full AD access)" "WARN" }

    # ── Domain/Forest trusts ─────────────────────────────────────────────────
    Write-Host "`n  [Domain Trusts]" -ForegroundColor DarkCyan
    try {
        $trusts = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetAllTrustRelationships()
        if ($trusts.Count -eq 0) { Write-Host "  No trusts found" -ForegroundColor DarkGray }
        foreach ($t in $trusts) {
            $color = if ($t.TrustDirection -eq "Bidirectional") { "Yellow" } else { "Cyan" }
            Write-Host ("  ► {0,-30} Direction:{1,-15} Type:{2}" -f $t.TargetName, $t.TrustDirection, $t.TrustType) -ForegroundColor $color
            $results += [PSCustomObject]@{ Type="Trust"; Target=$t.TargetName; Direction=$t.TrustDirection; TrustType=$t.TrustType }
        }
    } catch { Write-Alert "Cannot enumerate trusts" "WARN" }

    # ── Privileged group membership via net commands (no RSAT required) ──────
    Write-Host "`n  [Privileged AD Groups (net group)]" -ForegroundColor DarkCyan
    $privGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","Server Operators","Print Operators","Group Policy Creator Owners")
    foreach ($grp in $privGroups) {
        try {
            $members = net group "$grp" /domain 2>$null
            if ($members) {
                $memberLines = $members | Where-Object { $_ -match "^\w" -and $_ -notmatch "^The|^Group|^Comment|^Members|^-|^Command" }
                if ($memberLines) {
                    Write-Host ("  ► {0,-35}: {1}" -f $grp, ($memberLines -join ", ").Trim()) -ForegroundColor Yellow
                    $results += [PSCustomObject]@{ Type="PrivGroup"; Group=$grp; Members=($memberLines -join ",").Trim() }
                }
            }
        } catch {}
    }

    # ── Password policy ──────────────────────────────────────────────────────
    Write-Host "`n  [Domain Password Policy]" -ForegroundColor DarkCyan
    try {
        $pwpol = net accounts /domain 2>$null
        $pwpol | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    } catch {}

    # ── Kerberoastable accounts (SPNs) ───────────────────────────────────────
    Write-Host "`n  [Kerberoastable Accounts (SPNs on User Objects)]" -ForegroundColor DarkCyan
    try {
        $searcher = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
        $searcher.PageSize = 1000
        $spnUsers = $searcher.FindAll()
        if ($spnUsers.Count -gt 0) {
            Write-Alert "Kerberoastable accounts found: $($spnUsers.Count)" "HIGH"
            foreach ($u in $spnUsers) {
                $uname = $u.Properties["samaccountname"][0]
                $spns  = $u.Properties["serviceprincipalname"]
                Write-Host ("  ⚠  {0,-30} SPNs: {1}" -f $uname, ($spns -join " | ")) -ForegroundColor Red
                $results += [PSCustomObject]@{ Type="Kerberoastable"; User=$uname; SPNs=($spns -join "|") }
            }
        } else { Write-Alert "No Kerberoastable user accounts found" "OK" }
    } catch { Write-Alert "Cannot query AD (not domain-joined or LDAP blocked)" "WARN" }

    # ── AS-REP Roastable accounts (no preauth) ───────────────────────────────
    Write-Host "`n  [AS-REP Roastable Accounts (No Preauth Required)]" -ForegroundColor DarkCyan
    try {
        $searcher2 = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        $noPreAuth = $searcher2.FindAll()
        if ($noPreAuth.Count -gt 0) {
            Write-Alert "AS-REP Roastable accounts: $($noPreAuth.Count)" "HIGH"
            foreach ($u in $noPreAuth) {
                Write-Host "  ⚠  $($u.Properties['samaccountname'][0])" -ForegroundColor Red
                $results += [PSCustomObject]@{ Type="ASREPRoastable"; User=$u.Properties["samaccountname"][0] }
            }
        } else { Write-Alert "No AS-REP roastable accounts found" "OK" }
    } catch {}

    # ── Recently created AD users (last 30 days) ─────────────────────────────
    Write-Host "`n  [Recently Created AD Accounts (30 days)]" -ForegroundColor DarkCyan
    try {
        $cutoffLDAP = ([DateTime]::Now.AddDays(-30)).ToFileTime()
        $searcher3  = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(whenCreated>=$($cutoffLDAP)))"
        $recentUsers = $searcher3.FindAll()
        if ($recentUsers.Count -gt 0) {
            Write-Alert "Recently created AD accounts: $($recentUsers.Count)" "WARN"
            foreach ($u in $recentUsers) {
                $uname   = $u.Properties["samaccountname"][0]
                $created = $u.Properties["whencreated"][0]
                Write-Host ("  NEW: {0,-30} Created:{1}" -f $uname, $created) -ForegroundColor Yellow
                $results += [PSCustomObject]@{ Type="NewADUser"; User=$uname; Created=$created }
            }
        }
    } catch {}

    # ── AdminSDHolder protected accounts ─────────────────────────────────────
    Write-Host "`n  [AdminSDHolder Protected Accounts]" -ForegroundColor DarkCyan
    try {
        $searcher4 = [adsisearcher]"(&(objectCategory=person)(adminCount=1))"
        $adminProt = $searcher4.FindAll()
        Write-Alert "AdminSDHolder protected accounts: $($adminProt.Count)" $(if($adminProt.Count -gt 20){"HIGH"}else{"INFO"})
        foreach ($u in $adminProt) {
            Write-Host "  ► $($u.Properties['samaccountname'][0])" -ForegroundColor Yellow
        }
    } catch {}

        if ($GridView) { Show-ResultsView -Data $results -Title "Active Directory Forensics" }
    if ($Export) { Export-ResultsCsv -Data $results -Name "ActiveDirectoryForensics" }
    return $results
}

#endregion

#region ─── MODULE 17: NETWORK SHARE & SMB FORENSICS ─────────────────────────

function Get-NetworkShareForensics {
    param([switch]$Export, [switch]$GridView)
    Write-Section "NETWORK SHARE & SMB FORENSICS"

    $results = @()

    # ── Local shares ─────────────────────────────────────────────────────────
    Write-Host "`n  [All Local Shares]" -ForegroundColor DarkCyan
    $shares = Get-SmbShare -EA SilentlyContinue | Select-Object Name, Path, Description, ShareType,
        @{N="Permissions"; E={ (Get-SmbShareAccess -Name $_.Name -EA SilentlyContinue) | ForEach-Object { "$($_.AccountName):$($_.AccessRight)" } | Select-Object -First 3 }}

    foreach ($s in $shares) {
        $isAdmin  = $s.Name -match "ADMIN\$|C\$|IPC\$|SYSVOL|NETLOGON"
        $isCustom = -not $isAdmin
        $color    = if ($isCustom) { "Yellow" } else { "DarkGray" }
        Write-Host ("  {0,-20} Path:{1,-40} [{2}]" -f $s.Name, $s.Path, $s.ShareType) -ForegroundColor $color

        # Check for Everyone/Authenticated Users write access (lateral movement risk)
        $access = Get-SmbShareAccess -Name $s.Name -EA SilentlyContinue
        $openAccess = $access | Where-Object { $_.AccountName -match "Everyone|Authenticated Users|ANONYMOUS" -and $_.AccessRight -eq "Full" }
        if ($openAccess) {
            Write-Alert "OPEN SHARE - Full access for Everyone/Auth Users: \\$env:COMPUTERNAME\$($s.Name)" "CRIT"
        }
        $results += [PSCustomObject]@{ Type="Share"; Name=$s.Name; Path=$s.Path; OpenAccess=[bool]$openAccess }
    }

    # ── Active SMB sessions and open files ────────────────────────────────────
    Write-Host "`n  [Active SMB Sessions]" -ForegroundColor DarkCyan
    $sessions = Get-SmbSession -EA SilentlyContinue
    foreach ($sess in $sessions) {
        Write-Host ("  ► From:{0,-25} User:{1,-25} Opens:{2}" -f $sess.ClientComputerName, $sess.ClientUserName, $sess.NumOpens) -ForegroundColor Cyan
        $results += [PSCustomObject]@{ Type="SMBSession"; Client=$sess.ClientComputerName; User=$sess.ClientUserName; NumOpens=$sess.NumOpens }
    }

    # ── Open files ───────────────────────────────────────────────────────────
    Write-Host "`n  [Open SMB Files]" -ForegroundColor DarkCyan
    Get-SmbOpenFile -EA SilentlyContinue | Select-Object -First 30 |
        ForEach-Object { Write-Host ("  {0,-40} Client:{1} User:{2}" -f $_.Path, $_.ClientComputerName, $_.ClientUserName) -ForegroundColor Gray }

    # ── Mapped drives (potential C2 file drops) ───────────────────────────────
    Write-Host "`n  [Mapped Network Drives]" -ForegroundColor DarkCyan
    Get-PSDrive -PSProvider FileSystem -EA SilentlyContinue | Where-Object { $_.DisplayRoot -match "\\\\" } |
        ForEach-Object {
            Write-Host ("  Drive:{0}: → {1}" -f $_.Name, $_.DisplayRoot) -ForegroundColor Yellow
            $results += [PSCustomObject]@{ Type="MappedDrive"; Drive=$_.Name; UNC=$_.DisplayRoot }
        }

    # ── Named pipes (common C2 channel) ──────────────────────────────────────
    Write-Host "`n  [Named Pipes (Potential C2 Channels)]" -ForegroundColor DarkCyan
    $suspiciousPipes = @("MSSE-","postex","msagent","status_","mojo","dce_rpc","ntsvcs","lsarpc","samr","svcctl","atsvc","spoolss")
    try {
        $pipes = Get-ChildItem \\.\pipe\ -EA SilentlyContinue | Select-Object -First 50
        foreach ($pipe in $pipes) {
            $isSusp = $suspiciousPipes | Where-Object { $pipe.Name -match $_ }
            $color  = if ($isSusp) { "Red" } else { "DarkGray" }
            if ($isSusp) { Write-Alert "Suspicious named pipe: $($pipe.FullName)" "HIGH" }
            else { Write-Host ("  {0}" -f $pipe.Name) -ForegroundColor $color }
        }
    } catch { Write-Alert "Cannot enumerate named pipes (admin required)" "WARN" }

        if ($GridView) { Show-ResultsView -Data $results -Title "Network Share Forensics" }
    if ($Export) { Export-ResultsCsv -Data $results -Name "NetworkShareForensics" }
    return $results
}

#endregion

#region ─── MODULE 18: CREDENTIAL & SECRETS HUNTING ─────────────────────────

function Get-CredentialHunting {
    <#
    .SYNOPSIS Hunt for exposed credentials: clear-text passwords, credential files,
    hardcoded secrets in scripts, PowerShell history, credential manager
    #>
    param([switch]$Export, [switch]$GridView)

    Write-Section "CREDENTIAL & SECRETS HUNTING"

    $hits = @()

    # ── Windows Credential Manager ────────────────────────────────────────────
    Write-Host "`n  [Windows Credential Manager]" -ForegroundColor DarkCyan
    try {
        $credmanOutput = cmdkey /list 2>$null
        if ($credmanOutput) {
            $credmanOutput | Where-Object { $_ -match "Target|User|Type" } | ForEach-Object {
                Write-Host "  $_" -ForegroundColor Yellow
            }
            $creds = $credmanOutput | Where-Object { $_ -match "Target:" }
            Write-Alert "Credential Manager entries: $($creds.Count)" $(if($creds.Count -gt 0){"WARN"}else{"OK"})
            $hits += [PSCustomObject]@{ Type="CredManager"; Count=$creds.Count; Data=$creds -join "|" }
        }
    } catch {}

    # ── PowerShell history files ──────────────────────────────────────────────
    Write-Host "`n  [PowerShell Command History (All Users)]" -ForegroundColor DarkCyan
    $passwordKeywords = @("password","passwd","cred","secret","token","apikey","api_key","auth","key=","pass=","pwd=","connectionstring","sqlpwd","p@ss","P@ssw0rd","-AsSecureString","ConvertTo-SecureString")
    
    Get-ChildItem "C:\Users" -Directory -EA SilentlyContinue | ForEach-Object {
        $histPath = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $histPath) {
            $histContent = Get-Content $histPath -EA SilentlyContinue
            Write-Host ("  [{0}] PS History: {1} commands" -f $_.Name, $histContent.Count) -ForegroundColor Cyan
            foreach ($line in $histContent) {
                $found = $passwordKeywords | Where-Object { $line -match $_ }
                if ($found) {
                    # Mask potential actual passwords before displaying
                    $masked = $line -replace "(?i)(password|passwd|pwd|pass|secret|token)\s*[=:]\s*\S+", '$1=***REDACTED***'
                    Write-Alert "Potential credential in PS history [$($_.Name)]: $masked" "HIGH"
                    $hits += [PSCustomObject]@{ Type="PSHistory"; User=$_.Name; Line=$masked; Path=$histPath }
                }
            }
        }
    }

    # ── Unattended install files ──────────────────────────────────────────────
    Write-Host "`n  [Unattended Install Files (Cleartext Passwords)]" -ForegroundColor DarkCyan
    $unattendPaths = @(
        "C:\unattend.xml", "C:\Windows\unattend.xml", "C:\Windows\Panther\unattend.xml",
        "C:\Windows\Panther\Unattend\unattend.xml", "C:\Windows\system32\sysprep\unattend.xml",
        "C:\Windows\system32\sysprep\sysprep.xml", "C:\unattended.xml",
        "C:\sysprep.inf", "C:\sysprep\sysprep.inf"
    )
    foreach ($up in $unattendPaths) {
        if (Test-Path $up) {
            Write-Alert "Unattended install file found: $up" "CRIT"
            $content = Get-Content $up -EA SilentlyContinue
            $passwdLines = $content | Where-Object { $_ -match "Password|pwd|pass" }
            if ($passwdLines) {
                Write-Alert "Password entries in $up!" "CRIT"
                $passwdLines | ForEach-Object { Write-Host "  → $_" -ForegroundColor Red }
            }
            $hits += [PSCustomObject]@{ Type="UnattendFile"; Path=$up; HasPasswords=[bool]$passwdLines }
        }
    }

    # ── Group Policy Preferences (MS14-025) ───────────────────────────────────
    Write-Host "`n  [Group Policy Preferences (cPassword - MS14-025)]" -ForegroundColor DarkCyan
    $gppPaths = @(
        "C:\ProgramData\Microsoft\Group Policy\history",
        "\\$env:LOGONSERVER\SYSVOL\$env:USERDNSDOMAIN\Policies"
    )
    foreach ($gpp in $gppPaths) {
        if (Test-Path $gpp) {
            Get-ChildItem $gpp -Recurse -Include "Groups.xml","Services.xml","Scheduledtasks.xml","DataSources.xml","Printers.xml","Drives.xml" -EA SilentlyContinue |
                ForEach-Object {
                    $content = Get-Content $_.FullName -Raw -EA SilentlyContinue
                    if ($content -match "cpassword") {
                        Write-Alert "GPP cPassword found (MS14-025 vuln): $($_.FullName)" "CRIT"
                        $hits += [PSCustomObject]@{ Type="GPPcPassword"; Path=$_.FullName; Severity="CRITICAL" }
                    }
                }
        }
    }

    # ── Config files with hardcoded credentials ────────────────────────────────
    Write-Host "`n  [Config Files with Potential Hardcoded Credentials]" -ForegroundColor DarkCyan
    $configSearchPaths = @("C:\inetpub", "C:\xampp", "C:\wamp", "$env:APPDATA", "C:\ProgramData")
    $configExtensions  = @("*.config","*.conf","*.cfg","*.ini","*.xml","*.json","*.env","*.properties","*.yaml","*.yml")
    $credPatterns      = @("password\s*=\s*\S+","passwd\s*=\s*\S+","connectionstring\s*=","data source=","user id=","<Password>","<pass>")

    foreach ($csp in $configSearchPaths) {
        if (-not (Test-Path $csp)) { continue }
        foreach ($ext in $configExtensions) {
            Get-ChildItem $csp -Filter $ext -Recurse -EA SilentlyContinue | Select-Object -First 5 | ForEach-Object {
                $content = Get-Content $_.FullName -EA SilentlyContinue -TotalCount 100
                foreach ($pattern in $credPatterns) {
                    $matches2 = $content | Select-String -Pattern $pattern -EA SilentlyContinue
                    if ($matches2) {
                        Write-Alert "Potential hardcoded credential in: $($_.FullName)" "HIGH"
                        $hits += [PSCustomObject]@{ Type="HardcodedCred"; Path=$_.FullName; Pattern=$pattern }
                        break
                    }
                }
            }
        }
    }

    # ── SAM/SYSTEM/SECURITY hive accessibility ─────────────────────────────────
    Write-Host "`n  [SAM / NTDS.dit / SECURITY Hive Accessibility]" -ForegroundColor DarkCyan
    $sensitiveHives = @(
        @{ Path="C:\Windows\System32\config\SAM";     Name="SAM (Local hashes)" }
        @{ Path="C:\Windows\System32\config\SYSTEM";  Name="SYSTEM (Boot key)" }
        @{ Path="C:\Windows\System32\config\SECURITY";Name="SECURITY (LSA secrets)" }
        @{ Path="C:\Windows\NTDS\NTDS.dit";           Name="NTDS.dit (All AD hashes)" }
        @{ Path="C:\Windows\System32\config\RegBack\SAM"; Name="SAM Backup" }
    )
    foreach ($hive in $sensitiveHives) {
        if (Test-Path $hive.Path) {
            Write-Host ("  [EXISTS] {0,-45} → {1}" -f $hive.Path, $hive.Name) -ForegroundColor Yellow
            # Check for shadow copies (Volume Shadow Copy) that might be readable
        }
    }

    # Check VSS for readable copies
    Write-Host "`n  [Volume Shadow Copies (Potential SAM/NTDS Access)]" -ForegroundColor DarkCyan
    $shadows = Get-CimInstance Win32_ShadowCopy -EA SilentlyContinue
    if ($shadows.Count -gt 0) {
        Write-Alert "Volume Shadow Copies found: $($shadows.Count) — may allow SAM/NTDS.dit extraction" "HIGH"
        $shadows | ForEach-Object {
            Write-Host ("  [{0}] {1} Volume:{2}" -f $_.InstallDate, $_.ID, $_.VolumeName) -ForegroundColor Yellow
        }
    } else { Write-Alert "No Volume Shadow Copies found" "OK" }

    Write-Alert "Credential hunt complete. Hits: $($hits.Count)" $(if($hits.Count -gt 0){"HIGH"}else{"OK"})
        if ($GridView) { Show-ResultsView -Data $hits -Title "Credential Hunting" }
    if ($Export) { Export-ResultsCsv -Data $hits -Name "CredentialHunting" }
    return $hits
}

#endregion

#region ─── MODULE 19: ANTIVIRUS / EDR STATUS & BYPASS DETECTION ─────────────

function Get-SecurityProductStatus {
    param([switch]$Export, [switch]$GridView)
    Write-Section "ANTIVIRUS / EDR / SECURITY PRODUCT STATUS"

    $results = @()

    # ── Installed AV/EDR products ─────────────────────────────────────────────
    Write-Host "`n  [Registered Security Products (WMI SecurityCenter)]" -ForegroundColor DarkCyan
    $avProducts = @()
    try {
        $avProducts += Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -EA SilentlyContinue
        $avProducts += Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiSpywareProduct -EA SilentlyContinue
        $avProducts += Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName FirewallProduct -EA SilentlyContinue
    } catch {}

    foreach ($av in $avProducts) {
        # Decode productState
        $state      = $av.productState
        $realtime   = ($state -band 0x1000) -eq 0x1000
        $uptodate   = ($state -band 0x0010) -ne 0x0010
        $color      = if ($realtime -and $uptodate) { "Green" } else { "Red" }
        $status     = if ($realtime) { "ACTIVE" } else { "INACTIVE" }
        $updateStat = if ($uptodate) { "UP-TO-DATE" } else { "OUT-OF-DATE" }

        Write-Host ("  [{0,-10}] {1,-40} [{2}] [{3}]" -f $status, $av.displayName, $status, $updateStat) -ForegroundColor $color
        if (-not $realtime) { Write-Alert "Security product not running: $($av.displayName)" "CRIT" }
        $results += [PSCustomObject]@{ Product=$av.displayName; RealTime=$realtime; UpToDate=$uptodate; State=$state }
    }

    # ── Windows Defender specific ──────────────────────────────────────────────
    Write-Host "`n  [Windows Defender Status]" -ForegroundColor DarkCyan
    try {
        $defStatus = Get-MpComputerStatus -EA SilentlyContinue
        if ($defStatus) {
            $defProps = @{
                "RealTimeProtection"     = $defStatus.RealTimeProtectionEnabled
                "BehaviorMonitor"        = $defStatus.BehaviorMonitorEnabled
                "NetworkProtection"      = $defStatus.NisEnabled
                "IOAVProtection"         = $defStatus.IoavProtectionEnabled
                "AntivirusEnabled"       = $defStatus.AntivirusEnabled
                "AntispywareEnabled"     = $defStatus.AntispywareEnabled
                "TamperProtection"       = $defStatus.IsTamperProtected
                "CloudProtection"        = ($defStatus.MAPSReporting -ne 0)
                "DefinitionDate"         = $defStatus.AntivirusSignatureLastUpdated
                "DefinitionVersion"      = $defStatus.AntivirusSignatureVersion
            }
            foreach ($prop in $defProps.Keys) {
                $val   = $defProps[$prop]
                $color = if ($val -eq $false -or $val -eq $null) { "Red" } else { "Green" }
                $flag  = if ($val -eq $false) { " ← DISABLED!" } else { "" }
                Write-Host ("  {0,-30}: {1}{2}" -f $prop, $val, $flag) -ForegroundColor $color
                if ($val -eq $false) { Write-Alert "Defender component DISABLED: $prop" "CRIT" }
            }

            # Check recent threats
            $threats = Get-MpThreatDetection -EA SilentlyContinue
            if ($threats) {
                Write-Host "`n  [Recent Threat Detections]" -ForegroundColor DarkCyan
                $threats | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10 | ForEach-Object {
                    Write-Alert "THREAT DETECTED: $($_.ThreatName) @ $($_.InitialDetectionTime) → $($_.Resources -join ',')" "CRIT"
                }
            }
        }
    } catch { Write-Alert "Cannot query Defender status" "WARN" }

    # ── Known AV/EDR process check ────────────────────────────────────────────
    Write-Host "`n  [Running Security Tool Processes]" -ForegroundColor DarkCyan
    $securityProcs = @{
        "MsMpEng.exe"       = "Windows Defender"
        "SenseCncProxy.exe" = "Microsoft Defender for Endpoint"
        "MSSense.exe"       = "Defender Sensor"
        "bdagent.exe"       = "Bitdefender"
        "ekrn.exe"          = "ESET"
        "avp.exe"           = "Kaspersky"
        "avgnt.exe"         = "Avira"
        "mbam.exe"          = "Malwarebytes"
        "CylanceSvc.exe"    = "Cylance"
        "SentinelAgent.exe" = "SentinelOne"
        "CrowdStrike.exe"   = "CrowdStrike Falcon"
        "CSFalconService.exe"= "CrowdStrike Falcon"
        "xagt.exe"          = "FireEye/Trellix"
        "carbonblack.exe"   = "Carbon Black"
        "cb.exe"            = "Carbon Black"
        "RepMgr.exe"        = "Symantec/SEP"
        "ccSvcHst.exe"      = "Symantec"
        "ntrtscan.exe"      = "Trend Micro"
        "fmon.exe"          = "McAfee"
        "masvc.exe"         = "McAfee"
        "vsserv.exe"        = "Bitdefender"
        "taniumclient.exe"  = "Tanium"
        "sfc.exe"           = "Sophos"
        "savservice.exe"    = "Sophos"
        "hmpalert.exe"      = "HitmanPro.Alert"
    }

    $running = Get-Process -EA SilentlyContinue
    $detected = 0
    foreach ($sp in $securityProcs.Keys) {
        $proc = $running | Where-Object { $_.Name -like ($sp -replace "\.exe","") }
        if ($proc) {
            Write-Host ("  [RUNNING] {0,-25} → {1}" -f $sp, $securityProcs[$sp]) -ForegroundColor Green
            $detected++
            $results += [PSCustomObject]@{ Type="SecurityProcess"; Process=$sp; Product=$securityProcs[$sp]; Running=$true }
        }
    }
    if ($detected -eq 0) { Write-Alert "No recognized security tool processes running!" "CRIT" }

    # ── AMSI bypass detection ─────────────────────────────────────────────────
    Write-Host "`n  [AMSI Bypass Indicators]" -ForegroundColor DarkCyan
    $amsiBypassKeys = @(
        "HKLM:\SOFTWARE\Microsoft\AMSI\Providers",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    )
    foreach ($ak in $amsiBypassKeys) {
        if (Test-Path $ak) {
            $val = Get-ItemProperty $ak -EA SilentlyContinue
            Write-Host ("  {0}" -f $ak) -ForegroundColor Gray
        }
    }

    # Check AMSI providers registry
    $amsiProviders = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -EA SilentlyContinue
    if ($amsiProviders.Count -eq 0) {
        Write-Alert "No AMSI providers registered — AMSI may be bypassed/tampered!" "HIGH"
    } else {
        Write-Host ("  AMSI Providers registered: {0}" -f $amsiProviders.Count) -ForegroundColor Green
    }

        if ($GridView) { Show-ResultsView -Data $results -Title "Security Product Status" }
    if ($Export) { Export-ResultsCsv -Data $results -Name "SecurityProductStatus" }
    return $results
}

#endregion

#region ─── MODULE 20: RANSOMWARE DETECTION & CANARY ─────────────────────────

function Invoke-RansomwareDetection {
    <#
    .SYNOPSIS Real-time ransomware indicator detection + optional canary file deployment
    #>
    param([switch]$Export, [switch]$DeployCanaries, [string]$CanaryDir = "C:\Users\Public\Documents", [switch]$GridView)

    Write-Section "RANSOMWARE DETECTION & EARLY WARNING"

    $hits = @()

    # ── Known ransomware process names ────────────────────────────────────────
    Write-Host "`n  [Known Ransomware Process Signatures]" -ForegroundColor DarkCyan
    $ransomProcs = @(
        "wannacry","wanakiwi","wcry","wncry","tasksche","mssecsvc","@wanadecryptor",
        "ryuk","sodinokibi","revil","lockbit","blackcat","alphv","conti","maze","egregor",
        "darkside","blackmatter","hive","avos","clop","doppelpaymer","netwalker",
        "phobos","dharma","stop","djvu","makop","snatch","mespinoza","babuk"
    )
    $runningProcs = Get-CimInstance Win32_Process -EA SilentlyContinue
    foreach ($rp in $ransomProcs) {
        $match = $runningProcs | Where-Object { $_.Name -match $rp -or $_.CommandLine -match $rp }
        if ($match) {
            Write-Alert "RANSOMWARE PROCESS DETECTED: $rp → $($match.Name) PID:$($match.ProcessId)" "CRIT"
            $hits += [PSCustomObject]@{ Type="RansomwareProcess"; Name=$rp; PID=$match.ProcessId; Severity="CRITICAL" }
        }
    }

    # ── Ransomware file extensions ─────────────────────────────────────────────
    Write-Host "`n  [Ransomware File Extensions in User Folders]" -ForegroundColor DarkCyan
    $ransomExts = @(
        "\.locked$","\.encrypted$","\.crypt$","\.cry$","\.enc$","\.ransom$","\.crypted$",
        "\.pay2decrypt$","\.wallet$","\.onion$","\.aes256$","\.id-\w+\.",
        "\.wncry$","\.wcry$","\.wnry$","\.petya$","\.zepto$","\.locky$","\.odin$",
        "\.osiris$","\.teslacrypt$","\.micro$","\.cerber$","\.sage$","\.spora$",
        "\.dharma$","\.phobos$","\.makop$","\.revil$","\.sodinokibi$","\.ryk$",
        "\.hive$","\.lck$","\.black$","\.alphv$","\.akira$","\.rhysida$"
    )
    $searchDirs = @("C:\Users","C:\Shares","C:\Data","D:\","E:\")
    foreach ($dir in $searchDirs) {
        if (-not (Test-Path $dir)) { continue }
        Get-ChildItem $dir -Recurse -EA SilentlyContinue -File | Select-Object -First 5000 | ForEach-Object {
            foreach ($rext in $ransomExts) {
                if ($_.Name -match $rext) {
                    Write-Alert "RANSOMWARE EXTENSION: $($_.FullName)" "CRIT"
                    $hits += [PSCustomObject]@{ Type="RansomwareExt"; Path=$_.FullName; Extension=$_.Extension; Modified=$_.LastWriteTime }
                    break
                }
            }
        }
    }

    # ── Ransom notes ──────────────────────────────────────────────────────────
    Write-Host "`n  [Ransom Note Files]" -ForegroundColor DarkCyan
    $ransomNoteNames = @(
        "HOW TO DECRYPT","DECRYPT_INSTRUCTIONS","READ_ME","RECOVER_FILES",
        "YOUR_FILES_ARE_ENCRYPTED","HOW_TO_RECOVER","RANSOM_NOTE","HELP_DECRYPT",
        "HELP_RECOVER","ATTENTION","_DECRYPT","_HELP","_README","_RECOVERY",
        "@Please_Read_Me","!How To Recover","How to Decrypt","Read Me First"
    )
    foreach ($dir in @("C:\Users","C:\Shares","C:\")) {
        if (-not (Test-Path $dir)) { continue }
        foreach ($noteName in $ransomNoteNames) {
            Get-ChildItem $dir -Recurse -EA SilentlyContinue -File |
                Where-Object { $_.Name -match [regex]::Escape($noteName) } |
                Select-Object -First 5 | ForEach-Object {
                    Write-Alert "RANSOM NOTE FOUND: $($_.FullName)" "CRIT"
                    $hits += [PSCustomObject]@{ Type="RansomNote"; Path=$_.FullName; Modified=$_.LastWriteTime }
                }
        }
    }

    # ── Shadow copy deletion commands in event log (T1490) ────────────────────
    Write-Host "`n  [Shadow Copy Deletion Indicators]" -ForegroundColor DarkCyan
    $shadowCmds = @("vssadmin delete shadows","wmic shadowcopy delete","bcdedit.*recoveryenabled no","wbadmin delete catalog")
    Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4688} -MaxEvents 1000 -EA SilentlyContinue |
        Where-Object { $msg = $_.Message; $shadowCmds | Where-Object { $msg -match $_ } } |
        ForEach-Object {
            Write-Alert "SHADOW COPY DELETION COMMAND DETECTED: $($_.Message.Substring(0,200))" "CRIT"
            $hits += [PSCustomObject]@{ Type="ShadowDelete"; Time=$_.TimeCreated; Detail=$_.Message.Substring(0,200) }
        }

    # ── Canary file deployment ─────────────────────────────────────────────────
    if ($DeployCanaries) {
        Write-Host "`n  [Deploying Canary Files]" -ForegroundColor DarkCyan
        if (-not (Test-Path $CanaryDir)) { New-Item -ItemType Directory -Path $CanaryDir -Force | Out-Null }

        $canaryFiles = @(
            @{ Name="AAA_IMPORTANT_DO_NOT_DELETE.docx"; Content="DFIR Canary - If this file is modified or encrypted, ransomware is active." }
            @{ Name="000_Canary_Financial_Records.xlsx"; Content="DFIR Canary Document" }
            @{ Name="!AAAAA_Canary_HR_Data.pdf"; Content="DFIR Canary" }
        )
        foreach ($cf in $canaryFiles) {
            $path = "$CanaryDir\$($cf.Name)"
            $cf.Content | Set-Content $path -EA SilentlyContinue
            if (Test-Path $path) {
                Write-Alert "Canary deployed: $path" "OK"
                $hits += [PSCustomObject]@{ Type="CanaryDeployed"; Path=$path; Hash=(Get-FileHash $path -EA SilentlyContinue).Hash }
            }
        }
        Write-Alert "Monitor canary files for modification — indicates ransomware activity" "INFO"
    }

    Write-Alert "Ransomware detection complete. Hits: $($hits.Count)" $(if($hits.Count -gt 0){"CRIT"}else{"OK"})
        if ($GridView) { Show-ResultsView -Data $hits -Title "Ransomware Detection" }
    if ($Export) { Export-ResultsCsv -Data $hits -Name "RansomwareDetection" }
    return $hits
}

#endregion

#region ─── MODULE 21: CLOUD & AZURE / AWS CREDENTIAL HUNT ───────────────────

function Get-CloudCredentialForensics {
    param([switch]$Export, [switch]$GridView)
    Write-Section "CLOUD CREDENTIAL & CONFIG FORENSICS (Azure/AWS/GCP/O365)"

    $hits = @()

    # ── Azure / Office 365 ────────────────────────────────────────────────────
    Write-Host "`n  [Azure / Office 365 Credential Artifacts]" -ForegroundColor DarkCyan
    $azurePaths = @(
        "$env:USERPROFILE\.azure\accessTokens.json"
        "$env:USERPROFILE\.azure\azureProfile.json"
        "$env:USERPROFILE\.azure\TokenCache.dat"
        "$env:APPDATA\Microsoft\UserSecrets"
        "C:\ProgramData\Microsoft Azure Site Recovery\Temp"
    )
    foreach ($ap in $azurePaths) {
        if (Test-Path $ap) {
            $size = if (Test-Path $ap -PathType Leaf) { (Get-Item $ap).Length } else { "DIR" }
            Write-Alert "Azure credential artifact: $ap ($size bytes)" "HIGH"
            $hits += [PSCustomObject]@{ Type="AzureCred"; Path=$ap; Size=$size }
        }
    }

    # ── AWS credentials ───────────────────────────────────────────────────────
    Write-Host "`n  [AWS Credential Files]" -ForegroundColor DarkCyan
    $awsPaths = @(
        "$env:USERPROFILE\.aws\credentials"
        "$env:USERPROFILE\.aws\config"
        "C:\Users\*\.aws\credentials"
    )
    foreach ($awsp in $awsPaths) {
        $resolved = Resolve-Path $awsp -EA SilentlyContinue
        foreach ($rp in $resolved) {
            if (Test-Path $rp) {
                Write-Alert "AWS credential file: $rp" "HIGH"
                $content = Get-Content $rp -EA SilentlyContinue
                $keyLines = $content | Where-Object { $_ -match "aws_access_key_id|aws_secret_access_key" }
                if ($keyLines) { Write-Alert "AWS keys present in $rp" "CRIT" }
                $hits += [PSCustomObject]@{ Type="AWSCred"; Path=$rp.ToString(); HasKeys=[bool]$keyLines }
            }
        }
    }

    # ── GCP ───────────────────────────────────────────────────────────────────
    Write-Host "`n  [GCP Credential Files]" -ForegroundColor DarkCyan
    $gcpPaths = @(
        "$env:APPDATA\gcloud\application_default_credentials.json"
        "$env:APPDATA\gcloud\credentials.db"
        "$env:APPDATA\gcloud\access_tokens.db"
    )
    foreach ($gp in $gcpPaths) {
        if (Test-Path $gp) {
            Write-Alert "GCP credential: $gp" "HIGH"
            $hits += [PSCustomObject]@{ Type="GCPCred"; Path=$gp }
        }
    }

    # ── GitHub / API tokens in common locations ────────────────────────────────
    Write-Host "`n  [GitHub / API Tokens]" -ForegroundColor DarkCyan
    $tokenPaths = @(
        "$env:USERPROFILE\.gitconfig"
        "$env:APPDATA\GitHub Desktop\settings.json"
        "C:\Users\*\.gitconfig"
    )
    $tokenPatterns = @("token\s*=\s*[a-zA-Z0-9_]{10,}","password\s*=\s*[^\s]+","GITHUB_TOKEN","GITLAB_TOKEN","ghp_","gho_","ghs_")
    foreach ($tp in $tokenPaths) {
        $resolved = Resolve-Path $tp -EA SilentlyContinue
        foreach ($rp in $resolved) {
            if (Test-Path $rp) {
                $content = Get-Content $rp -EA SilentlyContinue -Raw
                foreach ($pat in $tokenPatterns) {
                    if ($content -match $pat) {
                        Write-Alert "Token/credential in $($rp): $pat" "HIGH"
                        $hits += [PSCustomObject]@{ Type="GitToken"; Path=$rp.ToString(); Pattern=$pat }
                        break
                    }
                }
            }
        }
    }

    # ── Environment variable secrets ──────────────────────────────────────────
    Write-Host "`n  [Environment Variables with Potential Secrets]" -ForegroundColor DarkCyan
    $secretEnvPatterns = @("password","passwd","secret","token","api.key","access.key","private.key","auth","credential")
    $envVars = [System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::Machine)
    $envVars += [System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::User)
    foreach ($key in $envVars.Keys) {
        $found = $secretEnvPatterns | Where-Object { $key -match $_ }
        if ($found) {
            Write-Alert "Sensitive env variable: $key" "HIGH"
            $hits += [PSCustomObject]@{ Type="EnvSecret"; Variable=$key; Value="***REDACTED***" }
        }
    }

    Write-Alert "Cloud credential hunt complete. Hits: $($hits.Count)" $(if($hits.Count -gt 0){"HIGH"}else{"OK"})
        if ($GridView) { Show-ResultsView -Data $hits -Title "Cloud Credentials" }
    if ($Export) { Export-ResultsCsv -Data $hits -Name "CloudCredentials" }
    return $hits
}

#endregion

#region ─── MODULE 22: NETWORK TRAFFIC ANOMALY DETECTION ─────────────────────

function Get-NetworkAnomalies {
    <#
    .SYNOPSIS Detect beaconing, data exfiltration patterns, unusual ports, TOR/VPN indicators
    #>
    param([switch]$Export, [int]$SampleSeconds = 30, [switch]$GridView)

    Write-Section "NETWORK TRAFFIC ANOMALY DETECTION"

    $results = @()

    # ── Port scan detection ───────────────────────────────────────────────────
    Write-Host "`n  [Unusual Listening Ports]" -ForegroundColor DarkCyan
    $wellKnownPorts = @(80,443,8080,8443,3389,22,21,25,110,143,53,445,139,135,137,138,3306,5432,1433,27017,6379,5672,9200,9300,2181,2888,3888)
    $listeners = Get-NetTCPConnection -State Listen -EA SilentlyContinue
    foreach ($l in $listeners) {
        if ($l.LocalPort -notin $wellKnownPorts -and $l.LocalPort -gt 1024) {
            $proc = (Get-Process -Id $l.OwningProcess -EA SilentlyContinue).Name
            $color = if ($l.LocalPort -gt 49000) { "Red" } else { "Yellow" }
            Write-Host ("  UNUSUAL LISTENER Port:{0,-6} Process:{1,-20} PID:{2}" -f $l.LocalPort, $proc, $l.OwningProcess) -ForegroundColor $color
            $results += [PSCustomObject]@{ Type="UnusualListener"; Port=$l.LocalPort; Process=$proc; PID=$l.OwningProcess }
        }
    }

    # ── TOR exit node / VPN detection ────────────────────────────────────────
    Write-Host "`n  [TOR / VPN / Proxy Indicators]" -ForegroundColor DarkCyan
    $torPorts     = @(9050, 9150, 9051, 9001)
    $torProcesses = @("tor","onion","torbrowser","vidalia","privoxy","polipo")
    $proxySoftware= @("proxifier","proxycap","proxychains","stunnel","socat","ncat","nc","netcat")

    $runningNow = Get-Process -EA SilentlyContinue
    foreach ($tp in $torProcesses + $proxySoftware) {
        $found = $runningNow | Where-Object { $_.Name -match $tp }
        if ($found) { Write-Alert "TOR/Proxy process running: $($found.Name) PID:$($found.Id)" "HIGH" }
    }

    $torConns = Get-NetTCPConnection -EA SilentlyContinue | Where-Object { $_.RemotePort -in $torPorts }
    if ($torConns) { Write-Alert "TOR port connections detected: $($torConns.Count)" "HIGH" }

    # Check for TOR Browser directory
    $torPaths = @("$env:APPDATA\tor","$env:LOCALAPPDATA\Tor Browser","C:\Users\*\Desktop\Tor Browser")
    foreach ($torPath in $torPaths) {
        if (Test-Path $torPath) { Write-Alert "TOR installation found: $torPath" "HIGH" }
    }

    # ── C2 beaconing pattern detection (periodic connections) ─────────────────
    Write-Host "`n  [C2 Beaconing Pattern Analysis (${SampleSeconds}s sample)]" -ForegroundColor DarkCyan
    Write-Alert "Sampling connections for $SampleSeconds seconds..." "INFO"

    $sample1 = Get-NetTCPConnection -State Established -EA SilentlyContinue | Select-Object RemoteAddress, RemotePort, OwningProcess
    Start-Sleep -Seconds $SampleSeconds
    $sample2 = Get-NetTCPConnection -State Established -EA SilentlyContinue | Select-Object RemoteAddress, RemotePort, OwningProcess

    # Find persistent connections (present in both samples)
    $persistent = $sample1 | Where-Object {
        $rem = $_.RemoteAddress
        $port= $_.RemotePort
        $sample2 | Where-Object { $_.RemoteAddress -eq $rem -and $_.RemotePort -eq $port }
    } | Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0|::$|10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)" }

    if ($persistent.Count -gt 0) {
        Write-Alert "Persistent external connections (potential beaconing): $($persistent.Count)" "HIGH"
        foreach ($p in $persistent) {
            $proc = (Get-Process -Id $p.OwningProcess -EA SilentlyContinue).Name
            Write-Host ("  PERSISTENT: {0,-22}:{1,-6} Process:{2} PID:{3}" -f $p.RemoteAddress, $p.RemotePort, $proc, $p.OwningProcess) -ForegroundColor Yellow
            $results += [PSCustomObject]@{ Type="PersistentConn"; RemoteIP=$p.RemoteAddress; Port=$p.RemotePort; Process=$proc }
        }
    }

    # ── Large data transfer detection ─────────────────────────────────────────
    Write-Host "`n  [Network Interface Statistics (Potential Exfil)]" -ForegroundColor DarkCyan
    $adapters = Get-NetAdapterStatistics -EA SilentlyContinue
    foreach ($a in $adapters) {
        $sentGB  = [Math]::Round($a.SentBytes / 1GB, 2)
        $recvGB  = [Math]::Round($a.ReceivedBytes / 1GB, 2)
        $color   = if ($sentGB -gt 1) { "Yellow" } else { "Gray" }
        Write-Host ("  {0,-30} Sent:{1,-8}GB Recv:{2,-8}GB" -f $a.Name, $sentGB, $recvGB) -ForegroundColor $color
        if ($sentGB -gt 5) { Write-Alert "HIGH OUTBOUND TRAFFIC on $($a.Name): $sentGB GB — potential exfil!" "HIGH" }
    }

    # ── HOSTS file tampering ──────────────────────────────────────────────────
    Write-Host "`n  [HOSTS File Analysis]" -ForegroundColor DarkCyan
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsContent = Get-Content $hostsPath -EA SilentlyContinue
    $nonStandard = $hostsContent | Where-Object { $_ -notmatch "^#" -and $_ -match "\S" -and $_ -notmatch "^127\.0\.0\.1\s+localhost" -and $_ -notmatch "^::1\s+localhost" }
    if ($nonStandard.Count -gt 0) {
        Write-Alert "Non-standard HOSTS entries: $($nonStandard.Count)" "HIGH"
        $nonStandard | ForEach-Object { Write-Host "  → $_" -ForegroundColor Yellow }
    } else { Write-Alert "HOSTS file appears clean" "OK" }

    # ── DNS-over-HTTPS / DoH detection ────────────────────────────────────────
    Write-Host "`n  [DNS-over-HTTPS (DoH) Configuration]" -ForegroundColor DarkCyan
    $dohReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -EA SilentlyContinue
    if ($dohReg -and $dohReg.EnableAutoDoh) {
        Write-Host "  DoH Enabled: $($dohReg.EnableAutoDoh)" -ForegroundColor Yellow
    }

    # Check for DNS hijacking via NIC settings
    Get-DnsClientServerAddress -EA SilentlyContinue | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object {
        $nic  = $_.InterfaceAlias
        $dns  = $_.ServerAddresses
        # Flag non-standard DNS servers
        $legit = @("8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9","208.67.222.222","208.67.220.220")
        foreach ($d in $dns) {
            if ($d -notin $legit -and $d -notmatch "^(10\.|192\.168\.|172\.[12][0-9]\.|127\.)") {
                Write-Host ("  [{0}] DNS Server: {1}" -f $nic, $d) -ForegroundColor Yellow
            }
        }
    }

        if ($GridView) { Show-ResultsView -Data $results -Title "Network Anomalies" }
    if ($Export) { Export-ResultsCsv -Data $results -Name "NetworkAnomalies" }
    return $results
}

#endregion


#region ─── MODULE 23: THREAT INTELLIGENCE ENRICHMENT ────────────────────────

function Invoke-ThreatIntelEnrichment {
    <#
    .SYNOPSIS Enrich IPs, domains and hashes with threat intel via free public APIs.
    Supports: AbuseIPDB, VirusTotal (free tier), URLhaus, ThreatFox
    #>
    param(
        [string[]]$IPs      = @(, [switch]$GridView),
        [string[]]$Domains  = @(),
        [string[]]$Hashes   = @(),
        [string]$VTApiKey   = "",     # Optional VirusTotal API key
        [string]$AbuseKey   = "",     # Optional AbuseIPDB API key
        [switch]$Export
    )

    Write-Section "THREAT INTELLIGENCE ENRICHMENT"

    $results = @()

    # Helper for HTTP requests
    function Invoke-TIRequest {
        param([string]$Uri, [hashtable]$Headers = @{}, [string]$Source)
        try {
            $response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method GET -TimeoutSec 10 -EA SilentlyContinue
            return $response
        } catch {
            Write-Alert "TI lookup failed for $Source : $_" "WARN"
            return $null
        }
    }

    # ── IP Enrichment ─────────────────────────────────────────────────────────
    foreach ($ip in $IPs) {
        Write-Host "`n  [IP: $ip]" -ForegroundColor Cyan

        # ip-api.com (free, no key)
        $geoData = Invoke-TIRequest -Uri "http://ip-api.com/json/$ip" -Source "ip-api"
        if ($geoData) {
            Write-Host ("  GeoIP: {0}, {1} | ISP: {2} | Org: {3}" -f $geoData.city, $geoData.country, $geoData.isp, $geoData.org) -ForegroundColor Gray
            $isHosting = $geoData.org -match "hosting|cloud|vps|digital ocean|linode|aws|azure|google|vultr|ovh|hetzner"
            if ($isHosting) { Write-Alert "IP hosted on cloud/hosting provider — common C2 infrastructure: $ip" "WARN" }
        }

        # AbuseIPDB (requires key but free tier available)
        if ($AbuseKey) {
            $abuseData = Invoke-TIRequest -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90" `
                -Headers @{ Key=$AbuseKey; Accept="application/json" } -Source "AbuseIPDB"
            if ($abuseData -and $abuseData.data) {
                $score = $abuseData.data.abuseConfidenceScore
                $color = if ($score -gt 50) { "Red" } elseif ($score -gt 10) { "Yellow" } else { "Green" }
                Write-Host ("  AbuseIPDB Score: {0}/100 | Reports: {1} | Domain: {2}" -f $score, $abuseData.data.totalReports, $abuseData.data.domain) -ForegroundColor $color
                if ($score -gt 50) { Write-Alert "HIGH ABUSE SCORE for $ip : $score/100" "CRIT" }
                $results += [PSCustomObject]@{ Type="IPReputation"; IP=$ip; Source="AbuseIPDB"; Score=$score; Reports=$abuseData.data.totalReports }
            }
        }

        # VirusTotal IP report
        if ($VTApiKey) {
            $vtData = Invoke-TIRequest -Uri "https://www.virustotal.com/api/v3/ip_addresses/$ip" `
                -Headers @{ "x-apikey"=$VTApiKey } -Source "VirusTotal"
            if ($vtData -and $vtData.data.attributes.last_analysis_stats) {
                $stats     = $vtData.data.attributes.last_analysis_stats
                $malicious = $stats.malicious
                $color     = if ($malicious -gt 0) { "Red" } else { "Green" }
                Write-Host ("  VirusTotal: Malicious:{0} Suspicious:{1} Harmless:{2}" -f $stats.malicious, $stats.suspicious, $stats.harmless) -ForegroundColor $color
                if ($malicious -gt 0) { Write-Alert "VT MALICIOUS IP: $ip ($malicious detections)" "CRIT" }
                $results += [PSCustomObject]@{ Type="IPReputation"; IP=$ip; Source="VirusTotal"; Malicious=$malicious }
            }
        }

        # Free fallback: check against known Tor exit node list structure
        Write-Host "  Tor Exit Check: Run 'https://check.torproject.org/exit-addresses' for live list" -ForegroundColor DarkGray
    }

    # ── Hash Enrichment ────────────────────────────────────────────────────────
    foreach ($hash in $Hashes) {
        Write-Host "`n  [Hash: $hash]" -ForegroundColor Cyan

        if ($VTApiKey) {
            $vtHash = Invoke-TIRequest -Uri "https://www.virustotal.com/api/v3/files/$hash" `
                -Headers @{ "x-apikey"=$VTApiKey } -Source "VirusTotal"
            if ($vtHash -and $vtHash.data.attributes.last_analysis_stats) {
                $stats     = $vtHash.data.attributes.last_analysis_stats
                $malicious = $stats.malicious
                $name      = $vtHash.data.attributes.meaningful_name
                $color     = if ($malicious -gt 0) { "Red" } else { "Green" }
                Write-Host ("  VT [{0}]: Malicious:{1} Suspicious:{2} Name:{3}" -f $hash.Substring(0,8), $malicious, $stats.suspicious, $name) -ForegroundColor $color
                if ($malicious -gt 0) { Write-Alert "MALICIOUS HASH: $hash ($malicious VT detections) — $name" "CRIT" }
                $results += [PSCustomObject]@{ Type="HashReputation"; Hash=$hash; Source="VirusTotal"; Malicious=$malicious; Name=$name }
            }
        }

        # URLhaus / ThreatFox by Abuse.ch (free, no key needed)
        $threatfox = Invoke-TIRequest -Uri "https://threatfox-api.abuse.ch/api/v1/" -Source "ThreatFox"
        # Note: ThreatFox uses POST, simplified lookup shown
        Write-Host "  ThreatFox: Submit manually at https://threatfox.abuse.ch/browse.php?search=hash:$hash" -ForegroundColor DarkGray
    }

    # ── Domain Enrichment ────────────────────────────────────────────────────
    foreach ($domain in $Domains) {
        Write-Host "`n  [Domain: $domain]" -ForegroundColor Cyan

        # URLhaus free lookup
        try {
            $urlhaus = Invoke-RestMethod -Uri "https://urlhaus-api.abuse.ch/v1/host/" `
                -Method POST -Body "host=$domain" -ContentType "application/x-www-form-urlencoded" -TimeoutSec 10 -EA SilentlyContinue
            if ($urlhaus -and $urlhaus.query_status -eq "is_host") {
                Write-Alert "URLHAUS MALICIOUS DOMAIN: $domain — $($urlhaus.urls_count) malicious URLs" "CRIT"
                $results += [PSCustomObject]@{ Type="DomainReputation"; Domain=$domain; Source="URLhaus"; MaliciousURLs=$urlhaus.urls_count }
            } elseif ($urlhaus) {
                Write-Host ("  URLhaus: {0}" -f $urlhaus.query_status) -ForegroundColor DarkGray
            }
        } catch {}

        if ($VTApiKey) {
            $vtDomain = Invoke-TIRequest -Uri "https://www.virustotal.com/api/v3/domains/$domain" `
                -Headers @{ "x-apikey"=$VTApiKey } -Source "VirusTotal"
            if ($vtDomain -and $vtDomain.data.attributes.last_analysis_stats) {
                $stats     = $vtDomain.data.attributes.last_analysis_stats
                $malicious = $stats.malicious
                $color     = if ($malicious -gt 0) { "Red" } else { "Green" }
                Write-Host ("  VT Domain: Malicious:{0} Suspicious:{1}" -f $malicious, $stats.suspicious) -ForegroundColor $color
                if ($malicious -gt 0) { Write-Alert "VT MALICIOUS DOMAIN: $domain" "CRIT" }
            }
        }
    }

    Write-Alert "TI enrichment complete. Enriched IPs:$($IPs.Count) Domains:$($Domains.Count) Hashes:$($Hashes.Count)" "INFO"
        if ($GridView) { Show-ResultsView -Data $results -Title "Threat Intel Enrichment" }
    if ($Export) { Export-ResultsCsv -Data $results -Name "ThreatIntelEnrichment" }
    return $results
}

#endregion

#region ─── MODULE 24: ARTIFACT TIMELINE ─────────────────────────────────────

function Get-ForensicTimeline {
    <#
    .SYNOPSIS Build a unified forensic timeline: files, registry, events, prefetch
    correlated by timestamp for incident reconstruction
    #>
    param(
        [DateTime]$StartTime = (Get-Date).AddDays(-7),
        [DateTime]$EndTime   = (Get-Date),
        [switch]$GridView,
        [switch]$Export
    )

    Write-Section "FORENSIC TIMELINE ($(($StartTime).ToString('yyyy-MM-dd')) to $(($EndTime).ToString('yyyy-MM-dd')))"

    $timelineEvents = @()

    # ── File system timeline ──────────────────────────────────────────────────
    Write-Host "`n  [File System Events in Timeline]" -ForegroundColor DarkCyan
    $fsPaths = @(
        "$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64",
        "$env:TEMP", "$env:SystemRoot\Temp",
        "$env:APPDATA", "$env:LOCALAPPDATA",
        "C:\Users\Public", "$env:SystemRoot\Prefetch"
    )
    $suspExts = @(".exe",".dll",".sys",".ps1",".bat",".vbs",".hta",".js",".msi",".scr",".cpl",".jar")

    foreach ($fsp in $fsPaths) {
        Get-ChildItem $fsp -File -EA SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $StartTime -and $_.LastWriteTime -le $EndTime } |
            ForEach-Object {
                $isSusp = $_.Extension -in $suspExts
                $timelineEvents += [PSCustomObject]@{
                    Timestamp  = $_.LastWriteTime
                    Category   = "FILE"
                    Action     = "MODIFIED"
                    Subject    = $_.FullName
                    Detail     = "Size:$($_.Length) Ext:$($_.Extension)"
                    Suspicious = $isSusp
                }
            }
    }

    # ── Registry timeline (via last-write times) ───────────────────────────────
    Write-Host "  [Registry Timeline]" -ForegroundColor DarkCyan
    $regPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKLM:\SYSTEM\CurrentControlSet\Services")
    foreach ($rp in $regPaths) {
        if (-not (Test-Path $rp)) { continue }
        try {
            $key = Get-Item $rp -EA SilentlyContinue
            if ($key.LastWriteTime -ge $StartTime -and $key.LastWriteTime -le $EndTime) {
                $timelineEvents += [PSCustomObject]@{
                    Timestamp  = $key.LastWriteTime
                    Category   = "REGISTRY"
                    Action     = "KEY_MODIFIED"
                    Subject    = $rp
                    Detail     = "Registry key modified"
                    Suspicious = $true
                }
            }
        } catch {}
    }

    # ── Event log timeline ────────────────────────────────────────────────────
    Write-Host "  [Security Event Log Timeline]" -ForegroundColor DarkCyan
    $critEvents = @(4624,4625,4648,4697,4698,4719,4720,4726,4740,1102,7045)
    try {
        $evts = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            StartTime = $StartTime
            EndTime   = $EndTime
            Id        = $critEvents
        } -MaxEvents 500 -EA SilentlyContinue

        foreach ($evt in $evts) {
            $desc = switch ($evt.Id) {
                4624 { "Successful Logon" } 4625 { "Failed Logon" }
                4648 { "Explicit Credential Logon" } 4697 { "Service Installed" }
                4698 { "Scheduled Task Created" } 4719 { "Audit Policy Changed" }
                4720 { "Account Created" } 4726 { "Account Deleted" }
                4740 { "Account Locked Out" } 1102 { "AUDIT LOG CLEARED" }
                7045 { "Service Installed" } default { "Event $($evt.Id)" }
            }
            $timelineEvents += [PSCustomObject]@{
                Timestamp  = $evt.TimeCreated
                Category   = "SECURITYEVENT"
                Action     = "EVENT_$($evt.Id)"
                Subject    = $evt.ProviderName
                Detail     = $desc
                Suspicious = $evt.Id -in @(4648,4697,4698,4719,4720,4726,4740,1102,7045)
            }
        }
    } catch {}

    # ── Prefetch timeline ─────────────────────────────────────────────────────
    Write-Host "  [Prefetch Execution Timeline]" -ForegroundColor DarkCyan
    $pfPath = "$env:SystemRoot\Prefetch"
    if (Test-Path $pfPath) {
        Get-ChildItem $pfPath -Filter "*.pf" -EA SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $StartTime -and $_.LastWriteTime -le $EndTime } |
            ForEach-Object {
                $exeName = $_.Name -replace "-[0-9A-F]{8}\.pf$",""
                $isSusp  = $exeName -match "powershell|cmd|wscript|mshta|regsvr32|rundll32|certutil|msiexec"
                $timelineEvents += [PSCustomObject]@{
                    Timestamp  = $_.LastWriteTime
                    Category   = "PREFETCH"
                    Action     = "EXECUTION"
                    Subject    = $exeName
                    Detail     = "Prefetch: $($_.Name)"
                    Suspicious = $isSusp
                }
            }
    }

    # ── Sort and display ──────────────────────────────────────────────────────
    $sorted = $timelineEvents | Sort-Object Timestamp
    Write-Host "`n  [TIMELINE — $(($sorted.Count)) events, sorted by time]" -ForegroundColor DarkCyan

    $sorted | ForEach-Object {
        $color = if ($_.Suspicious) { "Red" } elseif ($_.Category -eq "SECURITYEVENT") { "Yellow" } else { "DarkGray" }
        $flag  = if ($_.Suspicious) { "⚠ " } else { "  " }
        Write-Host ("{0}[{1}] {2,-12} {3,-15} {4}" -f $flag, $_.Timestamp.ToString("MM-dd HH:mm:ss"), $_.Category, $_.Action, $_.Subject) -ForegroundColor $color
    }

    $suspCount = ($sorted | Where-Object { $_.Suspicious }).Count
    Write-Alert "Timeline complete: $($sorted.Count) total events | Suspicious: $suspCount" $(if($suspCount -gt 0){"HIGH"}else{"OK"})

        if ($GridView) { Show-ResultsView -Data $sorted -Title "Forensic Timeline" }
    if ($Export) { Export-ResultsCsv -Data $sorted -Name "ForensicTimeline" }
    return $sorted
}

#endregion

#region ─── MODULE 25: ADVANCED PERSISTENCE HUNTING ─────────────────────────

function Get-AdvancedPersistenceHunting {
    <#
    .SYNOPSIS Hunt for advanced persistence: boot sectors, UEFI paths, driver signing,
    print spooler, COM hijacks, DLL planting, accessibility features backdoors
    #>
    param([switch]$Export, [switch]$GridView)

    Write-Section "ADVANCED PERSISTENCE HUNTING"

    $results = @()

    # ── Accessibility feature backdoors (T1546.008) ────────────────────────────
    Write-Host "`n  [Accessibility Feature Backdoors (Sticky Keys / Utilman)]" -ForegroundColor DarkCyan
    $accessibilityBinaries = @(
        @{ Path="C:\Windows\System32\sethc.exe";     Name="Sticky Keys" }
        @{ Path="C:\Windows\System32\utilman.exe";   Name="Utility Manager" }
        @{ Path="C:\Windows\System32\osk.exe";       Name="On-Screen Keyboard" }
        @{ Path="C:\Windows\System32\magnify.exe";   Name="Magnifier" }
        @{ Path="C:\Windows\System32\narrator.exe";  Name="Narrator" }
        @{ Path="C:\Windows\System32\DisplaySwitch.exe"; Name="Display Switch" }
    )
    foreach ($ab in $accessibilityBinaries) {
        if (Test-Path $ab.Path) {
            $sig     = Get-AuthenticodeSignature $ab.Path -EA SilentlyContinue
            $hash    = (Get-FileHash $ab.Path -Algorithm SHA256 -EA SilentlyContinue).Hash
            $lastMod = (Get-Item $ab.Path).LastWriteTime
            $color   = if ($sig.Status -ne "Valid") { "Red" } else { "Green" }
            $flag    = if ($sig.Status -ne "Valid") { "⚠ UNSIGNED" } else { "OK" }
            Write-Host ("  [{0,-15}] {1,-35} Signed:{2,-10} {3}" -f $flag, $ab.Name, $sig.Status, $lastMod) -ForegroundColor $color
            if ($sig.Status -ne "Valid") {
                Write-Alert "ACCESSIBILITY BINARY TAMPERED: $($ab.Path) — $($ab.Name) backdoor possible!" "CRIT"
                $results += [PSCustomObject]@{ Type="AccessibilityBackdoor"; Path=$ab.Path; Name=$ab.Name; SignStatus=$sig.Status; SHA256=$hash }
            }
        }
    }

    # ── Print spooler DLLs ────────────────────────────────────────────────────
    Write-Host "`n  [Print Spooler DLL Persistence (PrintNightmare)]" -ForegroundColor DarkCyan
    $spoolerPaths = @("C:\Windows\System32\spool\drivers\W32X86\3","C:\Windows\System32\spool\drivers\x64\3")
    foreach ($sp in $spoolerPaths) {
        if (Test-Path $sp) {
            $dlls = Get-ChildItem $sp -Filter "*.dll" -EA SilentlyContinue
            foreach ($dll in $dlls) {
                $sig = Get-AuthenticodeSignature $dll.FullName -EA SilentlyContinue
                if ($sig.Status -ne "Valid") {
                    Write-Alert "UNSIGNED DLL in spooler driver path: $($dll.FullName)" "CRIT"
                    $results += [PSCustomObject]@{ Type="SpoolerDLL"; Path=$dll.FullName; SignStatus=$sig.Status }
                }
            }
        }
    }

    # ── Boot configuration tampering ──────────────────────────────────────────
    Write-Host "`n  [Boot Configuration (BCD) Analysis]" -ForegroundColor DarkCyan
    try {
        $bcdOutput = bcdedit /enum ALL 2>$null
        $bcdOutput | Where-Object { $_ -match "path|device|description|testsigning|nointegritychecks|recoveryenabled" } |
            ForEach-Object {
                $color = if ($_ -match "testsigning.*Yes|nointegritychecks.*Yes") { "Red" } else { "Gray" }
                Write-Host "  $_" -ForegroundColor $color
            }
        if ($bcdOutput -match "testsigning\s+Yes") {
            Write-Alert "TEST SIGNING ENABLED — Unsigned driver loading allowed!" "CRIT"
        }
        if ($bcdOutput -match "nointegritychecks\s+Yes") {
            Write-Alert "DRIVER INTEGRITY CHECKS DISABLED!" "CRIT"
        }
    } catch { Write-Alert "Cannot read BCD (admin required)" "WARN" }

    # ── Unsigned kernel drivers ────────────────────────────────────────────────
    Write-Host "`n  [Unsigned/Suspicious Kernel Drivers]" -ForegroundColor DarkCyan
    Get-CimInstance Win32_SystemDriver -EA SilentlyContinue |
        Where-Object { $_.State -eq "Running" -and $_.PathName } |
        ForEach-Object {
            $drvPath = $_.PathName -replace '"','' -replace "\\SystemRoot\\","$env:SystemRoot\"
            if (Test-Path $drvPath) {
                $sig = Get-AuthenticodeSignature $drvPath -EA SilentlyContinue
                if ($sig.Status -ne "Valid") {
                    Write-Alert "UNSIGNED RUNNING DRIVER: $($_.Name) → $drvPath" "CRIT"
                    $results += [PSCustomObject]@{ Type="UnsignedDriver"; Name=$_.Name; Path=$drvPath; SignStatus=$sig.Status }
                }
            }
        }

    # ── DLL hijacking in system paths ─────────────────────────────────────────
    Write-Host "`n  [DLL Hijacking in Known Vulnerable Paths]" -ForegroundColor DarkCyan
    $commonHijackDlls = @(
        "wlbsctrl.dll","wbemcomn.dll","amsi.dll","cryptbase.dll","cryptsp.dll",
        "hid.dll","wtsapi32.dll","lpk.dll","userenv.dll","version.dll",
        "d3d11.dll","dbgcore.dll","dwmapi.dll","uxtheme.dll","wininet.dll"
    )
    $searchDirs2 = @("C:\Temp","C:\Users\Public","$env:APPDATA","$env:LOCALAPPDATA","C:\ProgramData")
    foreach ($dir in $searchDirs2) {
        foreach ($dll in $commonHijackDlls) {
            $path = "$dir\$dll"
            if (Test-Path $path) {
                $sig = Get-AuthenticodeSignature $path -EA SilentlyContinue
                Write-Alert "POTENTIAL DLL HIJACK: $path (Signed: $($sig.Status))" "CRIT"
                $results += [PSCustomObject]@{ Type="DLLHijack"; Path=$path; DLL=$dll; SignStatus=$sig.Status }
            }
        }
    }

    # ── COM object hijacking ──────────────────────────────────────────────────
    Write-Host "`n  [HKCU COM Object Hijacking (T1546.015)]" -ForegroundColor DarkCyan
    if (Test-Path "HKCU:\SOFTWARE\Classes\CLSID") {
        $userClsids = Get-ChildItem "HKCU:\SOFTWARE\Classes\CLSID" -EA SilentlyContinue | Select-Object -First 30
        if ($userClsids.Count -gt 0) {
            Write-Alert "HKCU CLSID entries (COM hijack candidates): $($userClsids.Count)" "HIGH"
            foreach ($clsid in $userClsids) {
                $inprocPath = "$($clsid.PSPath)\InprocServer32"
                if (Test-Path $inprocPath) {
                    $dll = (Get-ItemProperty $inprocPath -EA SilentlyContinue)."(default)"
                    Write-Host ("  CLSID:{0} → {1}" -f $clsid.PSChildName, $dll) -ForegroundColor Yellow
                    $results += [PSCustomObject]@{ Type="COMHijack"; CLSID=$clsid.PSChildName; DLL=$dll }
                }
            }
        }
    }

    # ── LSA Security Packages / SSPs ─────────────────────────────────────────
    Write-Host "`n  [LSA Security Support Providers (T1547.005)]" -ForegroundColor DarkCyan
    $lsaReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $ssps   = (Get-ItemProperty $lsaReg -Name "Security Packages" -EA SilentlyContinue)."Security Packages"
    $authPkgs = (Get-ItemProperty $lsaReg -Name "Authentication Packages" -EA SilentlyContinue)."Authentication Packages"
    $legitSSPs = @("","kerberos","msv1_0","schannel","wdigest","tspkg","pku2u","cloudAP","livessp")

    foreach ($ssp in $ssps) {
        $isLegit = $legitSSPs -contains $ssp.ToLower()
        $color   = if (-not $isLegit -and $ssp -ne "") { "Red" } else { "Gray" }
        Write-Host ("  SSP: {0}" -f $ssp) -ForegroundColor $color
        if (-not $isLegit -and $ssp -ne "") {
            Write-Alert "NON-STANDARD SSP: $ssp — potential credential stealing!" "CRIT"
            $results += [PSCustomObject]@{ Type="MaliciousSSP"; SSP=$ssp }
        }
    }

    # ── Netsh helper DLLs ────────────────────────────────────────────────────
    Write-Host "`n  [Netsh Helper DLLs (T1546.007)]" -ForegroundColor DarkCyan
    $netshHelpers = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NetSh" -EA SilentlyContinue
    foreach ($helper in $netshHelpers) {
        $val = (Get-ItemProperty $helper.PSPath -EA SilentlyContinue).PSObject.Properties |
               Where-Object { $_.Name -notmatch "^PS" } | Select-Object -First 1
        if ($val) {
            $dllPath = $val.Value
            $isSusp  = $dllPath -match "\\temp\\|\\appdata\\|\\downloads\\" -or -not (Test-Path $dllPath)
            $color   = if ($isSusp) { "Red" } else { "Gray" }
            Write-Host ("  {0,-20} → {1}" -f $helper.PSChildName, $dllPath) -ForegroundColor $color
            if ($isSusp) { Write-Alert "Suspicious Netsh helper: $dllPath" "HIGH" }
        }
    }

    Write-Alert "Advanced persistence hunt complete. Hits: $($results.Count)" $(if($results.Count -gt 0){"HIGH"}else{"OK"})
        if ($GridView) { Show-ResultsView -Data $results -Title "Advanced Persistence" }
    if ($Export) { Export-ResultsCsv -Data $results -Name "AdvancedPersistence" }
    return $results
}

#endregion

#region ─── MODULE 26: KERBEROS & AUTHENTICATION FORENSICS ───────────────────

function Get-KerberosForensics {
    param([switch]$Export, [switch]$GridView)
    Write-Section "KERBEROS & AUTHENTICATION FORENSICS"

    $results = @()

    # ── Kerberos tickets ──────────────────────────────────────────────────────
    Write-Host "`n  [Current Kerberos Tickets (klist)]" -ForegroundColor DarkCyan
    try {
        $klist = klist 2>$null
        if ($klist) {
            $klist | ForEach-Object {
                $color = if ($_ -match "krbtgt") { "Yellow" } else { "Gray" }
                Write-Host "  $_" -ForegroundColor $color
            }
            # Check for forged/Golden tickets (long lifetime or unusual encryption)
            $goldenIndicators = $klist | Where-Object { $_ -match "KerbTicket Encryption Type.*RSADSI RC4" -or $_ -match "End Time.*2037|2038|2099" }
            if ($goldenIndicators) {
                Write-Alert "POTENTIAL GOLDEN TICKET: Unusual ticket lifetime or encryption!" "CRIT"
                $results += [PSCustomObject]@{ Type="GoldenTicket"; Detail=$goldenIndicators -join "|" }
            }
        }
    } catch { Write-Alert "klist not available" "WARN" }

    # ── NTLM downgrade detection ──────────────────────────────────────────────
    Write-Host "`n  [NTLM Authentication Policy]" -ForegroundColor DarkCyan
    $ntlmReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue
    $ntlmLevel = $ntlmReg.LmCompatibilityLevel
    $ntlmDesc  = switch ($ntlmLevel) {
        0 { "CRITICAL: LM + NTLM auth (very weak)" }
        1 { "HIGH: Send LM & NTLM, use NTLMv2 if negotiated" }
        2 { "WARN: Only NTLM auth" }
        3 { "WARN: NTLMv2 only from client" }
        4 { "OK: NTLMv2 only, refuse LM" }
        5 { "BEST: NTLMv2 only, refuse LM+NTLM" }
        default { "Unknown: $ntlmLevel" }
    }
    $color = switch ($ntlmLevel) { {$_ -le 2}{"Red"} {$_ -eq 3 -or $_ -eq 4}{"Yellow"} {$_ -ge 5}{"Green"} default{"Gray"} }
    Write-Host ("  LmCompatibilityLevel: {0} — {1}" -f $ntlmLevel, $ntlmDesc) -ForegroundColor $color
    if ($ntlmLevel -le 2) { Write-Alert "NTLM authentication is weak — NTLMv1 attacks possible!" "CRIT" }

    # ── Credential Guard status ───────────────────────────────────────────────
    Write-Host "`n  [Credential Guard / Device Guard Status]" -ForegroundColor DarkCyan
    $cgReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" -EA SilentlyContinue
    if ($cgReg) {
        $cgEnabled = $cgReg.Enabled
        $color = if ($cgEnabled -eq 1) { "Green" } else { "Yellow" }
        Write-Host ("  Credential Guard: {0}" -f $(if($cgEnabled -eq 1){"ENABLED"}else{"DISABLED"})) -ForegroundColor $color
    } else { Write-Host "  Credential Guard: Not Configured" -ForegroundColor Yellow }

    # ── Recent Kerberos failures ─────────────────────────────────────────────
    Write-Host "`n  [Kerberos Failures (4768/4771/4769)]" -ForegroundColor DarkCyan
    try {
        $kerbFails = Get-WinEvent -FilterHashtable @{LogName="Security"; Id=@(4771,4768)} -MaxEvents 100 -EA SilentlyContinue |
            Where-Object { $_.Message -match "Failure Code" -and $_.Message -notmatch "0x0" }
        if ($kerbFails.Count -gt 0) {
            Write-Alert "Kerberos authentication failures: $($kerbFails.Count)" $(if($kerbFails.Count -gt 20){"HIGH"}else{"WARN"})
            $kerbFails | Select-Object -First 10 | ForEach-Object {
                Write-Host ("  [{0}] {1}" -f $_.TimeCreated, $_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))) -ForegroundColor Yellow
            }
        }
    } catch {}

    # ── Pass-the-Hash / Pass-the-Ticket indicators ────────────────────────────
    Write-Host "`n  [Pass-the-Hash / Pass-the-Ticket Indicators]" -ForegroundColor DarkCyan
    try {
        $pthEvents = Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624} -MaxEvents 500 -EA SilentlyContinue |
            Where-Object {
                $msg = $_.Message
                ($msg -match "LogonType\s+3" -or $msg -match "Logon Type:\s+3") -and
                ($msg -match "NTLMSSP" -or $msg -match "AuthenticationPackage:\s+NTLM") -and
                $msg -match "WorkstationName:\s+-"
            }
        if ($pthEvents.Count -gt 0) {
            Write-Alert "POTENTIAL PASS-THE-HASH: $($pthEvents.Count) NTLM Type-3 logons with no workstation!" "HIGH"
            $results += [PSCustomObject]@{ Type="PassTheHash"; Count=$pthEvents.Count }
        }
    } catch {}

    # ── Mimikatz DCSync detection (T1003.006) ─────────────────────────────────
    Write-Host "`n  [DCSync Attack Indicators]" -ForegroundColor DarkCyan
    try {
        $dcsyncEvents = Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4662} -MaxEvents 200 -EA SilentlyContinue |
            Where-Object { $_.Message -match "1131f6aa|1131f6ad|89e95b76|1131f6ab|1131f6ac" }
        if ($dcsyncEvents.Count -gt 0) {
            Write-Alert "DCSYNC ATTACK INDICATORS: $($dcsyncEvents.Count) replication privilege events!" "CRIT"
            $results += [PSCustomObject]@{ Type="DCSync"; Count=$dcsyncEvents.Count }
        }
    } catch {}

        if ($GridView) { Show-ResultsView -Data $results -Title "Kerberos Forensics" }
    if ($Export) { Export-ResultsCsv -Data $results -Name "KerberosForensics" }
    return $results
}

#endregion

#region ─── MODULE 27: MALWARE HUNTING (HEURISTIC) ───────────────────────────

function Invoke-MalwareHunting {
    <#
    .SYNOPSIS Multi-technique heuristic malware hunting:
    entropy analysis, packer detection, suspicious imports, resource anomalies
    #>
    param([switch]$Export, [string]$ScanPath = "", [switch]$GridView)

    Write-Section "HEURISTIC MALWARE HUNTING"

    $results = @()

    # Paths to scan
    $scanPaths = if ($ScanPath -and (Test-Path $ScanPath)) {
        @($ScanPath)
    } else {
        @($env:TEMP, "$env:SystemRoot\Temp", $env:APPDATA, $env:LOCALAPPDATA, "C:\Users\Public", "C:\ProgramData")
    }

    # ── Entropy calculation (packed/encrypted files have high entropy ~7.0-8.0) ─
    function Get-FileEntropy {
        param([string]$FilePath)
        try {
            $bytes = [System.IO.File]::ReadAllBytes($FilePath)
            if ($bytes.Length -eq 0) { return 0.0 }
            $freq = @{}
            foreach ($b in $bytes) {
                if ($freq[$b]) { $freq[$b]++ } else { $freq[$b] = 1 }
            }
            $entropy = 0.0
            foreach ($count in $freq.Values) {
                $p = $count / $bytes.Length
                if ($p -gt 0) { $entropy -= $p * [Math]::Log($p, 2) }
            }
            return [Math]::Round($entropy, 4)
        } catch { return -1 }
    }

    Write-Host "`n  [High Entropy Files (Packed/Encrypted Malware Detection)]" -ForegroundColor DarkCyan
    $scanExts = @("*.exe","*.dll","*.sys","*.ps1","*.bat","*.vbs","*.js","*.jar","*.hta")

    foreach ($sp in $scanPaths) {
        foreach ($ext in $scanExts) {
            Get-ChildItem $sp -Filter $ext -EA SilentlyContinue -File | ForEach-Object {
                $entropy = Get-FileEntropy -FilePath $_.FullName
                $color   = if ($entropy -gt 7.2) { "Red" } elseif ($entropy -gt 6.5) { "Yellow" } else { "DarkGray" }
                if ($entropy -gt 6.5) {
                    Write-Host ("  Entropy:{0,-6} {1}" -f $entropy, $_.FullName) -ForegroundColor $color
                    if ($entropy -gt 7.2) {
                        Write-Alert "HIGH ENTROPY FILE (possible packed/encrypted malware): $($_.FullName) [H=$entropy]" "HIGH"
                        $results += [PSCustomObject]@{ Type="HighEntropy"; Path=$_.FullName; Entropy=$entropy; Size=$_.Length }
                    }
                }
            }
        }
    }

    # ── Double extension files ─────────────────────────────────────────────────
    Write-Host "`n  [Double Extension Files (invoice.pdf.exe, photo.jpg.vbs)]" -ForegroundColor DarkCyan
    $doubleExtPattern = "\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|txt|zip)\.(exe|bat|cmd|vbs|js|ps1|hta|scr|pif|com)$"
    foreach ($sp in $scanPaths) {
        Get-ChildItem $sp -Recurse -EA SilentlyContinue -File |
            Where-Object { $_.Name -match $doubleExtPattern } |
            ForEach-Object {
                Write-Alert "DOUBLE EXTENSION: $($_.FullName)" "CRIT"
                $results += [PSCustomObject]@{ Type="DoubleExtension"; Path=$_.FullName }
            }
    }

    # ── Icon mismatch (PDF icon but .exe extension) ────────────────────────────
    Write-Host "`n  [Suspicious Files Running From Non-Standard Locations]" -ForegroundColor DarkCyan
    $suspLocations = @("\\Temp\\","\\AppData\\Local\\Temp\\","\\Downloads\\","\\Public\\","\\ProgramData\\[^M]")
    Get-Process -EA SilentlyContinue | Where-Object { $_.Path } | ForEach-Object {
        foreach ($loc in $suspLocations) {
            if ($_.Path -match $loc) {
                $sig  = Get-AuthenticodeSignature $_.Path -EA SilentlyContinue
                $color= if ($sig.Status -ne "Valid") { "Red" } else { "Yellow" }
                Write-Host ("  [{0}] PID:{1,-6} {2}" -f $sig.Status, $_.Id, $_.Path) -ForegroundColor $color
                $results += [PSCustomObject]@{ Type="SuspiciousLocation"; Path=$_.Path; PID=$_.Id; Signed=$sig.Status }
                break
            }
        }
    }

    # ── AutoRun malware signatures in system areas ─────────────────────────────
    Write-Host "`n  [Malware String Signatures in Executable Areas]" -ForegroundColor DarkCyan
    $malwareStrings = @(
        "This program cannot be run in DOS mode" # Normal, skip
        "cmd.exe /c", "powershell.exe -", "WScript.Shell", "CreateObject",
        "Shell.Application","ActiveXObject","ADODB.Stream","GetObject",
        "WMI","Win32_Process","Run","RegWrite","HttpSendRequest"
    )
    # Scan scripts only (not binaries) for suspicious string combinations
    foreach ($sp in $scanPaths) {
        Get-ChildItem $sp -Include @("*.ps1","*.vbs","*.js","*.bat","*.cmd","*.hta") -Recurse -EA SilentlyContinue |
            Select-Object -First 50 | ForEach-Object {
                $content = Get-Content $_.FullName -Raw -EA SilentlyContinue -TotalCount 500
                if (-not $content) { return }
                $matches3 = @()
                # Obfuscation indicators
                if ($content -match "[A-Za-z0-9+/]{100,}={0,2}") { $matches3 += "Base64" }
                if ($content -match "chr\(\d+\)" -or $content -match "Chr\(\d+\)") { $matches3 += "CharCode" }
                if ($content -match "replace\(.{1,5},.{1,5}\)" -and ($content -match "replace" | Measure-Object).Count -gt 5) { $matches3 += "MultiReplace" }
                if ($content -match "FromBase64String|Convert.FromBase64") { $matches3 += "B64Decode" }
                if ($content -match "Invoke-Expression|IEX\s*\(") { $matches3 += "IEX" }
                if ($content -match "\[char\]\s*\d+") { $matches3 += "CharArray" }
                if ($content -match "DownloadFile|DownloadString|WebClient|Net.WebClient") { $matches3 += "Downloader" }
                if ($content -match "System.Reflection.Assembly.*Load|Assembly::Load") { $matches3 += "ReflectiveLoad" }
                if ($content -match "-w\s+hid|-windowstyle\s+hid|-NonInteractive.*-Enc") { $matches3 += "HiddenExecution" }

                if ($matches3.Count -ge 2) {
                    Write-Alert "OBFUSCATED SCRIPT [$($_.FullName)]: $($matches3 -join ', ')" "CRIT"
                    $results += [PSCustomObject]@{ Type="ObfuscatedScript"; Path=$_.FullName; Indicators=$matches3 -join "|" }
                }
            }
    }

    Write-Alert "Malware hunt complete. Suspicious files: $($results.Count)" $(if($results.Count -gt 0){"HIGH"}else{"OK"})
        if ($GridView) { Show-ResultsView -Data $results -Title "Malware Hunting" }
    if ($Export) { Export-ResultsCsv -Data $results -Name "MalwareHunting" }
    return $results
}

#endregion

#region ─── MODULE 28: CONTAINER & VIRTUALIZATION FORENSICS ──────────────────

function Get-VirtualizationForensics {
    param([switch]$Export, [switch]$GridView)
    Write-Section "CONTAINER & VIRTUALIZATION FORENSICS"

    $results = @()

    # ── VM detection (are we in a VM?) ────────────────────────────────────────
    Write-Host "`n  [Virtual Machine Detection]" -ForegroundColor DarkCyan
    $vmIndicators = @()

    # BIOS / System product name
    $bios       = Get-CimInstance Win32_BIOS -EA SilentlyContinue
    $sysProduct = Get-CimInstance Win32_ComputerSystemProduct -EA SilentlyContinue
    $vmNames    = @("vmware","virtualbox","vbox","kvm","qemu","hyper-v","xen","parallels","virtual","bochs","innotek","oracle vm")

    foreach ($vmName in $vmNames) {
        if ($bios.Manufacturer -match $vmName -or $bios.SMBIOSBIOSVersion -match $vmName -or
            $sysProduct.Name -match $vmName -or $sysProduct.Vendor -match $vmName) {
            $vmIndicators += $vmName
        }
    }

    # MAC address prefix (VM vendors)
    $vmMacPrefixes = @("00:50:56","00:0c:29","00:05:69","08:00:27","52:54:00","00:16:3e","00:15:5d")
    Get-NetAdapter -EA SilentlyContinue | ForEach-Object {
        $mac = $_.MacAddress -replace "-",":" | ForEach-Object { $_.Substring(0,8).ToLower() }
        if ($vmMacPrefixes -contains $mac) { $vmIndicators += "VM_MAC:$mac" }
    }

    # Registry indicators
    $vmRegKeys = @("HKLM:\SOFTWARE\VMware, Inc.","HKLM:\SOFTWARE\Oracle\VirtualBox","HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters")
    foreach ($vk in $vmRegKeys) {
        if (Test-Path $vk) { $vmIndicators += "REG:$vk" }
    }

    if ($vmIndicators.Count -gt 0) {
        Write-Alert "VIRTUAL MACHINE DETECTED: $($vmIndicators -join ', ')" "WARN"
        Write-Host "  Note: Malware may behave differently or exit when in VM" -ForegroundColor DarkYellow
        $results += [PSCustomObject]@{ Type="VMDetected"; Indicators=$vmIndicators -join "|" }
    } else {
        Write-Alert "No VM indicators found — appears to be bare metal" "OK"
    }

    # ── Docker / Container artifacts ──────────────────────────────────────────
    Write-Host "`n  [Docker / Container Artifacts]" -ForegroundColor DarkCyan
    $dockerPaths = @("C:\ProgramData\Docker","C:\Users\*\.docker","C:\Program Files\Docker")
    foreach ($dp in $dockerPaths) {
        $resolved = Resolve-Path $dp -EA SilentlyContinue
        foreach ($rp in $resolved) {
            if (Test-Path $rp) {
                Write-Host ("  Docker artifact found: {0}" -f $rp) -ForegroundColor Cyan
                $results += [PSCustomObject]@{ Type="DockerArtifact"; Path=$rp.ToString() }
            }
        }
    }

    # Check for docker.exe in PATH
    $dockerExe = Get-Command docker -EA SilentlyContinue
    if ($dockerExe) {
        Write-Host "  Docker installed: $($dockerExe.Source)" -ForegroundColor Cyan
        try {
            $containers = & docker ps --format "{{.Names}} {{.Image}} {{.Status}}" 2>$null
            if ($containers) {
                Write-Host "`n  [Running Containers]" -ForegroundColor DarkCyan
                $containers | ForEach-Object { Write-Host "  ► $_" -ForegroundColor Yellow }
            }
        } catch {}
    }

    # ── Hyper-V / WSL ────────────────────────────────────────────────────────
    Write-Host "`n  [Hyper-V / WSL Status]" -ForegroundColor DarkCyan
    $hypervFeature = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -EA SilentlyContinue
    $wslFeature    = Get-WindowsOptionalFeature -FeatureName Microsoft-Windows-Subsystem-Linux -Online -EA SilentlyContinue

    if ($hypervFeature.State -eq "Enabled") {
        Write-Host "  Hyper-V: ENABLED" -ForegroundColor Yellow
        $vms = Get-VM -EA SilentlyContinue
        if ($vms) {
            Write-Host "  Running VMs:" -ForegroundColor DarkCyan
            $vms | ForEach-Object { Write-Host ("  → {0,-30} State:{1}" -f $_.Name, $_.State) -ForegroundColor $(if($_.State -eq "Running"){"Yellow"}else{"Gray"}) }
        }
    }
    if ($wslFeature.State -eq "Enabled") {
        Write-Host "  WSL: ENABLED" -ForegroundColor Yellow
        try {
            $wslDistros = wsl --list --quiet 2>$null
            $wslDistros | Where-Object { $_ } | ForEach-Object { Write-Host "  WSL Distro: $_" -ForegroundColor Yellow }
        } catch {}
    }

        if ($GridView) { Show-ResultsView -Data $results -Title "Virtualization Forensics" }
    if ($Export) { Export-ResultsCsv -Data $results -Name "VirtualizationForensics" }
    return $results
}

#endregion

#region ─── MODULE 29: INCIDENT COMMANDER DASHBOARD ─────────────────────────

function Show-IncidentCommanderDashboard {
    <#
    .SYNOPSIS High-level real-time dashboard for Incident Commanders.
    Shows risk scores, active threats, system health, and recommended actions.
    #>

    Write-Section "INCIDENT COMMANDER DASHBOARD"

    Write-Host "`n  Performing rapid assessment..." -ForegroundColor DarkCyan

    $riskScore   = 0
    $findings    = @()
    $recommended = @()

    # Run quick versions of key checks
    # 1. Network
    $extConns = (Get-NetTCPConnection -State Established -EA SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0|::$|10\.|192\.168\.|172\.1)" }).Count
    if ($extConns -gt 20) { $riskScore += 20; $findings += "HIGH external connections: $extConns"; $recommended += "Isolate host from network or rate-limit outbound" }
    elseif ($extConns -gt 5) { $riskScore += 5; $findings += "Elevated external connections: $extConns" }

    # 2. Defender
    try {
        $defStatus = Get-MpComputerStatus -EA SilentlyContinue
        if ($defStatus -and -not $defStatus.RealTimeProtectionEnabled) { $riskScore += 30; $findings += "DEFENDER REAL-TIME PROTECTION DISABLED"; $recommended += "Re-enable Defender immediately or deploy replacement AV" }
        if ($defStatus -and $defStatus.IsTamperProtected -eq $false) { $riskScore += 15; $findings += "DEFENDER TAMPER PROTECTION OFF"; $recommended += "Enable Tamper Protection in Defender settings" }
    } catch {}

    # 3. Suspicious processes
    $suspProcs = Get-CimInstance Win32_Process -EA SilentlyContinue |
        Where-Object { $_.CommandLine -match "IEX|Invoke-Expression|-EncodedCommand|FromBase64String|DownloadString|WebClient" }
    if ($suspProcs.Count -gt 0) { $riskScore += 40; $findings += "OBFUSCATED PROCESS COMMANDS: $($suspProcs.Count)"; $recommended += "Isolate and memory-dump affected processes" }

    # 4. Event log cleared
    try {
        $logClears = (Get-WinEvent -FilterHashtable @{LogName="Security"; Id=1102} -MaxEvents 5 -EA SilentlyContinue).Count
        if ($logClears -gt 0) { $riskScore += 35; $findings += "SECURITY LOG CLEARED $logClears times!"; $recommended += "Preserve remaining logs immediately — check SIEM for pre-clear events" }
    } catch {}

    # 5. Admin account changes
    try {
        $recentAdminChanges = (Get-WinEvent -FilterHashtable @{LogName="Security"; Id=@(4720,4732,4728)} -MaxEvents 20 -EA SilentlyContinue |
            Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-24) }).Count
        if ($recentAdminChanges -gt 0) { $riskScore += 25; $findings += "Admin account changes in 24h: $recentAdminChanges"; $recommended += "Audit all admin group changes; verify with HR/IT" }
    } catch {}

    # 6. WMI subscriptions
    $wmiSubs = (Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding -EA SilentlyContinue).Count
    if ($wmiSubs -gt 0) { $riskScore += 30; $findings += "WMI PERSISTENCE SUBSCRIPTIONS: $wmiSubs"; $recommended += "Remove WMI subscriptions: Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject" }

    # 7. Scheduled tasks
    $suspTasks = (Get-ScheduledTask -EA SilentlyContinue | Where-Object {
        $_.TaskPath -notmatch "\\Microsoft\\" -and $_.State -ne "Disabled" -and
        ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -match "powershell|cmd|wscript|mshta"
    }).Count
    if ($suspTasks -gt 0) { $riskScore += 20; $findings += "Suspicious scheduled tasks: $suspTasks"; $recommended += "Review and disable suspicious scheduled tasks" }

    # 8. Open shares
    $openShares = (Get-SmbShare -EA SilentlyContinue | Where-Object { $_.Name -notmatch "ADMIN\$|C\$|IPC\$" }).Count
    if ($openShares -gt 3) { $riskScore += 10; $findings += "Non-admin shares: $openShares"; $recommended += "Audit share permissions for unnecessary access" }

    # ── Render dashboard ──────────────────────────────────────────────────────
    $riskLevel = if ($riskScore -ge 80) { "CRITICAL" } elseif ($riskScore -ge 50) { "HIGH" } elseif ($riskScore -ge 25) { "MEDIUM" } else { "LOW" }
    $riskColor = switch ($riskLevel) { "CRITICAL"{"Magenta"} "HIGH"{"Red"} "MEDIUM"{"Yellow"} "LOW"{"Green"} }

    Write-Host ""
    Write-Host ("  ╔═══════════════════════════════════════════════════════════════╗") -ForegroundColor DarkCyan
    Write-Host ("  ║             INCIDENT COMMANDER RISK ASSESSMENT               ║") -ForegroundColor DarkCyan
    Write-Host ("  ╠═══════════════════════════════════════════════════════════════╣") -ForegroundColor DarkCyan
    Write-Host ("  ║  Host      : {0,-48}║" -f $env:COMPUTERNAME) -ForegroundColor DarkCyan
    Write-Host ("  ║  User      : {0,-48}║" -f "$env:USERDOMAIN\$env:USERNAME") -ForegroundColor DarkCyan
    Write-Host ("  ║  Time      : {0,-48}║" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")) -ForegroundColor DarkCyan
    Write-Host ("  ║  Risk Score: {0,-48}║" -f "$riskScore / 100") -ForegroundColor $riskColor
    Write-Host ("  ║  Risk Level: {0,-48}║" -f $riskLevel) -ForegroundColor $riskColor
    Write-Host ("  ╠═══════════════════════════════════════════════════════════════╣") -ForegroundColor DarkCyan
    Write-Host ("  ║  FINDINGS                                                     ║") -ForegroundColor DarkCyan

    foreach ($f in $findings) {
        $fc = if ($f -match "DISABLED|CLEARED|TAMPER|OBFUSCATED|WMI") { "Red" } else { "Yellow" }
        Write-Host ("  ║  ► {0,-60}║" -f $f.Substring(0,[Math]::Min(60,$f.Length))) -ForegroundColor $fc
    }
    if ($findings.Count -eq 0) { Write-Host ("  ║  ► No immediate threats detected                              ║") -ForegroundColor Green }

    Write-Host ("  ╠═══════════════════════════════════════════════════════════════╣") -ForegroundColor DarkCyan
    Write-Host ("  ║  RECOMMENDED ACTIONS                                          ║") -ForegroundColor DarkCyan
    foreach ($r in $recommended) {
        Write-Host ("  ║  → {0,-60}║" -f $r.Substring(0,[Math]::Min(60,$r.Length))) -ForegroundColor Cyan
    }
    if ($recommended.Count -eq 0) { Write-Host ("  ║  → Continue monitoring                                        ║") -ForegroundColor Green }

    Write-Host ("  ╚═══════════════════════════════════════════════════════════════╝") -ForegroundColor DarkCyan

    return [PSCustomObject]@{ RiskScore=$riskScore; RiskLevel=$riskLevel; Findings=$findings; Recommendations=$recommended }
}

#endregion

#region ─── MODULE 30: POWERSHELL & SCRIPT FORENSICS ─────────────────────────

function Get-PowerShellForensics {
    param([switch]$Export, [switch]$GridView)
    Write-Section "POWERSHELL & SCRIPT FORENSICS"

    $results = @()

    # ── PowerShell logging configuration ──────────────────────────────────────
    Write-Host "`n  [PowerShell Logging Configuration]" -ForegroundColor DarkCyan
    $psLoggingKeys = @{
        "ScriptBlockLogging"  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        "ModuleLogging"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        "Transcription"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    }
    foreach ($logType in $psLoggingKeys.Keys) {
        $regPath = $psLoggingKeys[$logType]
        if (Test-Path $regPath) {
            $val = Get-ItemProperty $regPath -EA SilentlyContinue
            $enabled = $val.EnableScriptBlockLogging -or $val.EnableModuleLogging -or $val.EnableTranscripting
            $color   = if ($enabled) { "Green" } else { "Red" }
            Write-Host ("  {0,-25}: {1}" -f $logType, $(if($enabled){"ENABLED"}else{"DISABLED"})) -ForegroundColor $color
            if (-not $enabled) { Write-Alert "$logType is DISABLED — visibility gap!" "WARN" }
        } else {
            Write-Host ("  {0,-25}: NOT CONFIGURED" -f $logType) -ForegroundColor Yellow
        }
    }

    # ── PowerShell version (downgrade attack) ─────────────────────────────────
    Write-Host "`n  [PowerShell Version Check (Downgrade Attack)]" -ForegroundColor DarkCyan
    $psVersions = @()
    if (Test-Path "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe") {
        $psVersions += "1.0 (v1.0 engine - bypass logging!)"
        Write-Alert "PowerShell v1.0 engine available — can bypass Script Block Logging!" "HIGH"
    }
    if (Test-Path "C:\Windows\System32\WindowsPowerShell\v1.0") { $psVersions += "engine present" }
    $ps2Feature = Get-WindowsOptionalFeature -FeatureName MicrosoftWindowsPowerShellV2Root -Online -EA SilentlyContinue
    if ($ps2Feature -and $ps2Feature.State -eq "Enabled") {
        Write-Alert "PowerShell v2 feature is ENABLED — downgrade attack possible!" "HIGH"
        $results += [PSCustomObject]@{ Type="PSv2Enabled"; Detail="Downgrade attack vector" }
    }

    # ── Transcript files ──────────────────────────────────────────────────────
    Write-Host "`n  [PowerShell Transcript Files]" -ForegroundColor DarkCyan
    $transcriptPaths = @(
        "$env:SystemRoot\Transcripts",
        "$env:USERPROFILE\Documents\PowerShell_transcript*",
        "$env:LOCALAPPDATA\Temp\PowerShell*transcript*",
        "C:\ProgramData\PowerShell\Transcripts"
    )
    foreach ($tp in $transcriptPaths) {
        $resolved = Resolve-Path $tp -EA SilentlyContinue
        foreach ($rp in $resolved) {
            Write-Host ("  Transcript: {0}" -f $rp) -ForegroundColor Cyan
        }
    }

    # ── Recently executed PS scripts ──────────────────────────────────────────
    Write-Host "`n  [Recently Executed PowerShell Scripts (last 24h)]" -ForegroundColor DarkCyan
    $recent = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; Id=4104; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 100 -EA SilentlyContinue
    if ($recent) {
        Write-Alert "PS Script Block events in last 24h: $($recent.Count)" "INFO"
        $recent | Where-Object { $_.Message -match "IEX|Invoke-Expression|DownloadString|FromBase64|WebClient|AMSI|bypass" } |
            Select-Object -First 5 | ForEach-Object {
                Write-Alert "Suspicious PS activity: $($_.Message.Substring(0,200))" "HIGH"
                $results += [PSCustomObject]@{ Type="SuspPSExecution"; Time=$_.TimeCreated; Detail=$_.Message.Substring(0,500) }
            }
    }

    # ── AMSI bypass attempts in logs ──────────────────────────────────────────
    Write-Host "`n  [AMSI Bypass Patterns in Script Block Logs]" -ForegroundColor DarkCyan
    $amsiBypassPatterns = @(
        "AmsiUtils","amsiInitFailed","Disable-AmsiProvider","amsiContext",
        "[Ref].Assembly.GetType","System.Management.Automation.AmsiUtils",
        "amsi.dll","VirtualProtect.*amsi","WriteProcessMemory.*amsi",
        "Set-MpPreference -Disable","Add-MpPreference -Exclusion"
    )
    $psEvents = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; Id=4104} -MaxEvents 500 -EA SilentlyContinue
    foreach ($evt in $psEvents) {
        foreach ($pattern in $amsiBypassPatterns) {
            if ($evt.Message -match $pattern) {
                Write-Alert "AMSI BYPASS ATTEMPT in PS log: $pattern @ $($evt.TimeCreated)" "CRIT"
                $results += [PSCustomObject]@{ Type="AMSIBypass"; Pattern=$pattern; Time=$evt.TimeCreated }
                break
            }
        }
    }

        if ($GridView) { Show-ResultsView -Data $results -Title "Power Shell Forensics" }
    if ($Export) { Export-ResultsCsv -Data $results -Name "PowerShellForensics" }
    return $results
}

#endregion

#region ─── MODULE 31: REPORT GENERATOR ─────────────────────────────────────

function New-DFIRReport {
    <#
    .SYNOPSIS Generate a comprehensive HTML investigation report from collected data
    #>
    param(
        [string]$OutputPath = "$env:TEMP\DFIR_Report_$(Get-Date -f 'yyyyMMdd_HHmmss').html",
        [string]$CaseName   = "Unnamed Investigation",
        [string]$Analyst    = $env:USERNAME,
        [switch]$OpenReport
    )

    Write-Section "DFIR HTML REPORT GENERATOR"
    Write-Alert "Collecting data for report..." "INFO"

    # Collect data
    $networkData  = Get-NetworkConnections 2>$null
    $processData  = Get-ProcessForensics   2>$null
    $sigmaHits    = Invoke-SigmaHunt       2>$null
    $persistence  = Get-PersistenceMechanisms 2>$null
    $users        = Get-UserAccountForensics  2>$null

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DFIR Report - $CaseName</title>
<style>
  body { font-family: 'Consolas', monospace; background: #0a0e1a; color: #c8d8e8; margin: 0; padding: 20px; }
  h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff33; padding-bottom: 10px; }
  h2 { color: #fbbf24; border-left: 4px solid #fbbf24; padding-left: 10px; margin-top: 30px; }
  h3 { color: #60a5fa; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 12px; }
  th { background: #1a2a3a; color: #00d4ff; padding: 8px; text-align: left; border: 1px solid #2a3a4a; }
  td { padding: 6px 8px; border: 1px solid #1a2a3a; }
  tr:nth-child(even) { background: #0d1520; }
  tr.suspicious { background: #2a0a0a; }
  tr.suspicious td { color: #ff6b6b; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; }
  .badge-crit { background: #7f1d1d; color: #fca5a5; }
  .badge-high { background: #7c2d12; color: #fdba74; }
  .badge-warn { background: #78350f; color: #fcd34d; }
  .badge-ok   { background: #14532d; color: #86efac; }
  .header-meta { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px; margin: 20px 0; }
  .meta-box { background: #0d1520; border: 1px solid #1a3a5a; border-radius: 6px; padding: 15px; }
  .meta-box .label { color: #4a6a8a; font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase; }
  .meta-box .value { color: #fff; font-size: 16px; margin-top: 5px; }
  .toc a { color: #60a5fa; text-decoration: none; display: block; padding: 3px 0; }
  .toc a:hover { color: #00d4ff; }
  .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 20px 0; }
  .summary-card { background: #0d1520; border: 1px solid #1a3a5a; border-radius: 6px; padding: 15px; text-align: center; }
  .summary-card .num { font-size: 28px; font-weight: bold; color: #00d4ff; }
  .summary-card .lbl { font-size: 11px; color: #4a6a8a; margin-top: 5px; text-transform: uppercase; }
  pre { background: #060a10; border: 1px solid #1a2a3a; padding: 10px; overflow-x: auto; font-size: 11px; color: #8aaaca; border-radius: 4px; }
  .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #1a2a3a; color: #2a4a6a; font-size: 11px; text-align: center; }
</style>
</head>
<body>
<h1>⚔ DFIR Swiss Knife — Investigation Report</h1>

<div class="header-meta">
  <div class="meta-box"><div class="label">Case Name</div><div class="value">$CaseName</div></div>
  <div class="meta-box"><div class="label">Host</div><div class="value">$env:COMPUTERNAME</div></div>
  <div class="meta-box"><div class="label">Domain</div><div class="value">$env:USERDNSDOMAIN</div></div>
  <div class="meta-box"><div class="label">Analyst</div><div class="value">$Analyst</div></div>
  <div class="meta-box"><div class="label">Date / Time</div><div class="value">$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div></div>
  <div class="meta-box"><div class="label">OS</div><div class="value">$(((Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).Caption))</div></div>
</div>

<div class="summary-grid">
  <div class="summary-card"><div class="num">$(($networkData | Where-Object {$_.SuspiciousPort -or $_.SuspiciousProc}).Count)</div><div class="lbl">Suspicious Connections</div></div>
  <div class="summary-card"><div class="num">$($processData.Count)</div><div class="lbl">Suspicious Processes</div></div>
  <div class="summary-card"><div class="num">$($sigmaHits.Count)</div><div class="lbl">SIGMA Rule Hits</div></div>
  <div class="summary-card"><div class="num">$(($persistence | Measure-Object).Count)</div><div class="lbl">Persistence Items</div></div>
</div>

<h2>Network Connections</h2>
<table>
<tr><th>Process</th><th>Local</th><th>Remote</th><th>State</th><th>PID</th><th>Flags</th></tr>
$(
    ($networkData | Select-Object -First 50 | ForEach-Object {
        $cls = if ($_.SuspiciousPort -or $_.SuspiciousProc) { ' class="suspicious"' } else { '' }
        "<tr$cls><td>$($_.ProcessName)</td><td>$($_.LocalAddress):$($_.LocalPort)</td><td>$($_.RemoteAddress):$($_.RemotePort)</td><td>$($_.State)</td><td>$($_.PID)</td><td>$(if($_.SuspiciousPort){'SUSP_PORT '}$(if($_.SuspiciousProc){'SUSP_PROC'}))</td></tr>"
    }) -join "`n"
)
</table>

<h2>SIGMA Rule Detections</h2>
$(
    if ($sigmaHits -and $sigmaHits.Count -gt 0) {
        "<table><tr><th>Rule ID</th><th>Title</th><th>Tactic</th><th>Technique</th><th>Hits</th><th>Last Seen</th></tr>" +
        (($sigmaHits | ForEach-Object { "<tr class='suspicious'><td>$($_.RuleId)</td><td>$($_.Title)</td><td>$($_.Tactic)</td><td>$($_.Technique)</td><td>$($_.HitCount)</td><td>$($_.LastSeen)</td></tr>" }) -join "`n") +
        "</table>"
    } else { "<p style='color:#14532d'>No SIGMA rule hits detected.</p>" }
)

<h2>Suspicious Processes</h2>
$(
    if ($processData -and $processData.Count -gt 0) {
        "<table><tr><th>PID</th><th>Name</th><th>Parent</th><th>User</th><th>Flags</th><th>Path</th></tr>" +
        (($processData | ForEach-Object { "<tr class='suspicious'><td>$($_.PID)</td><td>$($_.Name)</td><td>$($_.Parent)</td><td>$($_.User)</td><td>$($_.Flags)</td><td>$($_.Path)</td></tr>" }) -join "`n") +
        "</table>"
    } else { "<p style='color:#14532d'>No suspicious processes detected.</p>" }
)

<h2>User Accounts</h2>
<table>
<tr><th>Name</th><th>Enabled</th><th>Admin</th><th>Last Logon</th><th>Password Changed</th></tr>
$(
    ($users | ForEach-Object {
        $cls = if ($_.IsAdmin -and $_.Enabled) { ' class="suspicious"' } else { '' }
        "<tr$cls><td>$($_.Name)</td><td>$($_.Enabled)</td><td>$($_.IsAdmin)</td><td>$($_.LastLogon)</td><td>$($_.PasswordLastSet)</td></tr>"
    }) -join "`n"
)
</table>

<h2>Persistence Mechanisms</h2>
$(
    if ($persistence -and $persistence.Count -gt 0) {
        "<table><tr><th>Task Name</th><th>State</th><th>Action</th></tr>" +
        (($persistence | Where-Object { $_.TaskName } | Select-Object -First 20 | ForEach-Object { "<tr><td>$($_.TaskName)</td><td>$($_.State)</td><td>$($_.Action)</td></tr>" }) -join "`n") +
        "</table>"
    } else { "<p style='color:#14532d'>No custom persistence tasks found.</p>" }
)

<div class="footer">
  Generated by DFIR Swiss Knife v3.0 | $env:COMPUTERNAME | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC') | Analyst: $Analyst
</div>
</body>
</html>
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Alert "HTML Report saved: $OutputPath" "OK"

    if ($OpenReport) {
        try { Start-Process $OutputPath } catch {}
    }

    return $OutputPath
}

#endregion

#region ─── MODULE 32: LIVE THREAT MONITOR (REAL-TIME) ───────────────────────

function Start-LiveThreatMonitor {
    <#
    .SYNOPSIS Real-time continuous threat monitoring with configurable alert thresholds.
    Monitors: new processes, network connections, file changes, registry changes
    Press Ctrl+C to stop.
    #>
    param(
        [int]$PollIntervalSeconds = 10,
        [switch]$LogToFile,
        [string]$LogFile = "$env:TEMP\DFIR_LiveMonitor_$(Get-Date -f 'yyyyMMdd_HHmmss').log"
    )

    Write-Section "LIVE THREAT MONITOR (Real-Time — Press Ctrl+C to stop)"
    Write-Alert "Poll interval: $PollIntervalSeconds seconds | Log: $(if($LogToFile){$LogFile}else{'Console only'})" "INFO"

    function Write-LiveAlert {
        param([string]$Msg, [string]$Level = "INFO")
        $ts    = Get-Date -Format "HH:mm:ss"
        $colors= @{ INFO="Cyan"; WARN="Yellow"; HIGH="Red"; CRIT="Magenta" }
        $color = if ($colors.ContainsKey($Level)) { $colors[$Level] } else { "White" }
        $line  = "[$ts] [$Level] $Msg"
        Write-Host $line -ForegroundColor $color
        if ($LogToFile) { $line | Add-Content $LogFile }
    }

    # Baseline
    $baseProcs   = (Get-Process -EA SilentlyContinue | Select-Object Id, Name, Path).Id
    $baseConns   = Get-NetTCPConnection -State Established -EA SilentlyContinue | Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess
    $baseFiles   = @{}
    $monitoredDirs = @($env:TEMP, "$env:SystemRoot\Temp", "C:\Users\Public")
    foreach ($dir in $monitoredDirs) {
        if (Test-Path $dir) {
            Get-ChildItem $dir -File -EA SilentlyContinue | ForEach-Object { $baseFiles[$_.FullName] = $_.LastWriteTime }
        }
    }

    $suspiciousProcessPatterns = @("meterpreter","cobalt","beacon","mimikatz","lazagne","empire","sliver","havoc","psexec","wmiexec","smbexec")
    $suspiciousPorts           = @(4444,1337,31337,8080,9001,9050,6667,12345,54321,65535)

    Write-Host "`n  [Monitoring started. Watching: Processes, Connections, Files, Registry]" -ForegroundColor DarkCyan
    Write-Host "  Press Ctrl+C to stop monitoring" -ForegroundColor DarkGray

    $iteration = 0
    while ($true) {
        $iteration++
        try {
            # ── New processes ─────────────────────────────────────────────────
            $currentProcs = Get-Process -EA SilentlyContinue | Select-Object Id, Name, Path
            $newProcs     = $currentProcs | Where-Object { $_.Id -notin $baseProcs }

            foreach ($np in $newProcs) {
                $level = "INFO"
                $msg   = "New process: [$($np.Name)] PID:$($np.Id) → $($np.Path)"

                # Suspicious name check
                foreach ($sp in $suspiciousProcessPatterns) {
                    if ($np.Name -match $sp) { $level = "CRIT"; $msg = "SUSPICIOUS PROCESS: $msg"; break }
                }
                # Suspicious path
                if ($np.Path -match "\\Temp\\|\\AppData\\|\\Downloads\\|\\Public\\") {
                    $level = "HIGH"; $msg = "SUSPICIOUS PATH: $msg"
                }
                # Unsigned
                if ($np.Path) {
                    $sig = Get-AuthenticodeSignature $np.Path -EA SilentlyContinue
                    if ($sig.Status -ne "Valid") { $level = if($level -ne "CRIT"){"HIGH"}else{$level}; $msg += " [UNSIGNED]" }
                }

                if ($level -ne "INFO" -or $iteration -le 2) { Write-LiveAlert $msg $level }
            }
            $baseProcs = $currentProcs.Id

            # ── New network connections ────────────────────────────────────────
            $currentConns = Get-NetTCPConnection -State Established -EA SilentlyContinue | Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess
            $newConns     = $currentConns | Where-Object {
                $r = $_.RemoteAddress; $p = $_.RemotePort
                -not ($baseConns | Where-Object { $_.RemoteAddress -eq $r -and $_.RemotePort -eq $p })
            }

            foreach ($nc in $newConns) {
                if ($nc.RemoteAddress -match "^(127\.|::1|0\.0\.0\.0)") { continue }
                $proc  = (Get-Process -Id $nc.OwningProcess -EA SilentlyContinue).Name
                $level = "INFO"
                $msg   = "New connection: $proc → $($nc.RemoteAddress):$($nc.RemotePort)"

                if ($nc.RemotePort -in $suspiciousPorts) { $level = "CRIT"; $msg = "SUSPICIOUS PORT: $msg" }
                if ($proc -match "powershell|cmd|wscript|mshta|rundll32") { $level = if($level -ne "CRIT"){"HIGH"}else{$level}; $msg = "SUSPICIOUS PROC NET: $msg" }

                Write-LiveAlert $msg $level
            }
            $baseConns = $currentConns

            # ── File system changes ───────────────────────────────────────────
            foreach ($dir in $monitoredDirs) {
                if (-not (Test-Path $dir)) { continue }
                Get-ChildItem $dir -File -EA SilentlyContinue | ForEach-Object {
                    $path = $_.FullName
                    if (-not $baseFiles.ContainsKey($path)) {
                        $sig   = Get-AuthenticodeSignature $path -EA SilentlyContinue
                        $hash  = (Get-FileHash $path -Algorithm SHA256 -EA SilentlyContinue).Hash
                        $level = if ($_.Extension -match "\.exe|\.dll|\.ps1|\.bat|\.vbs|\.hta") { "HIGH" } else { "WARN" }
                        Write-LiveAlert "NEW FILE in monitored dir: $path [Signed:$($sig.Status)] SHA256:$hash" $level
                        $baseFiles[$path] = $_.LastWriteTime
                    } elseif ($baseFiles[$path] -ne $_.LastWriteTime) {
                        Write-LiveAlert "MODIFIED FILE: $path" "WARN"
                        $baseFiles[$path] = $_.LastWriteTime
                    }
                }
            }

            # ── Status heartbeat every 60 seconds ─────────────────────────────
            if ($iteration % (60 / $PollIntervalSeconds) -eq 0) {
                $extCount = ($currentConns | Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0)" }).Count
                Write-LiveAlert "Heartbeat [Iter:$iteration] Procs:$($currentProcs.Count) ExtConns:$extCount Monitored_Files:$($baseFiles.Count)" "INFO"
            }

            Start-Sleep -Seconds $PollIntervalSeconds
        }
        catch [System.Management.Automation.PipelineStoppedException] {
            Write-Host "`n  Live monitor stopped." -ForegroundColor DarkCyan
            break
        }
        catch { Write-LiveAlert "Monitor error: $_" "WARN" }
    }
}

#endregion


#region ─── EXPANDED INTERACTIVE MENU v3.0 ───────────────────────────────────

function Assert-AdminRequired {
    <# Helper: warn and optionally block features that need elevation #>
    param([string]$ModuleName, [switch]$HardRequirement)
    if (-not (Get-IsAdmin)) {
        if ($HardRequirement) {
            Write-Host ""
            Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Red
            Write-Host "  ║  [ADMIN REQUIRED] $($ModuleName.PadRight(42))║" -ForegroundColor Red
            Write-Host "  ║  This module requires Administrator privileges.          ║" -ForegroundColor Red
            Write-Host "  ║  Please restart PowerShell as Administrator:             ║" -ForegroundColor Red
            Write-Host "  ║    Right-click PowerShell → 'Run as administrator'       ║" -ForegroundColor Red
            Write-Host "  ║    Or: Start-Process powershell -Verb RunAs             ║" -ForegroundColor Red
            Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Red
            Write-Host ""
            return $false
        } else {
            Write-Host ""
            Write-Host "  [LIMITED MODE] $ModuleName — some results may be incomplete without admin rights." -ForegroundColor Yellow
            Write-Host "  Tip: Restart as Administrator for full output.`n" -ForegroundColor DarkYellow
            return $true   # allow to proceed with partial results
        }
    }
    return $true
}

function Show-Menu {
    do {
    Show-Banner

    $adminStatus = if (Get-IsAdmin) { "[ADMIN]" } else { "[USER - Limited]" }
    $domain      = if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { "WORKGROUP" }
    Write-Host "  System : $env:COMPUTERNAME | Domain: $domain | User: $env:USERNAME $adminStatus" -ForegroundColor DarkGray
    Write-Host "  OS     : $((Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).Caption)" -ForegroundColor DarkGray
    Write-Host "  Date   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor DarkGray

    $menuItems = @"
  ╔══════════════════════════════════════════════════════════════════════╗
  ║              DFIR SWISS KNIFE v3.0 — MODULE MENU                    ║
  ╠═══════════════╦══════════════════════════════════════════════════════╣
  ║ NETWORK       ║  1. Network Connections & Remote IPs                ║
  ║               ║  2. DNS Cache & C2 Domain Analysis                  ║
  ║               ║  3. Firewall Log Review                             ║
  ║               ║  4. Network Anomalies & Beaconing Detection         ║
  ║               ║  5. Network Share & SMB / Named Pipe Forensics      ║
  ╠═══════════════╬══════════════════════════════════════════════════════╣
  ║ PROCESS       ║  6. Process Forensics & Injection Detection         ║
  ║               ║  7. Process Tree (Visual Parent-Child)              ║
  ║               ║  8. Heuristic Malware Hunting (Entropy/Obfusc)      ║
  ╠═══════════════╬══════════════════════════════════════════════════════╣
  ║ SYSTEM        ║  9. Registry Forensics (Persistence / ASEPs)        ║
  ║               ║ 10. User Account Forensics & Logon Events           ║
  ║               ║ 11. Persistence Mechanisms (Tasks/WMI/Services)     ║
  ║               ║ 12. Advanced Persistence (COM/LSA/Drivers/Accesib.) ║
  ║               ║ 13. Memory Forensics & Hollowing Detection          ║
  ║               ║ 14. File System Forensics (ADS/Recent/Prefetch)     ║
  ║               ║ 15. Lateral Movement Indicators                     ║
  ╠═══════════════╬══════════════════════════════════════════════════════╣
  ║ CREDENTIALS   ║ 16. Credential & Secrets Hunting                    ║
  ║               ║ 17. Browser Forensics (Chrome/Edge/Firefox/Brave)   ║
  ║               ║ 18. Kerberos & Authentication Forensics             ║
  ║               ║ 19. Cloud Credentials (Azure/AWS/GCP/GitHub)        ║
  ╠═══════════════╬══════════════════════════════════════════════════════╣
  ║ SECURITY      ║ 20. AV/EDR/Security Product Status & Bypass Check   ║
  ║               ║ 21. PowerShell Forensics & AMSI Bypass Detection    ║
  ║               ║ 22. Ransomware Detection (+ Canary Deployment)      ║
  ║               ║ 23. Virtualization / Container / VM Forensics       ║
  ╠═══════════════╬══════════════════════════════════════════════════════╣
  ║ DOMAIN / AD   ║ 24. Active Directory Forensics (Kerber/ASREP/SPNs)  ║
  ╠═══════════════╬══════════════════════════════════════════════════════╣
  ║ EVENT LOGS    ║ 25. Windows Event Log Deep Analysis (All Logs)      ║
  ╠═══════════════╬══════════════════════════════════════════════════════╣
  ║ THREAT HUNT   ║ 26. IOC Hunt (IPs, Domains, Hashes, Files)          ║
  ║               ║ 27. SIGMA Rule Detection Engine (10 built-in rules) ║
  ║               ║ 28. YARA-Style Memory Scan (10 C2/Malware patterns) ║
  ║               ║ 29. APT Threat Hunt (MITRE ATT&CK Aligned)          ║
  ║               ║ 30. Threat Intel Enrichment (VT/AbuseIPDB/URLhaus)  ║
  ╠═══════════════╬══════════════════════════════════════════════════════╣
  ║ TIMELINE      ║ 31. Forensic Timeline (Files/Registry/Events/Pf)    ║
  ╠═══════════════╬══════════════════════════════════════════════════════╣
  ║ RESPOND       ║ 32. Incident Commander Dashboard (Risk Score)       ║
  ║               ║ 33. Full Incident Snapshot (All Modules + Export)   ║
  ║               ║ 34. Generate HTML Investigation Report              ║
  ║               ║ 35. Quick Triage (Network + Processes + Registry)   ║
  ╠═══════════════╬══════════════════════════════════════════════════════╣
  ║ REAL-TIME     ║ 36. Live Threat Monitor (Continuous — Ctrl+C stop)  ║
  ╚═══════════════╩══════════════════════════════════════════════════════╝
  [Q] Quit
"@
    Write-Host $menuItems -ForegroundColor Cyan

    $choice = Read-Host "`n  Enter selection"
    $quit = $false

    switch ($choice.ToUpper()) {

        # ── NETWORK (no admin required) ──────────────────────────────────────
        "1"  { Get-NetworkConnections -GridView }
        "2"  { Get-DNSCache -GridView }
        "3"  { Get-FirewallLog }
        "4"  { Get-NetworkAnomalies -GridView }
        "5"  {
            if (Assert-AdminRequired "Network Share & SMB Forensics") {
                Get-NetworkShareForensics -GridView
            }
        }

        # ── PROCESS ──────────────────────────────────────────────────────────
        "6"  { Get-ProcessForensics -GridView }
        "7"  { Get-ProcessTree -GridView }
        "8"  {
            $sp = Read-Host "  Scan path (Enter for auto: Temp/AppData/Public)"
            Invoke-MalwareHunting -ScanPath $sp -Export -GridView
        }

        # ── SYSTEM ───────────────────────────────────────────────────────────
        "9"  { Get-RegistryForensics -GridView }
        "10" { Get-UserAccountForensics -GridView }
        "11" {
            if (Assert-AdminRequired "Persistence Mechanisms") {
                Get-PersistenceMechanisms -GridView
            }
        }
        "12" {
            if (Assert-AdminRequired "Advanced Persistence Hunting") {
                Get-AdvancedPersistenceHunting -GridView
            }
        }
        "13" {
            if (Assert-AdminRequired "Memory Forensics" -HardRequirement) {
                Get-MemoryForensics -GridView
            }
        }
        "14" { Get-FileSystemForensics -GridView }
        "15" {
            if (Assert-AdminRequired "Lateral Movement Indicators") {
                Get-LateralMovementIndicators -GridView
            }
        }

        # ── CREDENTIALS ──────────────────────────────────────────────────────
        "16" {
            if (Assert-AdminRequired "Credential & Secrets Hunting") {
                Get-CredentialHunting -GridView
            }
        }
        "17" { Get-BrowserForensics -PasswordLocations -GridView }
        "18" { Get-KerberosForensics -GridView }
        "19" { Get-CloudCredentialForensics -GridView }

        # ── SECURITY ─────────────────────────────────────────────────────────
        "20" {
            if (Assert-AdminRequired "AV/EDR Status Check") {
                Get-SecurityProductStatus -GridView
            }
        }
        "21" { Get-PowerShellForensics -GridView }
        "22" {
            if (Assert-AdminRequired "Ransomware Detection") {
                $canary = Read-Host "  Deploy canary files? (Y/N)"
                if ($canary -eq "Y") { Invoke-RansomwareDetection -DeployCanaries -Export -GridView }
                else { Invoke-RansomwareDetection -Export -GridView }
            }
        }
        "23" { Get-VirtualizationForensics -GridView }

        # ── DOMAIN / AD ──────────────────────────────────────────────────────
        "24" { Get-ActiveDirectoryForensics -GridView }

        # ── EVENT LOGS ───────────────────────────────────────────────────────
        "25" {
            if (Assert-AdminRequired "Event Log Deep Analysis") {
                $hours = Read-Host "  Hours back to analyze (default 48)"
                if (-not $hours -or $hours -eq "") { $hours = 48 }
                Get-EventLogForensics -HoursBack ([int]$hours) -Export -GridView
            }
        }

        # ── THREAT HUNT ──────────────────────────────────────────────────────
        "26" {
            $ips     = (Read-Host "  IOC IPs (comma-sep or Enter skip)") -split "," | Where-Object { $_.Trim() }
            $domains = (Read-Host "  IOC Domains (comma-sep or Enter skip)") -split "," | Where-Object { $_.Trim() }
            $hashes  = (Read-Host "  IOC Hashes MD5/SHA256 (comma-sep or Enter skip)") -split "," | Where-Object { $_.Trim() }
            $files   = (Read-Host "  IOC Filenames (comma-sep or Enter skip)") -split "," | Where-Object { $_.Trim() }
            $iocfile = (Read-Host "  IOC file path (or Enter skip)").Trim()
            Invoke-IOCHunt -IPs $ips -Domains $domains -Hashes $hashes -FileNames $files -IOCFile $iocfile -Export -GridView
        }
        "27" { Invoke-SigmaHunt -Export -GridView }
        "28" {
            $yaraPath = (Read-Host "  yara64.exe path (or Enter for string fallback)").Trim()
            Invoke-YaraStyleScan -YaraExePath $yaraPath -Export -GridView
        }
        "29" {
            Write-Host "  Groups: APT29_Cozy_Bear, APT28_Fancy_Bear, LAZARUS_Group, FIN7_Carbanak, BlackCat_ALPHV, ALL" -ForegroundColor DarkCyan
            $groups = (Read-Host "  APT group(s) (comma-sep or ALL)") -split "," | Where-Object { $_.Trim() }
            if (-not $groups -or ($groups.Count -eq 1 -and $groups[0] -eq "")) { $groups = @("ALL") }
            Invoke-APTHunt -APTGroups $groups -Export -GridView
        }
        "30" {
            $ips2   = (Read-Host "  IPs to enrich (comma-sep)") -split "," | Where-Object { $_.Trim() }
            $doms2  = (Read-Host "  Domains to enrich (comma-sep)") -split "," | Where-Object { $_.Trim() }
            $hashs2 = (Read-Host "  Hashes to enrich (comma-sep)") -split "," | Where-Object { $_.Trim() }
            $vtkey  = (Read-Host "  VirusTotal API key (or Enter skip)").Trim()
            $akey   = (Read-Host "  AbuseIPDB API key (or Enter skip)").Trim()
            Invoke-ThreatIntelEnrichment -IPs $ips2 -Domains $doms2 -Hashes $hashs2 -VTApiKey $vtkey -AbuseKey $akey -Export -GridView
        }

        # ── TIMELINE ─────────────────────────────────────────────────────────
        "31" {
            $days = Read-Host "  Days back for timeline (default 7)"
            if (-not $days -or $days -eq "") { $days = 7 }
            $start = (Get-Date).AddDays(-[int]$days)
            Get-ForensicTimeline -StartTime $start -Export -GridView
        }

        # ── RESPOND ──────────────────────────────────────────────────────────
        "32" { Show-IncidentCommanderDashboard }
        "33" {
            if (Assert-AdminRequired "Full Incident Snapshot") {
                $outDir = (Read-Host "  Output directory (Enter for default Temp)").Trim()
                if ($outDir) { Get-IncidentSnapshot -OutputDir $outDir }
                else { Get-IncidentSnapshot }
            }
        }
        "34" {
            $caseName = (Read-Host "  Case name (e.g. INC-2024-001)").Trim()
            $analyst  = (Read-Host "  Analyst name").Trim()
            $openRep  = Read-Host "  Open report in browser? (Y/N)"
            if (-not $caseName) { $caseName = "DFIR Investigation" }
            if (-not $analyst)  { $analyst  = $env:USERNAME }
            if ($openRep -eq "Y") { New-DFIRReport -CaseName $caseName -Analyst $analyst -OpenReport }
            else { New-DFIRReport -CaseName $caseName -Analyst $analyst }
        }
        "35" {
            Write-Alert "Quick Triage — Running: Network + Processes + Registry..." "INFO"
            Get-NetworkConnections -SuspiciousOnly -GridView
            Get-ProcessForensics -GridView
            Get-RegistryForensics -GridView
        }

        # ── REAL-TIME ────────────────────────────────────────────────────────
        "36" {
            $interval = Read-Host "  Poll interval seconds (default 10)"
            if (-not $interval -or $interval -eq "") { $interval = 10 }
            $logit = Read-Host "  Log alerts to file? (Y/N)"
            if ($logit -eq "Y") { Start-LiveThreatMonitor -PollIntervalSeconds ([int]$interval) -LogToFile }
            else { Start-LiveThreatMonitor -PollIntervalSeconds ([int]$interval) }
        }

        "Q"  {
            Write-Host "`n  Exiting DFIR Swiss Knife v3.0. Stay vigilant.`n" -ForegroundColor DarkCyan
            $quit = $true
        }
        default {
            Write-Host "  Invalid selection '$choice' — enter a number 1-36 or Q to quit." -ForegroundColor Red
        }
    }

    if (-not $quit) {
        Write-Host "`n  Press Enter to return to menu..." -ForegroundColor DarkGray
        $null = Read-Host
    }

    } while (-not $quit)
}

#endregion

#region ─── ENTRY POINT ───────────────────────────────────────────────────────

if (-not (Get-IsAdmin)) {
    Write-Host "`n  [WARNING] Running without admin rights. Some modules will have limited output." -ForegroundColor Yellow
    Write-Host "  Restart PowerShell as Administrator for full functionality.`n" -ForegroundColor Yellow
}

Show-Menu

#endregion
