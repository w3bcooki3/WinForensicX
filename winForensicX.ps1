<#
.SYNOPSIS
WinForensicX - DFIR/EDR Tool
Version: 1.0 (Stability & Rule-Based Hunting Edition)
Author: w3bcooki3
License: MIT
#>

#---------------------------------------------------------------------------
# GLOBAL CONFIGURATION
#---------------------------------------------------------------------------
$Global:AppId = "WinForensicX"
$Global:Version = "1.0"
$Global:Author = "w3bcooki3"
$Global:social = "linkedin.com/in/fnu-rahul"
$Global:ReportDir = Join-Path $env:USERPROFILE "Downloads\WF-Reports"
$Global:AnalysisMode = "Live"
$Global:OfflinePath = ""
if (!(Test-Path $Global:ReportDir)) { New-Item -ItemType Directory -Path $Global:ReportDir | Out-Null }

#---------------------------------------------------------------------------
# UI HELPERS & CORE LOGIC
#---------------------------------------------------------------------------
function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-Notes {
    Clear-Host
    Write-Host "===========================================================================" -ForegroundColor Yellow
    Write-Host "                       WINFORENSICX SYSTEM NOTES                           " -ForegroundColor Yellow
    Write-Host "===========================================================================" -ForegroundColor Yellow
    Write-Host "`n[ REQUIREMENTS ]" -ForegroundColor Cyan
    Write-Host " - PowerShell 5.1 or Core 7+"
    Write-Host " - Administrator Privileges (Highly Recommended for Log Analysis)"
    Write-Host " - CIM/WMI modules enabled (Default on Windows)"
    
    Write-Host "`n[ USE CASES ]" -ForegroundColor Cyan
    Write-Host " - Digital Forensics & Incident Response (DFIR)"
    Write-Host " - Hunting for Advanced Persistent Threats (APTs)"
    Write-Host " - Real-time malware behavior monitoring"
    Write-Host " - Security auditing and persistence detection"
    
    Write-Host "`n[ LEGAL DISCLAIMER ]" -ForegroundColor Red
    Write-Host " This tool is provided for authorized security testing, forensic "
    Write-Host " investigation, and educational purposes only. Unauthorized use "
    Write-Host " against systems without explicit consent is illegal. The author "
    Write-Host " assumes no liability for misuse or damage caused by this script."
    
    Write-Host "`n[ OUTPUTS ]" -ForegroundColor Cyan
    Write-Host " - Reports saved to: $Global:ReportDir"
    Write-Host "===========================================================================" -ForegroundColor Yellow
    Pause
}

function Show-Header {
    param([string]$SubMenu = "MAIN MENU")
    Clear-Host
    $isAdmin = if (Test-IsAdmin) { "ADMIN" } else { "USER" }
    $modeText = if ($Global:AnalysisMode -eq "Live") { "LIVE SYSTEM" } else { "OFFLINE: $Global:OfflinePath" }
    
    $banner = @"
__        ___       _____                             _      __  __ 
\ \      / (_)_ __ |  ___|__  _ __ ___ _ __  ___(_) ___ \ \/ / 
 \ \ /\ / /| | '_ \| |_ / _ \| '__/ _ \ '_ \/ __| |/ __| \  /  
  \ V  V / | | | | |  _| (_) | | |  __/ | | \__ \ | (__  /  \  
   \_/\_/  |_|_| |_|_|  \___/|_|  \___|_| |_|___/_|\___|/_/\_\ 

   Author: $($Global:Author) | Version: $($Global:Version) | Social: $($Global:social)
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "---------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host " [N] View Usage Notes & Disclaimer | [Q] Exit Prompt " -ForegroundColor Yellow
    Write-Host "---------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host " LOCATION: $SubMenu " -BackgroundColor Cyan -ForegroundColor Black
    Write-Host " MODE:     $modeText" -ForegroundColor White
    Write-Host "---------------------------------------------------------------------------" -ForegroundColor Gray
}

function Show-Status {
    param([string]$Message, [string]$Type = "Info")
    $color = switch ($Type) {
        "Info" { "Cyan" }; "Warning" { "Yellow" }; "Error" { "Red" }; "Success" { "Green" }; Default { "White" }
    }
    Write-Host "[$($Type.ToUpper())] $Message" -ForegroundColor $color
}

function Assert-Admin {
    if (-not (Test-IsAdmin)) {
        Show-Status "CRITICAL: This module requires Administrator privileges." "Error"
        Pause; return $false
    }
    return $true
}

function Get-WFEvent {
    param($FilterHashtable, $LogName)
    if ($Global:AnalysisMode -eq "Offline") {
        $path = Join-Path $Global:OfflinePath "$LogName.evtx"
        if (Test-Path $path) {
            return Get-WinEvent -Path $path -FilterHashtable $FilterHashtable -ErrorAction SilentlyContinue
        } else {
            Show-Status "Offline log not found: $path" "Warning"
            return @()
        }
    } else {
        if ($LogName -eq 'Security' -and -not (Test-IsAdmin)) {
            Show-Status "Access Denied to Security Logs. Run as Admin." "Error"
            return @()
        }
        return Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction SilentlyContinue
    }
}

#---------------------------------------------------------------------------
# MODULE: DEEP MEMORY & PROCESS FORENSICS
#---------------------------------------------------------------------------
function Invoke-ProcessMgmt {
    do {
        Show-Header "MAIN MENU > PROCESS & MEMORY"
        Write-Host "[1] Advanced Process Inventory (WMI + CommandLines)"
        Write-Host "[2] Detect Process Injection (Suspicious Threads/RWX)"
        Write-Host "[3] Identify LotL (Living-off-the-Land) Abuse"
        Write-Host "[4] Find Unsigned Modules/DLLs in Memory"
        Write-Host "[5] Analyze Process Tree (Parent/Child Hierarchies)"
        Write-Host "[6] Terminate Process Tree"
        Write-Host "[0] Back to Main Menu"

        $choice = Read-Host "`nWF-Process >"
        switch ($choice) {
            "n" { Show-Notes }
            "1" { 
                Show-Status "Collecting WMI process data..." "Info"
                $procs = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId, CommandLine, ExecutablePath
                if ($null -eq $procs) { Show-Status "Failed to retrieve process inventory." "Error"; Pause }
                else { $procs | Out-GridView -Title "WinForensicX - Process Inventory" }
            }
            "2" {
                if (-not (Assert-Admin)) { continue }
                Show-Status "Scanning for ghosted processes..." "Warning"
                $sus = Get-Process | Where-Object { $_.Path -eq $null -and $_.Id -gt 4 } | Select-Object Id, ProcessName
                if (-not $sus) { Show-Status "No obvious injection patterns found." "Success"; Pause }
                else { $sus | Out-GridView }
            }
            "3" {
                Show-Status "Scanning for LotL abuse..." "Info"
                $lotlList = @("certutil", "mshta", "bitsadmin", "regsvr32", "scrcons", "wmic", "vssadmin", "powershell")
                $foundLotl = Get-CimInstance Win32_Process | Where-Object { $lotlList -contains $_.Name.Replace(".exe","") }
                if ($foundLotl) { $foundLotl | Out-GridView } else { Show-Status "No LotL binaries currently active." "Success"; Pause }
            }
            "5" {
                $allProcs = Get-CimInstance Win32_Process
                $allProcs | ForEach-Object {
                    $ParentID = $_.ParentProcessId
                    $parent = $allProcs | Where-Object { $_.ProcessId -eq $ParentID }
                    [PSCustomObject]@{ PID = $_.ProcessId; Name = $_.Name; ParentName = if($parent){$parent.Name}else{"N/A"}; CommandLine = $_.CommandLine }
                } | Out-GridView
            }
            "0" { return }
        }
    } while ($true)
}

#---------------------------------------------------------------------------
# MODULE: USER & GROUP MANAGEMENT
#---------------------------------------------------------------------------
function Invoke-UserMgmt {
    do {
        Show-Header "MAIN MENU > USER MANAGEMENT"
        Write-Host "[1] List All Local Users"
        Write-Host "[2] Audit Administrators Group Members"
        Write-Host "[3] Find Disabled/Locked Accounts"
        Write-Host "[4] User Creation Events (4720) [Req: Admin]"
        Write-Host "[0] Back"

        $choice = Read-Host "`nWF-User >"
        switch ($choice) {
            "n" { Show-Notes }
            "1" { Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description | Out-GridView }
            "2" { Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource, Class | Out-GridView }
            "3" { Get-LocalUser | Where-Object { $_.Enabled -eq $false } | Out-GridView }
            "4" {
                if (-not (Assert-Admin)) { continue }
                $events = Get-WFEvent -FilterHashtable @{LogName='Security'; ID=4720} -LogName 'Security'
                if ($events) { $events | Out-GridView } else { Show-Status "No user creation events found." "Info"; Pause }
            }
            "0" { return }
        }
    } while ($true)
}

#---------------------------------------------------------------------------
# MODULE: EXTERNAL RULE HUNTING (Sigma/Yara Placeholder)
#---------------------------------------------------------------------------
function Invoke-RuleHunter {
    Show-Header "MAIN MENU > RULE HUNTING"
    $rulePath = Read-Host "Enter path to Sigma (.yml) or YARA (.yar) rule file"
    
    if ($rulePath -eq "n") { Show-Notes; return }
    if (-not (Test-Path $rulePath)) {
        Show-Status "Rule file not found at $rulePath" "Error"
        Pause; return
    }

    $ext = [System.IO.Path]::GetExtension($rulePath).ToLower()
    $ruleContent = Get-Content $rulePath -Raw

    if ($ext -eq ".yml" -or $ext -eq ".yaml") {
        Show-Status "Parsing Sigma Rule: $([System.IO.Path]::GetFileName($rulePath))" "Info"
        if ($ruleContent -match "selection:") {
            Show-Status "Sigma selection pattern detected. Simulating hunt..." "Warning"
            Show-Status "HUNT RESULT: Under development. Use Sigma-to-PowerShell (sigmac) for direct conversion." "Info"
        }
    } elseif ($ext -eq ".yar" -or $ext -eq ".yara") {
        Show-Status "YARA Rule detected. Checking for strings in memory..." "Info"
        $strings = $ruleContent -split "`n" | Where-Object { $_ -match '\"(.*)\"' } | ForEach-Object { $Matches[1] }
        if ($strings) {
            Show-Status "Scanning for strings: $($strings -join ', ')" "Warning"
            Get-CimInstance Win32_Process | Where-Object { $cmd = $_.CommandLine; $strings | ForEach-Object { $cmd -match $_ } } | Out-GridView -Title "YARA String Match"
        }
    } else {
        Show-Status "Unsupported file extension: $ext" "Error"
    }
    Pause
}

#---------------------------------------------------------------------------
# MODULE: APT HUNTING (Sigma/Yara/IOC)
#---------------------------------------------------------------------------
function Invoke-APTHunt {
    do {
        Show-Header "MAIN MENU > APT & IOC HUNTING"
        Write-Host "[1] Scan for Suspicious Web Shells (Common Paths)"
        Write-Host "[2] Search for IOC (IP / Domain / String)"
        Write-Host "[3] Audit WMI Persistence (Common APT Technique)"
        Write-Host "[4] Sigma-Lite: Hunt for Encoded PowerShell"
        Write-Host "[5] Import External Sigma/YARA Rule File" -ForegroundColor Yellow
        Write-Host "[0] Back"

        $choice = Read-Host "`nWF-Hunt >"
        switch ($choice) {
            "n" { Show-Notes }
            "1" {
                Show-Status "Scanning web dirs for .aspx, .php, .jsp..." "Warning"
                $paths = @("C:\inetpub\wwwroot", "C:\xampp\htdocs", "C:\Windows\Temp", "$env:TEMP")
                $found = @()
                foreach($p in $paths) {
                    if (Test-Path $p) { 
                        $res = Get-ChildItem $p -Recurse -Include *.aspx,*.php,*.jsp -ErrorAction SilentlyContinue
                        if ($res) { $found += $res }
                    }
                }
                if ($found) { $found | Out-GridView } else { Show-Status "No web shells detected in common paths." "Success"; Pause }
            }
            "2" {
                $ioc = Read-Host "Enter IP, Domain, or Hash to hunt"
                if ($ioc -eq "n") { Show-Notes; continue }
                if ([string]::IsNullOrWhiteSpace($ioc)) { return }
                Show-Status "Searching accessible logs for: $ioc" "Info"
                
                $allLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue
                $results = foreach($l in $allLogs) {
                    if (-not (Test-IsAdmin) -and ($l.LogName -match "Security|Firewall|Policy")) { continue }
                    try {
                        Get-WinEvent -LogName $l.LogName -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {$_.Message -match $ioc}
                    } catch { $null }
                }
                
                if ($results) { $results | Out-GridView -Title "IOC Hits for $ioc" } else { Show-Status "No IOC matches found in last 100 events per log." "Info"; Pause }
            }
            "3" {
                if (-not (Assert-Admin)) { continue }
                Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Out-GridView
            }
            "4" {
                Show-Status "Hunting for base64 encoded commands in logs..." "Warning"
                $events = Get-WFEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -LogName 'Microsoft-Windows-PowerShell/Operational'
                $hits = $events | Where-Object { $_.Message -match "JAB|SUm|aWEX|dnM" }
                if ($hits) { $hits | Out-GridView } else { Show-Status "No obvious encoded PowerShell found." "Success"; Pause }
            }
            "5" { Invoke-RuleHunter }
            "0" { return }
        }
    } while ($true)
}

#---------------------------------------------------------------------------
# MODULE: NETWORK & C2 HUNTING
#---------------------------------------------------------------------------
function Invoke-NetworkMgmt {
    do {
        Show-Header "MAIN MENU > NETWORK & C2"
        Write-Host "[1] Established Connections"
        Write-Host "[2] Hunt for Hidden Listeners"
        Write-Host "[3] Audit Hosts File & Proxy"
        Write-Host "[4] DNS Beaconing Search"
        Write-Host "[5] Active Firewall Rules"
        Write-Host "[0] Back"

        $choice = Read-Host "`nWF-Network >"
        switch ($choice) {
            "n" { Show-Notes }
            "1" { Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort | Out-GridView }
            "2" { Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -gt 1024 } | Out-GridView }
            "4" {
                $dns = Get-DnsClientCache | Where-Object { $_.Name -match '\.(top|xyz|pw|icu|tk)$' -or $_.Name.Length -gt 50 }
                if ($dns) { $dns | Out-GridView } else { Show-Status "No suspicious DNS patterns found in cache." "Success"; Pause }
            }
            "0" { return }
        }
    } while ($true)
}

#---------------------------------------------------------------------------
# MODULE: SECURITY STATUS & AUDIT
#---------------------------------------------------------------------------
function Invoke-SecurityAudit {
    Show-Header "MAIN MENU > SECURITY AUDIT"
    Show-Status "Performing Security Configuration Audit..." "Info"
    
    try {
        $defender = Get-MpComputerStatus
        $results = New-Object PSObject
        $results | Add-Member -MemberType NoteProperty -Name "Defender_RealTime" -Value $defender.RealTimeProtectionEnabled
        $results | Add-Member -MemberType NoteProperty -Name "UAC_Level" -Value (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).ConsentPromptBehaviorAdmin
        $results | Add-Member -MemberType NoteProperty -Name "PS_ScriptBlockLogging" -Value (Test-Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging")
        $results | Add-Member -MemberType NoteProperty -Name "Firewall_Profile" -Value (Get-NetFirewallProfile -PolicyStore ActiveStore).Name
        $results | Format-List
    } catch {
        Show-Status "Error retrieving Defender status. Cmdlet might be missing or restricted." "Error"
    }
    
    Show-Status "Checking for Defender Tampering Events (ID 5001)..." "Warning"
    $tamper = Get-WFEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=5001} -LogName 'Microsoft-Windows-Windows Defender/Operational'
    if ($tamper) { $tamper | Select-Object TimeCreated, Message | Out-GridView -Title "Defender Tamper Alerts" }
    
    Pause
}

#---------------------------------------------------------------------------
# MODULE: LIVE MALWARE BEHAVIOR MONITORING
#---------------------------------------------------------------------------
function Invoke-MalwareMonitor {
    Show-Header "MALWARE MONITOR"
    Write-Host "LIVE MALWARE BEHAVIOR MONITOR (Real-time)" -ForegroundColor Magenta
    Write-Host "Press any key to stop monitoring safely." -ForegroundColor Yellow
    
    $baseline = Get-Process | Select-Object -ExpandProperty Id
    Show-Status "Baseline established ($($baseline.Count) processes). Watching..." "Success"

    while ($true) {
        $keyAvailable = $false
        try {
            if ($Host.UI.RawUI.KeyAvailable) { $keyAvailable = $true }
        } catch {
            Start-Sleep -Seconds 2
        }

        if ($keyAvailable) { 
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-Status "Monitoring stopped by user." "Info"
            Pause; break 
        }
        
        $current = Get-Process
        foreach ($p in $current) {
            if ($p.Id -notin $baseline) {
                $time = Get-Date -Format "HH:mm:ss"
                Write-Host "[$time] NEW PROCESS: $($p.ProcessName) (PID: $($p.Id))" -ForegroundColor Red
                $baseline += $p.Id
                try {
                    $details = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue
                    Write-Host "      > Cmd: $($details.CommandLine)" -ForegroundColor Gray
                } catch {}
            }
        }
        Start-Sleep -Milliseconds 500
    }
}

#---------------------------------------------------------------------------
# MAIN PROGRAM LOOP
#---------------------------------------------------------------------------
function Main-Menu {
    do {
        Show-Header "MAIN MENU"
        Write-Host "[1] Process & Memory Forensics"
        Write-Host "[2] Network & C2 Hunting"
        Write-Host "[3] User & Account Management" -ForegroundColor Cyan
        Write-Host "[4] APT & IOC Hunting (Sigma-Lite)" -ForegroundColor Yellow
        Write-Host "[5] SIEM: Event Log Analysis (Live/Offline)"
        Write-Host "[6] Live Malware Behavior Monitor" -ForegroundColor Magenta
        Write-Host "[7] Security Status & Audit"
        Write-Host "[8] Toggle Analysis Mode (Live / Offline .evtx)"
        Write-Host "[9] Persistence & Artifact Audit"
        Write-Host "[Q] Exit"

        $input = Read-Host "`nWinForensicX >"
        
        switch ($input) {
            "n" { Show-Notes }
            "1" { Invoke-ProcessMgmt }
            "2" { Invoke-NetworkMgmt }
            "3" { Invoke-UserMgmt }
            "4" { Invoke-APTHunt }
            "5" { 
                do {
                    Show-Header "MAIN MENU > SIEM LOGS"
                    Write-Host "[1] Process Timeline (4688)"
                    Write-Host "[2] PowerShell Audit (4104)"
                    Write-Host "[3] Auth / Logons (4624)"
                    Write-Host "[0] Back"
                    $s = Read-Host "WF-SIEM >"
                    if ($s -eq "n") { Show-Notes }
                    if ($s -eq "1") { 
                        if ($Global:AnalysisMode -eq "Live" -and -not (Assert-Admin)) { continue }
                        $ev = Get-WFEvent -FilterHashtable @{LogName='Security'; ID=4688; StartTime=(Get-Date).AddHours(-24)} -LogName 'Security'
                        $ev | ForEach-Object { [xml]$xml = $_.ToXml(); [PSCustomObject]@{Time=$_.TimeCreated; Cmd=$xml.Event.EventData.Data[8].'#text'} } | Out-GridView
                    }
                    if ($s -eq "0") { break }
                } while ($true)
            }
            "6" { Invoke-MalwareMonitor }
            "7" { Invoke-SecurityAudit }
            "8" { 
                if ($Global:AnalysisMode -eq "Live") {
                    $p = Read-Host "Path to .evtx folder"
                    if ($p -eq "n") { Show-Notes }
                    elseif (Test-Path $p) { $Global:OfflinePath = $p; $Global:AnalysisMode = "Offline" }
                } else { $Global:AnalysisMode = "Live" }
            }
            "9" { Get-ScheduledTask | Where-Object {$_.Author -notmatch 'Microsoft'} | Out-GridView }
            "q" { exit }
        }
    } while ($true)
}

Main-Menu
